# Linux 네트워크 메모

현재 Rust Core는 Linux TUN adapter와 UDP transport를 제공한다. network namespace 연동, IP forwarding, nftables
MASQUERADE, route 관리, DNS 설정·복원, IPv6 주소, endpoint exception route는 library의 자동 부작용이 아니라 배포 작업이다.

`LinuxTunDevice`는 `/dev/net/tun` descriptor를 소유하고 명시적인 `TunnelDevice::close`와 `Drop` 양쪽에서 닫는다.
`TUNSETIFF`를 호출하기 전에 Linux interface name을 검사하며 empty, embedded-NUL, `IFNAMSIZ` 초과 이름을 로컬에서 거부한다. 이미
사용 중이거나 접근할 수 없는 이름은 kernel·권한 오류로 남기고 process를 종료하지 않는 제한된 `DeviceError::Io`로 반환한다.

## 초기 네트워크 값

- VPN IPv4 대역: `10.80.0.0/16`
- server 주소: `10.80.0.1`
- UDP port: `51820`
- tunnel MTU: `1400`
- IPv6 대역: `fd80:1234:5678::/64`

Rust Core는 `TunnelNetworkConfig`를 통해 이 값을 노출한다. 기본 policy는 dual-stack이며 UDP port `51820`을 사용한다. 암호화
payload 예산은 설정 MTU에서 `1400 - 24-byte header - 16-byte AEAD tag = 1360 bytes`로 계산한다. 잘못된 server 주소,
0인 port, IPv6 안전 최소값보다 작은 MTU는 engine 시작 전에 거부한다.

`MtuBudget::validate_inner_packet`은 이 암호화 payload 예산에 맞춰 완전한 IPv4/IPv6 packet을 검증한다. 주소 family,
header·전체 길이, IPv4 header checksum을 확인하고 dual-stack이 꺼져 있으면 IPv6를 거부한다. fragmentation과 reassembly는
초기 범위 밖이므로 호출자가 계산된 예산을 넘는 packet을 암호화 전에 거부해야 한다.

`validate_inner_ip_packet_from_tunnel`은 source가 설정된 tunnel 대역에 속하는지 확인한다. 인증된 session에 Peer 할당이 있으면
`validate_inner_ip_packet_from_peer`를 사용해 할당된 IPv4/IPv6와 정확히 일치하는지 추가 확인한다. 외부 NAT와 다중 client
namespace 동작은 별도 integration test가 필요하다.

양쪽 주소 family의 payload 한도는 설정 MTU에서 동일하게 계산하므로 고정된 IPv4 전용 값이 아니다. IPv6 식별과 dual-stack 예산은 Core test로
검증하며, path-MTU discovery, ICMP Packet Too Big 처리, host별 측정은 integration 작업으로 남긴다.

`PathMtuObservation`은 그 integration 경계다. 권한 있는 adapter가 interface MTU, 측정 path MTU, 선택적인 ICMP Packet
Too Big/fragmentation-needed MTU를 전달할 수 있다. Core는 IPv6 최소값보다 작거나 interface보다 큰 값을 거부하고
`effective_tunnel_mtu()`로 가장 작은 안전값을 노출한다. probe와 error-queue parsing, 환경별 benchmark는 adapter가 담당한다.

## route·DNS·Kill Switch 경계

full-tunnel route를 활성화하기 전 UDP endpoint로 가는 route를 보존한다. firewall rule을 바꾸기 전 기존 rule을 snapshot하고
rollback 경로를 제공한다. Rust library는 선언적인 Kill Switch plan만 만들며 rule 적용·rollback은 권한 있는 adapter가 담당한다.

Configuration validation은 route, firewall, DNS, NAT rule을 적용하지 않는다. 이 작업은 privileged
platform/deployment layer에 남기며 endpoint exception route와 rollback 경로를 보존해야 한다.

`DnsPolicy`는 IPv4/IPv6 upstream과 search domain의 순서를 검증한다. 미래 resolver 구현을 위해 UDP, TCP, DoT, DoH
transport를 표현할 수 있지만 `LinuxDnsPlan`은 현재 host adapter가 지원하는 `resolvectl` 형식인 UDP/TCP 53만 출력한다.
DoT/DoH 값은 configuration model placeholder이며 전용 adapter와 integration test 전에는 활성 transport로 광고하지
않는다.

Tunnel policy 적용 전 현재 resolver 주소와 domain을 `DnsSnapshot`에 저장한다. `LinuxDnsPlan::restore_commands`는
link를 먼저 되돌린 뒤 snapshot 값을 복원하고 cache를 flush한다. Rust library는 argv-safe command record만 반환하며 host
resolver를 직접 바꾸지 않는다. 이 restore plan이 disconnect 경로다.

## UDP와 session endpoint

UDP transport에 pinned remote endpoint가 있으면 protocol decoding 전에 수신 datagram의 sender 주소를 검사한다. 초기
admission 중인 server는 아직 endpoint가 없을 수 있으며 인증된 handshake가 Peer를 확정한 뒤 주소를 pin해야 한다.

Loopback transport와 engine test는 일반적인 UDP request/response와 설정된 최대 크기 datagram을 다룬다. 다중 client
admission, public-IP egress, NAT, 두 process namespace 검증은 배포 수준 test다.

`SessionEndpointTable`은 다중 session 경계를 제공한다. 인증된 admission에서 `pin`을 한 번 호출하고 수신 datagram마다 session
ID에 대한 `validate`를 통과해야 한다. 검증 중 endpoint를 바꾸지 않으며 새 인증 handshake와 server identity 확인을 마친 뒤
`rebind_after_authenticated_handshake`를 호출한다. session 제거 시 endpoint mapping도 제거하고, table은 설정된
session 한도 안에서 bounded 상태를 유지한다.

Transport loop는 `UdpTransport::close`를 공통 취소 신호로 사용한다. close 뒤 `is_closed`는 true이고 `send`·`receive`는
`TransportError::Closed`를 반환하므로 무한 재시도 대신 loop를 종료한다. receive timeout은 일시적인 I/O 결과다.

Malformed datagram은 현재 receive 시도에만 영향을 준다. typed protocol error를 반환하고 device에는 쓰지 않으며 같은 socket에서
다음 datagram을 계속 받을 수 있다. process-level loop가 logging, metrics, 제한된 retry 정책을 소유하며 packet decode
실패만으로 process를 종료하지 않는다.

## Linux route plan

`LinuxNetworkPlan`은 검증된 policy와 privileged layer 사이의 경계다. server interface 설정, IPv4 MASQUERADE, 선택적
IPv6 주소, cleanup을 위한 argv-safe `ip`, `sysctl`, `nft` command record를 만들지만 직접 실행하지 않는다. interface
name은 안전한 Linux device-name 문자만 허용하고 VPN 주소 안의 endpoint는 routing loop 방지를 위해 거부한다.

`LinuxClientRoutePlan`은 physical gateway를 통한 endpoint host route를 먼저 추가한 다음 TUN interface를 통한 IPv4
default route와 dual-stack policy의 IPv6 default route를 추가한다. cleanup은 자신이 추가한 route만 제거한다. 기존 route
snapshot 복원과 중단 process 복구는 privileged caller의 책임이다.

physical network가 바뀌면 `LinuxClientRoutePlan::rebind_endpoint`가 초기 생성과 동일한 family·interface·tunnel 주소
검증으로 endpoint exception route를 다시 만든다. reconnect 전에 새 plan을 적용해야 한다.

`LinuxClientNetworkPlan`은 검증된 IPv4/IPv6 주소를 TUN interface에 추가하고, 주소 설정을 routing보다 먼저 수행한 뒤 역순
cleanup을 출력한다.

## Windows 네트워크 계획

`WindowsClientNetworkPlan`은 Wintun adapter를 실제로 변경하지 않고 Windows host adapter가 실행할
`netsh`·`route` 명령의 argv-safe record를 만든다. interface friendly name은 따옴표와 control character를 거부하고,
tunnel·physical interface index, endpoint port, endpoint와 physical gateway의 address family, DNS 주소를 실행 전에 검증한다.

적용 계획은 tunnel IPv4 주소와 netmask를 설정한 뒤 physical gateway를 통한 endpoint 예외 경로, tunnel interface를 통한 IPv4
default route, IPv4/IPv6 DNS 순서로 구성한다. IPv4 endpoint는 `route` host route를 사용하고 IPv6 endpoint는 `netsh interface
ipv6` route를 사용한다. rollback 계획은 endpoint와 default route를 제거하고 주소와 사용한 DNS family를 DHCP로 되돌린다.

이 계획은 명령의 구성과 검증을 담당하는 Core 경계이며, 권한 상승, 기존 route/DNS snapshot 보존, 실제 명령 실행, 중단 process
복구는 Windows privileged adapter의 책임이다. Windows host에서 adapter가 실제로 생성되고 인터넷 연결이 유지되는지는 전용
integration test에서 검증해야 한다.

DNS upstream은 IPv4 전용 문자열이 아니라 IP 주소로 표현한다. `DnsPolicy::upstreams_for_family`는 순서를 바꾸거나 family 사이에서
잘못 fallback하지 않고 IPv6·IPv4 resolver를 고르게 한다. 외부 DNS-leak test와 OS별 resolver 동작은 각 platform adapter가
수행해야 한다.

session policy는 인증된 keepalive를 transport adapter의 NAT mapping refresh 신호로 취급한다.
`SessionPolicy::keepalives_per`는 battery/radio 예산을 위한 bounded estimate를 제공하고, suspend 시 작업 억제는
adapter가 담당한다. reconnect는 기본 `ReconnectDataPolicy::Drop` 또는 제한된 packet/byte 예산을 사용할 수 있으며 state
machine은 packet 내용을 저장하지 않는다.

`LinuxRouteSnapshot`은 VPN 이전 IPv4/IPv6 default route와 physical endpoint route를 저장한다.
`LinuxClientRoutePlan::cleanup_commands_with_snapshot`은 VPN route를 먼저 제거하고 검증된 snapshot만 복원한다.
gateway family가 route와 맞지 않거나 IPv4-only plan에 IPv6 route를 넣으면 snapshot을 거부한다.

`TunnelNetworkConfig::kill_switch_plan`은 `kill_switch`가 명시적으로 활성화된 경우에만 plan을 반환한다.
`LinuxKillSwitchPlan`은 default drop 정책의 선택적 nftables output chain을 만든다. loopback, tunnel interface,
established/related traffic, physical interface를 통한 VPN UDP endpoint는 허용한다. rollback은 전용 nftables
table을 삭제한다. plan을 실제 적용하는 adapter는 atomic 적용과 비정상 종료 복구용 rollback command 보관을 담당한다.

개발 중 Kill Switch는 opt-in으로 유지해 선언적 plan이 개발자 host firewall을 실수로 바꾸지 않게 한다. production VPN release
gate에서는 privileged Linux integration test로 endpoint 도달성, default-drop, rollback, 중단 process 복구를 확인해야
한다.

`ClientAddressPool`은 `10.80.0.2`와 `fd80:1234:5678::2`부터 client 주소 쌍을 할당하고 server·network/broadcast
주소를 건너뛴다. 두 family는 한 단위로 반환하며 capacity 소진은 부분 쌍이 caller로 나가기 전에 보고한다.

management configuration은 payload byte 8을 명시적인 NAT66 policy로 예약한다. dual-stack과 함께 활성화하면
`LinuxNetworkPlan`이 IPv6 MASQUERADE rule을 출력한다. 기본값은 비활성으로 두어 routed IPv6를 선택할 때 NAT가 조용히 적용되지 않게
한다.

UDP 장애 정책은 [`udp-failure-policy.md`](./udp-failure-policy.md)에 따른다. datagram loss는 무한 재전송하지 않고
session timeout과 제한된 reconnect로 처리한다. Core 재시작은 승인 상태만 복원하고 이전 session key와 counter는 복원하지 않는다.

`DnsCache`는 query 원문 대신 caller가 계산한 opaque fingerprint만 key로 사용하고 response TTL을 1초~24시간으로 제한한다.
cache 용량은 고정되어 있으며 만료 response는 조회 전에 제거한다. 실제 DoT/DoH adapter가 연결되기 전까지 Linux 기본 적용 계층은 UDP/TCP 53만
사용한다.

## UDP transport 복구

`UdpTransport::rebind`는 교체할 local endpoint를 먼저 bind한 뒤 active socket을 교체하고 pinned remote endpoint를
보존한다. `TransportError`는 `WouldBlock`, `Interrupted`, `TimedOut`을 일시 오류로 분류하므로 reconnect loop가
session을 영구 실패로 처리하지 않고 재시도할 수 있다.
