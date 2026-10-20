# Linux networking notes

The current Rust core provides a Linux TUN adapter and UDP transport. Network
namespace integration, IP forwarding, nftables MASQUERADE, route management,
DNS setup/restoration, IPv6 addressing, and endpoint exception routes are
deployment work rather than automatic side effects of the library.

`LinuxTunDevice` owns its `/dev/net/tun` descriptor and closes it from both the
explicit `TunnelDevice::close` path and `Drop`. The adapter validates the
requested Linux interface name before issuing `TUNSETIFF`; empty, embedded-NUL,
and `IFNAMSIZ`-overflowing names are rejected locally. Names already occupied
or inaccessible remain kernel/permission errors and are returned as a bounded
`DeviceError::Io` rather than terminating the process.

The intended initial values are:

- VPN IPv4 range: `10.80.0.0/16`
- server address: `10.80.0.1`
- UDP port: `51820`
- tunnel MTU: `1400`
- IPv6 range: `fd80:1234:5678::/64`

The Rust core exposes these values through `TunnelNetworkConfig`. Its default
policy is dual-stack and uses UDP port `51820`. The encrypted payload budget
is derived from the configured MTU: `1400 - 24-byte header - 16-byte AEAD tag
= 1360 bytes`. Invalid server addresses, zero ports, and MTUs below the
IPv6-safe minimum are rejected before an engine starts.

`MtuBudget::validate_inner_packet` validates a complete IPv4 or IPv6 packet
against that encrypted payload budget. It identifies the address family,
checks exact header and total lengths, verifies the IPv4 header checksum, and
rejects IPv6 when dual-stack mode is disabled. Packet fragmentation and
reassembly are outside the initial scope; callers should reject packets above
the derived budget before encryption.
`validate_inner_ip_packet_from_tunnel` adds the server-side source-address
boundary: IPv4 and IPv6 sources must belong to the configured tunnel ranges.
This prevents a client from injecting another client's address into the NAT
path; external NAT and multi-client namespace behavior still require an
integration test.

The same budget is derived from the configured MTU for both address families,
so the payload limit is not a fixed IPv4-only constant. IPv6 identification
and dual-stack budget validation are covered by Core tests; path-MTU discovery,
ICMP Packet Too Big handling, and host-specific measurements remain integration
work.

`PathMtuObservation` is the boundary for that integration work. A privileged
adapter may pass the interface MTU, the probed path MTU, and an optional MTU
carried by an ICMP Packet Too Big/fragmentation-needed error. The core rejects
values below the IPv6 minimum or above the interface and exposes the smallest
safe value as `effective_tunnel_mtu()`. This prevents a packet-too-big signal
from silently increasing the configured MTU. The adapter still owns probing,
error-queue parsing, and environment-specific benchmarking; the core model is
covered by deterministic tests.

Before enabling a full-tunnel route, preserve a route to the UDP endpoint.
Before changing firewall rules, capture the existing rules and provide a
rollback path. The Rust library only builds a declarative Kill Switch plan;
the privileged adapter still owns rule application and rollback.

Configuration validation does not apply routes, firewall rules, DNS settings,
or NAT rules. Those operations remain in a privileged platform/deployment
layer and must preserve an endpoint exception route plus a rollback path.

`DnsPolicy` validates an ordered list of IPv4/IPv6 upstreams and search
domains. It can represent UDP, TCP, DoT, and DoH transports for a future
resolver implementation, while `LinuxDnsPlan` currently emits only the
`resolvectl` form supported by the host adapter: port 53 over UDP or TCP.
The ordered list is retained so a resolver adapter can implement upstream
fallback without changing the control-plane model. This means DoT/DoH values
are configuration-model placeholders only: the current Linux application does
not establish encrypted DNS connections, and callers must not advertise those
transports as active until a dedicated adapter and integration test exist.

Before applying a tunnel policy, capture the current resolver addresses and
domains in `DnsSnapshot`. `LinuxDnsPlan::restore_commands` first reverts the
link and then restores the captured values, followed by a cache flush. The
Rust library only returns argv-safe command records; it never changes the
host resolver itself. This restore plan is the required disconnect path, and
the unit test asserts that the captured upstreams and search domains are
restored after the link revert.

When a UDP transport has a pinned remote endpoint, received datagrams are
checked against the sender address before protocol decoding. A server may
receive from an unset endpoint during initial admission; the authenticated
handshake must establish the peer before pinning a remote address.

Loopback transport and engine tests cover ordinary UDP request/response and
datagrams at the configured maximum size. Multi-client admission, public-IP
egress, NAT, and two-process namespace checks remain deployment-level tests.

`SessionEndpointTable` provides the corresponding multi-session boundary.
The authenticated admission path calls `pin` once, and each received
datagram must pass `validate` for its `SessionId`. Endpoint changes never
happen during validation: the caller must complete a new authenticated
handshake and server-identity check before calling
`rebind_after_authenticated_handshake`. Removing a session also removes its
endpoint mapping. The table is bounded so an endpoint cannot be allocated
outside the configured session limit.

Transport loops use `UdpTransport::close` as their shared cancellation signal.
After close, `is_closed` is true and both `send` and `receive` return
`TransportError::Closed`; a loop should exit on that result rather than retry
indefinitely. A receive timeout remains a transient I/O result and does not
pretend that the transport was closed.

Malformed datagrams are scoped to the current receive attempt. The tunnel
returns a typed protocol error, does not write to the device, and can continue
receiving subsequent datagrams on the same socket. The process-level loop owns
the policy for logging, metrics, or bounded retry; packet decode failure alone
must not terminate the process.

`LinuxNetworkPlan` is the boundary between the validated policy and that
privileged layer. It emits argv-safe `ip`, `sysctl`, and `nft` command records
for server interface setup, IPv4 MASQUERADE, optional IPv6 addressing, and
cleanup. It never executes commands. Interface names are restricted to safe
Linux device-name characters, and an endpoint inside the VPN address space is
rejected to prevent a routing loop.

`LinuxClientRoutePlan` emits the client-side route transition in a safe order:
first an endpoint host route through the physical gateway, then the IPv4
default route (and the IPv6 default route for dual-stack policy) through the
TUN interface. Its cleanup plan removes only the routes it introduced. The
privileged caller still owns route snapshots, restoration of pre-existing
routes, and recovery after an interrupted process.

When the physical network changes, `LinuxClientRoutePlan::rebind_endpoint`
rebuilds the endpoint exception route using the same family, interface, and
tunnel-address validation as initial construction. The new plan must be
applied before reconnecting the session; route cleanup and snapshot restoration
remain owned by the privileged caller.

`LinuxClientNetworkPlan` adds validated IPv4/IPv6 addresses for the TUN
interface and emits address setup before routing, followed by reverse cleanup.

DNS upstreams are represented as IP addresses rather than IPv4-only strings.
`DnsPolicy::upstreams_for_family` lets an adapter select IPv6 or IPv4 resolvers
without changing order or falling back across address families accidentally.
The existing `LinuxDnsPlan` remains a `resolvectl` command planner, so external
DNS-leak tests and OS-specific resolver behavior must be run by each platform
adapter before those deployment checkboxes are considered complete.

The session policy treats authenticated keepalives as the transport adapter's
NAT-mapping refresh signal. `SessionPolicy::keepalives_per` provides a bounded
estimate for a battery or radio budget, while the adapter remains responsible
for suppressing work when the platform is suspended. A reconnect can use
`ReconnectDataPolicy::Drop` (the default) or a bounded packet/byte budget; the
state machine never stores packet contents. Server shutdown and client network
changes remain explicit lifecycle events, so a platform can re-establish the
endpoint and authenticated session without silently forwarding stale data.
It is still a command planner; applying the commands and restoring a route
snapshot belong to the privileged platform adapter.

`LinuxRouteSnapshot` captures the pre-VPN IPv4/IPv6 default routes and the
physical Endpoint route. `LinuxClientRoutePlan::cleanup_commands_with_snapshot`
removes the VPN routes first, then restores only the validated snapshot entries.
The snapshot is rejected when its gateway family does not match its route or
when an IPv6 route is supplied to an IPv4-only plan. This makes restoration
replayable after an interrupted cleanup without allowing arbitrary command
arguments into the planner.

`TunnelNetworkConfig::kill_switch_plan` returns no plan unless `kill_switch`
is explicitly enabled. `LinuxKillSwitchPlan` then emits an optional nftables output chain with a default
drop policy. Loopback, tunnel-interface traffic, established/related
traffic, and the VPN UDP Endpoint through the physical interface are allowed.
Rollback deletes the dedicated nftables table. The plan does not execute
firewall changes; the privileged adapter must apply it atomically and retain
the rollback command for abnormal termination recovery.

Kill Switch remains opt-in during development so that a declarative plan cannot
accidentally alter a developer's host firewall. It is a release gate for a
production VPN: before enabling it for users, a privileged Linux integration
test must verify endpoint reachability, default-drop behavior, rollback, and
recovery after an interrupted process.

`ClientAddressPool` allocates paired client addresses starting at
`10.80.0.2` and `fd80:1234:5678::2`, skips the server and network/broadcast
addresses, and releases both families as one unit. Capacity exhaustion is
reported before a partial pair can escape to the caller.

The management configuration reserves payload byte 8 for the explicit NAT66
policy. When enabled with dual-stack mode, `LinuxNetworkPlan` emits an IPv6
MASQUERADE rule; the default remains disabled so routed IPv6 can be selected
without silently applying NAT.

UDP 장애 정책은 [`udp-failure-policy.md`](./udp-failure-policy.md)에 따른다.
데이터그램 손실은 무한 재전송하지 않고 세션 타임아웃·제한된 재연결로
처리하며, 중복·재정렬은 키 세대별 Replay Window가 결정한다. Core 재시작은
승인 상태만 복원하고 이전 세션 키와 카운터는 복원하지 않는다.

`DnsCache`는 질의 원문 대신 호출자가 계산한 opaque fingerprint만 키로
사용하고, 응답 TTL을 1초에서 24시간 사이로 제한한다. 캐시 용량은 고정되어
있으며 만료 응답은 조회 전에 제거된다. 실제 DoT/DoH resolver adapter가
연결되기 전까지 Linux 기본 적용 계층은 UDP/TCP 53만 사용한다.
## UDP transport recovery

`UdpTransport::rebind` binds the replacement local endpoint before replacing
the active socket and preserves the pinned remote endpoint. `TransportError`
classifies `WouldBlock`, `Interrupted`, and `TimedOut` as transient so a
reconnection loop can retry them without treating the session as permanently
failed.
