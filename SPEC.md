# GSM VPN — 자체 VPN 터널링 엔진 및 프로토콜 설계 명세서

**프로젝트:** GSM VPN  
**GitHub Organization:** `github.com/gsm-vpn`  
**신규 Repository:** `github.com/gsm-vpn/tunnel`  
**프로젝트 유형:** 실제 인터넷 VPN 서비스  
**핵심 개발 언어:** Go + Rust 하이브리드
**기존 서버 기술:** TypeScript / Fastify  
**통신 방식:** UDP 기반 자체 VPN 프로토콜  
**문서 버전:** 1.1.1
**작성일:** 2026년 10월 19일
**문서 상태:** 초기 설계 명세서  
**주요 목적:** 기존 WireGuard 의존성을 대체할 수 있는 독립적인 VPN 터널링 엔진 및 자체 통신 프로토콜 개발

---

# 1. 프로젝트 개요

## 1.1. 프로젝트 배경

GSM VPN은 현재 WireGuard를 기반으로 동작하는 VPN 서비스이다.

기존 GSM VPN은 Gateway Server, VPN Server, VPN Client로 구성되어 있으며, VPN 연결과 사용자 관리를 위한 서비스 계층을 자체적으로 구현하고 실제 VPN 터널링은 WireGuard에 의존하는 구조이다.

기존 구현에서는 VPN Server가 WireGuard 인터페이스 및 피어를 관리하고, Gateway Server는 인증과 VPN 서버 관련 기능을 담당한다.

그러나 본 프로젝트는 학교 프로젝트로서 네트워크 시스템에 대한 기술적 이해와 직접적인 구현 역량을 보여주는 것을 중요한 목표로 한다.

WireGuard를 그대로 사용하는 방식은 안정성 및 개발 효율성 측면에서 장점이 있지만, VPN의 핵심 동작인 터널링, 패킷 캡슐화, 암호화된 데이터 전송, 키 교환, 세션 관리 등의 내부 구현을 직접 경험하기 어렵다는 한계가 있다.

따라서 GSM VPN은 기존 서비스 구조를 유지하면서 WireGuard에 의존하는 터널링 계층을 자체 구현한 VPN 엔진으로 대체하는 것을 목표로 한다.

이를 위해 새로운 독립 저장소인 `gsm-vpn/tunnel`을 개발한다.

## 1.2. 최종 목표

GSM VPN은 단순히 장치끼리 연결되는 사설 네트워크 VPN이 아니라, 사용자의 인터넷 트래픽을 VPN 서버로 전달하는 **실제 인터넷 VPN(Internet VPN)** 서비스를 목표로 한다.

클라이언트가 GSM VPN에 연결하면 운영체제에서 발생하는 인터넷 트래픽이 VPN의 가상 네트워크 인터페이스를 통해 전달된다.

GSM VPN 클라이언트는 해당 IP 패킷을 읽고, 자체 프로토콜에 따라 암호화 및 캡슐화하여 VPN 서버로 전송한다.

VPN 서버는 수신한 패킷을 검증하고 복호화한 뒤 실제 인터넷으로 전달한다.

인터넷에서 돌아온 응답 패킷은 VPN 서버에서 다시 암호화되어 클라이언트로 전송된다.

이를 통해 외부 웹사이트 및 서비스에는 사용자의 실제 공인 IP 주소가 아닌 VPN 서버의 공인 IP 주소가 노출된다.

최종적으로 다음과 같은 시스템을 구현한다.

```text
User Application
      │
      ▼
Operating System
      │
      ▼
Virtual Network Interface
      │
      ▼
GSM Tunnel Client
      │
      ▼
Custom VPN Protocol
      │
      ▼
Encrypted UDP Transport
      │
      ▼
GSM Tunnel Server
      │
      ▼
IP Forwarding / NAT
      │
      ▼
Internet
```

## 1.3. 프로젝트의 기술적 목적

본 프로젝트는 VPN 서비스를 운영하는 것뿐 아니라 다음 기술을 직접 구현하고 검증하는 것을 목표로 한다.

1. 운영체제의 가상 네트워크 인터페이스 제어
2. IP 패킷 읽기 및 쓰기
3. UDP 기반 네트워크 통신
4. 자체 바이너리 패킷 포맷 설계
5. 암호화된 터널링 프로토콜 구현
6. 인증된 핸드셰이크 및 세션 키 수립
7. 암호화 및 복호화
8. 암호화 키 갱신
9. 세션 생성, 유지, 종료 및 재연결
10. 패킷 재전송 공격 방어
11. IP 라우팅
12. Network Address Translation
13. 다중 클라이언트 처리
14. DNS 및 IPv6 트래픽 관리
15. 운영체제별 네트워크 설정
16. VPN 연결 장애 대응
17. 패킷 처리 성능 최적화
18. 네트워크 보안 테스트
19. WireGuard와의 성능 비교
20. 시스템 프로그래밍 및 네트워크 프로토콜 설계 역량 확보

## 1.4. 프로젝트 기본 원칙

GSM VPN은 다음 설계 원칙을 따른다.

**원칙 1. 기존 서버 구조 유지**

기존 `gateway-server` 및 `vpn-server` 저장소를 유지한다.

두 서버를 하나로 합치거나 전체 시스템을 새로 작성하지 않는다.

**원칙 2. VPN 터널링 엔진 독립**

자체 VPN 프로토콜과 터널링 기능은 새로운 `tunnel` 저장소에 구현한다.

**원칙 3. 인증과 트래픽 처리의 분리**

VPN Server는 사용자의 서비스 이용 권한과 터널 사용 승인을 관리한다.

Tunnel Engine은 승인된 클라이언트의 암호학적 신원, 연결 상태 및 실제 IP 패킷 전송을 처리한다.

**원칙 4. 자체 프로토콜 구현**

WireGuard의 터널링 구현체를 그대로 사용하지 않는다.

패킷 포맷, 세션 관리, 데이터 전송 및 터널링 엔진은 직접 구현한다.

**원칙 5. 검증된 암호화 기술 사용**

암호화 알고리즘 자체를 새롭게 발명하지 않는다.

X25519, HKDF, ChaCha20-Poly1305, Noise Protocol Framework 등 검증된 암호학적 구성요소와 구현체를 활용한다.

**원칙 6. 플랫폼 독립성**

데이터 플레인은 Rust로 구현한다. TUN 입출력, UDP 데이터 전송, 패킷 포맷,
핸드셰이크, 암호화, Replay 방어 및 패킷 전달은 하나의 Rust Tunnel Core가
담당한다.

제어 플레인은 Go로 구현한다. 설정, 피어 승인, 엔진 수명주기, 관리용 세션
상태, IPC, 메트릭 및 운영 도구는 Go Tunnel Controller가 담당한다.

패킷마다 Go와 Rust 사이의 FFI를 호출하지 않는다. Go Controller와 Rust
Tunnel Core는 프로세스 경계를 두고 관리용 IPC로 통신하여 데이터 경로의
복사와 호출 비용을 줄인다.

운영체제별 네트워크 인터페이스 처리는 별도의 플랫폼 계층으로 분리한다.

**원칙 7. 단계적 개발**

초기에는 Linux 환경에서 개발 및 검증한다.

이후 Windows 클라이언트 지원을 추가하고, 최종적으로 macOS 지원을 고려한다.

**원칙 8. 보안 검증 우선**

자체 프로토콜이 WireGuard와 동등한 보안 수준을 제공한다고 가정하지 않는다.

외부 사용자에게 제공하기 전에 충분한 보안 테스트 및 독립적인 검토를 수행해야 한다.

---

# 2. 기존 GSM VPN 시스템

## 2.1. 현재 저장소 구성

현재 GSM VPN 조직은 다음 저장소를 중심으로 구성되어 있다.

| Repository | 역할 | 주요 기술 |
|---|---|---|
| `gateway-server` | 사용자 인증 및 VPN 서버 관리 | TypeScript, Fastify |
| `vpn-server` | VPN 서버 운영 및 터널 관리 | TypeScript, WireGuard |
| `Windows-Client-Release` | Windows 클라이언트 배포 | Windows |

GitHub Organization:

https://github.com/gsm-vpn

관련 저장소:

- https://github.com/gsm-vpn/gateway-server
- https://github.com/gsm-vpn/vpn-server
- https://github.com/gsm-vpn/Windows-Client-Release

## 2.2. 기존 Gateway Server

Gateway Server는 VPN 서비스의 관리 계층을 담당한다.

기존 기능 및 유지할 책임 범위는 다음과 같다.

- 사용자 인증
- VPN 서버 등록
- VPN 서버 목록 관리
- VPN 서버 선택
- VPN 연결 요청 처리
- VPN 서버와의 통신
- 사용자와 VPN 서버 간 연결 승인
- 서비스 수준의 피어 및 연결 관리

Gateway Server는 실제 IP 패킷을 전달하지 않는다.

또한 VPN 데이터 패킷을 직접 암호화하거나 복호화하지 않는다.

## 2.3. 기존 VPN Server

기존 VPN Server는 WireGuard를 기반으로 VPN 터널을 운영한다.

주요 기능은 다음과 같다.

- WireGuard 서버 실행
- WireGuard 인터페이스 관리
- WireGuard 피어 등록
- WireGuard 피어 해제
- VPN 연결 상태 관리
- VPN 트래픽 전달을 위한 환경 구성
- Gateway Server와의 연동

기존에는 VPN Server가 WireGuard에 필요한 설정과 상태를 관리하고, 실제 터널링 및 암호화된 데이터 전송은 WireGuard 구현체가 수행했다.

## 2.4. 기존 아키텍처

```text
                    GSM VPN
                       │
                 Gateway Server
                       │
          ┌────────────┴────────────┐
          │                         │
    Authentication             VPN Management
          │                         │
          └────────────┬────────────┘
                       │
                  VPN Server
                       │
                WireGuard Engine
                       │
                 Network Tunnel
                       │
                    Internet
```

## 2.5. 기존 방식의 특징

| 항목 | 기존 구현 |
|---|---|
| 사용자 인증 | GSM VPN |
| VPN 서버 등록 및 선택 | GSM VPN |
| VPN 연결 승인 | GSM VPN |
| 터널 프로토콜 | WireGuard |
| 암호화된 전송 | WireGuard |
| 키 교환 | WireGuard |
| 터널 세션 관리 | WireGuard |
| 패킷 캡슐화 | WireGuard |
| 패킷 재전송 방어 | WireGuard |
| 운영체제 네트워크 인터페이스 | WireGuard 기반 |

기존 시스템은 VPN 서비스 관리 소프트웨어로서 의미가 있지만, VPN의 핵심 프로토콜을 직접 구현한 시스템은 아니다.

---

# 3. 기존 WireGuard와 자체 프로토콜 비교

## 3.1. 비교 목적

WireGuard는 보안성과 성능이 우수한 VPN 프로토콜이다.

따라서 자체 프로토콜 개발의 목적은 WireGuard보다 반드시 빠르거나 안전한 프로토콜을 만드는 것이 아니다.

프로젝트의 핵심 목적은 네트워크 프로토콜과 터널링 엔진을 직접 설계하고, 개발 과정에서 얻은 기술적 성과를 검증하는 데 있다.

## 3.2. 기능 비교

| 구분 | WireGuard 기반 | GSM Tunnel 자체 구현 |
|---|---|---|
| 터널링 | WireGuard | 직접 구현 |
| 패킷 캡슐화 | WireGuard | 직접 구현 |
| 패킷 포맷 | WireGuard 규격 | GSM 자체 규격 |
| 암호화 알고리즘 | WireGuard 지정 | 검증된 알고리즘 선택 |
| 핸드셰이크 | WireGuard | 직접 통합 및 상태 관리 |
| 키 교환 | WireGuard | 검증된 프로토콜 기반 구현 |
| 세션 관리 | WireGuard | 직접 구현 |
| 재전송 공격 방어 | WireGuard | 직접 구현 |
| UDP 통신 | WireGuard | 직접 구현 |
| 가상 네트워크 인터페이스 | WireGuard 인터페이스 | TUN 인터페이스 제어 |
| IP 패킷 처리 | WireGuard | 직접 구현 |
| 연결 유지 | WireGuard | 직접 구현 |
| MTU 처리 | WireGuard 기반 | 직접 구현 |
| 성능 최적화 | WireGuard 구현에 의존 | GSM Tunnel 내부 최적화 |
| 보안 검증 | 널리 검토된 구현 활용 | 별도 검증 필요 |

## 3.3. 자체 구현의 기술적 의미

자체 터널링 엔진을 구현하면 다음 과정을 직접 이해하고 제어할 수 있다.

```text
IP Packet
    │
    ▼
TUN Read
    │
    ▼
Packet Validation
    │
    ▼
Encryption
    │
    ▼
Encapsulation
    │
    ▼
UDP Send
    │
    ▼
Network
    │
    ▼
UDP Receive
    │
    ▼
Packet Validation
    │
    ▼
Decryption
    │
    ▼
TUN Write
```

해당 과정은 운영체제 네트워크 스택, UDP 소켓, 비동기 입출력, 암호학, 메모리 관리, 패킷 구조 등에 대한 이해를 필요로 한다.

이러한 이유로 자체 프로토콜 구현은 학교 프로젝트에서 높은 기술적 가치를 가질 수 있다.

---

# 4. 신규 저장소 설계

## 4.1. 저장소 분리 결정

신규 저장소는 `protocol`이 아닌 **`tunnel`**이라는 이름을 사용한다.

최종 권장 저장소:

`https://github.com/gsm-vpn/tunnel`

이 주소는 생성할 저장소의 목표 경로를 의미하며, 저장소 생성 여부 자체를 나타내지는 않는다.

## 4.2. `protocol`과 `tunnel` 비교

| 항목 | `protocol` | `tunnel` |
|---|---|---|
| 주요 의미 | 통신 규약 | VPN 터널링 엔진 |
| 패킷 인코딩 | 포함 | 포함 |
| 패킷 디코딩 | 포함 | 포함 |
| 핸드셰이크 | 포함 | 포함 |
| 암호화 처리 | 포함 가능 | 포함 |
| 세션 관리 | 일부 | 포함 |
| UDP 송수신 | 선택적 | 포함 |
| TUN 인터페이스 | 일반적으로 제외 | 포함 |
| IP 패킷 전달 | 일반적으로 제외 | 포함 |
| 운영체제별 네트워크 제어 | 일반적으로 제외 | 포함 |
| 실행 가능한 VPN 엔진 | 필수 아님 | 구현 목표 |

`protocol`이라는 이름은 통신 규약 자체에 초점을 맞춘다.

반면 `tunnel`은 실제 운영체제의 IP 패킷을 처리하고 VPN 서버와 클라이언트 사이에서 암호화된 네트워크 터널을 제공하는 시스템을 의미한다.

GSM VPN의 신규 저장소에는 프로토콜뿐 아니라 TUN, UDP, 세션 관리, 패킷 전달 등의 기능이 포함될 예정이다.

따라서 `tunnel`이라는 이름이 실제 저장소의 책임에 더 부합한다.

## 4.3. 저장소 설명

**Repository Name**

`GSM-VPN/tunnel`

**Description**

> A cross-platform VPN tunneling engine implementing a custom secure transport protocol.

**Primary Language**

Go + Rust

**Repository Type**

Go Module과 Rust Crate를 포함하는 하이브리드 Workspace

**Primary Purpose**

GSM VPN에서 사용하는 자체 VPN 통신 프로토콜 및 터널링 엔진 구현

## 4.4. 최종 저장소 구성

```text
github.com/gsm-vpn/
│
├── gateway-server/
│   │
│   └── 사용자 인증 및 VPN 서비스 관리
│
├── vpn-server/
│   │
│   └── VPN 서버 운영 및 Tunnel Engine 관리
│
├── tunnel/
│   │
│   └── 자체 VPN 프로토콜 및 터널링 엔진
│
└── Windows-Client-Release/
    │
    └── Windows 클라이언트 배포
```

기존 저장소를 삭제하거나 통합하지 않는다.

`vpn-server`는 VPN 서버 운영 및 관리 계층을 유지한다.

`tunnel`은 실제 네트워크 터널 구현을 담당한다.

---

# 5. 시스템 책임 분리

## 5.1. Gateway Server

Gateway Server는 GSM VPN 서비스의 중앙 관리 계층이다.

담당 기능:

- 사용자 인증
- 서비스 이용 권한 확인
- VPN 서버 등록
- VPN 서버 상태 관리
- VPN 서버 목록 조회
- VPN 서버 선택
- VPN 연결 요청 처리
- VPN 서버와의 제어 통신
- 연결 승인 정보 전달

Gateway Server는 VPN 패킷을 직접 처리하지 않는다.

## 5.2. VPN Server

VPN Server는 VPN 서비스를 실제로 운영하는 서버 애플리케이션이다.

담당 기능:

- Gateway Server와 통신
- Gateway 인증 결과 검증
- VPN 연결 승인 및 거부
- 터널 클라이언트 등록
- 사용자별 가상 IP 할당 및 관리
- 터널 엔진 설정 관리
- 터널 세션 생성 요청
- 터널 세션 종료 요청
- Tunnel Engine 실행 및 상태 확인
- 서버 네트워크 설정 관리
- 서비스 수준의 접속 현황 관리

VPN Server는 계정과 서비스 권한을 이해할 수 있다.

그러나 실제 데이터 패킷의 암호화, 복호화 및 캡슐화를 직접 구현하지 않는다.

## 5.3. Tunnel Engine

Tunnel Engine은 독립적인 VPN 네트워크 엔진이다.

담당 기능:

- 자체 UDP 기반 통신 프로토콜
- 패킷 포맷 정의
- 패킷 인코딩
- 패킷 디코딩
- 암호화 및 복호화
- 핸드셰이크
- 키 교환
- 세션 키 관리
- 키 갱신
- 터널 연결 상태 관리
- 재전송 공격 방어
- UDP 소켓 통신
- TUN 인터페이스 입출력
- IP 패킷 전달
- Keepalive
- 연결 재수립
- 패킷 검증
- 네트워크 오류 처리
- 다중 세션 처리

Tunnel Engine은 GSM VPN의 사용자 계정이나 로그인 API를 직접 이해할 필요가 없다.

대신 VPN Server로부터 연결 허용에 필요한 정보를 전달받는다.

다만 서버 측 인증 승인만 신뢰하는 것으로 끝나서는 안 된다.

Tunnel Engine은 실제 연결을 수립할 때 등록된 공개키 등의 암호학적 신원을 검증해야 한다.

## 5.4. 책임 경계

| 기능 | Gateway Server | VPN Server | Tunnel Engine |
|---|---|---|---|
| 사용자 로그인 | 담당 | 제외 | 제외 |
| 사용자 이용 권한 | 담당 | 검증 | 제외 |
| VPN 서버 선택 | 담당 | 제외 | 제외 |
| 터널 접속 승인 | 승인 정보 발급 | 승인 적용 | 승인된 신원 검증 |
| 가상 IP 할당 정책 | 선택적 | 담당 | 할당된 IP 적용 |
| 서버 네트워크 설정 | 제외 | 담당 | 인터페이스 관련 처리 |
| 핸드셰이크 | 제외 | 제외 | 담당 |
| 암호화 및 복호화 | 제외 | 제외 | 담당 |
| UDP 데이터 전송 | 제외 | 제외 | 담당 |
| TUN 입출력 | 제외 | 관리 | 담당 |
| 패킷 캡슐화 | 제외 | 제외 | 담당 |
| 세션 암호키 관리 | 제외 | 제외 | 담당 |
| 계정별 접속 현황 | 관리 | 집계 | 연결 이벤트 제공 |
| 터널 상태 진단 | 조회 | 관리 | 상태 제공 |

## 5.5. 핵심 아키텍처 원칙

> VPN Server는 누가 VPN을 사용할 수 있는지 결정하고, Tunnel Engine은 승인된 클라이언트의 패킷을 어떻게 안전하게 전달할지 결정한다.

이 원칙을 통해 인증 시스템과 터널 프로토콜을 독립적으로 발전시킬 수 있다.

---

# 6. 전체 시스템 아키텍처

## 6.1. 논리적 아키텍처

```text
                           GSM VPN
                              │
                     Gateway Server
                              │
              ┌───────────────┴───────────────┐
              │                               │
        Authentication                 Server Registry
              │                               │
              └───────────────┬───────────────┘
                              │
                       VPN Server API
                              │
                         VPN Server
                              │
                 ┌────────────┴────────────┐
                 │                         │
          VPN Management              Tunnel Engine
                 │                         │
          Authorization             ┌──────┴──────┐
          IP Allocation             │             │
          Configuration         Control Plane  Data Plane
          Monitoring                │             │
                                    │             │
                               Handshake       TUN Device
                               Key Exchange    Packet Codec
                               Session         Encryption
                               Rekeying        UDP Transport
                                    │             │
                                    └──────┬──────┘
                                           │
                                      Networking
                                           │
                                        Internet
```

## 6.2. 서비스 계층과 데이터 계층

전체 시스템은 크게 세 가지 계층으로 구분한다.

### Service Plane

서비스 자체의 운영을 담당한다.

포함 요소:

- Gateway Server
- 사용자 인증
- VPN 서버 선택
- 사용자 권한 관리
- VPN 접속 승인

### Control Plane

실제 VPN 터널을 구성하고 연결 상태를 관리한다.

포함 요소:

- 인증된 연결 수립
- Handshake
- 키 교환
- 세션 생성 및 종료
- 세션 갱신
- Keepalive
- 연결 상태 관리

Control Plane은 Tunnel Engine 내부의 암호학적 연결 관리와 VPN Server의 서비스 승인 관리로 구성된다.

두 시스템의 책임은 명확히 분리한다.

### Data Plane

사용자 IP 패킷의 실제 전달을 담당한다.

포함 요소:

- TUN 인터페이스
- 패킷 읽기
- 패킷 캡슐화
- 암호화
- UDP 전송
- 복호화
- IP 패킷 전달

## 6.3. 전체 인터넷 VPN 데이터 경로

```text
                        VPN Client
                            │
                            ▼
                    User Application
                            │
                            ▼
                   Operating System
                            │
                            ▼
                    Routing Table
                            │
                            ▼
                     TUN Interface
                            │
                            │ Raw IP Packet
                            ▼
                    GSM Tunnel Client
                            │
                 ┌──────────┴──────────┐
                 │                     │
             Protocol               Transport
                 │                     │
           Encapsulation           UDP Socket
           Encryption              Session I/O
                 │                     │
                 └──────────┬──────────┘
                            │
                       Encrypted UDP
                            │
                            ▼
                         Internet
                            │
                            ▼
                       VPN Server
                            │
                            ▼
                    GSM Tunnel Server
                            │
                 ┌──────────┴──────────┐
                 │                     │
             Protocol                Device
                 │                     │
            Verification           TUN Interface
            Decryption             IP Forwarding
                 │                     │
                 └──────────┬──────────┘
                            │
                            ▼
                     Linux Networking
                            │
                            ▼
                        NAT / SNAT
                            │
                            ▼
                         Internet
                            │
                            ▼
                      Public Server
```

## 6.4. 서버 구성

VPN 서버는 Linux 환경을 기본으로 한다.

운영 환경의 주요 구성 요소는 다음과 같다.

```text
Linux Host
│
├── VPN Server
│   ├── Gateway Integration
│   ├── Authorization Manager
│   ├── IP Allocation Manager
│   ├── Tunnel Lifecycle Manager
│   └── Monitoring
│
├── GSM Tunnel
│   ├── Protocol Engine
│   ├── Session Manager
│   ├── UDP Transport
│   ├── Packet Processor
│   └── TUN Device
│
└── Linux Kernel
    ├── TUN
    ├── Routing
    ├── IP Forwarding
    ├── Conntrack
    └── nftables / NAT
```

VPN Server와 Tunnel Engine의 프로세스 분리 여부는 개발 단계에 따라 결정한다.

초기 버전에서는 직접 라이브러리를 호출하는 방식도 가능하다.

향후 프로세스를 분리하면 Unix Domain Socket 등의 IPC를 사용한다.

## 6.5. 클라이언트 구성

클라이언트는 운영체제별 네트워크 처리 계층과 공통 터널 엔진으로 구분한다.

```text
GSM VPN Client
│
├── User Interface
│   ├── Login
│   ├── Server Selection
│   ├── Connect
│   ├── Disconnect
│   └── Connection Status
│
├── Client Controller
│   ├── Gateway Communication
│   ├── Authorization
│   ├── Tunnel Configuration
│   └── Lifecycle Management
│
├── GSM Tunnel
│   ├── Handshake
│   ├── Encryption
│   ├── Packet Processing
│   ├── Session Management
│   └── UDP Transport
│
└── Platform Network Adapter
    ├── Linux TUN
    ├── Windows Wintun
    └── macOS Network Interface
```

UI와 VPN 엔진을 분리하는 이유는 플랫폼별 애플리케이션 구현에 상관없이 동일한 프로토콜과 암호화 코드를 재사용하기 위해서다.

---

# 7. Go + Rust 하이브리드 Workspace 설계

## 7.1. 기본 구조

신규 `tunnel` 저장소는 Go Module과 Rust Cargo Workspace를 함께 사용한다.
Go는 실행 계층과 운영 계층을 담당하고, Rust는 보안 민감한 프로토콜 코어를 담당한다.

기본 디렉터리 구조는 다음과 같다.

```text
tunnel/
│
├── go.mod
├── go.sum
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
│
├── internal/
│   │
│   ├── protocol/
│   │   ├── adapter.go
│   │   └── types.go
│   │
│   └── controller/
│       ├── controller.go
│       ├── lifecycle.go
│       ├── ipc.go
│       ├── policy.go
│       └── metrics.go
│
├── crates/
│   └── tunnel-core/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── protocol.rs
│           ├── handshake.rs
│           ├── crypto.rs
│           ├── transport.rs
│           ├── device.rs
│           └── session.rs
│
├── examples/
│   ├── client.go
│   └── server.go
│
└── tests/
    ├── handshake_test.go
    ├── encryption_test.go
    └── packet_test.go
```

이 구조는 최초 논의에서 제안된 기본 구조이다.

이후 기능 증가를 고려하면 다음 확장 구조를 사용할 수 있다.

## 7.2. 확장 가능한 디렉터리 구조

```text
tunnel/
│
├── go.mod
├── go.sum
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── test.yml
│       └── release.yml
│
├── internal/
│   │
│   ├── protocol/
│   │   ├── adapter.go
│   │   ├── types.go
│   │   └── error.go
│   │
│   └── controller/
│       ├── *.go
│       ├── lifecycle.go
│       ├── ipc.go
│       ├── policy.go
│       ├── metrics.go
│       └── error.go
│
├── examples/
│   ├── client.go
│   ├── server.go
│   └── local_tunnel.go
│
├── tests/
│   ├── handshake_test.go
│   ├── encryption_test.go
│   ├── packet_test.go
│   ├── session_test.go
│   ├── replay_test.go
│   ├── reconnect_test.go
│   └── integration_test.go
│
├── benches/
│   ├── packet_codec_test.go
│   ├── encryption_test.go
│   └── throughput_test.go
│
└── docs/
    ├── architecture.md
    ├── protocol.md
    ├── security.md
    ├── networking.md
    └── development.md
```

Rust Tunnel Core는 다음과 같이 별도 관리한다.

```text
crates/tunnel-core/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── protocol.rs
    ├── handshake.rs
    ├── crypto.rs
    ├── transport.rs
    ├── device.rs
    └── session.rs
```

이 확장 구조는 실제 개발 과정에서 기능을 관리하기 위한 제안이며, 최초 버전에서 모든 파일을 만들어야 한다는 의미는 아니다.

## 7.3. Package 및 Crate별 역할

### `protocol`

Go 측 프로토콜 Adapter와 공개 타입을 제공한다. 보안 민감한 실제 프로토콜 코어는
`crates/tunnel-core`의 Rust 구현을 호출한다.

담당 기능:

- 패킷 종류 정의
- 패킷 헤더 정의
- 패킷 직렬화
- 패킷 역직렬화
- 프로토콜 버전 관리
- Rust 코어 호출 경계
- 패킷 처리 결과 및 오류 매핑
- Go 계층에서 사용하는 설정·상태 타입

`protocol`은 운영체제의 TUN 인터페이스나 VPN 사용자 계정에 의존하지 않도록 설계한다.

Go 계층과 Rust 코어 사이의 경계를 작게 유지하고, 암호화 키 자료가 로그나
일반 관리 API로 노출되지 않도록 한다.

### `tunnel-core` (Rust)

보안 민감하고 성능에 직접 영향을 주는 프로토콜 코어와 실제 데이터 플레인을
함께 구현한다.

담당 기능:

- TUN 장치 입출력
- UDP 소켓 관리 및 데이터그램 송수신
- 바이너리 패킷 포맷의 핵심 검증
- Noise 핸드셰이크 상태 처리
- X25519, HKDF, AEAD 암호화 호출
- Nonce 및 키 세대 관리
- Replay Window 검증
- 세션별 데이터 전달
- 연결 상태 탐지
- Keepalive 전송
- 타임아웃 관리
- 패킷 재전송 방어 및 암호화 상태 관리
- 패킷 캡슐화·복호화 핫패스

암호 알고리즘 자체를 발명하지 않고 검증된 Rust 암호화 라이브러리를 사용한다.
- 통신 오류 처리

UDP는 TCP와 달리 연결 및 전달 순서를 보장하지 않으므로 세션과 연결 상태는 애플리케이션에서 관리해야 한다.

단, IP 패킷 전체에 무조건적인 재전송이나 순서 보장을 추가해서는 안 된다.

TCP 트래픽은 터널 내부의 TCP 프로토콜이 자체적으로 신뢰성 있는 전송을 제공한다.

### `controller` (Go)

Tunnel Core와 VPN Server를 연결하는 제어 플레인을 구현한다.

담당 기능:

- Tunnel Core 시작·종료 및 재시작
- 피어 승인 정보 전달
- 세션 생성·종료 요청
- 설정 및 정책 관리
- 상태 조회, 메트릭 및 운영 로그
- VPN Server와의 IPC

### `engine`

VPN 클라이언트와 서버의 실제 동작을 통합한다.

담당 기능:

- Tunnel Client 실행
- Tunnel Server 실행
- 설정 검증
- Protocol과 Transport 연결
- Transport와 Device 연결
- 연결 수립 및 종료
- 패킷 전달 파이프라인
- 세션 수명주기 관리
- 네트워크 오류 처리
- 연결 상태 및 통계 제공

`engine`은 Go Controller와 Rust `tunnel-core`를 조합하여 실제 동작하는
VPN 엔진을 구성한다. 데이터 패킷은 Rust 프로세스 내부에서 처리하고,
Go는 제어 메시지만 IPC로 전달한다.

## 7.4. Package 의존성 원칙

```text
             Go Controller
                    │ IPC
                    ▼
             Rust Tunnel Core
              /       |       \
             ▼        ▼        ▼
          TUN       UDP     Protocol
                             Core
```

권장 의존성 방향:

- Go `protocol` Adapter는 다른 실행 계층에 의존하지 않는다.
- Rust `tunnel-core`가 TUN, UDP 및 프로토콜 코어를 내부에서 조합한다.
- Go Controller는 데이터 패킷을 직접 처리하지 않는다.
- `tunnel-core`는 서비스 계정·Gateway API에 의존하지 않는다.
- `engine`은 Go Controller와 Rust Tunnel Core의 수명주기를 조합한다.

이를 통해 프로토콜 계층과 운영체제 계층을 분리한다.

## 7.5. 하이브리드 빌드 구성

Go Module과 Rust Cargo Workspace는 다음과 같이 구성할 수 있다.

```go
module github.com/gsm-vpn/tunnel

go 1.23

// Rust tunnel-core 연동 방식과 의존성 버전은 구현 착수 시 검토한다.
```

Rust Workspace에는 `crates/tunnel-core`를 등록한다. Go와 Rust의 ABI 경계는
초기 Linux 환경에서 C ABI 또는 cgo 기반으로 검증하고, Windows·macOS 빌드에서는
동일한 API 계약을 만족하는 플랫폼별 빌드 산출물을 사용한다.

라이선스는 최종적으로 프로젝트 정책에 따라 확정해야 한다.

Go와 Rust 버전 및 각 의존성의 지원 범위도 실제 개발 환경에서 검증해야 한다.
Go 측 패킷 전달 경로는 버퍼 재사용과 프로파일링을 통해 GC 및 메모리 할당 비용을
검증하고, 암호화 핫패스는 Rust 벤치마크로 별도 검증한다.

---

# 8. 자체 VPN 프로토콜 설계

## 8.1. 프로토콜의 역할

GSM Tunnel은 UDP를 기반으로 동작하는 암호화된 IP 패킷 터널링 프로토콜을 구현한다.

프로토콜의 목표는 다음과 같다.

1. 클라이언트와 서버가 인증된 암호화 세션을 수립한다.
2. 클라이언트의 IP 패킷을 서버에 안전하게 전달한다.
3. 서버의 응답 IP 패킷을 클라이언트에 안전하게 전달한다.
4. 여러 클라이언트의 세션을 구분한다.
5. 네트워크 연결이 변경되거나 일시적으로 끊긴 경우 복구할 수 있다.
6. 패킷 변조 및 재전송 공격을 방어한다.
7. 장기 연결에서 암호화 키를 안전하게 갱신한다.
8. 운영체제에 독립적인 패킷 규약을 제공한다.

## 8.2. 프로토콜 명칭

최초 논의에서는 가칭으로 `GSM Tunnel Protocol`, 줄여서 `GTP`라는 이름을 제안하였다.

다만 `GTP`는 이미 이동통신망에서 사용되는 GPRS Tunnelling Protocol과 약어가 중복된다.

따라서 `GTP`는 초기 논의의 가칭으로만 기록한다.

최종 프로토콜 명칭과 약어는 추후 별도로 확정한다.

이 명세서에서는 혼동을 방지하기 위해 `GSM Tunnel Protocol`이라는 전체 명칭을 사용한다.

## 8.3. 전송 방식

기본 전송 프로토콜은 UDP이다.

```text
GSM Tunnel Protocol
         │
         ▼
        UDP
         │
         ▼
         IP
         │
         ▼
     Physical NIC
```

UDP를 선택하는 이유는 다음과 같다.

- 낮은 전송 계층 오버헤드
- IP 패킷을 데이터그램 단위로 처리 가능
- 사용자 공간에서 전송 동작 제어 가능
- TCP-over-TCP 문제 회피
- VPN 패킷 처리 방식에 적합

UDP는 기본적으로 패킷의 전달과 순서를 보장하지 않는다.

따라서 GSM Tunnel은 재정렬된 데이터 패킷을 안전하게 검증하고 처리할 수 있어야 한다.

핸드셰이크 메시지의 재시도와 일반 IP 데이터 패킷의 재전송은 별개로 설계한다.

## 8.4. 패킷 구조 개념

최초 논의된 패킷의 논리적 구조는 다음과 같다.

```text
┌────────────────────────────────────────────┐
│             GSM VPN UDP Packet             │
├────────────────────────────────────────────┤
│ Version                                    │
├────────────────────────────────────────────┤
│ Packet Type                                │
├────────────────────────────────────────────┤
│ Session ID                                 │
├────────────────────────────────────────────┤
│ Sequence Number                            │
├────────────────────────────────────────────┤
│ Encrypted Payload                          │
├────────────────────────────────────────────┤
│ Authentication Tag                         │
└────────────────────────────────────────────┘
```

각 필드의 역할은 다음과 같다.

| 필드 | 역할 |
|---|---|
| Version | 프로토콜 버전 구분 |
| Packet Type | 핸드셰이크, 데이터 등의 메시지 유형 구분 |
| Session ID | 패킷이 속한 세션 식별 |
| Sequence Number | 데이터 패킷 카운터 및 재전송 방어 |
| Encrypted Payload | 암호화된 실제 데이터 |
| Authentication Tag | 메시지 무결성 및 인증 검증 |

이 구조는 아직 **논리적 초안**이다.

각 필드의 실제 크기, 바이트 순서, 헤더 보호 범위, 인증 태그의 위치 등은 프로토콜 보안 설계 후 확정한다.

특히 인증되지 않은 세션 식별자만으로 패킷의 신뢰성을 판단해서는 안 된다.

## 8.5. 패킷 유형

초기 프로토콜은 다음과 같은 메시지 유형을 고려한다.

| Packet Type | 목적 |
|---|---|
| Handshake Initiation | 핸드셰이크 시작 |
| Handshake Response | 핸드셰이크 응답 |
| Transport Data | 암호화된 IP 패킷 전송 |
| Keepalive | 연결 유지 |
| Session Termination | 정상적인 연결 종료 |
| Protocol Error | 필요시 오류 상태 전달 |

실제 Wire Format에서는 일부 메시지를 통합하거나 제거할 수 있다.

특히 핸드셰이크 메시지 구조는 선택한 Noise 패턴의 요구사항을 따라야 한다.

재시도, 키 갱신, 종료 메시지도 임의의 평문 제어 패킷으로 구현해서는 안 된다.

## 8.6. 데이터 패킷 처리

클라이언트에서 서버로 전달되는 데이터 패킷은 다음 과정을 거친다.

```text
Raw IP Packet
      │
      ▼
Validate Packet
      │
      ▼
Determine Session
      │
      ▼
Select Encryption Key
      │
      ▼
Generate Unique Nonce
      │
      ▼
AEAD Encryption
      │
      ▼
Encode Tunnel Packet
      │
      ▼
UDP Send
```

수신 측에서는 역순으로 처리한다.

```text
UDP Receive
      │
      ▼
Parse Tunnel Header
      │
      ▼
Locate Session
      │
      ▼
Validate Counter / Replay State
      │
      ▼
AEAD Authentication
      │
      ▼
Decrypt Payload
      │
      ▼
Validate Inner IP Packet
      │
      ▼
TUN Write
```

실제 구현에서는 재전송 방어 상태를 언제 갱신할지도 중요하다.

인증에 실패한 패킷이 유효한 패킷의 수신 상태를 변경할 수 있어서는 안 된다.

## 8.7. 프로토콜 버전 관리

모든 패킷은 규약에 맞는 버전 정보를 가져야 한다.

초기 버전은 논리적으로 `Protocol Version 1`을 사용한다.

향후 버전 변경 시 고려할 사항은 다음과 같다.

- 패킷 포맷 변경
- 암호화 구성 변경
- 핸드셰이크 변경
- 필드 확장
- 세션 관리 방식 변경
- 클라이언트와 서버의 호환성

알 수 없는 버전의 패킷은 안전하게 거부해야 한다.

버전 협상 과정에서 공격자가 보안 수준을 낮추는 다운그레이드 공격도 고려해야 한다.

따라서 단순히 클라이언트가 요청한 버전 중 서버가 지원하는 가장 낮은 버전을 선택하는 설계는 피한다.

---

# 9. 암호화 및 핸드셰이크 설계

## 9.1. 암호화 설계 원칙

GSM Tunnel은 자체 암호화 알고리즘을 개발하지 않는다.

자체 구현 범위는 다음과 같다.

- 암호화 라이브러리 통합
- 핸드셰이크 상태 관리
- 세션 키 관리
- 데이터 패킷 암호화 파이프라인
- Nonce 및 카운터 관리
- 키 갱신 정책
- 암호화 오류 처리

## 9.2. 암호화 구성요소

| 구성요소 | 권장 기술 |
|---|---|
| 핸드셰이크 | Noise Protocol Framework |
| 키 교환 | X25519 |
| 키 파생 | HKDF |
| 데이터 암호화 | ChaCha20-Poly1305 |
| 대체 암호화 후보 | AES-GCM |
| 난수 생성 | 운영체제 CSPRNG |
| 신원 인증 | 검증된 공개키 및 인증된 승인 정보 |

Noise Protocol Framework는 안전한 핸드셰이크를 구성하기 위한 프레임워크이다.

GSM Tunnel은 검증된 Noise 구현체를 사용하고, 선택한 패턴의 요구사항에 맞춰 연결을 수립한다.

핸드셰이크 메시지 형식과 상태 전이는 임의로 변경하지 않는다.

## 9.3. 핸드셰이크 개념

```text
VPN Client                         VPN Server
    │                                  │
    │          Initialization          │
    ├─────────────────────────────────►│
    │                                  │
    │      Handshake Response          │
    │◄─────────────────────────────────┤
    │                                  │
    │       Key Establishment          │
    │                                  │
    │       Secure Session Ready       │
    │                                  │
    │         Encrypted Data           │
    ├─────────────────────────────────►│
    │                                  │
    │         Encrypted Data           │
    │◄─────────────────────────────────┤
    │                                  │
```

위 그림은 절차를 설명하기 위한 개념도이다.

실제 메시지 수와 방향, 공개키 전송 방식은 채택하는 Noise 패턴에 따라 결정한다.

## 9.4. 신원 인증

서비스 로그인 인증과 터널의 암호학적 인증은 서로 구분한다.

서비스 인증 예시:

```text
Client
  │
  ▼
Gateway Login
  │
  ▼
Authorization
  │
  ▼
VPN Server Selection
```

터널 인증 예시:

```text
Client Tunnel Engine
  │
  ▼
Handshake
  │
  ▼
Server Identity Verification
  │
  ▼
Client Identity Verification
  │
  ▼
Authorized Session Establishment
```

Gateway에서 로그인에 성공했다는 사실만으로 임의의 UDP 패킷을 허용해서는 안 된다.

VPN Server가 승인한 암호학적 클라이언트 신원과 실제 핸드셰이크에서 증명된 신원이 일치해야 한다.

클라이언트 역시 사전에 신뢰하도록 구성된 VPN 서버의 신원을 검증해야 한다.

## 9.5. 세션 키 관리

각 터널 세션은 독립적인 키 자료를 사용한다.

개념적으로 다음과 같이 구성한다.

```text
Authenticated Handshake
          │
          ▼
      Key Material
          │
          ▼
     Key Derivation
          │
     ┌────┴────┐
     │         │
     ▼         ▼
Client TX   Client RX
Server RX   Server TX
```

서로 다른 통신 방향에서는 별도의 암호화 키를 사용한다.

동일한 키와 Nonce 조합이 반복되지 않도록 보장해야 한다.

서로 다른 세션 또는 키 세대의 카운터가 혼동되지 않도록 세션별 키 상태를 분리한다.

## 9.6. 키 갱신

장시간 연결되는 VPN에서는 키 갱신이 필요하다.

키 갱신은 다음과 같은 조건을 고려하여 설계한다.

- 일정 시간 경과
- 일정 데이터 전송량 도달
- 암호화 카운터 한계 접근
- 세션 재수립
- 보안 정책 변경

정확한 갱신 기준은 채택한 핸드셰이크 프로토콜과 위협 모델을 검토한 후 확정한다.

키 갱신 과정에서는 다음 사항을 보장해야 한다.

- 새로운 키의 안전한 수립
- 송수신 키 전환의 일관성
- 이전 키로 암호화된 지연 패킷 처리
- 오래된 키의 안전한 폐기
- 키 재사용 방지
- 통신 중단 최소화

## 9.7. 재전송 공격 방어

공격자가 과거에 전송된 암호화 패킷을 다시 전송하더라도 이를 새로운 패킷으로 받아들이지 않아야 한다.

이를 위해 패킷 카운터와 Replay Window를 사용한다.

```text
Received Counter
       │
       ▼
Session Lookup
       │
       ▼
Counter Range Check
       │
       ▼
AEAD Verification
       │
       ▼
Replay Window Update
       │
       ▼
Accept / Reject
```

재전송 방어 구현 시 고려할 사항:

- 중복 패킷 거부
- 지나치게 오래된 패킷 거부
- 정상적인 패킷 재정렬 허용
- 카운터 오버플로 방지
- 키 갱신 시 카운터 상태 분리
- 병렬 패킷 처리에서 경쟁 상태 방지

## 9.8. 암호화 실패 처리

다음과 같은 패킷은 안전하게 거부한다.

- 인증 태그가 잘못된 패킷
- 지원하지 않는 버전의 패킷
- 비정상적인 길이의 패킷
- 알 수 없는 세션의 패킷
- 이미 처리된 패킷
- 허용되지 않은 클라이언트가 생성한 패킷
- 세션 상태와 일치하지 않는 패킷

실패한 패킷의 암호화된 내용을 애플리케이션 로그에 기록하지 않는다.

공격자가 대량의 잘못된 패킷을 전송해 서버 자원을 고갈시키지 못하도록 처리 비용 제한과 요청량 제한도 고려한다.

---

# 10. 실제 인터넷 VPN 동작 구조

## 10.1. VPN의 인터넷 접속 방식

GSM VPN은 사설망 연결만 제공하는 VPN이 아니다.

사용자 인터넷 트래픽을 VPN 서버를 통해 실제 인터넷으로 전달하는 Full Tunnel 방식의 VPN을 목표로 한다.

```text
Client
  │
  ▼
Encrypted Tunnel
  │
  ▼
VPN Server
  │
  ▼
Public Internet
```

VPN 서버는 인터넷 트래픽의 출구 역할을 한다.

## 10.2. 클라이언트에서 인터넷 요청 발생

사용자가 웹 브라우저에서 다음 주소에 접속했다고 가정한다.

```text
https://example.com
```

VPN이 연결되어 있다면 해당 통신의 IP 패킷이 가상 네트워크 인터페이스로 전달되어야 한다.

```text
Browser
   │
   ▼
TCP / TLS
   │
   ▼
IP Packet
   │
   ▼
OS Routing Table
   │
   ▼
VPN TUN
```

이 과정에서 VPN은 웹 브라우저의 HTTPS 트래픽을 직접 해석할 필요가 없다.

GSM Tunnel은 IP 계층의 패킷을 처리한다.

## 10.3. 클라이언트 패킷 전송

클라이언트 엔진은 TUN 인터페이스에서 IP 패킷을 읽는다.

이후 패킷을 자체 프로토콜에 따라 암호화한다.

```text
TUN
 │
 ▼
IP Packet
 │
 ▼
GSM Tunnel Packet
 │
 ▼
AEAD Encryption
 │
 ▼
UDP Datagram
 │
 ▼
VPN Server
```

클라이언트에서 VPN 서버로 보내는 UDP 패킷 자체는 일반 인터넷 연결을 사용한다.

이 UDP 연결까지 VPN TUN으로 다시 전달되면 라우팅 루프가 발생할 수 있다.

따라서 VPN 서버의 엔드포인트로 향하는 전송 경로는 물리적 네트워크를 통해 유지해야 한다.

## 10.4. VPN 서버에서 패킷 수신

VPN 서버는 암호화된 UDP 패킷을 수신한다.

수신 후 다음 절차를 수행한다.

1. 패킷 헤더 검증
2. 세션 식별
3. 재전송 여부 확인
4. 암호화 인증 태그 검증
5. 패킷 복호화
6. 내부 IP 패킷 유효성 검증
7. 해당 클라이언트가 사용할 수 있는 출발지 IP인지 확인
8. TUN 인터페이스에 패킷 전달

특히 내부 IP 패킷의 출발지 주소를 검증해야 한다.

인증된 클라이언트라고 하더라도 다른 클라이언트의 가상 IP 주소를 임의로 사용해서는 안 된다.

## 10.5. IP Forwarding

Linux 서버는 TUN에서 전달된 패킷을 외부 인터넷 인터페이스로 라우팅해야 한다.

```text
GSM Tunnel
     │
     ▼
   TUN
     │
     ▼
Linux Routing
     │
     ▼
IP Forwarding
     │
     ▼
External NIC
```

IP Forwarding은 Linux 커널의 네트워크 기능을 활용한다.

이 기능 자체를 Go에서 새롭게 구현할 필요는 없다. Linux 커널의 IP Forwarding과
nftables/conntrack을 사용한다.

프로젝트의 자체 구현 범위는 사용자 공간 VPN 터널링이며, Linux의 IP 스택 전체를 재구현하는 것이 아니다.

## 10.6. NAT / SNAT

클라이언트의 VPN 내부 IP 주소는 일반적으로 공용 인터넷에서 직접 라우팅되지 않는다.

따라서 VPN 서버는 NAT를 사용해 외부로 나가는 패킷의 출발지 주소를 변환해야 한다.

예시:

```text
VPN Client
10.80.0.2
    │
    ▼
VPN Tunnel
    │
    ▼
VPN Server
10.80.0.1
    │
    ▼
SNAT
    │
    ▼
VPN Server Public IP
    │
    ▼
Internet
```

실제 NAT 기능은 Linux의 nftables와 커널 Connection Tracking을 활용한다.

사용자 공간에서 자체 NAT 엔진을 처음부터 구현하는 것은 초기 범위에 포함하지 않는다.

## 10.7. 응답 패킷 처리

외부 웹 서버의 응답은 VPN 서버의 공인 IP로 돌아온다.

서버의 NAT 및 Connection Tracking에 따라 응답 패킷은 해당 내부 VPN 클라이언트로 라우팅된다.

```text
Internet
   │
   ▼
VPN Server Public IP
   │
   ▼
NAT / Conntrack
   │
   ▼
TUN Interface
   │
   ▼
GSM Tunnel
   │
   ▼
Encrypt
   │
   ▼
UDP
   │
   ▼
Client
```

클라이언트는 패킷을 복호화한 뒤 TUN 인터페이스에 기록한다.

운영체제는 이를 정상적인 수신 IP 패킷으로 처리한다.

## 10.8. 전체 요청 및 응답 시퀀스

```text
User           Client          Tunnel          VPN Server        Internet
 │                │               │                │                │
 │ Open Website   │               │                │                │
 ├───────────────►│               │                │                │
 │                │ IP Packet     │                │                │
 │                ├──────────────►│                │                │
 │                │               │ Encrypt        │                │
 │                │               ├───────────────►│                │
 │                │               │   UDP Packet   │                │
 │                │               │                │ Decrypt        │
 │                │               │                │ Route + NAT    │
 │                │               │                ├───────────────►│
 │                │               │                │                │
 │                │               │                │    Response    │
 │                │               │                │◄───────────────┤
 │                │               │                │                │
 │                │               │◄───────────────┤                │
 │                │               │ Encrypted UDP  │                │
 │                │◄──────────────┤                │                │
 │                │ IP Packet     │                │                │
 │◄───────────────┤               │                │                │
 │ Web Response   │               │                │                │
```

---

# 11. 가상 네트워크 인터페이스

## 11.1. TUN 인터페이스

TUN은 운영체제와 사용자 공간 프로그램 사이에서 IP 패킷을 주고받을 수 있는 가상 네트워크 인터페이스이다.

GSM Tunnel은 TUN을 통해 운영체제에서 생성되는 IP 패킷을 읽고, 원격 VPN 서버에서 받은 IP 패킷을 운영체제에 전달한다.

TAP과 달리 TUN은 기본적으로 IP 계층 패킷을 처리한다.

GSM VPN은 Layer 3 기반 인터넷 VPN이므로 TUN을 기본으로 한다.

## 11.2. Linux 지원

Linux에서는 커널 TUN/TAP 인터페이스를 사용한다.

필요한 기능:

- TUN 장치 생성
- 장치 파일 열기
- 인터페이스 이름 설정
- 가상 IP 설정
- MTU 설정
- IP 패킷 읽기
- IP 패킷 쓰기
- 장치 종료
- 오류 처리

관련 Linux 문서:

https://docs.kernel.org/networking/tuntap.html

## 11.3. Windows 지원

Windows에서는 Wintun 사용을 권장한다.

Wintun은 Windows에서 Layer 3 패킷 처리를 위한 가상 네트워크 인터페이스 기능을 제공한다.

Windows 클라이언트의 주요 처리 과정은 다음과 같다.

```text
Windows Application
        │
        ▼
Windows Network Stack
        │
        ▼
Wintun Adapter
        │
        ▼
Rust Tunnel Core
        │
        ▼
UDP Socket
```

Wintun과 연동하는 Rust 계층은 다른 운영체제의 TUN 구현과 공통 인터페이스를 제공해야 한다.

Wintun 배포 및 라이선스 조건은 실제 클라이언트 패키징 전에 확인한다.

## 11.4. macOS 지원

macOS는 추후 지원 대상으로 둔다.

macOS의 네트워크 인터페이스 및 Network Extension 관련 요구사항을 검토해 플랫폼별 구현을 추가한다.

Linux나 Windows에서 사용하는 네트워크 인터페이스 생성 방식을 macOS에 그대로 적용하지 않는다.

## 11.5. 플랫폼 추상화

공통 엔진이 운영체제별 세부 구현을 직접 알아야 할 필요는 없다.

논리적으로 다음과 같은 인터페이스를 제공한다.

```go
type TunnelDevice interface {
    MTU() int
    ReadPacket([]byte) (int, error)
    WritePacket([]byte) (int, error)
    Close() error
}
```

실제 비동기 읽기 및 쓰기 API는 선택한 런타임과 장치 라이브러리에 맞춰 별도로 정의한다.

플랫폼별 구현은 동일한 논리적 계약을 만족해야 한다.

---

# 12. IP 라우팅 및 네트워크 설정

## 12.1. 기본 라우트

Full Tunnel VPN에서는 기본 인터넷 경로가 VPN TUN 인터페이스를 사용하도록 설정되어야 한다.

예를 들어 IPv4에서는 논리적으로 다음 목적지 범위를 VPN으로 전달한다.

```text
0.0.0.0/0
```

IPv6를 지원한다면 다음 범위도 고려해야 한다.

```text
::/0
```

실제 운영체제에서는 라우트 우선순위, 인터페이스 메트릭 및 정책 라우팅 등을 고려해야 한다.

## 12.2. VPN 서버 경로 예외

VPN 서버에 연결하는 외부 UDP 패킷은 VPN 터널 내부로 들어가서는 안 된다.

잘못된 예시:

```text
VPN UDP Packet
      │
      ▼
Default Route
      │
      ▼
VPN TUN
      │
      ▼
VPN UDP Packet
      │
      ▼
VPN TUN
      │
      ▼
...
```

올바른 처리:

```text
VPN UDP Packet
      │
      ▼
Physical Network Interface
      │
      ▼
Internet
      │
      ▼
VPN Server
```

이를 위해 서버 엔드포인트 라우트 예외 또는 운영체제별 소켓 바인딩 정책을 적용해야 한다.

네트워크가 변경되거나 VPN 서버 IP 주소가 달라지면 예외 경로도 적절하게 갱신해야 한다.

## 12.3. 라우팅 설정 복원

VPN 연결을 종료할 때 변경한 네트워크 설정을 복원해야 한다.

관리 대상:

- 기본 라우트
- DNS 설정
- 인터페이스 상태
- VPN 엔드포인트 예외 경로
- 방화벽 정책
- Kill Switch 상태

애플리케이션이 비정상 종료되는 경우도 고려해야 한다.

단순히 종료 함수에서 복원 작업을 호출하는 것만으로는 충분하지 않다.

크래시 복구와 재시작 후 상태 복구 정책을 별도로 마련한다.

---

# 13. DNS 처리

## 13.1. DNS 유출 문제

VPN 연결 중 DNS 요청이 물리적 네트워크를 통해 전달되면 사용자가 방문하려는 도메인에 대한 정보가 VPN 외부로 노출될 수 있다.

따라서 GSM VPN은 DNS 유출 방지 기능을 제공해야 한다.

## 13.2. DNS 처리 방식

초기에는 VPN 연결 시 운영체제의 DNS 설정을 VPN 정책에 맞게 변경한다.

DNS 요청은 VPN 터널을 통해 전달되도록 구성한다.

```text
Application
     │
     ▼
DNS Request
     │
     ▼
VPN TUN
     │
     ▼
GSM Tunnel
     │
     ▼
VPN Server
     │
     ▼
DNS Resolver
```

DNS Resolver를 VPN 서버에 직접 운영할지, 외부 Resolver를 사용할지는 운영 정책에 따라 결정한다.

## 13.3. DNS 관련 요구사항

- VPN 연결 시 DNS 정책 적용
- VPN 종료 시 DNS 설정 복원
- DNS 서버 접근 가능 여부 검증
- IPv4 및 IPv6 DNS 처리
- 운영체제별 DNS 설정 차이 대응
- VPN 외부 DNS 요청 방지
- 연결 실패 시 안전한 상태 유지

일부 애플리케이션은 자체 DoH 또는 DoT를 사용할 수 있으므로 운영체제 DNS 설정 변경만으로 모든 DNS 동작을 통제할 수 있다고 가정해서는 안 된다.

---

# 14. IPv6 처리

## 14.1. IPv6 유출 방지

IPv4 VPN만 구현한 상태에서 운영체제가 IPv6 인터넷 연결을 계속 사용할 경우 일부 트래픽이 VPN을 우회할 수 있다.

초기 버전에서는 두 가지 방향을 고려한다.

**방안 A. IPv6 터널링 구현**

IPv4와 IPv6 패킷을 모두 처리한다.

**방안 B. IPv6 우회 차단**

IPv6 터널링이 준비되지 않았다면 VPN 연결 중 IPv6 트래픽이 외부 네트워크로 우회하지 못하도록 차단한다.

## 14.2. 초기 구현 방향

최초 버전에서는 IPv4 인터넷 VPN을 우선 완성한다.

IPv6는 안전하게 차단하는 방식으로 시작할 수 있다.

단, 차단 정책은 시스템 전체의 네트워크 설정과 충돌하지 않도록 운영체제별로 검증해야 한다.

이후 IPv6 지원을 추가한다.

## 14.3. 향후 IPv6 지원 기능

- IPv6 가상 주소 할당
- IPv6 TUN 패킷 처리
- IPv6 라우팅
- IPv6 DNS 정책
- IPv6 인터넷 연결
- IPv6 트래픽 보안 검사

---

# 15. MTU 및 패킷 크기

## 15.1. MTU 문제

VPN은 원본 IP 패킷을 새로운 UDP 패킷 내부에 캡슐화한다.

따라서 외부 IP 헤더, UDP 헤더, 터널 프로토콜 헤더 및 인증 태그에 따른 추가 오버헤드가 발생한다.

```text
Outer IP Header
       +
UDP Header
       +
Tunnel Header
       +
Encrypted IP Packet
       +
Authentication Tag
```

그 결과 물리적 네트워크의 MTU보다 큰 패킷이 생성될 수 있다.

## 15.2. MTU 처리 요구사항

- 터널 MTU 설정
- 외부 전송 경로의 MTU 고려
- 암호화 패킷 크기 검증
- 과도하게 큰 패킷 거부
- Path MTU Discovery 관련 처리
- ICMP Packet Too Big 등의 오류 처리
- 패킷 단편화 문제 분석
- 성능 측정을 통한 적절한 MTU 결정

최초 버전에서 무조건적인 자체 패킷 분할 기능을 추가하지 않는다.

가능한 한 적절한 TUN MTU를 설정하고 IP 계층의 정상적인 동작을 활용한다.

필요한 경우 후속 버전에서 분할 및 재조립을 별도로 설계한다.

---

# 16. 세션 관리

## 16.1. 세션의 정의

Tunnel Session은 클라이언트와 VPN 서버 사이에 수립된 암호화 통신 상태를 의미한다.

세션에는 다음 정보가 포함될 수 있다.

| 정보 | 목적 |
|---|---|
| Session Identifier | 세션 식별 |
| Peer Identity | 암호학적 연결 상대 식별 |
| Remote Endpoint | UDP 전송 대상 |
| Assigned Tunnel IP | 클라이언트 가상 IP |
| Encryption State | 송수신 암호화 상태 |
| Key Generation | 현재 키 세대 |
| Send Counter | 송신 패킷 카운터 |
| Replay Window | 수신 패킷 재전송 방어 |
| Last Activity | 마지막 정상 통신 |
| Connection State | 현재 연결 상태 |
| Session Statistics | 송수신 통계 |

민감한 세션 키 자료는 로그나 일반 상태 조회 API를 통해 노출하지 않는다.

## 16.2. 세션 상태

세션은 다음과 같은 상태를 가질 수 있다.

```text
        DISCONNECTED
              │
              ▼
          CONNECTING
              │
              ▼
         HANDSHAKING
              │
              ▼
          ESTABLISHED
              │
       ┌──────┴──────┐
       │             │
       ▼             ▼
    REKEYING      RECONNECTING
       │             │
       └──────┬──────┘
              │
              ▼
          ESTABLISHED
              │
              ▼
           CLOSING
              │
              ▼
           CLOSED
```

이 상태도는 전체 연결 수명주기의 개념도이다.

실제 구현에서는 초기 연결, 인증 실패, 타임아웃, 키 만료, 연결 해제 등의 이벤트를 별도 상태 전이로 명확하게 정의한다.

특히 실패한 세션을 무한히 재시도하지 않도록 제한해야 한다.

## 16.3. 세션 생성

세션 생성 절차:

1. 사용자가 Gateway Server에서 인증한다.
2. 사용자가 VPN 서버를 선택한다.
3. Gateway Server가 연결 승인을 수행한다.
4. VPN Server가 승인 정보를 검증한다.
5. VPN Server가 클라이언트 공개키 및 허용된 가상 IP 등의 정보를 Tunnel Engine에 등록한다.
6. 클라이언트가 서버와 핸드셰이크를 수행한다.
7. 양측이 암호학적 신원을 확인한다.
8. 세션 키가 수립된다.
9. Tunnel Engine이 데이터 패킷 송수신을 시작한다.
10. VPN Server가 연결 상태를 관리한다.

여기서 Gateway의 승인 정보가 어떤 형식으로 전달되는지, 승인 만료 시간을 어떻게 적용하는지, 승인 철회 시 기존 세션을 어떻게 종료하는지는 연동 API 설계 단계에서 확정한다.

## 16.4. 세션 종료

세션은 다음 상황에서 종료될 수 있다.

- 사용자의 VPN 연결 해제
- VPN Server의 연결 종료 명령
- 서비스 이용 권한 철회
- 인증 실패
- 장기간 통신 불가
- 키 상태 오류
- 서버 종료
- 프로토콜 오류

종료된 세션의 키와 송수신 상태는 안전하게 폐기한다.

## 16.5. Keepalive

UDP에는 TCP와 같은 연결 상태 확인 기능이 없다.

또한 NAT 환경에서는 일정 시간 동안 통신이 없으면 매핑이 사라질 수 있다.

따라서 필요할 경우 Keepalive 기능을 구현한다.

Keepalive 처리 시 고려할 사항:

- 불필요한 패킷 발생 최소화
- 배터리 사용량
- NAT 매핑 유지
- 연결 상태 탐지
- 네트워크 변경 감지
- 서버 자원 사용량

Keepalive는 암호학적으로 인증된 데이터 또는 제어 메시지로 처리해야 한다.

## 16.6. 재연결

클라이언트의 인터넷 연결이 변경될 수 있다.

예시:

- Wi-Fi 연결 해제
- 다른 Wi-Fi 네트워크 연결
- 모바일 핫스팟으로 전환
- VPN 서버 재시작
- 네트워크 일시 장애

GSM Tunnel은 연결 변경을 감지하고 재연결을 시도할 수 있어야 한다.

다만 UDP 송신자의 IP 주소나 포트가 변경되었다는 이유만으로 기존 세션을 무조건 다른 주소에 연결해서는 안 된다.

새 엔드포인트의 신뢰성은 인증된 세션 및 암호학적 검증 결과에 근거해야 한다.

## 16.7. 다중 클라이언트

VPN Server는 여러 클라이언트의 연결을 동시에 처리할 수 있어야 한다.

예시:

```text
                   VPN Server
                       │
                 GSM Tunnel
                       │
             ┌─────────┼─────────┐
             │         │         │
             ▼         ▼         ▼
          Client A  Client B  Client C
             │         │         │
          10.80.0.2 10.80.0.3 10.80.0.4
```

서버는 클라이언트별로 세션 상태와 허용된 가상 IP를 구분한다.

한 클라이언트가 다른 클라이언트의 키나 세션 상태에 접근할 수 없어야 한다.

또한 한 클라이언트가 과도하게 패킷을 전송하더라도 다른 클라이언트의 통신이 중단되지 않도록 자원 제한을 고려한다.

---

# 17. VPN Server와 Tunnel Engine 연동

## 17.1. 연동 목표

기존 `vpn-server`는 유지한다.

`tunnel` 저장소는 실제 암호화된 IP 패킷 송수신과 터널 세션 관리를 담당한다.

두 컴포넌트는 명확한 내부 인터페이스를 통해 통신한다.

## 17.2. 통합 방식 후보

### 방식 A. 라이브러리 호출

VPN Server가 Tunnel Engine을 직접 호출한다.

장점:

- IPC 오버헤드 감소
- 배포 구조가 단순할 수 있음
- 함수 단위로 제어 가능

단점:

- 기존 TypeScript 서버와 Go 사이에 FFI 또는 별도 바인딩이 필요함
- 프로세스 장애 격리가 어려움
- 네이티브 모듈 배포 및 런타임 관리가 복잡해질 수 있음

### 방식 B. 별도 프로세스와 IPC

Tunnel Engine을 별도 프로세스로 실행한다.

VPN Server는 IPC를 통해 Tunnel Engine을 제어한다.

장점:

- 언어와 런타임 분리
- 장애 격리
- 독립적인 배포
- 터널 엔진 재시작 가능
- 운영 권한 분리 가능

단점:

- IPC 인터페이스 구현 필요
- 프로세스 수명주기 관리 필요
- 상태 동기화 필요

### 방식 C. HTTP 기반 내부 API

Tunnel Engine이 로컬 HTTP API를 제공한다.

VPN Server가 해당 API를 호출한다.

장점:

- TypeScript에서 쉽게 통합 가능
- 디버깅 편리
- API 설계가 직관적

단점:

- 별도 HTTP 서버 필요
- 접근 제어 필요
- 제어용 네트워크 인터페이스 노출 위험
- IPC보다 배포 구성이 복잡해질 수 있음

## 17.3. 권장 방식

**초기 독립 개발은 Go Controller와 Rust `tunnel-core`를 함께 검증하는 예제 실행 파일로 진행하고,
기존 TypeScript VPN Server와의 실제 통합에는 별도 프로세스와 Unix Domain Socket 기반 IPC를 권장한다.**

Go Controller는 Rust `tunnel-core`를 관리용 IPC로 제어하므로, 기존 서버를 Go나
Rust로 다시 작성하지 않고도 터널 엔진을 통합할 수 있다.

Windows 클라이언트에서는 운영체제에 적합한 별도의 연동 방식 또는 직접 라이브러리 호출을 사용할 수 있다.

## 17.4. 논리적 내부 API

다음 기능을 제공하는 제어 인터페이스를 설계한다.

| Operation | 기능 |
|---|---|
| Initialize Engine | 터널 엔진 초기화 |
| Start Engine | 터널 엔진 시작 |
| Stop Engine | 터널 엔진 종료 |
| Register Peer | 허용된 클라이언트 등록 |
| Remove Peer | 클라이언트 등록 해제 |
| Create Session | 세션 수립을 위한 상태 준비 |
| Terminate Session | 세션 종료 |
| Get Session | 세션 상태 조회 |
| List Sessions | 활성 세션 목록 조회 |
| Get Statistics | 트래픽 통계 조회 |
| Update Configuration | 설정 변경 |
| Get Health | 엔진 상태 확인 |

여기서 `Create Session`은 VPN Server가 임의로 암호화 세션을 완성한다는 의미가 아니다.

승인된 피어의 연결 수립을 준비하는 관리 동작이며, 실제 세션 키는 검증된 핸드셰이크를 통해 생성한다.

## 17.5. IPC 보안

내부 API는 외부 사용자에게 공개하지 않는다.

Unix Domain Socket 사용 시 다음 항목을 적용한다.

- 소켓 파일 접근 권한 제한
- 승인된 프로세스만 접근 허용
- 호출자 권한 확인
- 입력값 검증
- 명령별 권한 확인
- 요청 크기 제한
- 비정상 요청 처리
- 안전한 프로세스 종료

터널 엔진은 VPN Server로부터 전달받은 요청이라도 형식 및 범위를 검증해야 한다.

## 17.6. 인증 책임 분리

사용자의 기존 로그인 세션과 터널의 암호화 세션은 별개의 개념이다.

```text
Gateway Authentication
          │
          ▼
Service Authorization
          │
          ▼
VPN Server
          │
          ▼
Peer Authorization
          │
          ▼
Tunnel Handshake
          │
          ▼
Encrypted Session
```

Gateway Server가 사용자를 승인하면 VPN Server는 이에 대응하는 터널 접근 정책을 설정한다.

Tunnel Engine은 승인된 암호학적 신원만 연결할 수 있도록 제한한다.

이 구조를 통해 Gateway의 인증 구현이 변경되더라도 Tunnel Engine의 프로토콜 자체는 유지할 수 있다.

---

# 18. VPN Client 연동

## 18.1. 클라이언트 역할

VPN Client는 사용자와 VPN 서비스를 연결하는 애플리케이션이다.

주요 기능은 다음과 같다.

- 로그인
- VPN 서버 선택
- VPN 연결 요청
- VPN 연결 종료
- 연결 상태 표시
- 네트워크 설정 적용
- Tunnel Engine 실행
- 연결 오류 표시
- 네트워크 설정 복원

## 18.2. 클라이언트에서 Tunnel Engine 실행

```text
GSM VPN Client UI
        │
        ▼
Client Controller
        │
        ▼
Gateway Authentication
        │
        ▼
VPN Configuration
        │
        ▼
Tunnel Engine Start
        │
        ▼
TUN Interface Setup
        │
        ▼
Handshake
        │
        ▼
VPN Connected
```

## 18.3. 운영체제별 구성

| 플랫폼 | VPN 엔진 | 네트워크 인터페이스 |
|---|---|---|
| Linux | Go Controller + Rust Tunnel Core | TUN |
| Windows | Go Controller + Rust Tunnel Core | Wintun |
| macOS | Go Controller + Rust Tunnel Core | 플랫폼별 네트워크 인터페이스 |

프로토콜과 암호화 구현은 가능한 한 플랫폼별 차이 없이 재사용한다.

운영체제의 라우팅, DNS, 방화벽 및 인터페이스 설정만 플랫폼별 어댑터에서 처리한다.

## 18.4. Kill Switch

Kill Switch는 VPN 연결에 문제가 발생했을 때 사용자 트래픽이 일반 네트워크로 우회하는 것을 방지하기 위한 기능이다.

VPN 연결이 끊어졌다는 이유만으로 기존 네트워크 경로를 무조건 복원하면 트래픽 유출이 발생할 수 있다.

따라서 사용자가 Kill Switch를 활성화한 경우 다음을 보장해야 한다.

- VPN 연결 중에는 VPN 외부 트래픽 차단
- VPN 연결 장애 발생 시 우회 트래픽 차단
- VPN 서버와의 제어 연결에 필요한 경로 유지
- VPN 종료 정책에 따라 네트워크 상태 처리
- 비정상 종료 시 방화벽 상태의 안전한 복구

Kill Switch는 단순히 애플리케이션의 연결 상태를 확인하는 기능이 아니라 운영체제의 패킷 필터링 정책과 함께 구현해야 한다.

---

# 19. 보안 요구사항

## 19.1. 보안 목표

GSM Tunnel의 보안 목표는 다음과 같다.

- 패킷 기밀성
- 패킷 무결성
- 통신 상대 인증
- 재전송 공격 방어
- 세션 격리
- 안전한 키 갱신
- 임의의 패킷 주입 방지
- 승인되지 않은 네트워크 접근 방지
- 트래픽 우회 유출 방지

## 19.2. 보호 대상

보호해야 할 주요 자산은 다음과 같다.

- 사용자 인터넷 트래픽
- 터널 암호화 키
- 클라이언트 신원 정보
- VPN 서버의 암호학적 신원
- 연결 승인 정보
- 세션 상태
- VPN 가상 IP 주소
- 클라이언트 라우팅 및 DNS 정책

## 19.3. 위협 모델

고려할 공격 유형은 다음과 같다.

| 위협 | 대응 방향 |
|---|---|
| 네트워크 도청 | 인증된 암호화 |
| 패킷 변조 | AEAD 무결성 검증 |
| 패킷 재전송 | Replay Window |
| 서버 사칭 | 서버 신원 검증 |
| 클라이언트 사칭 | 승인된 피어 신원 검증 |
| 세션 탈취 | 암호화 키 및 세션 상태 보호 |
| 가상 IP 스푸핑 | 내부 패킷 출발지 검증 |
| 프로토콜 다운그레이드 | 버전 및 핸드셰이크 정책 검증 |
| 대량의 비정상 패킷 | Rate Limiting 및 자원 제한 |
| DNS 유출 | DNS 경로 제어 |
| IPv6 유출 | IPv6 지원 또는 우회 차단 |
| VPN 연결 장애 | Kill Switch |
| 키 유출 | 비밀키 접근 제한 및 키 갱신 |
| 악의적인 내부 API 호출 | IPC 접근 제어 |

## 19.4. 암호학적 안전성

프로토콜 개발 과정에서 다음 규칙을 준수한다.

1. 자체 암호화 알고리즘을 발명하지 않는다.
2. 검증된 암호화 라이브러리를 사용한다.
3. Nonce를 재사용하지 않는다.
4. 암호화 키를 평문 로그에 기록하지 않는다.
5. 인증되지 않은 패킷을 운영체제의 TUN에 기록하지 않는다.
6. 재전송 공격 방어 상태를 세션별로 분리한다.
7. 핸드셰이크 상태를 엄격하게 검증한다.
8. 키 갱신 실패 시 안전하지 않은 이전 상태로 무제한 동작하지 않는다.
9. 비밀키를 일반 설정 파일에 무방비로 저장하지 않는다.
10. 암호화 오류를 무시하고 패킷을 전달하지 않는다.

## 19.5. 운영체제 권한

TUN 생성, 라우팅 변경 및 방화벽 설정에는 높은 운영체제 권한이 필요할 수 있다.

그러나 VPN 엔진의 모든 기능을 관리자 권한으로 실행할 필요는 없다.

가능한 경우 다음과 같이 역할을 분리한다.

```text
Privileged Network Helper
          │
          ▼
TUN / Routing / Firewall Setup
          │
          ▼
Unprivileged Tunnel Engine
          │
          ▼
Packet Processing
```

운영체제별 지원 기능에 따라 실제 권한 분리 방법을 결정한다.

## 19.6. 실사용 제한

초기 자체 프로토콜은 연구 및 개발용으로 취급한다.

암호화 통신이 성공한다는 사실만으로 안전한 VPN이라고 판단하지 않는다.

최소한 다음 과정을 거친 이후에 실제 사용자를 대상으로 하는 배포를 검토한다.

- 프로토콜 설계 검토
- 암호화 구현 테스트
- 패킷 파서 Fuzzing
- 핸드셰이크 테스트
- 세션 상태 머신 테스트
- 재전송 공격 테스트
- 잘못된 패킷 처리 테스트
- DNS/IPv6 유출 테스트
- 장애 복구 테스트
- 독립적인 보안 검토

기존 WireGuard 엔진은 자체 프로토콜의 검증이 완료될 때까지 유지하는 것이 적절하다.

---

# 20. 성능 설계

## 20.1. 성능 목표

GSM Tunnel은 자체 프로토콜 구현을 통해 성능 특성을 측정하고 개선할 수 있어야 한다.

처음부터 WireGuard보다 높은 성능을 달성하는 것을 필수 목표로 설정하지 않는다.

대신 측정 가능한 지표를 통해 성능을 분석한다.

## 20.2. 주요 성능 지표

| 지표 | 측정 내용 |
|---|---|
| Throughput | 초당 전송 가능한 데이터량 |
| RTT | 왕복 통신 지연 |
| CPU Usage | 패킷 처리 중 CPU 사용량 |
| Memory Usage | 세션 및 패킷 처리에 필요한 메모리 |
| Packet Loss | 패킷 손실 환경에서의 동작 |
| Concurrent Sessions | 동시 접속 가능한 클라이언트 수 |
| Encryption Performance | 암호화 및 복호화 처리량 |
| Packet Processing Rate | 초당 처리 패킷 수 |
| Reconnection Time | 연결 장애 이후 복구 시간 |
| Handshake Time | 터널 연결 수립 시간 |

## 20.3. WireGuard 비교

비교 대상은 다음과 같다.

```text
                 Test Environment
                        │
            ┌───────────┴───────────┐
            │                       │
      WireGuard VPN             GSM Tunnel VPN
            │                       │
            └───────────┬───────────┘
                        │
                    Benchmark
```

동일한 서버와 네트워크 조건에서 측정한다.

비교 항목:

- 다운로드 처리량
- 업로드 처리량
- 평균 RTT
- 패킷 손실률
- CPU 사용량
- 메모리 사용량
- 동시 접속 처리 성능
- 연결 수립 시간
- 연결 복구 시간

서로 다른 구현 환경에서 발생한 성능 차이를 프로토콜 자체의 차이로 단정하지 않는다.

예를 들어 WireGuard의 커널 구현과 GSM Tunnel의 사용자 공간 구현을 비교한다면 실행 환경 차이도 결과 해석에 포함해야 한다.

## 20.4. 최적화 후보

프로파일링 결과에 따라 다음을 최적화할 수 있다.

- 불필요한 메모리 할당 제거
- 버퍼 재사용
- 패킷 복사 최소화
- 비동기 UDP 처리
- 암호화 연산 최적화
- 세션 조회 구조 개선
- 다중 패킷 처리
- TUN 입출력 최적화
- 동시성 병목 제거

최적화 전후의 성능을 동일한 조건에서 측정한다.

정확성과 보안 검증을 성능보다 우선한다.

---

# 21. 개발 단계

## 21.1. Phase 1 — Linux 기반 기본 터널

### 목표

Linux 클라이언트와 Linux 서버 사이에서 IP 패킷을 전달하는 기본 터널을 구현한다.

### 개발 기능

- Go Module 및 Rust Cargo Workspace 생성
- Go Controller 및 Rust `tunnel-core` 생성
- Controller IPC 생성
- Rust TUN·UDP 데이터 플레인 생성
- Linux TUN 인터페이스 제어
- UDP 패킷 송수신
- 기본 패킷 캡슐화
- 기본 패킷 역캡슐화
- 클라이언트와 서버 간 IP 패킷 전달
- Linux IP Forwarding
- NAT 설정
- 실제 인터넷 연결 테스트

### 동작 구조

```text
Linux Client
     │
     ▼
    TUN
     │
     ▼
GSM Tunnel
     │
     ▼
    UDP
     │
     ▼
Linux Server
     │
     ▼
    TUN
     │
     ▼
IP Forwarding
     │
     ▼
    NAT
     │
     ▼
 Internet
```

### 주의사항

암호화되지 않은 기본 터널은 기능 검증용으로만 사용한다.

해당 구현을 공용 네트워크에서 일반 VPN처럼 운영하지 않는다.

가능한 한 격리된 로컬 네트워크 또는 네트워크 네임스페이스에서 테스트한다.

### 완료 기준

- Linux TUN을 통해 IP 패킷 송수신 가능
- 클라이언트와 서버의 양방향 패킷 전달 가능
- UDP 전송 경로 확인
- 서버 IP Forwarding 동작
- NAT를 통한 인터넷 접근 확인
- 기본 오류 처리 구현

## 21.2. Phase 2 — 보안 프로토콜 구현

### 목표

기본 터널에 인증된 암호화 통신을 구현한다.

### 개발 기능

- 프로토콜 패킷 규격 확정
- Noise 기반 핸드셰이크 통합
- X25519 키 교환
- HKDF 키 파생
- ChaCha20-Poly1305 암호화
- 송수신 키 분리
- Nonce 및 카운터 관리
- 암호화 패킷 송수신
- 재전송 공격 방어
- 세션 생성 및 종료
- 세션 키 갱신
- Keepalive
- 연결 오류 처리

### 완료 기준

- 인증된 클라이언트만 세션 수립 가능
- 클라이언트의 서버 신원 검증 가능
- 암호화된 데이터 전송 가능
- 변조된 패킷 거부
- 중복 패킷 거부
- 키 갱신 테스트 통과
- 비정상 핸드셰이크 처리 테스트 통과

## 21.3. Phase 3 — GSM Gateway 및 VPN Server 연동

### 목표

독립적으로 개발한 Tunnel Engine을 기존 GSM VPN 서비스에 통합한다.

### 개발 기능

- VPN Server와 Tunnel Engine 연동
- 내부 제어 API
- Peer 등록
- Peer 제거
- 가상 IP 할당 연계
- 인증 결과 검증
- 터널 세션 승인
- 터널 세션 종료
- 상태 조회
- 접속 현황 및 통계
- Tunnel Engine 실행 및 종료 관리

### 완료 기준

- 기존 Gateway 인증 흐름 사용
- 기존 VPN Server에서 Tunnel Engine 제어
- 승인된 사용자만 VPN 연결 가능
- 사용자별 가상 IP 분리
- 연결 종료 및 권한 철회 처리
- 여러 사용자 동시 연결

## 21.4. Phase 4 — Windows 클라이언트

### 목표

Windows에서 자체 프로토콜 기반 인터넷 VPN을 사용할 수 있도록 한다.

### 개발 기능

- Wintun 연동
- Windows 가상 인터페이스 생성
- Windows 라우팅 설정
- DNS 설정
- VPN 엔드포인트 예외 경로
- Windows Tunnel Engine 실행
- 기존 클라이언트 UI 연동
- 연결 상태 표시
- VPN 종료 시 네트워크 복원

### 완료 기준

- Windows에서 VPN 서버 연결
- Windows 인터넷 트래픽의 VPN 터널 전달
- VPN 서버 공인 IP로 인터넷 접속
- 정상적인 연결 종료
- 기본적인 DNS 유출 방지
- 네트워크 설정 복원

## 21.5. Phase 5 — 안정성 및 성능 최적화

### 목표

개발용 터널 엔진을 실사용 검토가 가능한 수준으로 개선한다.

### 개발 기능

- IPv6 처리
- DNS 유출 방지 고도화
- Kill Switch
- MTU 최적화
- Path MTU 관련 처리
- 재연결 개선
- 대량 패킷 처리
- 동시 세션 최적화
- 성능 분석
- WireGuard 벤치마크
- 보안 테스트
- Fuzzing
- 오류 및 장애 복구 검증

### 완료 기준

- 정의된 보안 테스트 통과
- DNS/IPv6 유출 테스트 통과
- 네트워크 장애 복구 테스트 통과
- 다중 클라이언트 환경 검증
- WireGuard 성능 비교 보고서 작성
- 주요 성능 병목 분석
- 독립적인 보안 검토 수행

---

# 22. 테스트 설계

## 22.1. 테스트 분류

GSM Tunnel은 다음 테스트를 구현한다.

| 테스트 유형 | 대상 |
|---|---|
| Unit Test | 개별 함수 및 자료구조 |
| Integration Test | Crate 간 연동 |
| Protocol Test | 패킷 규격 |
| Cryptography Test | 암호화 및 키 교환 |
| Network Test | 실제 패킷 전달 |
| Security Test | 공격 및 비정상 입력 대응 |
| Performance Test | 처리량 및 지연 |
| Compatibility Test | 운영체제별 동작 |
| Recovery Test | 장애 및 재연결 |

## 22.2. Protocol 테스트

검증 항목:

- 패킷 인코딩 및 디코딩
- 정상적인 헤더 처리
- 비정상적인 헤더 거부
- 지원하지 않는 버전 처리
- 비정상적인 패킷 길이 처리
- 잘못된 Packet Type 처리
- 잘못된 Session ID 처리
- 빈 Payload 처리
- 최대 허용 크기의 패킷 처리

## 22.3. 암호화 테스트

검증 항목:

- 정상적인 핸드셰이크
- 잘못된 클라이언트 신원
- 잘못된 서버 신원
- 암호화 및 복호화 결과 일치
- 잘못된 암호화 키
- 잘못된 인증 태그
- 변조된 암호문
- Nonce 중복 방지
- 키 갱신
- 재전송 공격 방어
- 세션별 키 격리

암호화 자체의 정확성은 라이브러리의 검증뿐 아니라 알려진 테스트 벡터를 활용해 확인한다.

## 22.4. 네트워크 테스트

검증 항목:

- Linux TUN 생성
- Linux TUN 종료
- IP 패킷 읽기
- IP 패킷 쓰기
- UDP 패킷 송신
- UDP 패킷 수신
- 양방향 터널 통신
- IP Forwarding
- NAT
- 인터넷 접속
- 서버 공인 IP 적용
- 여러 클라이언트 연결

## 22.5. 장애 테스트

다음 상황을 검증한다.

- VPN 서버 종료
- VPN 서버 재시작
- 클라이언트 강제 종료
- UDP 패킷 손실
- UDP 패킷 중복
- UDP 패킷 재정렬
- 일시적인 네트워크 단절
- 네트워크 인터페이스 변경
- DNS 서버 장애
- VPN 서버 주소 변경
- 키 갱신 중 네트워크 장애
- 디스크 또는 메모리 부족
- Tunnel Engine 비정상 종료

## 22.6. 보안 테스트

초기 보안 테스트는 다음 항목을 포함한다.

```text
Security Tests
│
├── Packet Integrity
├── Replay Protection
├── Handshake Authentication
├── Session Isolation
├── Key Rotation
├── Invalid Packet Handling
├── Parser Fuzzing
├── Source IP Validation
├── DNS Leak Detection
├── IPv6 Leak Detection
└── Kill Switch Verification
```

## 22.7. 테스트 환경

초기 개발에서는 Linux Network Namespace를 활용하는 것을 추천한다.

예시:

```text
Linux Test Host
│
├── Client Namespace
│   └── GSM Tunnel Client
│
├── Network Namespace
│   └── Simulated Network
│
└── Server Namespace
    ├── GSM Tunnel Server
    └── Simulated Internet
```

이 구조를 이용하면 실제 외부 VPN 서버 없이도 패킷 전달과 라우팅을 검증할 수 있다.

또한 지연, 패킷 손실, 패킷 재정렬 등의 네트워크 조건을 재현하기 쉽다.

---

# 23. 기술 스택 최종 정리

## 23.1. 언어 후보 비교

최초 논의에서는 TypeScript, Go, Rust, C를 후보로 검토하였다.

| 언어 | 장점 | 단점 | 판단 |
|---|---|---|---|
| TypeScript | 기존 서버와 통합 용이 | 런타임 및 저수준 네트워크 제어 제약 | 기존 서버 유지 |
| Go | 동시성 처리, 관리 API, 배포 간결 | GC에 따른 지연 가능성, 저수준 데이터 경로의 일부 제약 | 제어·운영 계층 |
| Rust | 메모리 안전성, 성능, 저수준 제어 | 개발 난이도와 빌드 비용 | 데이터 플레인·프로토콜 코어 |
| C | 저수준 시스템 제어에 강점 | 메모리 안전성 확보 부담 | 비권장 |

Go를 제어·운영 계층에 선택하는 이유는 다음과 같다.

- 고루틴과 표준 패키지를 활용한 제어 요청·세션 상태 처리
- 단일 실행 파일 중심의 간단한 배포
- 기존 TypeScript VPN Server와 Unix Domain Socket, HTTP 또는 gRPC로 통합
- 설정·수명주기·IPC·운영 계층을 빠르게 반복 개발
- 테스트, 로깅, 메트릭 및 운영 도구 구현의 용이성
- Linux, Windows, macOS용 관리 계층과 Rust 데이터 플레인의 분리

Go의 GC로 인한 지연 가능성은 관리 요청과 상태 처리에 한정되도록 설계한다.
실제 패킷 처리와 암호화 핫패스는 Rust Tunnel Core 내부에서 처리한다.

암호화 알고리즘은 직접 발명하지 않으며, Rust 프로토콜 코어에서 검증된
암호화 라이브러리를 사용한다. Linux의 IP Forwarding과 NAT는 운영체제 커널
기능을 사용한다.

## 23.2. 최종 기술 선택

| 구성 요소 | 기술 |
|---|---|
| Gateway Server | TypeScript / Fastify |
| VPN Server | 기존 TypeScript 유지 |
| Tunnel Controller | Go |
| Tunnel Core / Data Plane | Rust |
| Protocol Core | Rust |
| Control IPC | Go ↔ Rust local IPC |
| UDP Transport | Rust |
| Go Runtime | Go net / goroutine |
| Rust Async Runtime | 필요 시 Tokio 검토 |
| Linux Device | Rust TUN Adapter |
| Windows Device | Rust Wintun Adapter |
| Handshake | Noise Protocol Framework |
| Key Exchange | X25519 |
| Key Derivation | HKDF |
| Encryption | ChaCha20-Poly1305 |
| Randomness | OS CSPRNG |
| IP Forwarding | Linux Kernel |
| NAT | nftables |
| Server IPC | Unix Domain Socket 권장 |
| Testing | Go Test + Rust Test / Integration Test / Fuzzing |
| Benchmark | Go Benchmark, pprof, Rust Criterion 및 네트워크 측정 도구 |

라이브러리의 실제 선택과 버전은 개발 착수 시 Go·Rust 생태계의 유지보수 현황,
라이선스, 보안 이력 및 API 안정성을 검토하여 확정한다.

---

# 24. 시스템 비기능 요구사항

## 24.1. 독립성

GSM Tunnel은 Gateway Server 및 VPN Server가 없어도 제한된 개발 환경에서 독립적으로 실행하고 테스트할 수 있어야 한다.

독립적인 클라이언트와 서버 예제 실행 파일을 제공한다.

## 24.2. 재사용성

동일한 프로토콜 구현을 클라이언트와 서버에서 공유한다.

운영체제별 차이는 Device 계층으로 분리한다.

## 24.3. 유지보수성

Protocol, Transport, Device, Engine 사이의 책임을 명확하게 구분한다.

상위 계층의 변경으로 인해 불필요하게 하위 계층 전체를 수정하지 않도록 한다.

## 24.4. 관측 가능성

Tunnel Engine은 다음 상태 정보를 제공할 수 있어야 한다.

- 엔진 실행 상태
- 활성 세션 수
- 클라이언트별 연결 상태
- 송신 바이트 수
- 수신 바이트 수
- 송신 패킷 수
- 수신 패킷 수
- 암호화 검증 실패 횟수
- 재연결 횟수
- 패킷 처리 오류

로그와 상태 조회 결과에는 암호화 키 또는 민감한 사용자 패킷 내용을 포함하지 않는다.

## 24.5. 오류 처리

모든 계층은 처리 가능한 오류를 명확한 오류 타입으로 표현한다.

프로토콜 계층에서 발생한 잘못된 패킷이 전체 서버 프로세스의 종료로 이어지지 않도록 한다.

예상할 수 없는 내부 상태 오류는 적절하게 기록하고, 영향을 받는 세션 또는 컴포넌트를 안전하게 종료한다.

## 24.6. 테스트 가능성

네트워크 장치, 전송 계층 및 시간 관련 동작은 가능하면 테스트용 구현으로 교체할 수 있도록 설계한다.

이를 통해 실제 TUN 장치 없이도 프로토콜 테스트를 수행할 수 있다.

## 24.7. 크로스 플랫폼

Protocol과 Transport의 핵심 로직은 운영체제에 의존하지 않아야 한다.

Linux, Windows, macOS의 차이는 플랫폼 계층에서 처리한다.

---

# 25. 학교 프로젝트 평가 및 기술적 성과

## 25.1. 프로젝트의 차별점

GSM VPN은 기존 VPN 솔루션을 단순히 설정하는 프로젝트가 아니라 실제 터널링 엔진을 구현하는 프로젝트를 목표로 한다.

평가에서 강조할 수 있는 기술적 요소는 다음과 같다.

| 분야 | 구현 및 검증 내용 |
|---|---|
| 컴퓨터 네트워크 | IP, UDP, 라우팅, NAT |
| 운영체제 | TUN, 가상 인터페이스, 시스템 권한 |
| 시스템 프로그래밍 | Go·Rust, 버퍼 관리, 네트워크 I/O, OS API 연동 |
| 암호학 응용 | Noise, X25519, AEAD |
| 프로토콜 설계 | 패킷 포맷, 세션, 메시지 처리 |
| 보안 | 재전송 방어, 신원 인증, 키 관리 |
| 소프트웨어 아키텍처 | 서버와 터널 엔진의 책임 분리 |
| 성능 분석 | 처리량, 지연, CPU, 메모리 |
| 품질 검증 | 자동화 테스트, Fuzzing, 벤치마크 |

## 25.2. 개발 성과물

최종적으로 다음 결과물을 만드는 것을 목표로 한다.

**첫 번째: GSM Tunnel**

Go Tunnel Controller와 Rust `tunnel-core`를 결합한 자체 VPN 프로토콜 및 터널링 엔진.

**두 번째: Linux VPN 구현**

Linux 클라이언트와 서버를 통해 실제 인터넷 접속이 가능한 VPN.

**세 번째: GSM VPN 통합**

기존 Gateway Server와 VPN Server를 활용한 인증 및 서비스 관리 기능 통합.

**네 번째: Windows 클라이언트**

기존 GSM VPN 클라이언트에서 자체 터널 엔진을 사용하는 구현.

**다섯 번째: 프로토콜 명세서**

실제 패킷 포맷, 상태 전이, 핸드셰이크 및 암호화 규칙을 정의한 기술 문서.

**여섯 번째: 성능 분석 보고서**

WireGuard와 GSM Tunnel의 성능 비교 및 병목 분석 결과.

**일곱 번째: 보안 검증 보고서**

재전송 공격, 변조된 패킷, 비정상 입력, 네트워크 유출 등의 테스트 결과.

## 25.3. 성능이 낮더라도 갖는 의미

자체 구현이 WireGuard보다 느리거나 더 많은 메모리를 사용할 수 있다.

그러나 이는 프로젝트 실패를 의미하지 않는다.

오히려 성능 차이가 발생한 원인을 분석하고 개선하는 과정 자체가 중요한 기술적 성과다.

예를 들어 다음과 같은 분석을 수행할 수 있다.

- 사용자 공간과 커널 공간 사이의 패킷 복사 비용
- 암호화 연산이 처리량에 미치는 영향
- UDP 송수신 구조의 병목
- 버퍼 할당 비용
- 세션 조회 방식의 오버헤드
- TUN 인터페이스 읽기 및 쓰기의 처리량

이러한 결과를 정량적으로 제시하면 단순 기능 구현 이상의 프로젝트로 발전시킬 수 있다.

---

# 26. 최초 개발 작업

## 26.1. 저장소 생성

신규 GitHub Repository를 생성한다.

```text
Organization: gsm-vpn
Repository: tunnel
Visibility: Public
Language: Go + Rust
```

저장소 설명:

```text
A cross-platform VPN tunneling engine implementing a custom secure transport protocol.
```

## 26.2. 초기 하이브리드 Workspace 생성

다음 Go package와 Rust crate를 생성한다.

```text
internal/controller
crates/tunnel-core
```

각 package의 초기 역할은 다음과 같다.

| 구성 요소 | 초기 개발 목표 |
|---|---|
| Go `internal/protocol` | Rust 코어 Adapter와 패킷 타입 연동 |
| Rust `tunnel-core` | TUN·UDP·패킷 검증 및 암호화 코어 |
| Go `internal/controller` | 클라이언트와 서버 실행 흐름 및 IPC |

## 26.3. 첫 번째 개발 목표

**Linux의 TUN 인터페이스에서 IP 패킷을 읽는 프로그램을 작성한다.**

이 작업에서는 아직 암호화나 서버 인증을 구현하지 않는다.

구현 범위:

1. Linux TUN 인터페이스 생성
2. TUN 장치 열기
3. 패킷 수신
4. 수신한 IP 패킷 길이 확인
5. IPv4 또는 IPv6 여부 식별
6. 정상 종료 시 장치 정리

첫 번째 개발이 완료되면 UDP 통신을 추가한다.

## 26.4. 두 번째 개발 목표

**클라이언트와 서버 사이에서 UDP 패킷을 송수신한다.**

구현 범위:

1. UDP 서버 실행
2. UDP 클라이언트 실행
3. 클라이언트에서 패킷 전송
4. 서버에서 패킷 수신
5. 기본 헤더 파싱
6. 비정상 패킷 처리
7. 양방향 전송 검증

## 26.5. 세 번째 개발 목표

**TUN에서 읽은 IP 패킷을 UDP로 전달한다.**

```text
Client TUN
     │
     ▼
Tunnel Client
     │
     ▼
UDP Transport
     │
     ▼
Tunnel Server
     │
     ▼
Server TUN
```

이 단계에서는 실제 IP 패킷을 한쪽 장치에서 다른 쪽 장치로 전달할 수 있어야 한다.

## 26.6. 네 번째 개발 목표

**서버의 IP Forwarding 및 NAT를 통해 외부 인터넷에 연결한다.**

이를 통해 자체 터널링 엔진의 가장 기본적인 기능이 완성된다.

이후에는 암호화 및 인증 프로토콜을 구현한다.

---

# 27. 기존 WireGuard와의 전환 정책

## 27.1. 전환 기본 원칙

기존 WireGuard 기반 VPN Server를 즉시 제거하지 않는다.

신규 Tunnel Engine을 독립적으로 개발하고, 기능 및 보안 검증을 마친 후 단계적으로 통합한다.

## 27.2. 병행 운영

개발 과정에서는 다음 두 엔진을 비교할 수 있도록 한다.

```text
                GSM VPN Server
                       │
           ┌───────────┴───────────┐
           │                       │
     WireGuard Engine        GSM Tunnel Engine
           │                       │
           ▼                       ▼
      Existing VPN             Custom VPN
```

VPN Server가 두 엔진을 모두 사용할 수 있도록 추상화하는 방안도 고려한다.

단, 최초 버전에서 반드시 동적인 프로토콜 선택 기능을 제공할 필요는 없다.

## 27.3. 전환 조건

자체 프로토콜로 전환하기 위해서는 다음 조건을 충족해야 한다.

- 주요 VPN 기능 완성
- 암호화 기능 검증
- 다중 클라이언트 지원
- 연결 안정성 검증
- 네트워크 유출 방지
- 서버 및 클라이언트 통합 테스트
- 장애 복구 검증
- 보안 검토
- 성능 측정

위 조건을 충족하지 못한다면 기존 WireGuard 구현을 유지한다.

---

# 28. 프로토콜 독립 배포 정책

## 28.1. 독립 라이브러리

GSM Tunnel은 GSM VPN 서비스에만 종속된 코드로 작성하지 않는다.

Go의 Transport·Engine과 Rust의 Protocol Core를 각각 재사용 가능한 package 및
crate 형태로 설계한다.

이를 통해 다음 사용 사례를 지원할 수 있다.

- GSM VPN 서버
- GSM VPN Windows 클라이언트
- GSM VPN Linux 클라이언트
- GSM VPN macOS 클라이언트
- 독립적인 네트워크 실험 프로그램
- 프로토콜 테스트 도구

## 28.2. Protocol Package 분리 가능성

현재는 `protocol`을 `tunnel` 저장소 내부의 package로 유지한다.

향후 다른 프로젝트에서 통신 규약만 독립적으로 사용해야 하는 요구사항이 생기면 별도 저장소 또는 패키지로 분리할 수 있다.

초기부터 독립 저장소를 여러 개로 나누지 않는 이유는 개발 초기의 변경 비용과 버전 관리 복잡도를 줄이기 위해서다.

## 28.3. 독립 실행 예제

저장소에는 클라이언트 및 서버 예제 프로그램을 제공한다.

```text
examples/client.go
examples/server.go
```

이 예제들은 Gateway Server 없이도 제한된 테스트 환경에서 터널의 기능을 확인할 수 있어야 한다.

운영 환경에서는 서비스 인증 및 접근 제어가 통합된 구성을 사용한다.

---

# 29. 현재 확정 사항 및 미확정 사항

## 29.1. 확정된 설계 방향

지금까지의 논의에서 결정한 주요 방향은 다음과 같다.

| 항목 | 결정 |
|---|---|
| VPN 종류 | 실제 인터넷 VPN |
| 연결 방식 | Full Tunnel 지향 |
| 기존 Gateway Server | 유지 |
| 기존 VPN Server | 유지 |
| 신규 Repository | `tunnel` |
| `protocol` Repository 별도 생성 | 초기에는 하지 않음 |
| 개발 언어 | Go + Rust 하이브리드 |
| Workspace | Go Module + Rust Cargo Workspace |
| 전송 계층 | UDP |
| 프로토콜 | 자체 구현 |
| 암호화 알고리즘 | 검증된 구현 사용 |
| 암호화 방식 | ChaCha20-Poly1305 권장 |
| 키 교환 | X25519 권장 |
| 키 파생 | HKDF 권장 |
| 핸드셰이크 | Noise 기반 권장 |
| Linux 네트워크 인터페이스 | TUN |
| Windows 네트워크 인터페이스 | Wintun |
| Linux 라우팅 | Kernel IP Forwarding |
| NAT | nftables |
| 초기 개발 플랫폼 | Linux |
| 다음 지원 플랫폼 | Windows |
| 추가 지원 후보 | macOS |
| 인증 책임 | Gateway / VPN Server |
| 데이터 전달 책임 | Tunnel Engine |
| 서비스 통합 | 내부 API 또는 IPC |
| 테스트 대상 | 기능, 보안, 안정성, 성능 |
| 비교 대상 | WireGuard |

## 29.2. 초기 구현에서 확정한 사항

다음 항목은 초기 구현의 기본값으로 확정했다. 운영 배포 전 성능·장애·보안
검증 결과에 따라 변경할 수 있으며, 변경 시 이 표와 연결된 상세 문서를 함께
갱신한다.

| 항목 | 현재 상태 |
|---|---|
| 프로토콜 공식 명칭·약어 | `gsm-tunnel` |
| 바이너리 헤더·패킷 Wire Format | 고정 24바이트 헤더, Big Endian, 상세 형식은 `docs/protocol-design.md` |
| 프로토콜 버전·협상 | `1.0.0` 고정 버전, 미지원 버전 즉시 차단 |
| Noise 핸드셰이크 패턴 | `Noise_IK_25519_ChaChaPoly_SHA256` |
| 비밀키 저장·배포 방식 | `SERVER_PRIVATE_KEY` 32바이트 표준 Base64 환경 경계, 변경 절차는 `docs/key-lifecycle.md` |
| 데이터 키 갱신·Replay Window | 1시간 또는 방향별 1GiB, 2,048 packets |
| Keepalive·세션 타임아웃 | 25초 유휴 Keepalive, 120초 유휴 만료 |
| VPN 내부 주소·UDP 포트·MTU | IPv4 `10.80.0.0/16`, UDP `51820`, MTU `1400` |
| IPv6 정책 | `fd80:1234:5678::/64` 듀얼스택, 라우팅 Prefix 또는 명시적 NAT66 |
| DNS Resolver 운영 방식 | 순서형 upstream, 장애 fallback, 질의 원문 영구 저장 금지, TTL 캐시는 후속 설계 |
| IPC 메시지·연결 방식 | Go Controller–Rust Core 프로세스 경계의 Unix socket 길이 프리픽스 바이너리 |
| 구현 라이브러리·FFI 방식 | Rust Core와 Go Controller의 프로세스 IPC, 패킷별 FFI 없음 |
| 성능·동시 사용자 목표 | 서버 512 MB/s 목표와 216 세션 기준, 실측은 배포 전 검증 |

암호화 설계는 상세 문서와 테스트를 기준으로 구현했지만, 독립적인 보안
검토와 실제 네트워크 검증을 완료하기 전에는 연구·개발 범위로만 취급한다.

---

# 30. 최종 프로젝트 구성

## 30.1. 전체 Repository

```text
GSM-VPN/
│
├── gateway-server/
│   │
│   ├── Authentication
│   ├── Server Registry
│   ├── Server Selection
│   ├── Authorization
│   └── Service Management
│
├── vpn-server/
│   │
│   ├── Gateway Integration
│   ├── Tunnel Management
│   ├── Peer Authorization
│   ├── IP Allocation
│   ├── Server Configuration
│   └── Monitoring
│
├── tunnel/
│   │
│   ├── internal/
│   │   │
│   │   ├── protocol/
│   │   │   ├── Packet Format
│   │   │   ├── Packet Codec
│   │   │   ├── Handshake
│   │   │   ├── Cryptography
│   │   │   └── Key Management
│   │   │
│   │   ├── transport/
│   │   │   ├── UDP Transport
│   │   │   ├── Session Transport
│   │   │   ├── Replay Protection
│   │   │   ├── Keepalive
│   │   │   └── Timeout
│   │   │
│   │   ├── device/
│   │   │   ├── TUN Abstraction
│   │   │   ├── Linux
│   │   │   ├── Windows
│   │   │   └── macOS
│   │   │
│   │   └── engine/
│   │       ├── Client Engine
│   │       ├── Server Engine
│   │       ├── Configuration
│   │       ├── Lifecycle
│   │       ├── Routing Integration
│   │       └── Metrics
│   │
│   ├── examples/
│   ├── tests/
│   ├── benches/
│   └── docs/
│
└── Windows-Client-Release/
    │
    └── Windows Client Distribution
```

## 30.2. 최종 시스템 흐름

```text
                            GSM VPN
                               │
                         Gateway Server
                               │
                    Authentication / Auth
                               │
                               ▼
                           VPN Server
                               │
                     Peer Authorization
                               │
                               ▼
                         GSM Tunnel
                               │
                    ┌──────────┴──────────┐
                    │                     │
               Control Plane          Data Plane
                    │                     │
               Handshake             TUN Device
               Key Exchange          Packet Codec
               Session               Encryption
               Rekeying              UDP Transport
                    │                     │
                    └──────────┬──────────┘
                               │
                        Encrypted Tunnel
                               │
                               ▼
                           Internet
```

---

# 31. 프로젝트 개발 최종 원칙

GSM VPN의 신규 자체 터널링 엔진은 다음 원칙을 기반으로 개발한다.

**첫째, 기존 시스템을 유지한다.**

Gateway Server와 VPN Server는 그대로 두고, 실제 패킷 전달에 필요한 Tunnel Engine을 별도 저장소로 구현한다.

**둘째, 자체 프로토콜을 설계한다.**

패킷 구조, 메시지 처리, 세션 상태 관리, UDP 전송과 터널링 기능은 GSM VPN에서 직접 설계하고 구현한다.

**셋째, 검증된 암호학을 활용한다.**

암호화 알고리즘을 직접 만들지 않으며, 검증된 구현체를 이용해 인증된 암호화 통신을 구성한다.

**넷째, 서비스 인증과 네트워크 통신을 분리한다.**

Gateway Server와 VPN Server는 서비스 이용 권한을 관리한다.

Tunnel Engine은 승인된 클라이언트의 신원을 검증하고 실제 네트워크 패킷을 전달한다.

**다섯째, 실제 인터넷 VPN을 구현한다.**

단순한 사설 네트워크 연결이나 UDP 메시지 전송이 아니라 사용자의 인터넷 트래픽을 VPN 서버를 통해 전달하는 Full Tunnel VPN을 구현한다.

**여섯째, Linux에서 시작한다.**

Linux TUN, UDP, IP Forwarding, NAT를 기반으로 기본 동작을 완성한 후 Windows를 지원한다.

**일곱째, 성능과 보안을 검증한다.**

WireGuard와 처리량, 지연, CPU, 메모리 사용량을 비교하고 프로토콜 보안 테스트를 수행한다.

**여덟째, 독립적인 오픈소스 엔진으로 개발한다.**

GSM Tunnel은 GSM VPN뿐 아니라 다른 프로그램에서도 활용할 수 있도록 독립성과 재사용성을 유지한다.

---

# 32. 최종 개발 목표

GSM VPN의 최종 아키텍처는 다음과 같다.

```text
                         GSM VPN
                            │
              ┌─────────────┴─────────────┐
              │                           │
         Management                 Networking
              │                           │
       ┌──────┴──────┐                    │
       │             │                    │
    Gateway      VPN Server           GSM Tunnel
       │             │                    │
       │             │              ┌─────┴─────┐
       │             │              │           │
 Authentication   Authorization   Protocol    Engine
       │             │              │           │
       │             │           Handshake      TUN
       │             │           Encryption     UDP
       │             │           Packet Codec   Routing
       │             │           Session        Transport
       │             │              │           │
       └─────────────┴──────────────┴─────┬─────┘
                                          │
                                 Encrypted Tunnel
                                          │
                                          ▼
                                      Internet
```

## 프로젝트의 최종 정의

> **GSM VPN은 기존의 Gateway Server 및 VPN Server 아키텍처를 유지하면서, Go 기반의 Controller와 Rust 기반의 Tunnel Core를 기능별로 결합한 자체 VPN 터널링 엔진으로 사용자의 인터넷 트래픽을 암호화된 UDP 터널을 통해 전달하는 크로스 플랫폼 인터넷 VPN 프로젝트이다.**

신규 `gsm-vpn/tunnel` 저장소는 다음 네 가지 핵심 구성요소를 포함한다.

| 구성 요소 | 최종 책임 |
|---|---|
| Go `internal/protocol` | Rust Tunnel Core와 관리 계층 사이의 타입 및 제어 Adapter |
| Rust `tunnel-core` | TUN, UDP, 패킷 형식 검증, 핸드셰이크, 암호화, 키·Replay 관리 |
| Rust `tunnel-core` | TUN, UDP 송수신, 데이터 세션 및 패킷 전달 |
| Go `internal/controller` | 엔진 수명주기, 정책, IPC, 메트릭 및 운영 제어 |

**최종 설계 결정은 기존 `gateway-server`와 `vpn-server`를 유지하고, `gsm-vpn/tunnel` 저장소를 별도로 생성하는 것이다.**

이를 통해 GSM VPN은 기존의 WireGuard 기반 VPN 서비스 관리 프로젝트에서, 자체 VPN 프로토콜과 터널링 엔진을 직접 구현하고 검증하는 네트워크 시스템 개발 프로젝트로 확장된다.

---

**문서 종료 — GSM VPN Tunnel Design Specification v1.0.0**
