# Windows Wintun 계층

## 구현 범위

Windows 클라이언트의 TUN 대체 장치 후보로 Wintun을 조사했다. 현재
저장소는 `wintun` Rust 바인딩을 Windows target에만 연결하고,
`WintunDevice`를 공통 `TunnelDevice` 계약의 플랫폼 구현으로 제공한다.
이 문서는 구현 경계와 Windows host에서 남은 검증을 함께 기록한다.

공식 자료:

- [Wintun 공식 저장소](https://git.zx2c4.com/wintun/)
- [Wintun API 헤더](https://git.zx2c4.com/wintun/tree/api/wintun.h)
- [Wintun 배포 페이지](https://www.wintun.net/)

## 확인한 API 경계

Wintun의 adapter 수명주기는 다음 순서로 분리한다.

1. DLL에서 API 함수를 로드한다.
2. `WintunCreateAdapter`로 adapter handle을 만든다.
3. `WintunStartSession`으로 packet session을 시작한다.
4. `WintunReceivePacket`으로 읽고 `WintunAllocateSendPacket`과
   `WintunSendPacket`으로 쓴다.
5. session을 종료한 뒤 `WintunCloseAdapter`로 adapter handle을 닫는다.

Rust의 공통 `TunnelDevice` 경계에는 adapter handle과 session handle을
보관하는 Windows 전용 구현을 연결한다. packet buffer의 소유권과
`WintunReleaseReceivePacket` 호출 시점을 한 함수 안에서 관리하고, handle
종료 후 추가 I/O를 `DeviceError::Closed`로 변환한다.

## 배포·라이선스 경계

Wintun 소스 저장소의 소스와 문서는 GPLv2 조건을 따르며, 공식 배포
페이지에서 제공하는 사전 빌드 DLL은 별도의 배포 조건을 가진다. 따라서
프로젝트가 소스와 DLL 중 무엇을 배포하는지에 따라 고지문과 패키지 구성을
분리해야 한다.

- 소스 저장소를 빌드·수정해 배포할 때는 해당 GPLv2 조건을 검토한다.
- 사전 빌드 `wintun.dll`을 포함할 때는 해당 배포 아카이브의 라이선스
  파일과 버전을 함께 보존한다.
- 드라이버 파일을 임의로 재명명하거나 자체 서명하지 않는다.
- 실제 배포 전 법무·라이선스 검토를 별도로 완료한다.

## 구현 상태와 검증 경계

- `crates/tunnel-core/src/wintun_device.rs`가 adapter 생성·session 시작,
  packet read/write, MTU 설정과 공통 오류 매핑을 담당한다.
- DLL 경로를 호출자가 명시하고, adapter/session은 `close`와 `Drop`에서
  session shutdown 이후 순서대로 해제한다.
- Linux 빌드에는 Wintun 의존성과 모듈이 포함되지 않는다.
- Windows target 정적 빌드와 실제 adapter 권한·DLL·packet I/O 검증은
  Windows CI 또는 전용 Windows host에서 수행해야 한다.
- 실제 검증 전에는 Windows Wintun의 adapter·네트워크·인터넷 연결
  체크포인트를 완료 처리하지 않는다.
