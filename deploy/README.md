# GSM Tunnel 실 적용 준비

이 디렉터리는 현재 저장소에서 실제로 실행 가능한 Rust Tunnel Core의
설치·환경 변수·systemd 기동 예시를 제공한다. 자체 프로토콜은 독립 보안
검토와 권한 있는 네트워크 검증 전까지 연구·개발용으로만 취급한다.

## 지원 범위

현재 배포 예시는 다음 경계까지만 다룬다.

- Linux에서 `tunnel-core` 프로세스 실행
- Unix Domain Socket 관리 IPC 생성
- `SERVER_PRIVATE_KEY` 기반 Core 신원 로딩
- Controller와 기존 `vpn-server`가 사용할 서비스 환경 변수 준비

다음 동작은 이 예시만으로 활성화되지 않는다.

- 실제 Gateway 로그인·VPN Server 운영 연동
- Linux 외부 인터넷 forwarding·NAT
- DNS·IPv6 leak 방지와 Kill Switch
- Windows Wintun adapter
- 공용 사용자 대상 배포

현재 범위와 남은 검증은 [`../docs/current-status.md`](../docs/current-status.md)와
[`../STEP.md`](../STEP.md)에 기록한다.

## 사전 조건

- Linux host와 systemd
- Rust toolchain
- `ip`, `/dev/net/tun` 등 권한이 필요한 네트워크 도구는 별도 검증 환경에서만 사용
- 기존 Gateway/VPN Server의 실제 서비스 secret과 승인 정책
- 독립 보안 검토 전에는 인터넷에 노출하지 않는 격리된 환경

## 빌드 및 설치

저장소 루트에서 실행한다.

```bash
cargo build --release --package tunnel-core --bin tunnel-core
sudo install -o root -g root -m 0755 \
  target/release/tunnel-core /usr/local/libexec/gsm-tunnel-core
```

서비스 계정과 런타임 디렉터리를 만든다.

```bash
sudo useradd --system --home-dir /var/lib/gsm-tunnel \
  --create-home --shell /usr/sbin/nologin gsm-tunnel
sudo install -d -o gsm-tunnel -g gsm-tunnel -m 0750 /run/gsm-tunnel
sudo install -d -o root -g gsm-tunnel -m 0750 /etc/gsm-tunnel
sudo install -o root -g gsm-tunnel -m 0600 \
  deploy/gsm-tunnel.env.example /etc/gsm-tunnel/gsm-tunnel.env
sudoedit /etc/gsm-tunnel/gsm-tunnel.env
```

`GATEWAY_SHARED_SECRET`, `VPN_SERVER_ID`, `SERVER_PRIVATE_KEY`는 실제 배포
환경의 값을 넣는다. secret과 private key를 shell history, issue, log, Git에
남기지 않는다.

## 기동

```bash
sudo install -o root -g root -m 0644 \
  deploy/systemd/gsm-tunnel-core.service \
  /etc/systemd/system/gsm-tunnel-core.service
sudo systemctl daemon-reload
sudo systemctl enable --now gsm-tunnel-core.service
sudo systemctl status --no-pager gsm-tunnel-core.service
```

기동 후 다음을 확인한다.

```bash
sudo stat -c '%A %U:%G %n' /run/gsm-tunnel/core.sock
sudo journalctl -u gsm-tunnel-core.service --since -5m --no-pager
```

소켓은 서비스 계정과 허용된 Controller만 접근할 수 있어야 하며, 로그에
private key·Gateway secret·평문 패킷·암호문을 출력하지 않아야 한다.

## 중지와 제거

```bash
sudo systemctl disable --now gsm-tunnel-core.service
sudo rm -f /etc/systemd/system/gsm-tunnel-core.service
sudo systemctl daemon-reload
```

운영 환경에서 제거하기 전에는 Controller와 기존 WireGuard 경로의 rollback
절차를 확인한다. 이 예시는 자동으로 routing, NAT, DNS, firewall 규칙을
변경하지 않는다.

## 검증 명령

배포 전 저장소 검증은 다음과 같이 실행한다.

```bash
./scripts/validate.sh
./scripts/test-tunnel-core-integration.sh
./scripts/run-core-benchmarks.sh benchmark-results/core-benchmark.md
```

권한 있는 Linux에서 외부망·TUN·NAT를 검증할 때는 실행 환경, 명령, 관찰
결과, 정리 결과를 [`docs/release-verification-matrix.md`](../docs/release-verification-matrix.md)에
기록하고 해당 `STEP.md` 항목을 그때 갱신한다.
