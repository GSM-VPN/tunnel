# 키 변경 및 재시작 운영 정책

`GATEWAY_SHARED_SECRET`와 `SERVER_PRIVATE_KEY`는 서로 다른 신뢰 경계에
속한다. 두 값을 한 번에 교체하거나 동일한 롤링 절차로 취급하지 않는다.

## Gateway shared secret 변경

`GATEWAY_SHARED_SECRET`는 Go Controller가 Gateway/VPN Server 승인 요청의
HMAC을 검증하는 서비스 인증 자격 증명이다. Tunnel Core의 Noise 키나 기존
세션 데이터 키에는 영향을 주지 않는다.

변경 절차는 다음과 같다.

1. Gateway와 VPN Server의 승인 변경 작업을 점검 창 동안 중지한다.
2. 모든 서비스 인증 계층에 새 secret을 배포하고 Go Controller를 재시작한다.
3. Controller가 새 secret으로 초기화된 것을 확인한 뒤 승인 변경 작업을 재개한다.
4. 기존 secret을 폐기하고 실패한 승인 요청이 재시도되지 않는지 확인한다.

현재 구현은 두 secret을 동시에 허용하는 무기한 전환 창을 제공하지 않는다.
따라서 일부 인스턴스만 새 secret을 사용하는 상태에서 승인 요청을 계속하지
않는다. 기존 데이터 세션은 이 변경만으로 종료하지 않지만, Controller가
재시작되는 동안 새 승인·철회 요청은 일시적으로 실패할 수 있다.

## Server private key 교체

`SERVER_PRIVATE_KEY`는 Rust Core의 Noise responder 장기 신원이다. 공개키가
바뀌므로 서비스 인증 secret 교체와 분리된 중단·재시작 절차가 필요하다.

1. 관리 계층에서 새 핸드셰이크를 차단하고 모든 활성 세션을 종료한다.
2. 새 32바이트 표준 Base64 키를 비밀 공급 경계에 배포한다.
3. 기존 Core 프로세스를 종료한다. 키를 실행 중 교체하거나 이전 키와 함께
   보관하지 않는다.
4. 새 키로 Core를 시작하고 Controller가 승인된 피어·네트워크 설정을
   동기화한다.
5. 클라이언트의 pinned server public key를 갱신한 뒤 새 Noise 핸드셰이크를
   허용한다.
6. 이전 개인키와 이전 공개키를 비밀 저장소·배포 산출물에서 폐기한다.

기존 암호화 세션은 새 장기 신원으로 재사용하지 않는다. Core 재시작 시
Controller의 승인 정보만 복원되며, 세션 키·카운터·이전 장기 키는 복원되지
않는다. 교체 중 승인되지 않은 연결과 이전 공개키를 사용하는 연결은 모두
거부한다.

두 절차 모두 키 원문을 로그·IPC·메트릭·상태 응답에 포함하지 않는다. 실제
운영 전에는 장애 주입, 복구, 키 폐기 확인과 독립적인 암호화 보안 검토를
완료해야 한다.
