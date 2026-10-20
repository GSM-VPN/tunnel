# 문서 언어 정책

이 프로젝트의 primary language는 한국어다. 따라서 `docs/`의 제목, 설명,
표, 운영 절차, 검증 결과는 한국어로 작성한다.

다음 항목은 호환성과 정확성을 위해 원문을 유지한다.

- Go/Rust 코드의 식별자, 타입명, 함수명, 환경 변수명
- protocol field, operation code, status code, wire format 명칭
- shell command, 파일 경로, 로그 event 이름
- 외부 표준·라이브러리 고유명사(예: Unix Domain Socket, ChaCha20-Poly1305)

영어 문서를 새로 추가해야 하는 경우에는 한국어 설명을 기본으로 제공하고,
필요하면 영어 용어를 괄호로 병기한다. 번역 과정에서 API·프로토콜 명칭을
번역하거나 코드 블록을 임의로 수정하지 않는다.

문서 변경은 관련 기능 영역의 issue와 PR에 포함한다. 언어 통일만을 위한
변경도 문서 diff와 검증 범위를 PR에 기록하며, 동작 변경이나 체크포인트
완료를 번역 변경만으로 주장하지 않는다.
