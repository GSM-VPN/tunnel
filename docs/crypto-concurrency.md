# 병렬 Replay Window

`ConcurrentReplayWindow`는 수신 worker들이 하나의 세션 Replay Window를
공유할 때 내부 상태를 Mutex로 보호합니다. sequence 확인과 기록은 하나의
임계 구역에서 수행되므로 동일 sequence가 경쟁 상황에서 두 번 승인되지
않습니다. 키와 평문은 래퍼에 저장하지 않습니다.
