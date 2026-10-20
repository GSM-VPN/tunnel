# 세션 관측성

`SessionMachine::apply_with_log`는 세션 ID, 이벤트, 이전/이후 상태와 재연결
지연만 담은 `SessionTransitionLog`를 반환합니다. 로그 레코드에는 키, 평문
패킷, 사용자 ID가 들어가지 않습니다.

재연결 어댑터는 `ReconnectMeasurement::started_at`을 재연결 진입 시 만들고
`recovered_at`으로 성공 시각을 측정합니다. 시스템 시각이 뒤로 이동한 경우
복구 시간은 0으로 보정해 잘못된 음수 지연을 노출하지 않습니다.

`Metrics::record_reconnect_start`와 `record_reconnect_recovered`는 이 측정을
운영 메트릭으로 집계합니다. 시작 시각은 최대 세션 수만큼만 일시 보관하고,
복구 후 삭제하며 평균 duration과 카운터만 노출합니다.
