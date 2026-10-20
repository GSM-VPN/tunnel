# DNS Resolver 정책

`DnsResolverPolicy`는 VPN 연결 중 사용할 Resolver 순서를 표현합니다.

- `vpn_upstreams`가 항상 먼저 시도됩니다.
- VPN 그룹의 모든 시도가 실패하면 `external_upstreams`로 넘어갑니다.
- `DnsSecureUpstream`은 DoT(`host:853`) 또는 DoH(`https://host/dns-query`) endpoint만 허용합니다.
- 이 계층은 endpoint와 순서만 검증합니다. 실제 TLS/HTTPS 연결은 권한이 필요한 플랫폼 어댑터가 수행하며, 질의 원문과 사용자 식별자를 저장하지 않습니다.

Linux의 기존 `LinuxDnsPlan`은 `resolvectl`이 직접 관리할 수 있는 UDP/TCP 53 upstream만 다룹니다. 보안 upstream은 별도 어댑터가 `DnsResolverPolicy::secure_upstreams`를 소비하도록 분리되어 있습니다.

`DnsUpstreamSelector::resolve_with`는 플랫폼 어댑터의 질의 함수를 받아
upstream을 순서대로 시도합니다. 실패한 Provider는 latency와 함께 실패로
기록되고 다음 Provider로 넘어가며, 모두 실패하면 명시적인 오류를 반환합니다.
