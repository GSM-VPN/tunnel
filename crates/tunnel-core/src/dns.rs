//! Validated DNS policy and platform command planning.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, SystemTime},
};

const MAX_UPSTREAMS: usize = 8;
const MAX_SEARCH_DOMAINS: usize = 8;
const MIN_CACHE_TTL: Duration = Duration::from_secs(1);
const MAX_CACHE_TTL: Duration = Duration::from_hours(24);

/// Transport used to reach an upstream resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransport {
    Udp,
    Tcp,
    Dot,
    Doh,
}

/// One ordered upstream resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsUpstream {
    pub address: IpAddr,
    pub port: u16,
    pub transport: DnsTransport,
}

/// An endpoint for a resolver transport that is not represented by a socket
/// address alone, such as DNS over TLS or DNS over HTTPS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSecureUpstream {
    pub endpoint: String,
    pub transport: DnsTransport,
}

/// Ordered resolver groups used while the VPN is active.
///
/// VPN upstreams are always attempted first. External upstreams are used only
/// after the VPN group is exhausted, which lets a platform adapter implement a
/// deliberate fallback policy without retaining query names or responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResolverPolicy {
    pub vpn_upstreams: Vec<DnsUpstream>,
    pub external_upstreams: Vec<DnsUpstream>,
    pub secure_upstreams: Vec<DnsSecureUpstream>,
    pub search_domains: Vec<String>,
}

/// Secret-free counters for one configured upstream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsUpstreamMetrics {
    pub successes: u64,
    pub failures: u64,
    pub total_latency: Duration,
}

/// Resolver policy applied while the tunnel is active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPolicy {
    pub upstreams: Vec<DnsUpstream>,
    pub search_domains: Vec<String>,
}

/// Resolver state captured before a VPN policy is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSnapshot {
    pub upstreams: Vec<DnsUpstream>,
    pub search_domains: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedDnsResponse {
    response: Vec<u8>,
    expires_at: SystemTime,
}

/// Bounded DNS response cache keyed by an opaque query fingerprint.
///
/// The cache deliberately does not accept query names or user identifiers.
/// Callers must provide a stable fingerprint and the complete response bytes;
/// entries are retained only until their bounded TTL expires.
#[derive(Clone, Debug)]
pub struct DnsCache {
    capacity: usize,
    entries: HashMap<u64, CachedDnsResponse>,
}

impl DnsCache {
    /// Creates a cache with a fixed positive entry limit.
    ///
    /// # Errors
    ///
    /// Returns [`DnsConfigError::InvalidCacheCapacity`] when `capacity` is
    /// zero.
    pub fn new(capacity: usize) -> Result<Self, DnsConfigError> {
        if capacity == 0 {
            return Err(DnsConfigError::InvalidCacheCapacity);
        }
        Ok(Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
        })
    }

    /// Inserts a response with a TTL clamped to one second through 24 hours.
    pub fn insert(&mut self, fingerprint: u64, response: Vec<u8>, ttl: Duration, now: SystemTime) {
        let bounded_ttl = ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL);
        let expires_at = now
            .checked_add(bounded_ttl)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.entries.insert(
            fingerprint,
            CachedDnsResponse {
                response,
                expires_at,
            },
        );
        self.remove_expired(now);
        while self.entries.len() > self.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
            {
                self.entries.remove(&oldest);
            }
        }
    }

    /// Returns a non-expired response without retaining query metadata.
    pub fn get(&mut self, fingerprint: u64, now: SystemTime) -> Option<&[u8]> {
        if self
            .entries
            .get(&fingerprint)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            self.entries.remove(&fingerprint);
            return None;
        }
        self.entries
            .get(&fingerprint)
            .map(|entry| entry.response.as_slice())
    }

    fn remove_expired(&mut self, now: SystemTime) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Ordered upstream selector for a resolver adapter.
///
/// The selector stores only policy addresses and a cursor. It does not retain
/// query names, responses, or per-user DNS history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsUpstreamSelector {
    upstreams: Vec<DnsUpstream>,
    current: usize,
    metrics: Vec<DnsUpstreamMetrics>,
}

/// One argv-safe command emitted by the privileged DNS adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Linux DNS application and restoration plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxDnsPlan {
    pub interface: String,
    pub policy: DnsPolicy,
    pub snapshot: DnsSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsConfigError {
    NoUpstreams,
    TooManyUpstreams,
    TooManySearchDomains,
    InvalidPort,
    UnsupportedLinuxTransport,
    InvalidInterfaceName,
    InvalidSearchDomain,
    InvalidCacheCapacity,
    InvalidSecureEndpoint,
    SecureTransportMismatch,
    NoFallbackUpstreams,
}

impl DnsPolicy {
    /// Validates an ordered resolver policy without changing host state.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy has no upstream, exceeds the bounded
    /// upstream/domain limits, or contains an invalid port/domain.
    pub fn new(
        upstreams: Vec<DnsUpstream>,
        search_domains: Vec<String>,
    ) -> Result<Self, DnsConfigError> {
        validate_upstreams(&upstreams)?;
        validate_search_domains(&search_domains)?;
        Ok(Self {
            upstreams,
            search_domains,
        })
    }
}

impl DnsSecureUpstream {
    /// Validates a `DoT` authority or `DoH` URL without resolving or contacting it.
    ///
    /// # Errors
    ///
    /// Returns [`DnsConfigError::InvalidSecureEndpoint`] when the endpoint
    /// does not match the selected secure transport.
    pub fn new(
        endpoint: impl Into<String>,
        transport: DnsTransport,
    ) -> Result<Self, DnsConfigError> {
        let endpoint = endpoint.into();
        if !valid_secure_endpoint(&endpoint, transport) {
            return Err(DnsConfigError::InvalidSecureEndpoint);
        }
        Ok(Self {
            endpoint,
            transport,
        })
    }
}

impl DnsResolverPolicy {
    /// Creates a VPN-first policy with an explicit external fallback group.
    ///
    /// # Errors
    ///
    /// Returns an error when all resolver groups are empty, an upstream is
    /// invalid, a secure endpoint uses the wrong transport, or a search domain
    /// is invalid.
    pub fn new(
        vpn_upstreams: Vec<DnsUpstream>,
        external_upstreams: Vec<DnsUpstream>,
        secure_upstreams: Vec<DnsSecureUpstream>,
        search_domains: Vec<String>,
    ) -> Result<Self, DnsConfigError> {
        if vpn_upstreams.is_empty() && external_upstreams.is_empty() && secure_upstreams.is_empty()
        {
            return Err(DnsConfigError::NoFallbackUpstreams);
        }
        validate_search_domains(&search_domains)?;
        validate_upstream_group(&vpn_upstreams)?;
        validate_upstream_group(&external_upstreams)?;
        if secure_upstreams
            .iter()
            .any(|upstream| !matches!(upstream.transport, DnsTransport::Dot | DnsTransport::Doh))
        {
            return Err(DnsConfigError::SecureTransportMismatch);
        }
        Ok(Self {
            vpn_upstreams,
            external_upstreams,
            secure_upstreams,
            search_domains,
        })
    }

    /// Returns the plain upstreams in VPN-first order for a fallback adapter.
    #[must_use]
    pub fn ordered_upstreams(&self) -> Vec<DnsUpstream> {
        self.vpn_upstreams
            .iter()
            .chain(&self.external_upstreams)
            .cloned()
            .collect()
    }

    /// Returns a selector that starts with the first VPN upstream when present.
    #[must_use]
    pub fn selector(&self) -> Option<DnsUpstreamSelector> {
        let upstreams = self.ordered_upstreams();
        if upstreams.is_empty() {
            return None;
        }
        Some(DnsUpstreamSelector::from_upstreams(upstreams))
    }
}

impl DnsUpstreamSelector {
    /// Creates a selector from an already validated policy.
    #[must_use]
    pub fn from_policy(policy: &DnsPolicy) -> Self {
        Self::from_upstreams(policy.upstreams.clone())
    }

    fn from_upstreams(upstreams: Vec<DnsUpstream>) -> Self {
        Self {
            metrics: vec![DnsUpstreamMetrics::default(); upstreams.len()],
            upstreams,
            current: 0,
        }
    }

    /// Returns the provider currently selected for the next query.
    #[must_use]
    pub fn current(&self) -> &DnsUpstream {
        &self.upstreams[self.current]
    }

    /// Keeps the successful provider selected and records a zero-latency
    /// success for callers that do not measure query duration.
    pub fn record_success(&mut self) {
        self.record_success_with_latency(Duration::ZERO);
    }

    /// Records a measured success without retaining query data.
    pub fn record_success_with_latency(&mut self, latency: Duration) {
        let metrics = &mut self.metrics[self.current];
        metrics.successes = metrics.successes.saturating_add(1);
        metrics.total_latency = metrics.total_latency.saturating_add(latency);
    }

    /// Advances to the next provider after a resolver failure.
    pub fn record_failure(&mut self) {
        self.record_failure_with_latency(Duration::ZERO);
    }

    /// Records a measured failure and advances to the next provider.
    pub fn record_failure_with_latency(&mut self, latency: Duration) {
        let metrics = &mut self.metrics[self.current];
        metrics.failures = metrics.failures.saturating_add(1);
        metrics.total_latency = metrics.total_latency.saturating_add(latency);
        self.current = (self.current + 1) % self.upstreams.len();
    }

    /// Returns provider metrics in the same order as the configured upstreams.
    #[must_use]
    pub fn metrics(&self) -> &[DnsUpstreamMetrics] {
        &self.metrics
    }
}

impl DnsSnapshot {
    /// Validates the resolver state that will be restored after disconnect.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot exceeds the bounded limits or
    /// contains an invalid upstream or domain.
    pub fn new(
        upstreams: Vec<DnsUpstream>,
        search_domains: Vec<String>,
    ) -> Result<Self, DnsConfigError> {
        if upstreams.len() > MAX_UPSTREAMS {
            return Err(DnsConfigError::TooManyUpstreams);
        }
        validate_search_domains(&search_domains)?;
        for upstream in &upstreams {
            validate_upstream(upstream)?;
        }
        Ok(Self {
            upstreams,
            search_domains,
        })
    }
}

impl LinuxDnsPlan {
    /// Builds a Linux `resolvectl` plan; commands are never executed here.
    ///
    /// # Errors
    ///
    /// Returns an error when the interface is unsafe or either the active
    /// policy or captured snapshot uses a transport unsupported by
    /// `resolvectl`.
    pub fn new(
        interface: impl Into<String>,
        policy: DnsPolicy,
        snapshot: DnsSnapshot,
    ) -> Result<Self, DnsConfigError> {
        let interface = interface.into();
        if !valid_interface_name(&interface) {
            return Err(DnsConfigError::InvalidInterfaceName);
        }
        validate_linux_upstreams(&policy.upstreams)?;
        validate_linux_upstreams(&snapshot.upstreams)?;
        Ok(Self {
            interface,
            policy,
            snapshot,
        })
    }

    #[must_use]
    pub fn apply_commands(&self) -> Vec<DnsCommand> {
        let mut args = vec!["dns".to_owned(), self.interface.clone()];
        args.extend(
            self.policy
                .upstreams
                .iter()
                .map(|upstream| upstream.address.to_string()),
        );
        let mut commands = vec![DnsCommand::new("resolvectl", args)];
        if !self.policy.search_domains.is_empty() {
            let mut domain_args = vec!["domain".to_owned(), self.interface.clone()];
            domain_args.extend(self.policy.search_domains.iter().cloned());
            commands.push(DnsCommand::new("resolvectl", domain_args));
        }
        commands.push(DnsCommand::new("resolvectl", ["flush-caches".to_owned()]));
        commands
    }

    #[must_use]
    pub fn restore_commands(&self) -> Vec<DnsCommand> {
        let mut commands = vec![DnsCommand::new(
            "resolvectl",
            ["revert".to_owned(), self.interface.clone()],
        )];
        if !self.snapshot.upstreams.is_empty() {
            let mut args = vec!["dns".to_owned(), self.interface.clone()];
            args.extend(
                self.snapshot
                    .upstreams
                    .iter()
                    .map(|upstream| upstream.address.to_string()),
            );
            commands.push(DnsCommand::new("resolvectl", args));
        }
        if !self.snapshot.search_domains.is_empty() {
            let mut domain_args = vec!["domain".to_owned(), self.interface.clone()];
            domain_args.extend(self.snapshot.search_domains.iter().cloned());
            commands.push(DnsCommand::new("resolvectl", domain_args));
        }
        commands.push(DnsCommand::new("resolvectl", ["flush-caches".to_owned()]));
        commands
    }
}

impl DnsCommand {
    fn new(program: &str, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.to_owned(),
            args: args.into_iter().collect(),
        }
    }
}

fn validate_upstreams(upstreams: &[DnsUpstream]) -> Result<(), DnsConfigError> {
    if upstreams.is_empty() {
        return Err(DnsConfigError::NoUpstreams);
    }
    if upstreams.len() > MAX_UPSTREAMS {
        return Err(DnsConfigError::TooManyUpstreams);
    }
    for upstream in upstreams {
        validate_upstream(upstream)?;
    }
    Ok(())
}

fn validate_upstream_group(upstreams: &[DnsUpstream]) -> Result<(), DnsConfigError> {
    if upstreams.len() > MAX_UPSTREAMS {
        return Err(DnsConfigError::TooManyUpstreams);
    }
    for upstream in upstreams {
        validate_upstream(upstream)?;
    }
    Ok(())
}

fn validate_upstream(upstream: &DnsUpstream) -> Result<(), DnsConfigError> {
    if upstream.port == 0 {
        return Err(DnsConfigError::InvalidPort);
    }
    Ok(())
}

fn validate_linux_upstreams(upstreams: &[DnsUpstream]) -> Result<(), DnsConfigError> {
    if upstreams.iter().any(|upstream| {
        upstream.port != 53 || !matches!(upstream.transport, DnsTransport::Udp | DnsTransport::Tcp)
    }) {
        return Err(DnsConfigError::UnsupportedLinuxTransport);
    }
    Ok(())
}

fn validate_search_domains(domains: &[String]) -> Result<(), DnsConfigError> {
    if domains.len() > MAX_SEARCH_DOMAINS {
        return Err(DnsConfigError::TooManySearchDomains);
    }
    if domains
        .iter()
        .any(|domain| domain.is_empty() || domain.chars().any(char::is_whitespace))
    {
        return Err(DnsConfigError::InvalidSearchDomain);
    }
    Ok(())
}

fn valid_secure_endpoint(endpoint: &str, transport: DnsTransport) -> bool {
    if endpoint.is_empty()
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.contains('#')
        || endpoint.contains('?')
    {
        return false;
    }
    match transport {
        DnsTransport::Dot => {
            if endpoint.contains('/') {
                return false;
            }
            endpoint
                .rsplit_once(':')
                .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
                .is_some_and(|(host, port)| !host.is_empty() && port == 853)
        }
        DnsTransport::Doh => endpoint.strip_prefix("https://").is_some_and(|authority| {
            let (host, path) = authority.split_once('/').unwrap_or((authority, ""));
            !host.is_empty() && (path == "dns-query" || path.starts_with("dns-query/"))
        }),
        DnsTransport::Udp | DnsTransport::Tcp => false,
    }
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{
        DnsCache, DnsPolicy, DnsSnapshot, DnsTransport, DnsUpstream, DnsUpstreamSelector,
        LinuxDnsPlan,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn upstream(address: IpAddr) -> DnsUpstream {
        DnsUpstream {
            address,
            port: 53,
            transport: DnsTransport::Udp,
        }
    }

    #[test]
    fn builds_ordered_dual_stack_apply_plan() {
        let policy = DnsPolicy::new(
            vec![
                upstream(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                upstream(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ],
            vec!["example.test".to_owned()],
        )
        .unwrap();
        let snapshot = DnsSnapshot::new(vec![], vec![]).unwrap();
        let plan = LinuxDnsPlan::new("tun0", policy, snapshot).unwrap();
        assert_eq!(plan.apply_commands()[0].program, "resolvectl");
        assert_eq!(plan.apply_commands()[0].args[2], "1.1.1.1");
        assert_eq!(plan.apply_commands()[1].args[2], "example.test");
    }

    #[test]
    fn restores_snapshot_after_revert() {
        let policy = DnsPolicy::new(vec![upstream("9.9.9.9".parse().unwrap())], vec![]).unwrap();
        let snapshot = DnsSnapshot::new(
            vec![upstream("192.0.2.1".parse().unwrap())],
            vec!["corp.test".to_owned()],
        )
        .unwrap();
        let plan = LinuxDnsPlan::new("tun0", policy, snapshot).unwrap();
        let commands = plan.restore_commands();
        assert_eq!(commands[0].args, ["revert", "tun0"]);
        assert_eq!(commands[1].args[2], "192.0.2.1");
        assert_eq!(commands[2].args[2], "corp.test");
    }

    #[test]
    fn rejects_empty_or_unsafe_policy_values() {
        assert!(DnsPolicy::new(vec![], vec![]).is_err());
        assert!(
            DnsPolicy::new(
                vec![upstream("1.1.1.1".parse().unwrap())],
                vec!["bad domain".to_owned()]
            )
            .is_err()
        );
        assert!(
            DnsPolicy::new(
                vec![DnsUpstream {
                    address: "1.1.1.1".parse().unwrap(),
                    port: 0,
                    transport: DnsTransport::Udp
                }],
                vec![]
            )
            .is_err()
        );
    }

    #[test]
    fn selects_ordered_upstreams_and_falls_back_after_failure() {
        let policy = DnsPolicy::new(
            vec![
                upstream("1.1.1.1".parse().unwrap()),
                upstream("9.9.9.9".parse().unwrap()),
            ],
            vec![],
        )
        .unwrap();
        let mut selector = DnsUpstreamSelector::from_policy(&policy);
        assert_eq!(
            selector.current().address,
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        selector.record_failure();
        assert_eq!(
            selector.current().address,
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
        selector.record_success();
        assert_eq!(
            selector.current().address,
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
        selector.record_failure();
        assert_eq!(
            selector.current().address,
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn records_bounded_upstream_outcomes_without_query_data() {
        let policy = DnsPolicy::new(
            vec![
                upstream("1.1.1.1".parse().unwrap()),
                upstream("9.9.9.9".parse().unwrap()),
            ],
            vec![],
        )
        .unwrap();
        let mut selector = DnsUpstreamSelector::from_policy(&policy);
        selector.record_failure_with_latency(Duration::from_millis(12));
        selector.record_success_with_latency(Duration::from_millis(7));
        assert_eq!(selector.metrics()[0].failures, 1);
        assert_eq!(selector.metrics()[0].successes, 0);
        assert_eq!(
            selector.metrics()[0].total_latency,
            Duration::from_millis(12)
        );
        assert_eq!(selector.metrics()[1].successes, 1);
        assert_eq!(
            selector.metrics()[1].total_latency,
            Duration::from_millis(7)
        );
    }

    #[test]
    fn rejects_non_default_linux_transport_and_bad_interface() {
        let policy = DnsPolicy::new(
            vec![DnsUpstream {
                address: "1.1.1.1".parse().unwrap(),
                port: 853,
                transport: DnsTransport::Dot,
            }],
            vec![],
        )
        .unwrap();
        let snapshot = DnsSnapshot::new(vec![], vec![]).unwrap();
        assert!(LinuxDnsPlan::new("tun0", policy.clone(), snapshot.clone()).is_err());
        let plain = DnsPolicy::new(vec![upstream("1.1.1.1".parse().unwrap())], vec![]).unwrap();
        assert!(LinuxDnsPlan::new("invalid interface", plain, snapshot).is_err());
    }

    #[test]
    fn clamps_ttl_expires_entries_and_bounds_capacity_without_query_data() {
        use std::time::{Duration, SystemTime};

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        assert!(DnsCache::new(0).is_err());
        let mut cache = DnsCache::new(1).unwrap();
        cache.insert(7, vec![1, 2, 3], Duration::ZERO, now);
        assert_eq!(cache.get(7, now), Some([1, 2, 3].as_slice()));
        assert!(cache.get(7, now + Duration::from_secs(1)).is_none());

        cache.insert(7, vec![4], Duration::from_hours(25), now);
        cache.insert(8, vec![5], Duration::from_secs(60), now);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(7, now), Some([4].as_slice()));
        assert!(cache.get(8, now).is_none());
    }

    #[test]
    fn validates_secure_dot_and_doh_endpoints() {
        let dot = super::DnsSecureUpstream::new("resolver.example:853", DnsTransport::Dot).unwrap();
        assert_eq!(dot.transport, DnsTransport::Dot);
        let doh =
            super::DnsSecureUpstream::new("https://resolver.example/dns-query", DnsTransport::Doh)
                .unwrap();
        assert_eq!(doh.endpoint, "https://resolver.example/dns-query");
        assert!(super::DnsSecureUpstream::new("resolver.example:443", DnsTransport::Dot).is_err());
        assert!(super::DnsSecureUpstream::new(":853", DnsTransport::Dot).is_err());
        assert!(
            super::DnsSecureUpstream::new("http://resolver.example/dns-query", DnsTransport::Doh)
                .is_err()
        );
        assert!(super::DnsSecureUpstream::new("https:///dns-query", DnsTransport::Doh).is_err());
    }

    #[test]
    fn prefers_vpn_upstreams_before_external_fallbacks() {
        let policy = super::DnsResolverPolicy::new(
            vec![upstream("10.0.0.53".parse().unwrap())],
            vec![upstream("1.1.1.1".parse().unwrap())],
            vec![],
            vec![],
        )
        .unwrap();
        let mut selector = policy.selector().unwrap();
        assert_eq!(
            selector.current().address,
            "10.0.0.53".parse::<IpAddr>().unwrap()
        );
        selector.record_failure();
        assert_eq!(
            selector.current().address,
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        assert!(super::DnsResolverPolicy::new(vec![], vec![], vec![], vec![]).is_err());
    }
}
