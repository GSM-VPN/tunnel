//! Validated DNS policy and platform command planning.

use std::net::IpAddr;

const MAX_UPSTREAMS: usize = 8;
const MAX_SEARCH_DOMAINS: usize = 8;

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

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{DnsPolicy, DnsSnapshot, DnsTransport, DnsUpstream, LinuxDnsPlan};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
}
