//! Validated tunnel network policy and MTU budget.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{AEAD_TAG_SIZE, protocol::HEADER_SIZE};

const MIN_DUAL_STACK_MTU: usize = 1_280;
const MAX_TUNNEL_MTU: usize = 9_000;

/// Network policy used by the tunnel engine before OS-level setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelNetworkConfig {
    pub ipv4_network: Ipv4Addr,
    pub ipv4_prefix: u8,
    pub server_ipv4: Ipv4Addr,
    pub ipv6_network: Ipv6Addr,
    pub ipv6_prefix: u8,
    pub server_ipv6: Ipv6Addr,
    pub udp_port: u16,
    pub mtu: usize,
    pub dual_stack: bool,
    pub nat66: bool,
    pub kill_switch: bool,
}

/// Derived packet limits for a configured tunnel MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtuBudget {
    pub max_packet_size: usize,
    pub max_payload_size: usize,
    pub max_encrypted_payload_size: usize,
}

/// Configuration validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkConfigError {
    InvalidIpv4Prefix,
    InvalidIpv6Prefix,
    ServerIpv4OutsideNetwork,
    ServerIpv4Reserved,
    ServerIpv6OutsideNetwork,
    InvalidUdpPort,
    InvalidMtu,
    InvalidInterfaceName,
    EndpointUsesTunnelAddress,
    EndpointGatewayFamilyMismatch,
    ClientIpv4OutsideNetwork,
    ClientIpv6OutsideNetwork,
}

/// One argv-safe command emitted by the privileged Linux network adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl NetworkCommand {
    fn new(program: &str, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.to_owned(),
            args: args.into_iter().collect(),
        }
    }
}

/// Validated Linux server network setup and rollback plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxNetworkPlan {
    pub tunnel_interface: String,
    pub external_interface: String,
    pub endpoint: SocketAddr,
    pub config: TunnelNetworkConfig,
}

/// Validated Linux client route setup and rollback plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxClientRoutePlan {
    pub tunnel_interface: String,
    pub physical_interface: String,
    pub endpoint: SocketAddr,
    pub gateway: IpAddr,
    pub config: TunnelNetworkConfig,
}

/// Validated client TUN addressing plus route transition and cleanup plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxClientNetworkPlan {
    pub tunnel_interface: String,
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_ipv6: Option<Ipv6Addr>,
    pub routes: LinuxClientRoutePlan,
}

impl LinuxClientNetworkPlan {
    /// Creates a client network plan without executing host mutations.
    ///
    /// # Errors
    ///
    /// Returns an error when the interface does not match the route plan or
    /// either client address is outside the configured tunnel network.
    pub fn new(
        tunnel_interface: impl Into<String>,
        tunnel_ipv4: Ipv4Addr,
        tunnel_ipv6: Option<Ipv6Addr>,
        routes: LinuxClientRoutePlan,
    ) -> Result<Self, NetworkConfigError> {
        let tunnel_interface = tunnel_interface.into();
        if !valid_interface_name(&tunnel_interface) || tunnel_interface != routes.tunnel_interface {
            return Err(NetworkConfigError::InvalidInterfaceName);
        }
        if !contains_ipv4(
            routes.config.ipv4_network,
            routes.config.ipv4_prefix,
            tunnel_ipv4,
        ) {
            return Err(NetworkConfigError::ClientIpv4OutsideNetwork);
        }
        if routes.config.dual_stack
            && tunnel_ipv6.is_some_and(|address| {
                !contains_ipv6(
                    routes.config.ipv6_network,
                    routes.config.ipv6_prefix,
                    address,
                )
            })
        {
            return Err(NetworkConfigError::ClientIpv6OutsideNetwork);
        }
        if !routes.config.dual_stack && tunnel_ipv6.is_some() {
            return Err(NetworkConfigError::InvalidIpv6Prefix);
        }
        Ok(Self {
            tunnel_interface,
            tunnel_ipv4,
            tunnel_ipv6,
            routes,
        })
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn apply_commands(&self) -> Vec<NetworkCommand> {
        let mut commands = vec![NetworkCommand::new(
            "ip",
            [
                "address".to_owned(),
                "replace".to_owned(),
                format!("{}/{}", self.tunnel_ipv4, self.routes.config.ipv4_prefix),
                "dev".to_owned(),
                self.tunnel_interface.clone(),
            ],
        )];
        if let Some(address) = self.tunnel_ipv6 {
            commands.push(NetworkCommand::new(
                "ip",
                [
                    "-6".to_owned(),
                    "address".to_owned(),
                    "replace".to_owned(),
                    format!("{}/{}", address, self.routes.config.ipv6_prefix),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ));
        }
        commands.extend(self.routes.apply_commands());
        commands
    }

    #[must_use]
    pub fn cleanup_commands(&self) -> Vec<NetworkCommand> {
        let mut commands = self.routes.cleanup_commands();
        if let Some(address) = self.tunnel_ipv6 {
            commands.push(NetworkCommand::new(
                "ip",
                [
                    "-6".to_owned(),
                    "address".to_owned(),
                    "del".to_owned(),
                    format!("{}/{}", address, self.routes.config.ipv6_prefix),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ));
        }
        commands.push(NetworkCommand::new(
            "ip",
            [
                "address".to_owned(),
                "del".to_owned(),
                format!("{}/{}", self.tunnel_ipv4, self.routes.config.ipv4_prefix),
                "dev".to_owned(),
            ],
        ));
        commands
    }
}

impl LinuxClientRoutePlan {
    /// Creates a client route plan without changing host routing state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid interface names, invalid network
    /// configuration, a tunnel-internal endpoint, or a gateway from the wrong
    /// address family.
    pub fn new(
        tunnel_interface: impl Into<String>,
        physical_interface: impl Into<String>,
        endpoint: SocketAddr,
        gateway: IpAddr,
        config: TunnelNetworkConfig,
    ) -> Result<Self, NetworkConfigError> {
        let tunnel_interface = tunnel_interface.into();
        let physical_interface = physical_interface.into();
        if !valid_interface_name(&tunnel_interface) || !valid_interface_name(&physical_interface) {
            return Err(NetworkConfigError::InvalidInterfaceName);
        }
        config.validate()?;
        if endpoint_is_inside_tunnel(endpoint.ip(), &config) {
            return Err(NetworkConfigError::EndpointUsesTunnelAddress);
        }
        if endpoint.ip().is_ipv4() != gateway.is_ipv4() {
            return Err(NetworkConfigError::EndpointGatewayFamilyMismatch);
        }
        Ok(Self {
            tunnel_interface,
            physical_interface,
            endpoint,
            gateway,
            config,
        })
    }

    #[must_use]
    pub fn apply_commands(&self) -> Vec<NetworkCommand> {
        let (family_flag, endpoint_cidr) = match self.endpoint.ip() {
            IpAddr::V4(address) => (None, format!("{address}/32")),
            IpAddr::V6(address) => (Some("-6"), format!("{address}/128")),
        };
        let mut endpoint_args = vec![
            "route".to_owned(),
            "replace".to_owned(),
            endpoint_cidr,
            "via".to_owned(),
            self.gateway.to_string(),
            "dev".to_owned(),
            self.physical_interface.clone(),
        ];
        if let Some(flag) = family_flag {
            endpoint_args.insert(0, flag.to_owned());
        }
        let mut commands = vec![NetworkCommand::new("ip", endpoint_args)];
        commands.push(NetworkCommand::new(
            "ip",
            [
                "route".to_owned(),
                "replace".to_owned(),
                "default".to_owned(),
                "dev".to_owned(),
                self.tunnel_interface.clone(),
            ],
        ));
        if self.config.dual_stack {
            commands.push(NetworkCommand::new(
                "ip",
                [
                    "-6".to_owned(),
                    "route".to_owned(),
                    "replace".to_owned(),
                    "default".to_owned(),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ));
        }
        commands
    }

    #[must_use]
    pub fn cleanup_commands(&self) -> Vec<NetworkCommand> {
        let (family_flag, endpoint_cidr) = match self.endpoint.ip() {
            IpAddr::V4(address) => (None, format!("{address}/32")),
            IpAddr::V6(address) => (Some("-6"), format!("{address}/128")),
        };
        let mut endpoint_args = vec![
            "route".to_owned(),
            "del".to_owned(),
            endpoint_cidr,
            "via".to_owned(),
            self.gateway.to_string(),
            "dev".to_owned(),
            self.physical_interface.clone(),
        ];
        if let Some(flag) = family_flag {
            endpoint_args.insert(0, flag.to_owned());
        }
        let mut commands = vec![NetworkCommand::new(
            "ip",
            [
                "route".to_owned(),
                "del".to_owned(),
                "default".to_owned(),
                "dev".to_owned(),
                self.tunnel_interface.clone(),
            ],
        )];
        if self.config.dual_stack {
            commands.push(NetworkCommand::new(
                "ip",
                [
                    "-6".to_owned(),
                    "route".to_owned(),
                    "del".to_owned(),
                    "default".to_owned(),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ));
        }
        commands.push(NetworkCommand::new("ip", endpoint_args));
        commands
    }
}

impl LinuxNetworkPlan {
    /// Creates a plan without executing commands or changing host networking.
    ///
    /// # Errors
    ///
    /// Returns an error when an interface name is invalid, the network
    /// configuration is invalid, or the endpoint would be routed into the
    /// tunnel address space.
    pub fn new(
        tunnel_interface: impl Into<String>,
        external_interface: impl Into<String>,
        endpoint: SocketAddr,
        config: TunnelNetworkConfig,
    ) -> Result<Self, NetworkConfigError> {
        let tunnel_interface = tunnel_interface.into();
        let external_interface = external_interface.into();
        if !valid_interface_name(&tunnel_interface) || !valid_interface_name(&external_interface) {
            return Err(NetworkConfigError::InvalidInterfaceName);
        }
        config.validate()?;
        if endpoint_is_inside_tunnel(endpoint.ip(), &config) {
            return Err(NetworkConfigError::EndpointUsesTunnelAddress);
        }
        Ok(Self {
            tunnel_interface,
            external_interface,
            endpoint,
            config,
        })
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn apply_commands(&self) -> Vec<NetworkCommand> {
        let mut commands = vec![
            NetworkCommand::new(
                "ip",
                [
                    "link".to_owned(),
                    "set".to_owned(),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                    "mtu".to_owned(),
                    self.config.mtu.to_string(),
                ],
            ),
            NetworkCommand::new(
                "ip",
                [
                    "addr".to_owned(),
                    "replace".to_owned(),
                    format!("{}/{}", self.config.server_ipv4, self.config.ipv4_prefix),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ),
        ];
        if self.config.dual_stack {
            commands.push(NetworkCommand::new(
                "ip",
                [
                    "-6".to_owned(),
                    "addr".to_owned(),
                    "replace".to_owned(),
                    format!("{}/{}", self.config.server_ipv6, self.config.ipv6_prefix),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ));
        }
        commands.extend([
            NetworkCommand::new(
                "ip",
                [
                    "link".to_owned(),
                    "set".to_owned(),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                    "up".to_owned(),
                ],
            ),
            NetworkCommand::new(
                "sysctl",
                ["-w".to_owned(), "net.ipv4.ip_forward=1".to_owned()],
            ),
            NetworkCommand::new(
                "nft",
                [
                    "add".to_owned(),
                    "table".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel".to_owned(),
                ],
            ),
            NetworkCommand::new(
                "nft",
                [
                    "add".to_owned(),
                    "chain".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel".to_owned(),
                    "postrouting".to_owned(),
                    "{".to_owned(),
                    "type".to_owned(),
                    "nat".to_owned(),
                    "hook".to_owned(),
                    "postrouting".to_owned(),
                    "priority".to_owned(),
                    "100;".to_owned(),
                    "policy".to_owned(),
                    "accept;".to_owned(),
                    "}".to_owned(),
                ],
            ),
            NetworkCommand::new(
                "nft",
                [
                    "add".to_owned(),
                    "rule".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel".to_owned(),
                    "postrouting".to_owned(),
                    "oifname".to_owned(),
                    self.external_interface.clone(),
                    "ip".to_owned(),
                    "saddr".to_owned(),
                    format!("{}/{}", self.config.ipv4_network, self.config.ipv4_prefix),
                    "masquerade".to_owned(),
                ],
            ),
        ]);
        if self.config.dual_stack && self.config.nat66 {
            commands.push(NetworkCommand::new(
                "nft",
                [
                    "add".to_owned(),
                    "rule".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel".to_owned(),
                    "postrouting".to_owned(),
                    "oifname".to_owned(),
                    self.external_interface.clone(),
                    "ip6".to_owned(),
                    "saddr".to_owned(),
                    format!("{}/{}", self.config.ipv6_network, self.config.ipv6_prefix),
                    "masquerade".to_owned(),
                ],
            ));
        }
        commands
    }

    #[must_use]
    pub fn cleanup_commands(&self) -> Vec<NetworkCommand> {
        let mut commands = vec![
            NetworkCommand::new(
                "nft",
                [
                    "delete".to_owned(),
                    "table".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel".to_owned(),
                ],
            ),
            NetworkCommand::new(
                "ip",
                [
                    "addr".to_owned(),
                    "del".to_owned(),
                    format!("{}/{}", self.config.server_ipv4, self.config.ipv4_prefix),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ),
        ];
        if self.config.dual_stack {
            commands.push(NetworkCommand::new(
                "ip",
                [
                    "-6".to_owned(),
                    "addr".to_owned(),
                    "del".to_owned(),
                    format!("{}/{}", self.config.server_ipv6, self.config.ipv6_prefix),
                    "dev".to_owned(),
                    self.tunnel_interface.clone(),
                ],
            ));
        }
        commands.push(NetworkCommand::new(
            "ip",
            [
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                self.tunnel_interface.clone(),
                "down".to_owned(),
            ],
        ));
        commands
    }
}

fn valid_interface_name(name: &str) -> bool {
    name != "."
        && name != ".."
        && !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn endpoint_is_inside_tunnel(endpoint: IpAddr, config: &TunnelNetworkConfig) -> bool {
    match endpoint {
        IpAddr::V4(address) => contains_ipv4(config.ipv4_network, config.ipv4_prefix, address),
        IpAddr::V6(address) if config.dual_stack => {
            contains_ipv6(config.ipv6_network, config.ipv6_prefix, address)
        }
        IpAddr::V6(_) => false,
    }
}

impl Default for TunnelNetworkConfig {
    fn default() -> Self {
        Self {
            ipv4_network: Ipv4Addr::new(10, 80, 0, 0),
            ipv4_prefix: 16,
            server_ipv4: Ipv4Addr::new(10, 80, 0, 1),
            ipv6_network: Ipv6Addr::new(0xfd80, 0x1234, 0x5678, 0, 0, 0, 0, 0),
            ipv6_prefix: 64,
            server_ipv6: Ipv6Addr::new(0xfd80, 0x1234, 0x5678, 0, 0, 0, 0, 1),
            udp_port: 51_820,
            mtu: 1_400,
            dual_stack: true,
            nat66: false,
            kill_switch: false,
        }
    }
}

impl TunnelNetworkConfig {
    /// Validates addresses and derives the configured packet budget.
    ///
    /// # Errors
    ///
    /// Returns an error when an address is outside its network, a reserved
    /// IPv4 address is selected, or the port/MTU is outside safe bounds.
    pub fn validate(&self) -> Result<MtuBudget, NetworkConfigError> {
        if self.ipv4_prefix > 32 {
            return Err(NetworkConfigError::InvalidIpv4Prefix);
        }
        if self.ipv6_prefix > 128 {
            return Err(NetworkConfigError::InvalidIpv6Prefix);
        }
        if !contains_ipv4(self.ipv4_network, self.ipv4_prefix, self.server_ipv4) {
            return Err(NetworkConfigError::ServerIpv4OutsideNetwork);
        }
        if self.ipv4_prefix <= 30
            && (self.server_ipv4 == self.ipv4_network
                || self.server_ipv4 == ipv4_broadcast(self.ipv4_network, self.ipv4_prefix))
        {
            return Err(NetworkConfigError::ServerIpv4Reserved);
        }
        if self.dual_stack && !contains_ipv6(self.ipv6_network, self.ipv6_prefix, self.server_ipv6)
        {
            return Err(NetworkConfigError::ServerIpv6OutsideNetwork);
        }
        if self.udp_port == 0 {
            return Err(NetworkConfigError::InvalidUdpPort);
        }
        if !(MIN_DUAL_STACK_MTU..=MAX_TUNNEL_MTU).contains(&self.mtu)
            || self.mtu <= HEADER_SIZE + AEAD_TAG_SIZE
        {
            return Err(NetworkConfigError::InvalidMtu);
        }
        Ok(MtuBudget {
            max_packet_size: self.mtu,
            max_payload_size: self.mtu - HEADER_SIZE,
            max_encrypted_payload_size: self.mtu - HEADER_SIZE - AEAD_TAG_SIZE,
        })
    }
}

fn contains_ipv4(network: Ipv4Addr, prefix: u8, address: Ipv4Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(address) & mask)
}

fn ipv4_broadcast(network: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from((u32::from(network) & mask) | !mask)
}

fn contains_ipv6(network: Ipv6Addr, prefix: u8, address: Ipv6Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(network) & mask) == (u128::from(address) & mask)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        LinuxClientNetworkPlan, LinuxClientRoutePlan, LinuxNetworkPlan, MtuBudget,
        NetworkConfigError, TunnelNetworkConfig,
    };

    #[test]
    fn defaults_match_dual_stack_spec_and_budget() {
        let config = TunnelNetworkConfig::default();
        let budget = config.validate().unwrap();
        assert_eq!(config.server_ipv4, Ipv4Addr::new(10, 80, 0, 1));
        assert_eq!(config.udp_port, 51_820);
        assert_eq!(
            budget,
            MtuBudget {
                max_packet_size: 1_400,
                max_payload_size: 1_376,
                max_encrypted_payload_size: 1_360,
            }
        );
    }

    #[test]
    fn rejects_invalid_ranges_and_reserved_server_addresses() {
        let mut config = TunnelNetworkConfig {
            server_ipv4: Ipv4Addr::new(192, 168, 1, 1),
            ..TunnelNetworkConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(NetworkConfigError::ServerIpv4OutsideNetwork)
        );
        config = TunnelNetworkConfig {
            server_ipv4: Ipv4Addr::new(10, 80, 255, 255),
            ..TunnelNetworkConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(NetworkConfigError::ServerIpv4Reserved)
        );
        config = TunnelNetworkConfig {
            server_ipv6: Ipv6Addr::LOCALHOST,
            ..TunnelNetworkConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(NetworkConfigError::ServerIpv6OutsideNetwork)
        );
    }

    #[test]
    fn rejects_zero_port_and_mtu_outside_dual_stack_bounds() {
        let mut config = TunnelNetworkConfig {
            udp_port: 0,
            ..TunnelNetworkConfig::default()
        };
        assert_eq!(config.validate(), Err(NetworkConfigError::InvalidUdpPort));
        config = TunnelNetworkConfig {
            mtu: 1_279,
            ..TunnelNetworkConfig::default()
        };
        assert_eq!(config.validate(), Err(NetworkConfigError::InvalidMtu));
    }

    #[test]
    fn validates_zero_prefix_without_shift_overflow() {
        let config = TunnelNetworkConfig {
            ipv4_network: Ipv4Addr::UNSPECIFIED,
            ipv4_prefix: 0,
            server_ipv4: Ipv4Addr::new(10, 80, 0, 1),
            ..TunnelNetworkConfig::default()
        };
        assert_eq!(
            config.validate(),
            Ok(MtuBudget {
                max_packet_size: 1_400,
                max_payload_size: 1_376,
                max_encrypted_payload_size: 1_360,
            })
        );
    }

    #[test]
    fn builds_argv_safe_linux_server_plan_and_rollback() {
        let plan = LinuxNetworkPlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            TunnelNetworkConfig::default(),
        )
        .unwrap();
        let commands = plan.apply_commands();
        assert_eq!(commands[0].program, "ip");
        assert!(commands.iter().any(|command| {
            command.program == "nft" && command.args.contains(&"masquerade".to_owned())
        }));
        assert_eq!(
            plan.cleanup_commands()[0].args.as_slice(),
            ["delete", "table", "inet", "gsm_tunnel"]
        );
    }

    #[test]
    fn emits_ipv6_masquerade_only_when_nat66_is_enabled() {
        let config = TunnelNetworkConfig {
            nat66: true,
            ..TunnelNetworkConfig::default()
        };
        let plan = LinuxNetworkPlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            config,
        )
        .unwrap();
        assert!(
            plan.apply_commands()
                .iter()
                .any(|command| { command.args.iter().any(|argument| argument == "ip6") })
        );
    }

    #[test]
    fn rejects_interface_injection_and_tunnel_endpoint() {
        assert_eq!(
            LinuxNetworkPlan::new(
                "gsm0;rm",
                "eth0",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 1),
                TunnelNetworkConfig::default(),
            ),
            Err(NetworkConfigError::InvalidInterfaceName)
        );
        assert_eq!(
            LinuxNetworkPlan::new(
                "gsm0",
                "eth0",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 80, 5, 10)), 1),
                TunnelNetworkConfig::default(),
            ),
            Err(NetworkConfigError::EndpointUsesTunnelAddress)
        );
    }

    #[test]
    fn builds_client_endpoint_and_default_route_plan() {
        let plan = LinuxClientRoutePlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            TunnelNetworkConfig::default(),
        )
        .unwrap();
        let commands = plan.apply_commands();
        assert_eq!(commands[0].args[0], "route");
        assert!(
            commands.iter().any(|command| {
                command.args == vec!["route", "replace", "default", "dev", "gsm0"]
            })
        );
        assert!(
            commands
                .iter()
                .any(|command| { command.args.first() == Some(&"-6".to_owned()) })
        );
        assert_eq!(plan.cleanup_commands().len(), 3);
    }

    #[test]
    fn rejects_client_route_gateway_family_mismatch() {
        assert_eq!(
            LinuxClientRoutePlan::new(
                "gsm0",
                "eth0",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 1),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                TunnelNetworkConfig::default(),
            ),
            Err(NetworkConfigError::EndpointGatewayFamilyMismatch)
        );
    }

    #[test]
    fn builds_client_address_and_route_transition_with_reverse_cleanup() {
        let routes = LinuxClientRoutePlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            TunnelNetworkConfig::default(),
        )
        .unwrap();
        let plan = LinuxClientNetworkPlan::new(
            "gsm0",
            Ipv4Addr::new(10, 80, 0, 2),
            Some("fd80:1234:5678::2".parse().unwrap()),
            routes,
        )
        .unwrap();
        let commands = plan.apply_commands();
        assert_eq!(
            commands[0].args[0..3],
            ["address", "replace", "10.80.0.2/16"]
        );
        assert!(commands.iter().any(|command| {
            command.args
                == vec![
                    "-6",
                    "address",
                    "replace",
                    "fd80:1234:5678::2/64",
                    "dev",
                    "gsm0",
                ]
        }));
        assert_eq!(plan.cleanup_commands().last().unwrap().args[1], "del");
    }
}
