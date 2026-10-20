//! Validated tunnel network policy and MTU budget.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::ip_packet::{InnerIpPacketError, InnerIpPacketInfo, validate_inner_ip_packet};
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

/// Path MTU information collected by a platform probe or an ICMP error.
///
/// The core does not open raw sockets or parse operating-system error queues.
/// A privileged adapter supplies the measurements here, and the resulting
/// effective MTU can then be applied consistently to both IP families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMtuObservation {
    pub interface_mtu: usize,
    pub path_mtu: usize,
    pub packet_too_big_mtu: Option<usize>,
}

impl PathMtuObservation {
    /// Builds a validated observation from an interface probe and optional
    /// `ICMPv6` Packet Too Big/IPv4 fragmentation-needed MTU.
    ///
    /// # Errors
    ///
    /// Returns an error when a measurement is below the IPv6 minimum, the
    /// path is larger than the interface, or an ICMP MTU is inconsistent with
    /// the measured path.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface_mtu: usize,
        path_mtu: usize,
        packet_too_big_mtu: Option<usize>,
    ) -> Result<Self, NetworkConfigError> {
        if interface_mtu < MIN_DUAL_STACK_MTU {
            return Err(NetworkConfigError::InvalidInterfaceMtu);
        }
        if path_mtu < MIN_DUAL_STACK_MTU || path_mtu > interface_mtu {
            return Err(NetworkConfigError::InvalidPathMtu);
        }
        if packet_too_big_mtu.is_some_and(|mtu| !(MIN_DUAL_STACK_MTU..=path_mtu).contains(&mtu)) {
            return Err(NetworkConfigError::InvalidPacketTooBigMtu);
        }
        Ok(Self {
            interface_mtu,
            path_mtu,
            packet_too_big_mtu,
        })
    }

    /// Returns the largest tunnel MTU that does not exceed the observed path.
    #[must_use]
    pub const fn effective_tunnel_mtu(self) -> usize {
        match self.packet_too_big_mtu {
            Some(mtu) if mtu < self.path_mtu => mtu,
            _ => self.path_mtu,
        }
    }
}

impl MtuBudget {
    /// Validates an inner packet against the encrypted payload budget.
    ///
    /// # Errors
    ///
    /// Returns an inner packet validation error when the packet is malformed,
    /// disabled by the address-family policy, or too large for the budget.
    pub fn validate_inner_packet(
        &self,
        packet: &[u8],
        dual_stack: bool,
    ) -> Result<InnerIpPacketInfo, InnerIpPacketError> {
        validate_inner_ip_packet(packet, self.max_encrypted_payload_size, dual_stack)
    }
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
    InvalidRouteSnapshot,
    InvalidInterfaceMtu,
    InvalidPathMtu,
    InvalidPacketTooBigMtu,
    InvalidRouteProbeOutput,
    InvalidInterfaceIndex,
    EmptyDnsServers,
    InvalidDnsAddress,
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

/// Route lookup used to identify the physical interface for a tunnel endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxExternalRouteProbe {
    pub endpoint: SocketAddr,
}

impl LinuxExternalRouteProbe {
    /// Creates a route probe without executing a system command.
    #[must_use]
    pub const fn new(endpoint: SocketAddr) -> Self {
        Self { endpoint }
    }

    /// Builds the argv-safe `ip route get` command for the endpoint family.
    #[must_use]
    pub fn command(self) -> NetworkCommand {
        let mut args = vec!["route".to_owned(), "get".to_owned()];
        if self.endpoint.ip().is_ipv6() {
            args.insert(0, "-6".to_owned());
        }
        args.push(self.endpoint.ip().to_string());
        NetworkCommand::new("ip", args)
    }

    /// Extracts the physical interface from `ip route get` output.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkConfigError::InvalidRouteProbeOutput`] when the
    /// output does not contain a valid `dev <interface>` pair.
    pub fn parse_interface(output: &str) -> Result<String, NetworkConfigError> {
        let mut tokens = output.split_whitespace();
        while let Some(token) = tokens.next() {
            if token != "dev" {
                continue;
            }
            let interface = tokens
                .next()
                .ok_or(NetworkConfigError::InvalidRouteProbeOutput)?;
            if valid_interface_name(interface) {
                return Ok(interface.to_owned());
            }
            return Err(NetworkConfigError::InvalidRouteProbeOutput);
        }
        Err(NetworkConfigError::InvalidRouteProbeOutput)
    }
}

/// One previously existing route captured by the privileged platform layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxRouteState {
    pub gateway: IpAddr,
    pub device: String,
}

impl LinuxRouteState {
    /// Creates a route snapshot entry without executing a route lookup.
    ///
    /// # Errors
    ///
    /// Returns an error when the device name cannot be safely passed to an
    /// argv-based Linux command.
    pub fn new(gateway: IpAddr, device: impl Into<String>) -> Result<Self, NetworkConfigError> {
        let device = device.into();
        if !valid_interface_name(&device) {
            return Err(NetworkConfigError::InvalidInterfaceName);
        }
        Ok(Self { gateway, device })
    }
}

/// Pre-VPN routes that must be restored when the client disconnects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxRouteSnapshot {
    pub ipv4_default: Option<LinuxRouteState>,
    pub ipv6_default: Option<LinuxRouteState>,
    pub endpoint: Option<LinuxRouteState>,
}

impl LinuxRouteSnapshot {
    /// Validates a snapshot captured by the privileged platform layer.
    ///
    /// # Errors
    ///
    /// Returns an error when a route gateway has the wrong address family for
    /// the route it is intended to restore.
    pub fn validate_for(
        &self,
        endpoint: SocketAddr,
        dual_stack: bool,
    ) -> Result<(), NetworkConfigError> {
        if self
            .ipv4_default
            .as_ref()
            .is_some_and(|route| !route.gateway.is_ipv4())
            || self
                .ipv6_default
                .as_ref()
                .is_some_and(|route| !route.gateway.is_ipv6())
            || self
                .endpoint
                .as_ref()
                .is_some_and(|route| route.gateway.is_ipv4() != endpoint.ip().is_ipv4())
            || (!dual_stack && self.ipv6_default.is_some())
        {
            return Err(NetworkConfigError::InvalidRouteSnapshot);
        }
        Ok(())
    }
}

/// Optional nftables policy that prevents traffic from bypassing the tunnel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxKillSwitchPlan {
    pub tunnel_interface: String,
    pub physical_interface: String,
    pub endpoint: SocketAddr,
}

impl LinuxKillSwitchPlan {
    /// Creates a Kill Switch plan without changing host firewall state.
    ///
    /// # Errors
    ///
    /// Returns an error when an interface name is invalid or the endpoint port
    /// is zero.
    pub fn new(
        tunnel_interface: impl Into<String>,
        physical_interface: impl Into<String>,
        endpoint: SocketAddr,
    ) -> Result<Self, NetworkConfigError> {
        let tunnel_interface = tunnel_interface.into();
        let physical_interface = physical_interface.into();
        if !valid_interface_name(&tunnel_interface) || !valid_interface_name(&physical_interface) {
            return Err(NetworkConfigError::InvalidInterfaceName);
        }
        if endpoint.port() == 0 {
            return Err(NetworkConfigError::InvalidUdpPort);
        }
        Ok(Self {
            tunnel_interface,
            physical_interface,
            endpoint,
        })
    }

    #[must_use]
    pub fn apply_commands(&self) -> Vec<NetworkCommand> {
        let mut commands = vec![
            NetworkCommand::new(
                "nft",
                [
                    "add".to_owned(),
                    "table".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel_killswitch".to_owned(),
                ],
            ),
            NetworkCommand::new(
                "nft",
                [
                    "add".to_owned(),
                    "chain".to_owned(),
                    "inet".to_owned(),
                    "gsm_tunnel_killswitch".to_owned(),
                    "output".to_owned(),
                    "{".to_owned(),
                    "type".to_owned(),
                    "filter".to_owned(),
                    "hook".to_owned(),
                    "output".to_owned(),
                    "priority".to_owned(),
                    "0;".to_owned(),
                    "policy".to_owned(),
                    "drop;".to_owned(),
                    "}".to_owned(),
                ],
            ),
            nft_output_rule(["oifname", "lo", "accept"]),
            nft_output_rule(["oifname", &self.tunnel_interface, "accept"]),
            nft_output_rule(["ct", "state", "established,related", "accept"]),
        ];
        let family = if self.endpoint.ip().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        commands.push(nft_output_rule([
            family,
            "daddr",
            &self.endpoint.ip().to_string(),
            "oifname",
            &self.physical_interface,
            "udp",
            "dport",
            &self.endpoint.port().to_string(),
            "accept",
        ]));
        commands
    }

    #[must_use]
    pub fn rollback_commands(&self) -> Vec<NetworkCommand> {
        vec![NetworkCommand::new(
            "nft",
            [
                "delete".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                "gsm_tunnel_killswitch".to_owned(),
            ],
        )]
    }
}

fn nft_output_rule(args: impl IntoIterator<Item = impl Into<String>>) -> NetworkCommand {
    let mut command_args = vec![
        "add".to_owned(),
        "rule".to_owned(),
        "inet".to_owned(),
        "gsm_tunnel_killswitch".to_owned(),
        "output".to_owned(),
    ];
    command_args.extend(args.into_iter().map(Into::into));
    NetworkCommand::new("nft", command_args)
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

/// Windows client address, route, and DNS transition plan.
///
/// The plan only emits argv-safe records. A privileged Windows adapter owns
/// command execution, snapshots of the pre-VPN state, and recovery after an
/// interrupted transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsClientNetworkPlan {
    pub interface_name: String,
    pub tunnel_interface_index: u32,
    pub physical_interface_index: u32,
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_prefix: u8,
    pub tunnel_gateway: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub physical_gateway: IpAddr,
    pub dns_servers: Vec<IpAddr>,
}

impl WindowsClientNetworkPlan {
    /// Creates a Windows network transition plan without changing host state.
    ///
    /// # Errors
    ///
    /// Returns an error when an interface name or index is invalid, the IPv4
    /// prefix is outside its range, the endpoint and physical gateway use
    /// different address families, or DNS input is not usable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface_name: impl Into<String>,
        tunnel_interface_index: u32,
        physical_interface_index: u32,
        tunnel_ipv4: Ipv4Addr,
        tunnel_prefix: u8,
        tunnel_gateway: Ipv4Addr,
        endpoint: SocketAddr,
        physical_gateway: IpAddr,
        dns_servers: Vec<IpAddr>,
    ) -> Result<Self, NetworkConfigError> {
        let interface_name = interface_name.into();
        if !valid_windows_interface_name(&interface_name) {
            return Err(NetworkConfigError::InvalidInterfaceName);
        }
        if tunnel_interface_index == 0 || physical_interface_index == 0 {
            return Err(NetworkConfigError::InvalidInterfaceIndex);
        }
        if tunnel_prefix > 32 {
            return Err(NetworkConfigError::InvalidIpv4Prefix);
        }
        if endpoint.port() == 0 {
            return Err(NetworkConfigError::InvalidUdpPort);
        }
        if endpoint.ip().is_ipv4() != physical_gateway.is_ipv4() {
            return Err(NetworkConfigError::EndpointGatewayFamilyMismatch);
        }
        if dns_servers.is_empty() {
            return Err(NetworkConfigError::EmptyDnsServers);
        }
        if dns_servers
            .iter()
            .any(|server| server.is_unspecified() || server.is_multicast())
        {
            return Err(NetworkConfigError::InvalidDnsAddress);
        }
        Ok(Self {
            interface_name,
            tunnel_interface_index,
            physical_interface_index,
            tunnel_ipv4,
            tunnel_prefix,
            tunnel_gateway,
            endpoint,
            physical_gateway,
            dns_servers,
        })
    }

    /// Builds address, endpoint exception, default route, and DNS commands.
    #[must_use]
    pub fn apply_commands(&self) -> Vec<NetworkCommand> {
        let interface = windows_interface_arg(&self.interface_name);
        let mut commands = vec![NetworkCommand::new(
            "netsh",
            [
                "interface".to_owned(),
                "ipv4".to_owned(),
                "set".to_owned(),
                "address".to_owned(),
                interface.clone(),
                "static".to_owned(),
                self.tunnel_ipv4.to_string(),
                ipv4_netmask(self.tunnel_prefix).to_string(),
                self.tunnel_gateway.to_string(),
                "1".to_owned(),
            ],
        )];
        commands.push(self.endpoint_route_command("add"));
        commands.push(NetworkCommand::new(
            "route",
            [
                "add".to_owned(),
                "0.0.0.0".to_owned(),
                "mask".to_owned(),
                "0.0.0.0".to_owned(),
                self.tunnel_gateway.to_string(),
                "if".to_owned(),
                self.tunnel_interface_index.to_string(),
                "metric".to_owned(),
                "1".to_owned(),
            ],
        ));
        commands.extend(self.dns_commands(&interface, "set"));
        commands
    }

    /// Builds commands that remove the transition and return address/DNS to DHCP.
    #[must_use]
    pub fn rollback_commands(&self) -> Vec<NetworkCommand> {
        let interface = windows_interface_arg(&self.interface_name);
        let mut commands = vec![self.endpoint_route_command("delete")];
        commands.push(NetworkCommand::new(
            "route",
            [
                "delete".to_owned(),
                "0.0.0.0".to_owned(),
                "if".to_owned(),
                self.tunnel_interface_index.to_string(),
            ],
        ));
        commands.push(NetworkCommand::new(
            "netsh",
            [
                "interface".to_owned(),
                "ipv4".to_owned(),
                "set".to_owned(),
                "address".to_owned(),
                interface.clone(),
                "source=dhcp".to_owned(),
            ],
        ));
        commands.extend(self.dns_commands(&interface, "set-dhcp"));
        commands
    }

    fn endpoint_route_command(&self, action: &str) -> NetworkCommand {
        match self.endpoint.ip() {
            IpAddr::V4(address) => NetworkCommand::new(
                "route",
                [
                    action.to_owned(),
                    address.to_string(),
                    "mask".to_owned(),
                    "255.255.255.255".to_owned(),
                    self.physical_gateway.to_string(),
                    "if".to_owned(),
                    self.physical_interface_index.to_string(),
                ],
            ),
            IpAddr::V6(address) => NetworkCommand::new(
                "netsh",
                [
                    "interface".to_owned(),
                    "ipv6".to_owned(),
                    action.to_owned(),
                    "route".to_owned(),
                    format!("{address}/128"),
                    format!("interface={}", self.physical_interface_index),
                    format!("nexthop={}", self.physical_gateway),
                ],
            ),
        }
    }

    fn dns_commands(&self, interface: &str, action: &str) -> Vec<NetworkCommand> {
        if action == "set-dhcp" {
            return [false, true]
                .into_iter()
                .filter(|is_ipv6| {
                    self.dns_servers
                        .iter()
                        .any(|server| server.is_ipv6() == *is_ipv6)
                })
                .map(|is_ipv6| {
                    let family = if is_ipv6 { "ipv6" } else { "ipv4" };
                    NetworkCommand::new(
                        "netsh",
                        [
                            "interface".to_owned(),
                            family.to_owned(),
                            "set".to_owned(),
                            "dnsservers".to_owned(),
                            interface.to_owned(),
                            "source=dhcp".to_owned(),
                        ],
                    )
                })
                .collect();
        }
        let mut family_indexes = [(false, 0usize), (true, 0usize)];
        let mut commands = Vec::new();
        for server in &self.dns_servers {
            let is_ipv6 = server.is_ipv6();
            let family_index = usize::from(is_ipv6);
            family_indexes[family_index].1 += 1;
            let index = family_indexes[family_index].1;
            let (family, address_action) = if is_ipv6 {
                ("ipv6", "dnsservers")
            } else {
                ("ipv4", "dnsservers")
            };
            let command = match action {
                "set" if index == 1 => vec![
                    "interface".to_owned(),
                    family.to_owned(),
                    "set".to_owned(),
                    address_action.to_owned(),
                    interface.to_owned(),
                    "source=static".to_owned(),
                    format!("address={server}"),
                    "register=primary".to_owned(),
                    "validate=no".to_owned(),
                ],
                "set" => vec![
                    "interface".to_owned(),
                    family.to_owned(),
                    "add".to_owned(),
                    address_action.to_owned(),
                    interface.to_owned(),
                    format!("address={server}"),
                    format!("index={index}"),
                ],
                _ => unreachable!("validated Windows DNS command action"),
            };
            commands.push(NetworkCommand::new("netsh", command));
        }
        commands
    }
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

    /// Rebuilds the endpoint exception route after a network change.
    ///
    /// The new endpoint and gateway pass the same validation as initial plan
    /// creation, so an endpoint cannot become tunnel-internal or cross address
    /// families during a rebind.
    ///
    /// # Errors
    ///
    /// Returns the same validation error as [`Self::new`] for an unsafe
    /// interface, tunnel-internal endpoint, or address-family mismatch.
    pub fn rebind_endpoint(
        &self,
        endpoint: SocketAddr,
        gateway: IpAddr,
    ) -> Result<Self, NetworkConfigError> {
        Self::new(
            self.tunnel_interface.clone(),
            self.physical_interface.clone(),
            endpoint,
            gateway,
            self.config.clone(),
        )
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

    /// Removes VPN routes and restores the captured pre-VPN route state.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot contains a route from the wrong
    /// address family or an IPv6 route for an IPv4-only plan.
    pub fn cleanup_commands_with_snapshot(
        &self,
        snapshot: &LinuxRouteSnapshot,
    ) -> Result<Vec<NetworkCommand>, NetworkConfigError> {
        snapshot.validate_for(self.endpoint, self.config.dual_stack)?;
        let mut commands = self.cleanup_commands();
        if let Some(route) = &snapshot.ipv4_default {
            commands.push(route_replace_command(None, "default", route));
        }
        if let Some(route) = &snapshot.ipv6_default {
            commands.push(route_replace_command(Some("-6"), "default", route));
        }
        if let Some(route) = &snapshot.endpoint {
            let endpoint = match self.endpoint.ip() {
                IpAddr::V4(address) => format!("{address}/32"),
                IpAddr::V6(address) => format!("{address}/128"),
            };
            let family = if self.endpoint.ip().is_ipv4() {
                None
            } else {
                Some("-6")
            };
            commands.push(route_replace_command(family, &endpoint, route));
        }
        Ok(commands)
    }
}

fn route_replace_command(
    family: Option<&str>,
    destination: &str,
    route: &LinuxRouteState,
) -> NetworkCommand {
    let mut args = vec![
        "route".to_owned(),
        "replace".to_owned(),
        destination.to_owned(),
        "via".to_owned(),
        route.gateway.to_string(),
        "dev".to_owned(),
        route.device.clone(),
    ];
    if let Some(family) = family {
        args.insert(0, family.to_owned());
    }
    NetworkCommand::new("ip", args)
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

fn valid_windows_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.bytes().any(|byte| byte.is_ascii_control())
        && !name.contains('"')
}

fn windows_interface_arg(name: &str) -> String {
    format!("name=\"{name}\"")
}

fn ipv4_netmask(prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(mask)
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

    /// Returns the Kill Switch plan only when the policy explicitly enables it.
    ///
    /// The returned plan is declarative: applying or rolling it back remains
    /// the responsibility of the privileged platform adapter.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the network policy or interface
    /// names are invalid.
    pub fn kill_switch_plan(
        &self,
        tunnel_interface: impl Into<String>,
        physical_interface: impl Into<String>,
        endpoint: SocketAddr,
    ) -> Result<Option<LinuxKillSwitchPlan>, NetworkConfigError> {
        self.validate()?;
        if !self.kill_switch {
            return Ok(None);
        }
        LinuxKillSwitchPlan::new(tunnel_interface, physical_interface, endpoint).map(Some)
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
        LinuxClientNetworkPlan, LinuxClientRoutePlan, LinuxExternalRouteProbe, LinuxKillSwitchPlan,
        LinuxNetworkPlan, LinuxRouteSnapshot, LinuxRouteState, MtuBudget, NetworkConfigError,
        PathMtuObservation, TunnelNetworkConfig, WindowsClientNetworkPlan,
    };

    fn valid_ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20 + payload.len()];
        packet[0] = 0x45;
        let total_length = u16::try_from(packet.len()).expect("test packet fits IPv4 length");
        packet[2..4].copy_from_slice(&total_length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 80, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..].copy_from_slice(payload);
        let checksum = crate::ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn builds_argv_safe_windows_client_plan_and_rollback() {
        let plan = WindowsClientNetworkPlan::new(
            "GSM Tunnel",
            42,
            7,
            Ipv4Addr::new(10, 80, 0, 2),
            16,
            Ipv4Addr::new(10, 80, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 80, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            ],
        )
        .unwrap();

        let apply = plan.apply_commands();
        assert_eq!(apply[0].program, "netsh");
        assert!(apply[0].args.contains(&"name=\"GSM Tunnel\"".to_owned()));
        assert!(apply[0].args.contains(&"255.255.0.0".to_owned()));
        assert_eq!(apply[1].program, "route");
        assert!(apply[1].args.contains(&"203.0.113.10".to_owned()));
        assert!(apply.iter().any(|command| {
            command
                .args
                .iter()
                .any(|argument| argument == "address=1.1.1.1")
        }));
        assert!(apply.iter().any(|command| {
            command
                .args
                .iter()
                .any(|argument| argument == "address=2001:4860:4860::8888")
        }));

        let rollback = plan.rollback_commands();
        assert!(rollback.iter().any(|command| {
            command
                .args
                .iter()
                .any(|argument| argument == "source=dhcp")
        }));
        assert_eq!(
            rollback
                .iter()
                .filter(|command| command
                    .args
                    .iter()
                    .any(|argument| argument == "source=dhcp"))
                .count(),
            3
        );
    }

    #[test]
    fn rejects_invalid_windows_network_plan_values() {
        let valid_dns = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let result = WindowsClientNetworkPlan::new(
            "bad\"name",
            42,
            7,
            Ipv4Addr::new(10, 80, 0, 2),
            16,
            Ipv4Addr::new(10, 80, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            valid_dns.clone(),
        );
        assert_eq!(result, Err(NetworkConfigError::InvalidInterfaceName));

        let result = WindowsClientNetworkPlan::new(
            "GSM Tunnel",
            0,
            7,
            Ipv4Addr::new(10, 80, 0, 2),
            16,
            Ipv4Addr::new(10, 80, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            valid_dns.clone(),
        );
        assert_eq!(result, Err(NetworkConfigError::InvalidInterfaceIndex));

        let result = WindowsClientNetworkPlan::new(
            "GSM Tunnel",
            42,
            7,
            Ipv4Addr::new(10, 80, 0, 2),
            16,
            Ipv4Addr::new(10, 80, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            valid_dns,
        );
        assert_eq!(
            result,
            Err(NetworkConfigError::EndpointGatewayFamilyMismatch)
        );

        let result = WindowsClientNetworkPlan::new(
            "GSM Tunnel",
            42,
            7,
            Ipv4Addr::new(10, 80, 0, 2),
            16,
            Ipv4Addr::new(10, 80, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        );
        assert_eq!(result, Err(NetworkConfigError::InvalidDnsAddress));
    }

    #[test]
    fn enforces_encrypted_payload_budget_for_inner_packets() {
        let budget = TunnelNetworkConfig::default().validate().unwrap();
        let packet = valid_ipv4_packet(&vec![0; budget.max_encrypted_payload_size - 20]);
        assert!(budget.validate_inner_packet(&packet, true).is_ok());
        let oversized = valid_ipv4_packet(&vec![0; budget.max_encrypted_payload_size - 19]);
        assert_eq!(
            budget.validate_inner_packet(&oversized, true),
            Err(crate::InnerIpPacketError::PayloadExceedsMtu)
        );
    }

    #[test]
    fn kill_switch_plan_is_absent_when_policy_is_disabled() {
        let config = TunnelNetworkConfig::default();
        assert_eq!(
            config
                .kill_switch_plan(
                    "gsm0",
                    "eth0",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
                )
                .unwrap(),
            None
        );
        let enabled = TunnelNetworkConfig {
            kill_switch: true,
            ..config
        };
        assert!(
            enabled
                .kill_switch_plan(
                    "gsm0",
                    "eth0",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
                )
                .unwrap()
                .is_some()
        );
    }

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
    fn derives_effective_mtu_from_path_probe_and_packet_too_big() {
        let observation = PathMtuObservation::new(1_500, 1_420, Some(1_280)).unwrap();
        assert_eq!(observation.effective_tunnel_mtu(), 1_280);
        let unchanged = PathMtuObservation::new(1_500, 1_420, None).unwrap();
        assert_eq!(unchanged.effective_tunnel_mtu(), 1_420);
    }

    #[test]
    fn rejects_inconsistent_path_mtu_observations() {
        assert_eq!(
            PathMtuObservation::new(1_279, 1_279, None),
            Err(NetworkConfigError::InvalidInterfaceMtu)
        );
        assert_eq!(
            PathMtuObservation::new(1_500, 1_501, None),
            Err(NetworkConfigError::InvalidPathMtu)
        );
        assert_eq!(
            PathMtuObservation::new(1_500, 1_400, Some(1_279)),
            Err(NetworkConfigError::InvalidPacketTooBigMtu)
        );
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
        assert!(
            commands.iter().any(|command| {
                command.args == ["addr", "replace", "10.80.0.1/16", "dev", "gsm0"]
            })
        );
        assert!(
            commands
                .iter()
                .any(|command| { command.args == ["-w", "net.ipv4.ip_forward=1"] })
        );
        assert!(commands.iter().any(|command| {
            command.args.contains(&"eth0".to_owned())
                && command.args.contains(&"postrouting".to_owned())
        }));
        assert!(commands.iter().any(|command| {
            command.program == "nft" && command.args.contains(&"masquerade".to_owned())
        }));
        assert_eq!(
            plan.cleanup_commands()[0].args.as_slice(),
            ["delete", "table", "inet", "gsm_tunnel"]
        );
    }

    #[test]
    fn builds_route_probe_for_endpoint_family_and_parses_external_interface() {
        let ipv4_probe = LinuxExternalRouteProbe::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            51_820,
        ));
        assert_eq!(ipv4_probe.command().args, ["route", "get", "203.0.113.10"]);
        assert_eq!(
            LinuxExternalRouteProbe::parse_interface(
                "203.0.113.10 via 192.0.2.1 dev eth0 src 192.0.2.2"
            ),
            Ok("eth0".to_owned())
        );

        let ipv6_probe = LinuxExternalRouteProbe::new(SocketAddr::new(
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            51_820,
        ));
        assert_eq!(
            ipv6_probe.command().args,
            ["-6", "route", "get", "2001:db8::10"]
        );
    }

    #[test]
    fn rejects_route_probe_output_without_a_safe_interface() {
        assert_eq!(
            LinuxExternalRouteProbe::parse_interface("unreachable 203.0.113.10"),
            Err(NetworkConfigError::InvalidRouteProbeOutput)
        );
        assert_eq!(
            LinuxExternalRouteProbe::parse_interface("203.0.113.10 dev bad/iface"),
            Err(NetworkConfigError::InvalidRouteProbeOutput)
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
    fn rebinds_endpoint_after_network_change_with_the_same_safety_checks() {
        let plan = LinuxClientRoutePlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            TunnelNetworkConfig::default(),
        )
        .unwrap();
        let rebound = plan
            .rebind_endpoint(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 51_821),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            )
            .unwrap();
        assert_eq!(rebound.endpoint.port(), 51_821);
        assert_eq!(rebound.apply_commands()[0].args[2], "198.51.100.20/32");
        assert_eq!(
            plan.rebind_endpoint(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 80, 0, 9)), 51_821),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            ),
            Err(NetworkConfigError::EndpointUsesTunnelAddress)
        );
    }

    #[test]
    fn restores_captured_routes_after_removing_vpn_routes() {
        let plan = LinuxClientRoutePlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            TunnelNetworkConfig::default(),
        )
        .unwrap();
        let snapshot = LinuxRouteSnapshot {
            ipv4_default: Some(
                LinuxRouteState::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), "eth0").unwrap(),
            ),
            ipv6_default: Some(
                LinuxRouteState::new(IpAddr::V6("2001:db8::1".parse().unwrap()), "eth0").unwrap(),
            ),
            endpoint: Some(
                LinuxRouteState::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), "eth0").unwrap(),
            ),
        };
        let commands = plan.cleanup_commands_with_snapshot(&snapshot).unwrap();
        assert_eq!(commands.len(), 6);
        assert!(commands.iter().any(|command| {
            command.args
                == vec![
                    "route",
                    "replace",
                    "default",
                    "via",
                    "192.0.2.1",
                    "dev",
                    "eth0",
                ]
        }));
        assert!(commands.iter().any(|command| {
            command.args
                == vec![
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    "2001:db8::1",
                    "dev",
                    "eth0",
                ]
        }));
    }

    #[test]
    fn rejects_route_snapshot_family_mismatch() {
        let plan = LinuxClientRoutePlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            TunnelNetworkConfig::default(),
        )
        .unwrap();
        let snapshot = LinuxRouteSnapshot {
            ipv4_default: Some(
                LinuxRouteState::new(IpAddr::V6(Ipv6Addr::LOCALHOST), "eth0").unwrap(),
            ),
            ..LinuxRouteSnapshot::default()
        };
        assert_eq!(
            plan.cleanup_commands_with_snapshot(&snapshot),
            Err(NetworkConfigError::InvalidRouteSnapshot)
        );
    }

    #[test]
    fn builds_kill_switch_with_endpoint_exception_and_rollback() {
        let plan = LinuxKillSwitchPlan::new(
            "gsm0",
            "eth0",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51_820),
        )
        .unwrap();
        let commands = plan.apply_commands();
        assert!(commands.iter().any(|command| {
            command
                .args
                .windows(3)
                .any(|window| window == ["oifname", "gsm0", "accept"])
        }));
        assert!(commands.iter().any(|command| {
            command
                .args
                .iter()
                .any(|argument| argument == "203.0.113.10")
                && command.args.iter().any(|argument| argument == "51820")
        }));
        assert_eq!(
            plan.rollback_commands()[0].args,
            ["delete", "table", "inet", "gsm_tunnel_killswitch"]
        );
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
