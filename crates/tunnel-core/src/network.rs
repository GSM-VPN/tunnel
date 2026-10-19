//! Validated tunnel network policy and MTU budget.

use std::net::{Ipv4Addr, Ipv6Addr};

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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{MtuBudget, NetworkConfigError, TunnelNetworkConfig};

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
}
