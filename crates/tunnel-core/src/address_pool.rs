//! Bounded client address allocation for the configured tunnel networks.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::network::TunnelNetworkConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAddresses {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressPoolError {
    InvalidConfiguration,
    Ipv4Exhausted,
    Ipv6Exhausted,
    UnknownAddress,
}

pub struct ClientAddressPool {
    config: TunnelNetworkConfig,
    next_ipv4: u32,
    next_ipv6: u128,
    allocated_ipv4: HashSet<Ipv4Addr>,
    allocated_ipv6: HashSet<Ipv6Addr>,
}

impl ClientAddressPool {
    /// Creates an allocator from a validated tunnel network configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AddressPoolError::InvalidConfiguration`] when the tunnel
    /// network configuration cannot be used for client allocation.
    pub fn new(config: TunnelNetworkConfig) -> Result<Self, AddressPoolError> {
        config
            .validate()
            .map_err(|_| AddressPoolError::InvalidConfiguration)?;
        let next_ipv4 = u32::from(config.ipv4_network)
            .checked_add(2)
            .ok_or(AddressPoolError::InvalidConfiguration)?;
        let next_ipv6 = u128::from(config.ipv6_network)
            .checked_add(2)
            .ok_or(AddressPoolError::InvalidConfiguration)?;
        Ok(Self {
            config,
            next_ipv4,
            next_ipv6,
            allocated_ipv4: HashSet::new(),
            allocated_ipv6: HashSet::new(),
        })
    }

    /// Allocates the next available IPv4 address and, when enabled, its IPv6 pair.
    ///
    /// # Errors
    ///
    /// Returns an exhaustion error when either address family has no free
    /// client address. A partially allocated pair is rolled back.
    pub fn allocate(&mut self) -> Result<ClientAddresses, AddressPoolError> {
        let ipv4 = self.allocate_ipv4()?;
        let ipv6 = if self.config.dual_stack {
            match self.allocate_ipv6() {
                Ok(address) => Some(address),
                Err(error) => {
                    self.allocated_ipv4.remove(&ipv4);
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(ClientAddresses { ipv4, ipv6 })
    }

    /// Releases a previously allocated address pair.
    ///
    /// # Errors
    ///
    /// Returns [`AddressPoolError::UnknownAddress`] when the pair is not
    /// currently allocated.
    pub fn release(&mut self, addresses: ClientAddresses) -> Result<(), AddressPoolError> {
        if !self.allocated_ipv4.remove(&addresses.ipv4) {
            return Err(AddressPoolError::UnknownAddress);
        }
        if let Some(ipv6) = addresses.ipv6
            && !self.allocated_ipv6.remove(&ipv6)
        {
            self.allocated_ipv4.insert(addresses.ipv4);
            return Err(AddressPoolError::UnknownAddress);
        }
        Ok(())
    }

    #[must_use]
    pub fn allocated(&self) -> usize {
        self.allocated_ipv4.len()
    }

    fn allocate_ipv4(&mut self) -> Result<Ipv4Addr, AddressPoolError> {
        let network = u32::from(self.config.ipv4_network);
        let broadcast = ipv4_broadcast(self.config.ipv4_network, self.config.ipv4_prefix);
        let limit = 1u64 << (32 - self.config.ipv4_prefix.min(31));
        for _ in 0..limit {
            let candidate = Ipv4Addr::from(self.next_ipv4);
            self.next_ipv4 = self.next_ipv4.wrapping_add(1);
            if u32::from(candidate) <= network
                || (self.config.ipv4_prefix <= 30 && u32::from(candidate) >= broadcast)
                || candidate == self.config.server_ipv4
                || self.allocated_ipv4.contains(&candidate)
            {
                continue;
            }
            if !contains_ipv4(self.config.ipv4_network, self.config.ipv4_prefix, candidate) {
                continue;
            }
            self.allocated_ipv4.insert(candidate);
            return Ok(candidate);
        }
        Err(AddressPoolError::Ipv4Exhausted)
    }

    fn allocate_ipv6(&mut self) -> Result<Ipv6Addr, AddressPoolError> {
        let network = u128::from(self.config.ipv6_network);
        let host_bits = 128 - self.config.ipv6_prefix;
        let limit = if host_bits >= 20 {
            1u128 << 20
        } else {
            1u128 << host_bits
        };
        for _ in 0..limit {
            let candidate = Ipv6Addr::from(self.next_ipv6);
            self.next_ipv6 = self.next_ipv6.wrapping_add(1);
            if u128::from(candidate) <= network
                || candidate == self.config.server_ipv6
                || self.allocated_ipv6.contains(&candidate)
                || !contains_ipv6(self.config.ipv6_network, self.config.ipv6_prefix, candidate)
            {
                continue;
            }
            self.allocated_ipv6.insert(candidate);
            return Ok(candidate);
        }
        Err(AddressPoolError::Ipv6Exhausted)
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

fn contains_ipv6(network: Ipv6Addr, prefix: u8, address: Ipv6Addr) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(network) & mask) == (u128::from(address) & mask)
}

fn ipv4_broadcast(network: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(network) | !mask
}

#[cfg(test)]
mod tests {
    use super::{AddressPoolError, ClientAddressPool};
    use crate::network::TunnelNetworkConfig;

    #[test]
    fn allocates_dual_stack_addresses_from_second_host_and_reuses_released_pair() {
        let mut pool = ClientAddressPool::new(TunnelNetworkConfig::default()).unwrap();
        let first = pool.allocate().unwrap();
        assert_eq!(first.ipv4.octets(), [10, 80, 0, 2]);
        assert_eq!(first.ipv6.unwrap().segments()[7], 2);
        assert_eq!(pool.allocated(), 1);
        pool.release(first).unwrap();
        assert_eq!(pool.allocated(), 0);
        let second = pool.allocate().unwrap();
        assert_ne!(second, first);
    }

    #[test]
    fn does_not_allocate_server_or_broadcast_addresses() {
        let config = TunnelNetworkConfig {
            ipv4_prefix: 30,
            ..TunnelNetworkConfig::default()
        };
        let mut pool = ClientAddressPool::new(config).unwrap();
        let first = pool.allocate().unwrap();
        assert_ne!(
            first.ipv4,
            "10.80.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert!(matches!(
            pool.allocate(),
            Err(AddressPoolError::Ipv4Exhausted)
        ));
    }
}
