//! Bounded validation for IPv4 and IPv6 packets read from a tunnel device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP version identified from the first nibble of an inner packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerIpVersion {
    V4,
    V6,
}

/// Safe metadata extracted without retaining the packet payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerIpPacketInfo {
    pub version: InnerIpVersion,
    pub header_length: usize,
    pub total_length: usize,
    pub next_header: u8,
    pub source: IpAddr,
    pub destination: IpAddr,
}

/// Errors returned by inner packet validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerIpPacketError {
    Empty,
    UnsupportedVersion(u8),
    TruncatedHeader,
    InvalidHeaderLength,
    InvalidTotalLength,
    PayloadExceedsMtu,
    Ipv6Disabled,
    InvalidIpv4Checksum,
    SourceOutsideTunnel,
    SourceNotAssigned,
}

/// Tunnel ranges and the addresses assigned to one authenticated Peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSourcePolicy {
    pub ipv4_network: Ipv4Addr,
    pub ipv4_prefix: u8,
    pub ipv6_network: Ipv6Addr,
    pub ipv6_prefix: u8,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub assigned_ipv6: Option<Ipv6Addr>,
}

/// Validates one complete inner IP packet against a tunnel MTU and address
/// family policy. No packet bytes are retained after this call.
///
/// # Errors
///
/// Returns an error for malformed headers, length mismatches, checksum
/// failures, packets larger than `mtu`, or IPv6 when `dual_stack` is false.
pub fn validate_inner_ip_packet(
    packet: &[u8],
    mtu: usize,
    dual_stack: bool,
) -> Result<InnerIpPacketInfo, InnerIpPacketError> {
    if packet.is_empty() {
        return Err(InnerIpPacketError::Empty);
    }
    if packet.len() > mtu {
        return Err(InnerIpPacketError::PayloadExceedsMtu);
    }
    match packet[0] >> 4 {
        4 => validate_ipv4(packet),
        6 if dual_stack => validate_ipv6(packet),
        6 => Err(InnerIpPacketError::Ipv6Disabled),
        version => Err(InnerIpPacketError::UnsupportedVersion(version)),
    }
}

/// Validates an inner packet and enforces the configured tunnel source ranges.
///
/// This check is intentionally separate from syntax validation so callers can
/// apply the same packet parser to client and server paths while choosing the
/// address policy at the network boundary.
///
/// # Errors
///
/// Returns the underlying packet error or [`InnerIpPacketError::SourceOutsideTunnel`]
/// when the parsed source is outside both configured tunnel ranges.
pub fn validate_inner_ip_packet_from_tunnel(
    packet: &[u8],
    mtu: usize,
    dual_stack: bool,
    ipv4_network: Ipv4Addr,
    ipv4_prefix: u8,
    ipv6_network: Ipv6Addr,
    ipv6_prefix: u8,
) -> Result<InnerIpPacketInfo, InnerIpPacketError> {
    let info = validate_inner_ip_packet(packet, mtu, dual_stack)?;
    let source_allowed = match info.source {
        IpAddr::V4(source) => contains_ipv4(ipv4_network, ipv4_prefix, source),
        IpAddr::V6(source) => contains_ipv6(ipv6_network, ipv6_prefix, source),
    };
    if source_allowed {
        Ok(info)
    } else {
        Err(InnerIpPacketError::SourceOutsideTunnel)
    }
}

/// Validates an inner packet against both the tunnel ranges and one approved
/// peer's assigned addresses. This is the server-side boundary that prevents
/// one authenticated peer from claiming another peer's virtual IP.
///
/// # Errors
///
/// Returns [`InnerIpPacketError::SourceNotAssigned`] when the packet family has
/// no assigned address or its source differs from the approved address.
pub fn validate_inner_ip_packet_from_peer(
    packet: &[u8],
    mtu: usize,
    dual_stack: bool,
    policy: PeerSourcePolicy,
) -> Result<InnerIpPacketInfo, InnerIpPacketError> {
    let info = validate_inner_ip_packet_from_tunnel(
        packet,
        mtu,
        dual_stack,
        policy.ipv4_network,
        policy.ipv4_prefix,
        policy.ipv6_network,
        policy.ipv6_prefix,
    )?;
    let assigned = match info.source {
        IpAddr::V4(source) => policy
            .assigned_ipv4
            .is_some_and(|assigned| assigned == source),
        IpAddr::V6(source) => policy
            .assigned_ipv6
            .is_some_and(|assigned| assigned == source),
    };
    if assigned {
        Ok(info)
    } else {
        Err(InnerIpPacketError::SourceNotAssigned)
    }
}

fn validate_ipv4(packet: &[u8]) -> Result<InnerIpPacketInfo, InnerIpPacketError> {
    if packet.len() < 20 {
        return Err(InnerIpPacketError::TruncatedHeader);
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 {
        return Err(InnerIpPacketError::InvalidHeaderLength);
    }
    if packet.len() < header_length {
        return Err(InnerIpPacketError::TruncatedHeader);
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_length || total_length != packet.len() {
        return Err(InnerIpPacketError::InvalidTotalLength);
    }
    if checksum(&packet[..header_length]) != 0 {
        return Err(InnerIpPacketError::InvalidIpv4Checksum);
    }
    Ok(InnerIpPacketInfo {
        version: InnerIpVersion::V4,
        header_length,
        total_length,
        next_header: packet[9],
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
    })
}

fn validate_ipv6(packet: &[u8]) -> Result<InnerIpPacketInfo, InnerIpPacketError> {
    if packet.len() < 40 {
        return Err(InnerIpPacketError::TruncatedHeader);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_length = 40usize
        .checked_add(payload_length)
        .ok_or(InnerIpPacketError::InvalidTotalLength)?;
    if total_length != packet.len() {
        return Err(InnerIpPacketError::InvalidTotalLength);
    }
    Ok(InnerIpPacketInfo {
        version: InnerIpVersion::V6,
        header_length: 40,
        total_length,
        next_header: packet[6],
        source: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).expect("validated IPv6 source length"),
        )),
        destination: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).expect("validated IPv6 destination length"),
        )),
    })
}

fn contains_ipv4(network: Ipv4Addr, prefix: u8, address: Ipv4Addr) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(address) & mask)
}

fn contains_ipv6(network: Ipv6Addr, prefix: u8, address: Ipv6Addr) -> bool {
    if prefix > 128 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(network) & mask) == (u128::from(address) & mask)
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = header.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum sum fits in u16")
}

/// Computes the IPv4 header checksum for test and packet-construction helpers.
#[must_use]
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut copy = header.to_vec();
    if copy.len() >= 12 {
        copy[10] = 0;
        copy[11] = 0;
    }
    checksum(&copy)
}

/// Returns whether an IPv4 address is in the fixed GSM tunnel network.
#[must_use]
pub fn is_tunnel_ipv4_address(address: Ipv4Addr) -> bool {
    let network = u32::from(Ipv4Addr::new(10, 80, 0, 0));
    let mask = u32::from(Ipv4Addr::new(255, 255, 0, 0));
    u32::from(address) & mask == network & mask
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        InnerIpPacketError, InnerIpVersion, PeerSourcePolicy, ipv4_header_checksum,
        validate_inner_ip_packet, validate_inner_ip_packet_from_peer,
        validate_inner_ip_packet_from_tunnel,
    };

    fn ipv4(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20 + payload.len()];
        packet[0] = 0x45;
        let total_length = u16::try_from(packet.len()).expect("test packet fits IPv4 length");
        packet[2..4].copy_from_slice(&total_length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 80, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..].copy_from_slice(payload);
        let checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv6(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        packet[0] = 0x60;
        let payload_length = u16::try_from(payload.len()).expect("test payload fits IPv6 length");
        packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[
            0xfd, 0x80, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn identifies_valid_ipv4_and_ipv6_packets() {
        let v4 = validate_inner_ip_packet(&ipv4(b"udp"), 1_400, true).unwrap();
        assert_eq!(v4.version, InnerIpVersion::V4);
        assert_eq!(v4.next_header, 17);
        let v6 = validate_inner_ip_packet(&ipv6(b"udp"), 1_400, true).unwrap();
        assert_eq!(v6.version, InnerIpVersion::V6);
        assert_eq!(v6.header_length, 40);
        assert_eq!(v4.source, IpAddr::V4(Ipv4Addr::new(10, 80, 0, 2)));
        assert_eq!(v6.destination, IpAddr::V6("2001:db08::1".parse().unwrap()));
    }

    #[test]
    fn rejects_inner_sources_outside_the_configured_tunnel_ranges() {
        let mut packet = ipv4(b"udp");
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        let checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            validate_inner_ip_packet_from_tunnel(
                &packet,
                1_400,
                true,
                Ipv4Addr::new(10, 80, 0, 0),
                16,
                Ipv6Addr::new(0xfd80, 0x1234, 0x5678, 0, 0, 0, 0, 0),
                64,
            ),
            Err(InnerIpPacketError::SourceOutsideTunnel)
        );
        let valid = ipv6(b"udp");
        assert!(
            validate_inner_ip_packet_from_tunnel(
                &valid,
                1_400,
                true,
                Ipv4Addr::new(10, 80, 0, 0),
                16,
                Ipv6Addr::new(0xfd80, 0x1234, 0x5678, 0, 0, 0, 0, 0),
                64,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_a_peer_claiming_another_assigned_virtual_address() {
        let network = Ipv4Addr::new(10, 80, 0, 0);
        let ipv6_network = Ipv6Addr::new(0xfd80, 0x1234, 0x5678, 0, 0, 0, 0, 0);
        let packet = ipv4(b"udp");
        assert!(
            validate_inner_ip_packet_from_peer(
                &packet,
                1_400,
                true,
                PeerSourcePolicy {
                    ipv4_network: network,
                    ipv4_prefix: 16,
                    ipv6_network,
                    ipv6_prefix: 64,
                    assigned_ipv4: Some(Ipv4Addr::new(10, 80, 0, 3)),
                    assigned_ipv6: None,
                },
            )
            .is_err_and(|error| error == InnerIpPacketError::SourceNotAssigned)
        );
        assert!(
            validate_inner_ip_packet_from_peer(
                &packet,
                1_400,
                true,
                PeerSourcePolicy {
                    ipv4_network: network,
                    ipv4_prefix: 16,
                    ipv6_network,
                    ipv6_prefix: 64,
                    assigned_ipv4: Some(Ipv4Addr::new(10, 80, 0, 2)),
                    assigned_ipv6: None,
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_malformed_versions_lengths_checksum_and_mtu() {
        assert_eq!(
            validate_inner_ip_packet(&[], 1_400, true),
            Err(InnerIpPacketError::Empty)
        );
        assert_eq!(
            validate_inner_ip_packet(&[0x70], 1_400, true),
            Err(InnerIpPacketError::UnsupportedVersion(7))
        );
        assert_eq!(
            validate_inner_ip_packet(&ipv4(b"x")[..10], 1_400, true),
            Err(InnerIpPacketError::TruncatedHeader)
        );
        let mut invalid = ipv4(b"x");
        invalid[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(
            validate_inner_ip_packet(&invalid, 1_400, true),
            Err(InnerIpPacketError::InvalidTotalLength)
        );
        let mut invalid = ipv4(b"x");
        invalid[10] ^= 1;
        assert_eq!(
            validate_inner_ip_packet(&invalid, 1_400, true),
            Err(InnerIpPacketError::InvalidIpv4Checksum)
        );
        assert_eq!(
            validate_inner_ip_packet(&ipv6(b"x"), 40, true),
            Err(InnerIpPacketError::PayloadExceedsMtu)
        );
        assert_eq!(
            validate_inner_ip_packet(&ipv6(b"x"), 1_400, false),
            Err(InnerIpPacketError::Ipv6Disabled)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_packets_never_panic(
            packet in proptest::collection::vec(any::<u8>(), 0..=2_048),
            mtu in 0usize..=1_500,
            dual_stack in any::<bool>(),
        ) {
            let _ = validate_inner_ip_packet(&packet, mtu, dual_stack);
        }
    }
}
