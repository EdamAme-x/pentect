use std::net::{Ipv4Addr, Ipv6Addr};

/// Extracts IPv4 addresses carried by IPv4-mapped, IPv4-compatible, NAT64,
/// or 6to4 IPv6 forms so every network boundary applies the same policy.
pub fn embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    if address.is_loopback() {
        return None;
    }
    if let Some(mapped) = address.to_ipv4_mapped() {
        return Some(mapped);
    }
    let octets = address.octets();
    if octets[..12] == [0; 12]
        || octets[..12]
            == [
                0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        || octets[..12]
            == [
                0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
    {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if octets[..2] == [0x20, 0x02] {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_supported_embedded_ipv4_forms_without_misreading_loopback() {
        assert_eq!(
            embedded_ipv4("::ffff:127.0.0.1".parse().unwrap()),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            embedded_ipv4("::127.0.0.1".parse().unwrap()),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            embedded_ipv4("64:ff9b::127.0.0.1".parse().unwrap()),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            embedded_ipv4("2002:7f00:0001::".parse().unwrap()),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(embedded_ipv4(Ipv6Addr::LOCALHOST), None);
    }
}
