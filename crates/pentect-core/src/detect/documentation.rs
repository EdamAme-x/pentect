use std::net::IpAddr;
use std::sync::LazyLock;

static DOCUMENTATION_HOSTS: LazyLock<HostPatternSet> =
    LazyLock::new(|| HostPatternSet::parse(include_str!("documentation_host_patterns.txt")));

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostPattern {
    Exact(String),
    Suffix(String),
    Cidr(IpCidr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IpCidr {
    network: IpAddr,
    prefix_bits: u8,
}

#[derive(Clone, Debug, Default)]
struct HostPatternSet {
    patterns: Vec<HostPattern>,
}

impl HostPatternSet {
    fn parse(raw: &str) -> Self {
        let patterns = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| {
                let (kind, pattern) = line.split_once(':')?;
                let pattern = normalize_host(pattern);
                match kind.trim() {
                    "exact" => Some(HostPattern::Exact(pattern)),
                    "suffix" => Some(HostPattern::Suffix(pattern)),
                    "cidr" => parse_ip_cidr(&pattern).map(HostPattern::Cidr),
                    _ => None,
                }
            })
            .collect();
        Self { patterns }
    }

    fn matches(&self, host: &str) -> bool {
        let host = normalize_host(host);
        let ip = host.parse::<IpAddr>().ok();
        self.patterns.iter().any(|pattern| match pattern {
            HostPattern::Exact(pattern) => host == *pattern,
            HostPattern::Suffix(pattern) => host.ends_with(pattern),
            HostPattern::Cidr(cidr) => ip.is_some_and(|ip| cidr.contains(ip)),
        })
    }
}

impl IpCidr {
    fn contains(&self, ip: IpAddr) -> bool {
        match (ip, self.network) {
            (IpAddr::V4(ip), IpAddr::V4(network)) => {
                let mask = cidr_mask(32, self.prefix_bits);
                (u32::from(ip) & mask as u32) == (u32::from(network) & mask as u32)
            }
            (IpAddr::V6(ip), IpAddr::V6(network)) => {
                let mask = cidr_mask(128, self.prefix_bits);
                (u128::from(ip) & mask) == (u128::from(network) & mask)
            }
            _ => false,
        }
    }
}

pub(crate) fn is_documentation_host(host: &str) -> bool {
    // RFC-reserved example hosts and documentation address ranges are public
    // teaching material, not deployed endpoints. The data file carries the RFC
    // numbers; this helper only centralizes parsing and CIDR matching.
    DOCUMENTATION_HOSTS.matches(host)
}

pub(crate) fn is_documentation_value(value: &str) -> bool {
    // Used only for explicit placeholder/doc-example suppression. Keep the
    // accepted shapes narrow: a bare host/IP or a URL whose authority is RFC
    // documentation-only and which does not embed credentials or parameters.
    let Some(host) = documentation_value_host(value) else {
        return false;
    };
    is_documentation_host(host)
}

fn documentation_value_host(value: &str) -> Option<&str> {
    let value = value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`'));
    if value.is_empty() || value.len() > 512 {
        return None;
    }
    if value.parse::<IpAddr>().is_ok() {
        return Some(value);
    }
    if let Some(bracketed) = bracketed_ipv6_host(value) {
        return Some(bracketed);
    }
    let lower = value.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        Some(&value[7..])
    } else if lower.starts_with("https://") {
        Some(&value[8..])
    } else {
        None
    };
    if let Some(rest) = rest {
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty()
            || authority.contains('@')
            || rest[authority_end..].contains(['?', '#'])
        {
            return None;
        }
        return host_without_port(authority);
    }
    if value.contains(['/', '?', '#', '@']) {
        return None;
    }
    host_without_port(value)
}

fn bracketed_ipv6_host(value: &str) -> Option<&str> {
    let rest = value.strip_prefix('[')?;
    let end = rest.find(']')?;
    let host = &rest[..end];
    let suffix = &rest[end + 1..];
    if suffix.is_empty() || suffix.starts_with(':') {
        host.parse::<IpAddr>().ok()?;
        Some(host)
    } else {
        None
    }
}

fn host_without_port(host_port: &str) -> Option<&str> {
    if host_port.is_empty() {
        return None;
    }
    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(&rest[..end]);
    }
    Some(
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host),
    )
}

fn parse_ip_cidr(raw: &str) -> Option<IpCidr> {
    let (network, prefix) = raw.split_once('/')?;
    let network = network.parse::<IpAddr>().ok()?;
    let prefix_bits = prefix.parse::<u8>().ok()?;
    let max_bits = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    (prefix_bits <= max_bits).then_some(IpCidr {
        network,
        prefix_bits,
    })
}

fn cidr_mask(total_bits: u8, prefix_bits: u8) -> u128 {
    if prefix_bits == 0 {
        return 0;
    }
    u128::MAX << (u32::from(total_bits - prefix_bits))
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_matches(|ch| matches!(ch, '[' | ']'))
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_documentation_hosts_match() {
        assert!(is_documentation_host("example.com"));
        assert!(is_documentation_host("api.example"));
        assert!(is_documentation_host("192.0.2.10"));
        assert!(is_documentation_host("198.51.100.10"));
        assert!(is_documentation_host("203.0.113.10"));
        assert!(is_documentation_host("2001:db8::1"));
        assert!(is_documentation_host("3fff::1"));
        assert!(!is_documentation_host("localhost"));
        assert!(!is_documentation_host("10.0.0.1"));
    }

    #[test]
    fn documentation_values_stay_narrow() {
        assert!(is_documentation_value("api.example.com"));
        assert!(is_documentation_value("https://example.net/path"));
        assert!(is_documentation_value("HTTPS://EXAMPLE.ORG/path"));
        assert!(is_documentation_value("[2001:db8::42]"));
        assert!(!is_documentation_value(
            "https://alice:letmein@example.com/path"
        ));
        assert!(!is_documentation_value(
            "https://example.com/path?token=abc123"
        ));
        assert!(!is_documentation_value("localhost"));
    }
}
