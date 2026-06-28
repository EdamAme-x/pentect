use std::sync::LazyLock;

use regex::Regex;

use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>()]+"#).unwrap());

/// Preserves useful URL structure for internal systems:
/// `http://local.jira.corp/api/issues/1234`
/// becomes `http://<<INTERNAL_ENDPOINT_...>>/api/issues/<<RESOURCE_ID_...>>`.
pub struct UrlDetector;

impl Detector for UrlDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let mut out = Vec::new();
        for m in URL_RE.find_iter(view.text()) {
            inspect_url(view, m.start(), m.as_str(), &mut out);
        }
        out
    }
}

fn inspect_url(view: &NormalizedView, base: usize, url: &str, out: &mut Vec<Span>) {
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return;
    };
    let authority_end = url[scheme_end..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| scheme_end + i);
    if authority_end <= scheme_end {
        return;
    }

    let authority = &url[scheme_end..authority_end];
    let host_start_in_authority = authority.rfind('@').map_or(0, |i| i + 1);
    let host_port = &authority[host_start_in_authority..];
    let Some(host) = host_without_port(host_port) else {
        return;
    };
    if !is_internal_host(host) {
        return;
    }

    let endpoint_start = base + scheme_end + host_start_in_authority;
    let endpoint_end = base + authority_end;
    out.push(Span {
        range: view.to_raw(ByteRange::new(endpoint_start, endpoint_end)),
        category: Category::Endpoint,
        label: labels::INTERNAL_ENDPOINT.to_string(),
        confidence: Confidence::High,
        source: DetectorId::Rule,
    });

    let path_start = authority_end;
    if url.as_bytes().get(path_start) != Some(&b'/') {
        return;
    }
    let path_end = url[path_start..]
        .find(['?', '#'])
        .map_or(url.len(), |i| path_start + i);
    inspect_path_ids(view, base, url, path_start, path_end, out);
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

fn is_internal_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if matches!(host.as_str(), "localhost" | "::1") {
        return true;
    }
    if let Some((a, b, c, d)) = parse_ipv4(&host) {
        return a == 10
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 127)
            || (a == 169 && b == 254)
            || (a == 100 && (64..=127).contains(&b))
            || (a == 0 && b == 0 && c == 0 && d == 0);
    }
    if !host.contains('.') {
        return true;
    }
    [
        ".corp",
        ".internal",
        ".intranet",
        ".local",
        ".lan",
        ".home",
        ".localhost",
    ]
    .iter()
    .any(|suffix| host.ends_with(suffix))
}

fn parse_ipv4(host: &str) -> Option<(u8, u8, u8, u8)> {
    let mut parts = host.split('.');
    let a = parts.next()?.parse().ok()?;
    let b = parts.next()?.parse().ok()?;
    let c = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c, d))
}

fn inspect_path_ids(
    view: &NormalizedView,
    base: usize,
    url: &str,
    path_start: usize,
    path_end: usize,
    out: &mut Vec<Span>,
) {
    let mut pos = path_start;
    while pos < path_end {
        if url.as_bytes()[pos] == b'/' {
            pos += 1;
            continue;
        }
        let start = pos;
        while pos < path_end && url.as_bytes()[pos] != b'/' {
            pos += 1;
        }
        let segment = &url[start..pos];
        if let Some((trim_start, trim_end)) = resource_id_bounds(segment) {
            out.push(Span {
                range: view.to_raw(ByteRange::new(
                    base + start + trim_start,
                    base + start + trim_end,
                )),
                category: Category::Identifier,
                label: labels::RESOURCE_ID.to_string(),
                confidence: Confidence::High,
                source: DetectorId::Rule,
            });
        }
    }
}

fn resource_id_bounds(segment: &str) -> Option<(usize, usize)> {
    let start = segment
        .find(|c: char| !matches!(c, '.' | ',' | ';' | ':' | '(' | '[' | '{'))
        .unwrap_or(segment.len());
    let end = segment
        .rfind(|c: char| !matches!(c, '.' | ',' | ';' | ':' | ')' | ']' | '}'))
        .map_or(start, |i| {
            i + segment[i..].chars().next().unwrap().len_utf8()
        });
    let s = &segment[start..end];
    if s.len() < 2 || s.len() > 128 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes.iter().all(u8::is_ascii_digit) {
        return Some((start, end));
    }
    if looks_uuid(s) {
        return Some((start, end));
    }
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let id_alphabet = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    (has_digit && has_alpha && id_alphabet && s.len() >= 6).then_some((start, end))
}

fn looks_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| bytes[i] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| [8, 13, 18, 23].contains(&i) || b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn labels(raw: &str) -> Vec<(String, String)> {
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        UrlDetector
            .detect(&view)
            .into_iter()
            .map(|span| {
                (
                    span.label,
                    raw[span.range.start..span.range.end].to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn internal_url_masks_endpoint_and_resource_id() {
        assert_eq!(
            labels("http://local.jira.corp/api/issues/1234"),
            [
                (
                    "INTERNAL_ENDPOINT".to_string(),
                    "local.jira.corp".to_string()
                ),
                ("RESOURCE_ID".to_string(), "1234".to_string()),
            ]
        );
    }

    #[test]
    fn external_url_is_not_granularly_masked() {
        assert!(labels("https://example.com/api/issues/1234").is_empty());
    }

    #[test]
    fn private_ip_and_dotless_hosts_are_internal() {
        assert!(labels("http://10.0.0.5/api/users/abc12345")
            .iter()
            .any(|(_, value)| value == "10.0.0.5"));
        assert!(labels("http://jira/api/users/abc12345")
            .iter()
            .any(|(_, value)| value == "jira"));
    }

    #[test]
    fn resource_id_keeps_sentence_punctuation_literal() {
        assert_eq!(
            labels("http://jira.corp/api/issues/1234."),
            [
                ("INTERNAL_ENDPOINT".to_string(), "jira.corp".to_string()),
                ("RESOURCE_ID".to_string(), "1234".to_string()),
            ]
        );
    }
}
