use std::sync::LazyLock;

use regex::Regex;

use super::documentation::is_documentation_host;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>()]*[^\s"'<>().,;:!?]"#).unwrap());
static URI_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s"'<>()/?#@]+@[^\s"'<>()]*[^\s"'<>().,;:!?]"#)
        .unwrap()
});

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
        for m in URI_USERINFO_RE.find_iter(view.text()) {
            if is_http_url(m.as_str()) {
                continue;
            }
            inspect_uri_userinfo(view, m.start(), m.as_str(), &mut out);
        }
        out
    }
}

fn is_http_url(url: &str) -> bool {
    let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
}

fn inspect_uri_userinfo(view: &NormalizedView, base: usize, url: &str, out: &mut Vec<Span>) {
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
    let Some(at) = authority.rfind('@').filter(|&at| at > 0) else {
        return;
    };
    let host_port = &authority[at + 1..];
    let Some(host) = host_without_port(host_port) else {
        return;
    };
    let userinfo = &authority[..at];
    if generic_uri_userinfo_is_credential(userinfo) && !is_documentation_host(host) {
        push_span(
            view,
            out,
            base + scheme_end,
            base + scheme_end + at,
            Category::Secret,
            labels::URL_CREDENTIAL,
        );
    }
}

fn generic_uri_userinfo_is_credential(userinfo: &str) -> bool {
    // The generic non-HTTP URI path has much less context than the HTTP and DB
    // handlers, so it needs one extra material-shape signal. This keeps
    // fixture prose like `nats://user:pass@localhost` out of the fallback while
    // preserving stronger passwords and token-as-username forms.
    if userinfo_is_template_or_redaction(userinfo) {
        return false;
    }
    if userinfo_token_like(userinfo) {
        return true;
    }
    userinfo
        .split_once(':')
        .map(|(_, password)| generic_uri_password_has_signal(password))
        .or_else(|| {
            let lower = userinfo.to_ascii_lowercase();
            lower
                .find("%3a")
                .map(|colon| generic_uri_password_has_signal(&userinfo[colon + 3..]))
        })
        .unwrap_or(false)
}

fn generic_uri_password_has_signal(password: &str) -> bool {
    let password = password.trim();
    if password.is_empty() {
        return false;
    }
    password.chars().count() >= 8
        || password.bytes().any(|b| b.is_ascii_digit())
        || password
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'%' | b'-' | b'_'))
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
    let userinfo_end = authority.rfind('@');
    let host_start_in_authority = userinfo_end.map_or(0, |i| i + 1);
    let host_port = &authority[host_start_in_authority..];
    let Some(host) = host_without_port(host_port) else {
        return;
    };
    if let Some(at) = userinfo_end.filter(|&at| at > 0) {
        let userinfo = &authority[..at];
        if userinfo_is_credential(userinfo) && !is_documentation_host(host) {
            push_span(
                view,
                out,
                base + scheme_end,
                base + scheme_end + at,
                Category::Secret,
                labels::URL_CREDENTIAL,
            );
        }
    }
    if !is_internal_host(host) {
        return;
    }

    push_span(
        view,
        out,
        base + scheme_end + host_start_in_authority,
        base + authority_end,
        Category::Endpoint,
        labels::INTERNAL_ENDPOINT,
    );

    let query_at = url[authority_end..].find('?').map(|i| authority_end + i);
    let fragment_at = url[authority_end..].find('#').map(|i| authority_end + i);
    let query_at = query_at.filter(|&q| fragment_at.is_none_or(|f| q < f));
    let path_end = [query_at, fragment_at]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(url.len());

    if url.as_bytes().get(authority_end) == Some(&b'/') {
        inspect_path_ids(view, base, url, authority_end, path_end, out);
    }
    if let Some(q) = query_at {
        let query_end = fragment_at.unwrap_or(url.len());
        inspect_query_values(view, base, url, q + 1, query_end, out);
    }
    if let Some(f) = fragment_at {
        inspect_fragment(view, base, url, f + 1, url.len(), out);
    }
}

fn push_span(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    start: usize,
    end: usize,
    category: Category,
    label: &str,
) {
    if start >= end {
        return;
    }
    out.push(Span {
        range: view.to_raw(ByteRange::new(start, end)),
        category,
        label: label.to_string(),
        confidence: Confidence::High,
        source: DetectorId::Rule,
    });
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

fn userinfo_is_credential(userinfo: &str) -> bool {
    // URL userinfo grammar allows a username without a password
    // (`https://alice@example.com`). That is identity metadata, not a secret.
    // A credential-bearing authority either has an explicit password separator
    // or uses a token as the username (`https://ghp_...@github.com`).
    !userinfo_is_template_or_redaction(userinfo)
        && (userinfo.contains(':')
            || userinfo.to_ascii_lowercase().contains("%3a")
            || userinfo_token_like(userinfo))
}

fn userinfo_is_template_or_redaction(userinfo: &str) -> bool {
    // URI docs commonly show userinfo as `[user[:password]@]` or `***:***`.
    // Brackets are template grammar, not URL userinfo. Literal `*` is treated
    // as a redaction marker here; real passwords with `*` should be
    // percent-encoded in URLs and remain covered after decoding elsewhere.
    // Placeholder pairs such as `username:password` or `token:MY_TOKEN` are
    // also template grammar. They do not expose reusable credential bytes.
    userinfo
        .bytes()
        .any(|b| matches!(b, b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b'*'))
        || split_userinfo_password(userinfo)
            .is_some_and(|(user, password)| userinfo_password_is_placeholder(user, password))
}

fn split_userinfo_password(userinfo: &str) -> Option<(&str, &str)> {
    userinfo.split_once(':').or_else(|| {
        let lower = userinfo.to_ascii_lowercase();
        lower
            .find("%3a")
            .map(|colon| (&userinfo[..colon], &userinfo[colon + 3..]))
    })
}

fn userinfo_password_is_placeholder(user: &str, password: &str) -> bool {
    let user = user.trim();
    let password = password.trim();
    if password.is_empty() {
        return true;
    }
    if userinfo_component_is_env_reference(password) {
        return true;
    }
    if userinfo_component_is_oauth_marker(password) {
        return !userinfo_token_like(user) || is_short_hex_userinfo_component(user);
    }
    userinfo_component_is_placeholder_user(user)
        && matches!(
            normalized_userinfo_component(password).as_str(),
            "password" | "passwd"
        )
}

fn userinfo_component_is_placeholder_user(value: &str) -> bool {
    matches!(
        normalized_userinfo_component(value).as_str(),
        "user" | "username" | "login"
    )
}

fn userinfo_component_is_oauth_marker(value: &str) -> bool {
    matches!(
        normalized_userinfo_component(value).as_str(),
        "x_oauth_token" | "x_oauth_basic"
    )
}

fn is_short_hex_userinfo_component(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value.len() < 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn userinfo_component_is_env_reference(value: &str) -> bool {
    let value = value.trim();
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        && value
            .split('_')
            .any(|part| matches!(part, "TOKEN" | "PASSWORD" | "PASSWD" | "SECRET" | "KEY"))
}

fn normalized_userinfo_component(value: &str) -> String {
    let mut out = String::new();
    let mut previous_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_sep = false;
        } else if !previous_sep {
            out.push('_');
            previous_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn userinfo_token_like(userinfo: &str) -> bool {
    let userinfo = userinfo.trim();
    let bytes = userinfo.as_bytes();
    if bytes.len() < 12 || bytes.iter().any(u8::is_ascii_whitespace) {
        return false;
    }
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_token_punct = bytes.iter().any(|b| matches!(b, b'_' | b'-' | b'.' | b'~'));
    has_alpha && (has_digit || has_token_punct)
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
            push_span(
                view,
                out,
                base + start + trim_start,
                base + start + trim_end,
                Category::Identifier,
                labels::RESOURCE_ID,
            );
        }
    }
}

fn inspect_query_values(
    view: &NormalizedView,
    base: usize,
    url: &str,
    query_start: usize,
    query_end: usize,
    out: &mut Vec<Span>,
) {
    let mut pos = query_start;
    while pos < query_end {
        while pos < query_end && matches!(url.as_bytes()[pos], b'&' | b';') {
            pos += 1;
        }
        let part_start = pos;
        while pos < query_end && !matches!(url.as_bytes()[pos], b'&' | b';') {
            pos += 1;
        }
        let part = &url[part_start..pos];
        if let Some(eq) = part.find('=') {
            let value_start = part_start + eq + 1;
            let value_end = pos;
            push_span(
                view,
                out,
                base + value_start,
                base + value_end,
                Category::Identifier,
                labels::URL_QUERY_VALUE,
            );
        } else if let Some((trim_start, trim_end)) = resource_id_bounds(part) {
            push_span(
                view,
                out,
                base + part_start + trim_start,
                base + part_start + trim_end,
                Category::Identifier,
                labels::RESOURCE_ID,
            );
        }
    }
}

fn inspect_fragment(
    view: &NormalizedView,
    base: usize,
    url: &str,
    fragment_start: usize,
    fragment_end: usize,
    out: &mut Vec<Span>,
) {
    if fragment_start >= fragment_end {
        return;
    }
    let fragment = &url[fragment_start..fragment_end];
    if fragment.contains('=') {
        inspect_query_values(view, base, url, fragment_start, fragment_end, out);
        return;
    }
    let mut any_resource = false;
    inspect_path_ids(view, base, url, fragment_start, fragment_end, out);
    for segment in fragment.split(['/', '&', ';', '?']) {
        if resource_id_bounds(segment).is_some() {
            any_resource = true;
            break;
        }
    }
    if !any_resource && fragment.len() >= 16 && fragment.bytes().any(|b| b.is_ascii_digit()) {
        push_span(
            view,
            out,
            base + fragment_start,
            base + fragment_end,
            Category::Identifier,
            labels::URL_FRAGMENT,
        );
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
    let id_alphabet = is_id_alphabet(s);
    (has_digit && has_alpha && id_alphabet && s.len() >= 6).then_some((start, end))
}

fn is_id_alphabet(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 3;
            }
            b if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-') => i += 1,
            _ => return false,
        }
    }
    true
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

    #[test]
    fn endpoint_keeps_sentence_punctuation_literal_without_path() {
        assert_eq!(
            labels("http://jira.corp."),
            [("INTERNAL_ENDPOINT".to_string(), "jira.corp".to_string())]
        );
    }

    #[test]
    fn masks_userinfo_port_query_and_fragment_without_losing_route_shape() {
        assert_eq!(
            labels("http://svc:p4ss@local.jira.corp:8080/api/issues/ABC-123?token=s3cr3t&project=OPS#comment-456"),
            [
                ("URL_CREDENTIAL".to_string(), "svc:p4ss".to_string()),
                (
                    "INTERNAL_ENDPOINT".to_string(),
                    "local.jira.corp:8080".to_string()
                ),
                ("RESOURCE_ID".to_string(), "ABC-123".to_string()),
                ("URL_QUERY_VALUE".to_string(), "s3cr3t".to_string()),
                ("URL_QUERY_VALUE".to_string(), "OPS".to_string()),
                ("RESOURCE_ID".to_string(), "comment-456".to_string()),
            ]
        );
    }

    #[test]
    fn non_http_uri_userinfo_masks_credentials_only() {
        let got = labels(
            "ftp://user:p4ss@files.internal/path redis://:p4ssw0rd@localhost/0 nats-route://ruser:rpass2026@127.0.0.1:6222/",
        );
        assert_eq!(
            got,
            [
                ("URL_CREDENTIAL".to_string(), "user:p4ss".to_string()),
                ("URL_CREDENTIAL".to_string(), ":p4ssw0rd".to_string()),
                ("URL_CREDENTIAL".to_string(), "ruser:rpass2026".to_string()),
            ]
        );
    }

    #[test]
    fn generic_uri_userinfo_stays_shape_gated() {
        assert!(labels("s3://bucket/key").is_empty());
        assert!(labels("nats://user:pass@localhost").is_empty());
        assert!(labels("ftp://alice:letmein@example.com/repo.git").is_empty());
    }

    #[test]
    fn username_only_userinfo_is_not_a_url_credential() {
        assert!(!labels("https://alice@example.com/repo.git")
            .iter()
            .any(|(label, _)| label == "URL_CREDENTIAL"));
        assert!(
            labels("https://ghp_abcdefghijklmnopqrstuvwxyz@github.com/repo.git")
                .iter()
                .any(|(label, value)| label == "URL_CREDENTIAL"
                    && value == "ghp_abcdefghijklmnopqrstuvwxyz")
        );
        assert!(labels("https://alice:letmein@example.com/repo.git")
            .iter()
            .all(|(label, _)| label != "URL_CREDENTIAL"));
        assert!(labels("https://alice:letmein@service.internal/repo.git")
            .iter()
            .any(|(label, value)| label == "URL_CREDENTIAL" && value == "alice:letmein"));
    }

    #[test]
    fn uri_template_userinfo_is_not_a_url_credential() {
        for raw in [
            "https://[user[:password]@]service.internal/path",
            "https://***:***@service.internal/path",
            "https://{user}:{password}@service.internal/path",
            "https://git:@github.com/org/repo.git",
            "https://username:password@proxyserver.net:3128/",
            "https://token:MY_GITHUB_TOKEN@github.com/acme/repo.git",
            "https://abcdef1234567890234578:x-oauth-token@github.com/",
        ] {
            assert!(
                labels(raw)
                    .iter()
                    .all(|(label, _)| label != "URL_CREDENTIAL"),
                "{raw}: {:?}",
                labels(raw)
            );
        }
        assert!(labels("https://user:pass@service.internal/path")
            .iter()
            .any(|(label, value)| label == "URL_CREDENTIAL" && value == "user:pass"));
        assert!(labels("https://USERID:APITOKEN@service.internal/path")
            .iter()
            .any(|(label, value)| label == "URL_CREDENTIAL" && value == "USERID:APITOKEN"));
        assert!(labels("https://alice:letmein@service.internal/path")
            .iter()
            .any(|(label, value)| label == "URL_CREDENTIAL" && value == "alice:letmein"));
        assert!(labels("https://user%3Asecret@service.internal/path")
            .iter()
            .any(|(label, value)| label == "URL_CREDENTIAL" && value == "user%3Asecret"));
    }

    #[test]
    fn rfc_documentation_hosts_do_not_emit_url_credentials() {
        for raw in [
            "https://alice:letmein@service.example/repo.git",
            "https://alice:letmein@service.test/repo.git",
            "https://alice:letmein@service.invalid/repo.git",
            "https://alice:letmein@192.0.2.10/repo.git",
            "https://alice:letmein@198.51.100.10/repo.git",
            "https://alice:letmein@203.0.113.10/repo.git",
            "https://alice:letmein@[2001:db8::1]/repo.git",
            "https://alice:letmein@[3fff::1]/repo.git",
        ] {
            assert!(
                labels(raw)
                    .iter()
                    .all(|(label, _)| label != "URL_CREDENTIAL"),
                "{raw}: {:?}",
                labels(raw)
            );
        }
    }

    #[test]
    fn localhost_userinfo_stays_sensitive() {
        assert!(labels("https://alice:letmein@localhost/repo.git")
            .iter()
            .any(|(label, value)| label == "URL_CREDENTIAL" && value == "alice:letmein"));
    }

    #[test]
    fn query_only_internal_url_masks_values() {
        assert_eq!(
            labels("http://jira.corp?issue=1234&debug="),
            [
                ("INTERNAL_ENDPOINT".to_string(), "jira.corp".to_string()),
                ("URL_QUERY_VALUE".to_string(), "1234".to_string()),
            ]
        );
    }

    #[test]
    fn percent_encoded_path_id_is_resource_id() {
        assert_eq!(
            labels("http://jira.corp/api/issues/ABC%2D123"),
            [
                ("INTERNAL_ENDPOINT".to_string(), "jira.corp".to_string()),
                ("RESOURCE_ID".to_string(), "ABC%2D123".to_string()),
            ]
        );
    }

    #[test]
    fn route_words_and_versions_are_not_resource_ids() {
        assert_eq!(
            labels("http://jira.corp/api/v1/issues/list"),
            [("INTERNAL_ENDPOINT".to_string(), "jira.corp".to_string())]
        );
    }

    #[test]
    fn fragment_query_values_are_masked() {
        assert_eq!(
            labels("http://jira.corp/#access_token=abc12345&state=xyz"),
            [
                ("INTERNAL_ENDPOINT".to_string(), "jira.corp".to_string()),
                ("URL_QUERY_VALUE".to_string(), "abc12345".to_string()),
                ("URL_QUERY_VALUE".to_string(), "xyz".to_string()),
            ]
        );
    }
}
