use std::sync::LazyLock;

use regex::Regex;

use super::benign::is_placeholder_value;
use super::documentation::is_documentation_host;
use super::{shell, Detector};
use crate::model::*;
use crate::normalize::NormalizedView;

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>()]*[^\s"'<>().,;:!?]"#).unwrap());
static URI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s"'<>()]*[^\s"'<>().,;:!?]"#).unwrap()
});
static URI_USERINFO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s"'<>()/?#@]+@[^\s"'<>()]*[^\s"'<>().,;:!?]"#)
        .unwrap()
});
static CLOUD_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z0-9][a-z0-9.-]{1,180}\.(?:amazonaws\.com|firebaseio\.com)\b"#).unwrap()
});

/// Preserves useful URL structure for internal systems:
/// `http://local.jira.corp/api/issues/1234`
/// becomes `http://<<INTERNAL_ENDPOINT_...>>/api/issues/<<RESOURCE_ID_...>>`.
pub struct UrlDetector;

impl Detector for UrlDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let mut out = Vec::new();
        inspect_curl_user_credentials(view, &mut out);
        for m in URL_RE.find_iter(view.text()) {
            inspect_url(view, m.start(), m.as_str(), &mut out);
        }
        for m in URI_RE.find_iter(view.text()) {
            if is_http_url(m.as_str()) {
                continue;
            }
            inspect_uri_query(view, m.start(), m.as_str(), &mut out);
        }
        for m in URI_USERINFO_RE.find_iter(view.text()) {
            if is_http_url(m.as_str()) {
                continue;
            }
            inspect_uri_userinfo(view, m.start(), m.as_str(), &mut out);
        }
        for m in CLOUD_HOST_RE.find_iter(view.text()) {
            inspect_cloud_host(view, m.start(), m.as_str(), &mut out);
        }
        out
    }
}

fn is_http_url(url: &str) -> bool {
    let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
}

fn inspect_uri_query(view: &NormalizedView, base: usize, uri: &str, out: &mut Vec<Span>) {
    let Some(scheme_end) = uri.find("://").map(|i| i + 3) else {
        return;
    };
    let authority_end = uri[scheme_end..]
        .find(['/', '?', '#'])
        .map_or(uri.len(), |i| scheme_end + i);
    let query_at = uri[authority_end..].find('?').map(|i| authority_end + i);
    let fragment_at = uri[authority_end..].find('#').map(|i| authority_end + i);
    let Some(q) = query_at.filter(|&q| fragment_at.is_none_or(|f| q < f)) else {
        return;
    };
    let query_end = fragment_at.unwrap_or(uri.len());
    inspect_query_values(view, base, uri, q + 1, query_end, false, out);
}

fn inspect_curl_user_credentials(view: &NormalizedView, out: &mut Vec<Span>) {
    let text = view.text();
    if !text.as_bytes().contains(&b'-') || !shell::contains_ascii_ci(text, "curl") {
        return;
    }

    let mut line_start = 0;
    for line in text.split_inclusive('\n') {
        inspect_curl_line(view, out, line_start, line.trim_end_matches(['\r', '\n']));
        line_start += line.len();
    }
    if !text.ends_with('\n') && line_start < text.len() {
        inspect_curl_line(view, out, line_start, &text[line_start..]);
    }
}

fn inspect_curl_line(view: &NormalizedView, out: &mut Vec<Span>, line_start: usize, line: &str) {
    if !shell::contains_ascii_ci(line, "curl") || !line.contains("-u") {
        return;
    }

    let tokens = shell::tokens(line, line_start);
    let Some(curl_index) = tokens
        .iter()
        .position(|token| shell_token_is_curl(&token.value))
    else {
        return;
    };

    let mut i = curl_index + 1;
    while i < tokens.len() {
        let token = &tokens[i];
        if matches!(token.value.as_str(), "-u" | "--user" | "--proxy-user") {
            if let Some(next) = tokens.get(i + 1) {
                inspect_curl_user_value(view, out, next, 0);
            }
            i += 2;
            continue;
        }
        if let Some(value_start) = token
            .value
            .strip_prefix("--user=")
            .map(|_| "--user=".len())
            .or_else(|| {
                token
                    .value
                    .strip_prefix("--proxy-user=")
                    .map(|_| "--proxy-user=".len())
            })
        {
            inspect_curl_user_value(view, out, token, value_start);
        } else if token.value.starts_with("-u") && token.value.len() > 2 {
            inspect_curl_user_value(view, out, token, 2);
        }
        i += 1;
    }
}

fn shell_token_is_curl(value: &str) -> bool {
    let basename = shell::basename(value);
    basename.eq_ignore_ascii_case("curl")
}

fn inspect_curl_user_value(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    token: &shell::Token,
    value_start: usize,
) {
    if value_start >= token.value.len() || value_start >= token.byte_to_raw.len() {
        return;
    }
    let value = &token.value[value_start..];
    let Some((_user, password)) = split_userinfo_password(value) else {
        return;
    };
    if userinfo_is_template_or_redaction(value) || !generic_uri_password_has_signal(password) {
        return;
    }
    let Some(colon) = value.find(':') else {
        return;
    };
    let mut password_start = value_start + colon + 1;
    let mut password_end = token.value.len();
    while password_start < password_end
        && token.value.as_bytes()[password_start].is_ascii_whitespace()
    {
        password_start += 1;
    }
    while password_end > password_start
        && matches!(
            token.value.as_bytes()[password_end - 1],
            b'.' | b',' | b')' | b']'
        )
    {
        password_end -= 1;
    }
    if password_start >= password_end {
        return;
    }
    push_span(
        view,
        out,
        token.byte_to_raw[password_start],
        token.byte_to_raw[password_end - 1] + 1,
        Category::Secret,
        labels::URL_CREDENTIAL,
    );
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
    inspect_s3_path_style_url(
        view,
        base,
        url,
        authority_end,
        host,
        fragment_or_query_path_end(url, authority_end),
        out,
    );
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
        inspect_query_values(view, base, url, q + 1, query_end, true, out);
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
    let range = view.to_raw(ByteRange::new(start, end));
    if out
        .iter()
        .any(|span| span.range == range && span.category == category && span.label == label)
    {
        return;
    }
    out.push(Span {
        range,
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
    let normalized_user = normalized_userinfo_component(user);
    let normalized_password = normalized_userinfo_component(password);
    password_derives_from_user_placeholder(&normalized_user, &normalized_password)
        || (userinfo_component_is_placeholder_user(user)
            && matches!(normalized_password.as_str(), "password" | "passwd"))
}

fn password_derives_from_user_placeholder(user: &str, password: &str) -> bool {
    if user.len() < 3 || password.len() <= user.len() {
        return false;
    }
    let Some(suffix) = password.strip_prefix(user) else {
        return false;
    };
    matches!(
        suffix.trim_start_matches('_'),
        "pwd" | "password" | "passwd"
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

fn inspect_cloud_host(view: &NormalizedView, host_start: usize, host: &str, out: &mut Vec<Span>) {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return;
    }
    if let Some(bucket_end) = s3_virtual_hosted_bucket_end(host) {
        push_span(
            view,
            out,
            host_start,
            host_start + bucket_end,
            Category::Secret,
            labels::AWS_S3_BUCKET,
        );
        return;
    }
    if let Some(project_end) = firebase_project_end(host) {
        push_span(
            view,
            out,
            host_start,
            host_start + project_end,
            Category::Secret,
            labels::FIREBASE_PROJECT_ID,
        );
    }
}

fn inspect_s3_path_style_url(
    view: &NormalizedView,
    base: usize,
    url: &str,
    authority_end: usize,
    host: &str,
    path_end: usize,
    out: &mut Vec<Span>,
) {
    if !s3_path_style_host(host) || url.as_bytes().get(authority_end) != Some(&b'/') {
        return;
    }
    let bucket_start = authority_end + 1;
    let bucket_end = url[bucket_start..path_end]
        .find('/')
        .map_or(path_end, |i| bucket_start + i);
    if bucket_start >= bucket_end {
        return;
    }
    let bucket = &url[bucket_start..bucket_end];
    if s3_bucket_name_is_valid(bucket) {
        push_span(
            view,
            out,
            base + bucket_start,
            base + bucket_end,
            Category::Secret,
            labels::AWS_S3_BUCKET,
        );
    }
}

fn fragment_or_query_path_end(url: &str, authority_end: usize) -> usize {
    let query_at = url[authority_end..].find('?').map(|i| authority_end + i);
    let fragment_at = url[authority_end..].find('#').map(|i| authority_end + i);
    [query_at, fragment_at]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(url.len())
}

fn s3_virtual_hosted_bucket_end(host: &str) -> Option<usize> {
    let lower = host.to_ascii_lowercase();
    for suffix in [".s3.amazonaws.com", ".s3-accelerate.amazonaws.com"] {
        if lower.ends_with(suffix) {
            let bucket_end = host.len().checked_sub(suffix.len())?;
            return s3_bucket_name_is_valid(&host[..bucket_end]).then_some(bucket_end);
        }
    }
    for marker in [".s3.dualstack.", ".s3.", ".s3-"] {
        let Some(marker_start) = lower.rfind(marker) else {
            continue;
        };
        let region_start = marker_start + marker.len();
        let Some(region) = lower[region_start..].strip_suffix(".amazonaws.com") else {
            continue;
        };
        if aws_region_label_like(region) && s3_bucket_name_is_valid(&host[..marker_start]) {
            return Some(marker_start);
        }
    }
    None
}

fn s3_path_style_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "s3.amazonaws.com" || host == "s3-accelerate.amazonaws.com" {
        return true;
    }
    if let Some(region) = host
        .strip_prefix("s3.")
        .and_then(|rest| rest.strip_suffix(".amazonaws.com"))
    {
        return aws_region_label_like(region);
    }
    if let Some(region) = host
        .strip_prefix("s3-")
        .and_then(|rest| rest.strip_suffix(".amazonaws.com"))
    {
        return aws_region_label_like(region);
    }
    false
}

fn s3_bucket_name_is_valid(bucket: &str) -> bool {
    // S3 general-purpose bucket names are DNS-shaped: 3-63 bytes, lowercase
    // letters/digits/dot/hyphen, starts and ends alphanumeric, no adjacent dot
    // pairs, and not IPv4-shaped. The host suffix supplies service context.
    let bytes = bucket.as_bytes();
    if !(3..=63).contains(&bytes.len()) {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    if bucket.contains("..") || bucket.contains(".-") || bucket.contains("-.") {
        return false;
    }
    if bucket.starts_with("xn--")
        || bucket.starts_with("sthree-")
        || bucket.starts_with("amzn-s3-demo-")
    {
        return false;
    }
    if bucket.ends_with("-s3alias")
        || bucket.ends_with("--ol-s3")
        || bucket.ends_with(".mrap")
        || bucket.ends_with("--x-s3")
        || bucket.ends_with("--table-s3")
    {
        return false;
    }
    if parse_ipv4(bucket).is_some() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

fn aws_region_label_like(region: &str) -> bool {
    let bytes = region.as_bytes();
    (6..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes.iter().any(u8::is_ascii_digit)
        && bytes.contains(&b'-')
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn firebase_project_end(host: &str) -> Option<usize> {
    let suffix = ".firebaseio.com";
    let lower = host.to_ascii_lowercase();
    if !lower.ends_with(suffix) {
        return None;
    }
    let project_end = host.len().checked_sub(suffix.len())?;
    firebase_project_id_is_valid(&host[..project_end]).then_some(project_end)
}

fn firebase_project_id_is_valid(project: &str) -> bool {
    let bytes = project.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
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
    mask_plain_values: bool,
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
            let key = &part[..eq];
            let value = &part[eq + 1..];
            if query_secret_kind(key).is_some_and(|kind| query_secret_value_has_signal(kind, value))
            {
                push_span(
                    view,
                    out,
                    base + value_start,
                    base + value_end,
                    Category::Secret,
                    labels::URL_CREDENTIAL,
                );
            } else if mask_plain_values {
                push_span(
                    view,
                    out,
                    base + value_start,
                    base + value_end,
                    Category::Identifier,
                    labels::URL_QUERY_VALUE,
                );
            }
        } else if mask_plain_values {
            if let Some((trim_start, trim_end)) = resource_id_bounds(part) {
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
        inspect_query_values(view, base, url, fragment_start, fragment_end, true, out);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuerySecretKind {
    Password,
    Token,
    Secret,
}

fn query_secret_kind(key: &str) -> Option<QuerySecretKind> {
    // URI query parameters have no schema, so only credential-bearing field
    // names move into Secret. Route/id fields stay in URL_QUERY_VALUE.
    let key = normalized_query_key(key);
    if key.is_empty() {
        return None;
    }
    let compact = key.replace('_', "");
    if matches!(
        compact.as_str(),
        "password" | "pass" | "passwd" | "pwd" | "passphrase"
    ) || compact.ends_with("password")
        || compact.ends_with("passwd")
        || compact.ends_with("passphrase")
    {
        return Some(QuerySecretKind::Password);
    }
    if matches!(
        compact.as_str(),
        "token" | "accesstoken" | "refreshtoken" | "idtoken" | "authtoken" | "bearertoken"
    ) || compact.ends_with("token")
    {
        return Some(QuerySecretKind::Token);
    }
    if matches!(
        compact.as_str(),
        "secret" | "clientsecret" | "sharedsecret" | "totpsecret" | "apikey"
    ) || compact.ends_with("secret")
        || compact.ends_with("apikey")
    {
        return Some(QuerySecretKind::Secret);
    }
    None
}

fn normalized_query_key(value: &str) -> String {
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

fn query_secret_value_has_signal(kind: QuerySecretKind, value: &str) -> bool {
    // The key supplies context; the value still needs to look material rather
    // than like generated docs (`$Base32String`, `FFF...`) or placeholders.
    let value = value.trim();
    if value.is_empty() || query_value_is_template_or_redaction(value) {
        return false;
    }
    let len = value.len();
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
    let has_token_punct = value
        .bytes()
        .any(|b| matches!(b, b'-' | b'_' | b'.' | b'~' | b'%' | b'='));
    match kind {
        QuerySecretKind::Password => len >= 4,
        QuerySecretKind::Token => {
            len >= 6 && (len >= 16 || (has_alpha && has_digit) || has_token_punct)
        }
        QuerySecretKind::Secret => {
            len >= 6 && (len >= 12 || (has_alpha && has_digit) || has_token_punct)
        }
    }
}

fn query_value_is_template_or_redaction(value: &str) -> bool {
    let value = value.trim();
    value
        .bytes()
        .any(|b| matches!(b, b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b'*'))
        || value.starts_with('$')
        || value.contains("...")
        || is_placeholder_value(value)
        || userinfo_component_is_env_reference(value)
        || matches!(
            normalized_userinfo_component(value).as_str(),
            "password"
                | "passwd"
                | "pass"
                | "pwd"
                | "secret"
                | "token"
                | "api_key"
                | "apikey"
                | "access_token"
                | "refresh_token"
                | "your_password"
                | "your_secret"
                | "your_token"
                | "example_password"
                | "example_secret"
                | "example_token"
        )
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
    fn cloud_resource_hosts_mask_service_identifier_only() {
        assert_eq!(
            labels("download from tenant-7-builds.s3.amazonaws.com/releases/app.zip"),
            [("AWS_S3_BUCKET".to_string(), "tenant-7-builds".to_string())]
        );
        assert_eq!(
            labels("https://media.assets-prod.s3.us-west-2.amazonaws.com/a.zip"),
            [("AWS_S3_BUCKET".to_string(), "media.assets-prod".to_string())]
        );
        assert_eq!(
            labels(r#""firebase_url":"https://tenant-7.firebaseio.com""#),
            [("FIREBASE_PROJECT_ID".to_string(), "tenant-7".to_string())]
        );
    }

    #[test]
    fn s3_path_style_url_masks_bucket_name() {
        assert_eq!(
            labels("https://s3.us-west-2.amazonaws.com/tenant-7-builds/releases/app.zip"),
            [("AWS_S3_BUCKET".to_string(), "tenant-7-builds".to_string())]
        );
    }

    #[test]
    fn cloud_resource_hosts_require_valid_service_names() {
        for raw in [
            "https://s3.amazonaws.com",
            "https://Bad_Name.s3.amazonaws.com",
            "https://192.168.0.1.s3.amazonaws.com",
            "https://tenant..prod.s3.amazonaws.com",
            "https://xn--tenant.s3.amazonaws.com",
            "https://tenant-s3alias.s3.amazonaws.com",
            "https://firebaseio.com",
            "https://abc.firebaseio.com",
            "https://Tenant_7.firebaseio.com",
        ] {
            assert!(
                labels(raw)
                    .iter()
                    .all(|(label, _)| label != "AWS_S3_BUCKET" && label != "FIREBASE_PROJECT_ID"),
                "{raw}: {:?}",
                labels(raw)
            );
        }
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
                ("URL_CREDENTIAL".to_string(), "s3cr3t".to_string()),
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
    fn non_http_uri_query_masks_sensitive_values_only() {
        let got = labels(
            "tcp://127.0.0.1:5381?role=sentinel&password=pjriln \
             redis://:@10.10.10.10/5?username=predis&password=qqcfpe \
             otpauth://totp/Example:alice@google.com?secret=SBVFH5KVSROV2TMO&issuer=Example \
             nats://host?token=OPS",
        );
        assert_eq!(
            got,
            [
                ("URL_CREDENTIAL".to_string(), "pjriln".to_string()),
                ("URL_CREDENTIAL".to_string(), "qqcfpe".to_string()),
                ("URL_CREDENTIAL".to_string(), "SBVFH5KVSROV2TMO".to_string()),
            ]
        );
    }

    #[test]
    fn uri_query_credentials_ignore_templates() {
        for raw in [
            "tcp://127.0.0.1:5381?password={password}",
            "redis://localhost/0?password=PASSWORD",
            "redis://localhost/0?password=ignored",
            "otpauth://totp/Example?secret=***",
            "otpauth://totp/Example?secret=$Base32String",
            "otpauth://hotp/user@example.com?secret=FFF...&counter=123",
            "app://callback?access_token=abc",
            "app://callback?token=112233",
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
    fn curl_user_option_masks_password_only() {
        assert_eq!(
            labels(
                r#"curl -X PUT -u "ff20f250a7b3a414781d1abe11cd8cee:eb895631e87331236180e3ab28c98374" https://api.service.com"#
            ),
            [(
                "URL_CREDENTIAL".to_string(),
                "eb895631e87331236180e3ab28c98374".to_string()
            )]
        );
        assert_eq!(
            labels("curl --user jacknich:b9dd-a5us9t-z@dgy1wd https://api.service.com"),
            [(
                "URL_CREDENTIAL".to_string(),
                "b9dd-a5us9t-z@dgy1wd".to_string()
            )]
        );
        assert_eq!(
            labels(
                r#"C:\Windows\System32\curl.exe -ujacknich:b9dd-a5us9t-z@dgy1wd https://api.service.com"#
            ),
            [(
                "URL_CREDENTIAL".to_string(),
                "b9dd-a5us9t-z@dgy1wd".to_string()
            )]
        );
    }

    #[test]
    fn curl_user_option_ignores_templates() {
        for raw in [
            "curl -u username:password https://api.service.com",
            "curl -u idp_admin:idp_admin_pwd https://api.service.com",
            r#"curl --user "$USER:$PASSWORD" https://api.service.com"#,
            "notcurl -u jacknich:b9dd-a5us9t-z@dgy1wd https://api.service.com",
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
            "https://idp_admin:idp_admin_pwd@service.internal/path",
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
                ("URL_CREDENTIAL".to_string(), "abc12345".to_string()),
                ("URL_QUERY_VALUE".to_string(), "xyz".to_string()),
            ]
        );
    }
}
