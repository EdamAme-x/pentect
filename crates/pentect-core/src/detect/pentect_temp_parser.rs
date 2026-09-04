//! Temporary, explicitly scoped compatibility coverage, not a replacement for
//! CredSweeper. Each case needs an issue and regression fixtures. Remove a case
//! once the engine integration passes those fixtures without this detector.
//!
//! Cases currently covered:
//! - #1396: separate-value CLI options for an explicit credential-name set.
//! - #1397: npm/pnpm and git credential-setting command forms.
//! - #1398: lone two-label config assignments for explicit service/key pairs.
//! - #1399: the leading cookie pair in attribute-bearing `Set-Cookie` headers.
//! - #1400: semicolon-delimited connection-string `Password`/`Pwd` fields.
//!
//! These cases do not claim an upstream CredSweeper defect or implement the
//! complete grammar of any of those formats.

use super::{cli, shell, Detector};
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

pub struct PentectTempParser;

impl Detector for PentectTempParser {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let mut out = Vec::new();
        let mut offset = 0;
        for line in view.text().split_inclusive('\n') {
            let content = line.trim_end_matches(['\r', '\n']);
            if cli_compatibility_candidate(content) {
                cli_compatibility(view, content, offset, &mut out);
            }
            if content.contains('.') && content.contains('=') {
                dotted_config_secrets(view, content, offset, &mut out);
            }
            if shell::contains_ascii_ci(content, "set-cookie:") {
                set_cookie_value(view, content, offset, &mut out);
            }
            if line.contains(';') {
                connection_passwords(view, content, offset, &mut out);
            }
            offset += line.len();
        }
        out
    }
}

fn cli_compatibility_candidate(line: &str) -> bool {
    shell::contains_ascii_ci(line, "--pwd")
        || shell::contains_ascii_ci(line, "--pass")
        || shell::contains_ascii_ci(line, "--mnemonic")
        || shell::contains_ascii_ci(line, "--seed-phrase")
        || shell::contains_ascii_ci(line, "--seed_phrase")
        || shell::contains_ascii_ci(line, "--recovery-phrase")
        || shell::contains_ascii_ci(line, "--recovery_phrase")
        || shell::contains_ascii_ci(line, "config")
}

fn cli_compatibility(view: &NormalizedView, line: &str, offset: usize, out: &mut Vec<Span>) {
    let tokens = shell::tokens(line, offset);
    for command in shell::command_slices(&tokens, view.text()) {
        separate_long_options(view, command, out);
        config_set_commands(view, command, out);
    }
}

fn separate_long_options(view: &NormalizedView, tokens: &[shell::Token], out: &mut Vec<Span>) {
    for pair in tokens.windows(2) {
        if pair[0].value == "--" {
            break;
        }
        let Some(name) = pair[0].value.strip_prefix("--") else {
            continue;
        };
        let name = name.to_ascii_lowercase().replace('-', "_");
        if !matches!(
            name.as_str(),
            "pwd" | "pass" | "passphrase" | "mnemonic" | "seed_phrase" | "recovery_phrase"
        ) || pair[1].value.starts_with('-')
        {
            continue;
        }
        push_token_value(view, &pair[1], out);
    }
}

fn config_set_commands(view: &NormalizedView, tokens: &[shell::Token], out: &mut Vec<Span>) {
    let Some((command, rest)) = tokens.split_first() else {
        return;
    };
    let executable = shell::basename(&command.value);
    let assignment = if matches_ignore_ascii_case(executable, &["npm", "pnpm"])
        && rest.len() >= 4
        && rest[0].value.eq_ignore_ascii_case("config")
        && rest[1].value.eq_ignore_ascii_case("set")
    {
        Some((&rest[2], &rest[3]))
    } else if executable.eq_ignore_ascii_case("git")
        && rest.len() >= 3
        && rest[0].value.eq_ignore_ascii_case("config")
    {
        Some((&rest[1], &rest[2]))
    } else {
        None
    };
    let Some((key, value)) = assignment else {
        return;
    };
    if temporary_sensitive_key(&key.value) && !value.value.starts_with('-') {
        push_token_value(view, value, out);
    }
}

fn matches_ignore_ascii_case(value: &str, choices: &[&str]) -> bool {
    choices
        .iter()
        .any(|choice| value.eq_ignore_ascii_case(choice))
}

fn temporary_sensitive_key(value: &str) -> bool {
    let normalized = value
        .trim_start_matches(['-', '_'])
        .to_ascii_lowercase()
        .replace(['-', '.'], "_");
    matches!(
        normalized.as_str(),
        "authtoken"
            | "auth_token"
            | "password"
            | "pwd"
            | "passphrase"
            | "token"
            | "secret"
            | "api_key"
            | "aws_secret_access_key"
    ) || normalized.ends_with("_password")
        || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
}

fn push_token_value(view: &NormalizedView, token: &shell::Token, out: &mut Vec<Span>) {
    if !cli::cli_secret_is_material(&token.value) || token.byte_to_raw.is_empty() {
        return;
    }
    push_span(
        view,
        ByteRange::new(
            token.byte_to_raw[0],
            token.byte_to_raw[token.byte_to_raw.len() - 1] + 1,
        ),
        out,
    );
}

fn dotted_config_secrets(view: &NormalizedView, line: &str, offset: usize, out: &mut Vec<Span>) {
    const SCOPES: &[&str] = &["db", "database", "jdbc", "mail", "redis", "smtp", "stripe"];
    const KEYS: &[&str] = &["password", "passwd", "pwd", "secret", "token", "api_key"];
    let bytes = line.as_bytes();
    let mut cursor = 0;
    while let Some(relative) = line[cursor..].find('=') {
        let equals = cursor + relative;
        cursor = equals + 1;
        let mut key_start = equals;
        while key_start > 0
            && (bytes[key_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[key_start - 1], b'_' | b'.' | b'-'))
        {
            key_start -= 1;
        }
        let key = line[key_start..equals].to_ascii_lowercase();
        let Some((scope, name)) = key.split_once('.') else {
            continue;
        };
        if name.contains('.') || !SCOPES.contains(&scope) || !KEYS.contains(&name) {
            continue;
        }
        if let Some((start, end, quoted)) = assignment_value(line, equals + 1) {
            cursor = cursor.max(end.saturating_add(usize::from(quoted)));
            let value = &line[start..end];
            if !quoted && looks_like_source_reference(value) {
                continue;
            }
            push_candidate(view, line, offset, start, end, out);
        }
    }
}

fn assignment_value(line: &str, mut start: usize) -> Option<(usize, usize, bool)> {
    let bytes = line.as_bytes();
    if matches!(bytes.get(start), Some(b'\'' | b'"')) {
        let quote = bytes[start];
        start += 1;
        let mut cursor = start;
        while cursor < bytes.len() {
            if bytes[cursor] == b'\\' && bytes.get(cursor + 1) == Some(&quote) {
                cursor += 2;
            } else if bytes[cursor] == quote {
                return Some((start, cursor, true));
            } else {
                cursor += 1;
            }
        }
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|byte| byte.is_ascii_whitespace())
        .map_or(bytes.len(), |relative| start + relative);
    Some((start, end, false))
}

fn looks_like_source_reference(value: &str) -> bool {
    value.contains(['(', ')'])
        || (value.contains('.')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
}

fn set_cookie_value(view: &NormalizedView, line: &str, offset: usize, out: &mut Vec<Span>) {
    let trimmed = line.trim_start();
    let Some(header) = trimmed.get(.."set-cookie:".len()) else {
        return;
    };
    if !header.eq_ignore_ascii_case("set-cookie:") {
        return;
    }
    let leading = line.len() - trimmed.len();
    let pair_start = leading + header.len();
    let Some(relative_end) = line[pair_start..].find(';') else {
        return;
    };
    let pair_end = pair_start + relative_end;
    let Some(equals) = line[pair_start..pair_end].find('=') else {
        return;
    };
    let start = pair_start + equals + 1;
    let value = &line[start..pair_end];
    let trim_left = value.len() - value.trim_start().len();
    let end = start + value.trim_end().len();
    let start = start + trim_left;
    if end <= start || end - start > 16 * 1024 {
        return;
    }
    // RFC 6265 allows large opaque cookie values in practice. Keep a generous
    // explicit cap for this line-oriented temporary parser without applying
    // CLI password-word heuristics to cookie bytes.
    if crate::placeholder::parse_placeholder(&line[start..end]).is_err() {
        push_span(view, ByteRange::new(offset + start, offset + end), out);
    }
}

fn push_candidate(
    view: &NormalizedView,
    line: &str,
    offset: usize,
    start: usize,
    end: usize,
    out: &mut Vec<Span>,
) {
    if end <= start || end - start > 4096 {
        return;
    }
    let value = &line[start..end];
    if !cli::cli_secret_is_material(value) {
        return;
    }
    push_span(view, ByteRange::new(offset + start, offset + end), out);
}

fn push_span(view: &NormalizedView, range: ByteRange, out: &mut Vec<Span>) {
    out.push(Span {
        range: view.to_raw(range),
        category: Category::Secret,
        label: labels::KEYED_SECRET.to_string(),
        confidence: Confidence::High,
        source: DetectorId::PentectTempParser,
    });
}

#[derive(Clone, Copy)]
struct Candidate {
    start: usize,
    end: usize,
}

fn connection_passwords(view: &NormalizedView, line: &str, offset: usize, out: &mut Vec<Span>) {
    let bytes = line.as_bytes();
    let mut cursor = 0;
    let mut field_count = 0;
    let mut candidates = Vec::new();

    while cursor < bytes.len() {
        while cursor < bytes.len() && (bytes[cursor] == b';' || bytes[cursor].is_ascii_whitespace())
        {
            cursor += 1;
        }
        let key_start = cursor;
        while cursor < bytes.len() && !matches!(bytes[cursor], b'=' | b';' | b'\n' | b'\r') {
            cursor += 1;
        }
        if cursor == bytes.len() || bytes[cursor] != b'=' {
            if cursor < bytes.len() {
                cursor += 1;
                continue;
            }
            break;
        }

        let key = line[key_start..cursor].trim();
        if key.is_empty() {
            cursor += 1;
            continue;
        }
        field_count += 1;
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }

        let opening = bytes.get(cursor).copied();
        let closing = match opening {
            Some(b'\'' | b'"') => opening,
            Some(b'{') => Some(b'}'),
            _ => None,
        };
        if closing.is_some() {
            cursor += 1;
        }
        let start = cursor;
        let end;

        if let Some(close) = closing {
            let mut value_end = bytes.len();
            while cursor < bytes.len() {
                if bytes[cursor] == close {
                    if bytes.get(cursor + 1) == Some(&close) {
                        cursor += 2;
                    } else {
                        value_end = cursor;
                        cursor += 1;
                        break;
                    }
                } else {
                    cursor += 1;
                }
            }
            end = value_end;
            // Do not reinterpret pseudo-fields after a quoted value before its
            // actual separator.
            while cursor < bytes.len() && !matches!(bytes[cursor], b';' | b'\n' | b'\r') {
                cursor += 1;
            }
        } else {
            while cursor < bytes.len() && !matches!(bytes[cursor], b';' | b'\n' | b'\r') {
                cursor += 1;
            }
            end = start + line[start..cursor].trim_end().len();
        }

        if (key.eq_ignore_ascii_case("password") || key.eq_ignore_ascii_case("pwd"))
            && end > start
            && crate::placeholder::parse_placeholder(&line[start..end]).is_err()
        {
            candidates.push(Candidate { start, end });
        }
    }

    // A connection string has multiple key/value fields. Requiring that shape
    // keeps this temporary parser from becoming a general Password= rule.
    if field_count < 2 {
        return;
    }
    out.extend(candidates.into_iter().map(|candidate| Span {
        range: view.to_raw(ByteRange::new(
            offset + candidate.start,
            offset + candidate.end,
        )),
        category: Category::Secret,
        label: labels::KEYED_SECRET.to_string(),
        confidence: Confidence::High,
        source: DetectorId::PentectTempParser,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(raw: &str) -> Vec<String> {
        let region = super::super::util::region(raw);
        PentectTempParser
            .detect(&NormalizedView::build(&region, raw))
            .iter()
            .map(|span| raw[span.range.start..span.range.end].to_string())
            .collect()
    }

    #[test]
    fn separate_long_credential_options_are_scoped() {
        for raw in [
            "app --pwd hunter2XyzAbc123",
            "app --passphrase '秘密 phrase 123'",
            "wallet --mnemonic recoveryWords123",
            "wallet --seed-phrase seedWords123",
            "wallet --seed_phrase seedWords123",
            "wallet --recovery-phrase recoveryWords123",
            "wallet --recovery_phrase recoveryWords123",
        ] {
            assert_eq!(values(raw).len(), 1, "{raw}");
        }
        for raw in [
            "app --passing hunter2XyzAbc123",
            "app --passphrase $PASSPHRASE",
            "app --mnemonic <phrase>",
            "app --pwd -",
            "app -- --pwd filename",
            "const args = ['--pwd', 'example'];",
        ] {
            assert!(values(raw).is_empty(), "{raw}: {:?}", values(raw));
        }
    }

    #[test]
    fn npm_pnpm_and_git_config_credentials_are_scoped() {
        for raw in [
            "npm config set _authToken npm_syntheticToken123",
            "pnpm config set _password '秘密Password123'",
            "npm\tconfig\tset\t_authToken\ttabSeparatedToken123",
            "git config user.password hunter2XyzAbc123",
        ] {
            assert_eq!(values(raw).len(), 1, "{raw}");
        }
        for raw in [
            "npm config get _authToken",
            "npm config set registry https://registry.example",
            "git config user.name alice",
            "echo npm config set _authToken syntheticToken123",
            "git config user.password $PASSWORD",
        ] {
            assert!(values(raw).is_empty(), "{raw}: {:?}", values(raw));
        }
    }

    #[test]
    fn lone_two_label_config_assignments_are_scoped() {
        for raw in [
            "db.password=hunter2XyzAbc123",
            "Please set mail.password=秘密Password123 before deploying.",
            "application.properties:12:redis.token=syntheticToken123",
            "stripe.secret='syntheticSecret123'",
            r#"db.password='synthetic\'Secret123'"#,
        ] {
            assert_eq!(values(raw).len(), 1, "{raw}");
        }
        for raw in [
            "obj.password=variable",
            "database.password = hunter2XyzAbc123",
            "db.password=$PASSWORD",
            "db.password=other.password",
            "db.password=getPassword()",
            "db.password=<password>",
            "db.host=localhost",
        ] {
            assert!(values(raw).is_empty(), "{raw}: {:?}", values(raw));
        }
    }

    #[test]
    fn set_cookie_masks_only_the_leading_pair_value() {
        for raw in [
            "Set-Cookie: session=abc123XYZdef456ghi789; HttpOnly",
            "set-cookie: sid=秘密Session123; Path=/; Secure; SameSite=Lax",
        ] {
            assert_eq!(values(raw).len(), 1, "{raw}");
        }
        assert!(values("Set-Cookie: session=bareValue123").is_empty());
        assert!(values("Cookie: session=abc123XYZdef456ghi789; other=1").is_empty());
        assert!(
            values(r#"const header = "Set-Cookie: session=abc123XYZdef456ghi789; Secure";"#)
                .is_empty()
        );
        let long_cookie = "x".repeat(512);
        assert_eq!(
            values(&format!("Set-Cookie: session={long_cookie}; HttpOnly")),
            [long_cookie]
        );
    }

    #[test]
    fn compatibility_cases_mask_and_recover_without_attributes() {
        use crate::policy::Profile;
        use crate::{restore, Config, Engine, Input};
        let raw = "app --pwd cliSecret123\nnpm config set _authToken npm_tokenSecret123\ndb.password=dbSecret123\nSet-Cookie: session=cookieSecret123; Path=/; HttpOnly";
        let config = Config::insecure_testing();
        for engine in [
            Engine::with_profile(Profile::Strict),
            Engine::secret_scan_with_profile_and_packs(Profile::Strict, Vec::new()),
        ] {
            let result = engine.mask(Input::text(raw), &config);
            for secret in [
                "cliSecret123",
                "npm_tokenSecret123",
                "dbSecret123",
                "cookieSecret123",
            ] {
                assert!(!result.masked.contains(secret), "{}", result.masked);
            }
            assert!(result.masked.contains("; Path=/; HttpOnly"));
            assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
        }
    }

    #[test]
    fn json_cookie_and_generated_placeholders_remain_structural() {
        use crate::policy::Profile;
        use crate::{Config, Engine, Input, Kind};
        let engine = Engine::with_profile(Profile::Strict);
        let config = Config::insecure_testing();
        let json = r#"{"header":"Set-Cookie: session=cookieSecret123; Path=/; HttpOnly"}"#;
        let result = engine.mask(
            Input {
                kind: Kind::Json,
                data: json.to_string(),
            },
            &config,
        );
        assert!(!result.masked.contains("cookieSecret123"));
        assert!(result.masked.contains("; Path=/; HttpOnly"));

        let first = engine.mask(Input::text("Password=syntheticSecretValue"), &config);
        let handle = first.masked.strip_prefix("Password=").unwrap();
        for raw in [
            format!("app --pwd {handle}"),
            format!("npm config set _authToken {handle}"),
            format!("db.password={handle}"),
            format!("Set-Cookie: session={handle}; HttpOnly"),
        ] {
            assert!(values(&raw).is_empty(), "{raw}");
            assert_eq!(engine.mask(Input::text(&raw), &config).masked, raw);
        }
    }

    #[test]
    fn connection_string_passwords() {
        for raw in [
            "Data Source=x;User ID=u;Password=hunter2XyzAbc123;",
            "Server=x;Initial Catalog=y;Password=hunter2XyzAbc123;Encrypt=True",
            "Data Source=x; PWD = hunter2XyzAbc123 ",
        ] {
            assert_eq!(values(raw), ["hunter2XyzAbc123"]);
        }
    }

    #[test]
    fn delimiters_inside_quoted_and_braced_values() {
        assert_eq!(
            values("Data Source=x;Password='ab;cd''ef';Encrypt=True"),
            ["ab;cd''ef"]
        );
        assert_eq!(values("Data Source=x;Pwd={ab;cd}}ef};"), ["ab;cd}}ef"]);
        assert!(values("Data Source='x;Password=not-a-field';Encrypt=True").is_empty());
    }

    #[test]
    fn backslashes_do_not_escape_connection_string_delimiters() {
        assert_eq!(
            values(r"Data Source=C:\;Password=secret;Encrypt=True"),
            ["secret"]
        );
        assert_eq!(
            values(r#"Data Source=x;Password="secret\";Encrypt=True"#),
            [r"secret\"]
        );
        assert_eq!(
            values(r"Data Source=x;Password={secret\};Encrypt=True"),
            [r"secret\"]
        );
    }

    #[test]
    fn boundaries_placeholders_empty_values_and_recovery() {
        assert_eq!(
            values("説明\nData Source=x;Password=秘密の値;\nPwd=second;Server=y"),
            ["秘密の値", "second"]
        );
        assert!(values("Data Source=x;Password=;User ID=u;").is_empty());
        assert!(values("Password=standalone;").is_empty());
        assert!(values("Data Source=x;PasswordFile=/tmp/config;").is_empty());
        assert_eq!(values("broken;Server=x;Password=secret;"), ["secret"]);
    }

    #[test]
    fn many_malformed_fields_still_reach_a_late_password() {
        let mut raw = "broken;".repeat(10_000);
        raw.push_str("Server=x;Password=secret;");
        assert_eq!(values(&raw), ["secret"]);
    }

    #[test]
    fn standard_and_secret_scan_pipelines_mask_and_recover_connection_password() {
        use crate::policy::Profile;
        use crate::{restore, Config, Engine, Input};
        let raw = "Data Source=x;User ID=u;Password=hunter2XyzAbc123;Encrypt=True";
        let config = Config::insecure_testing();
        for engine in [
            Engine::with_profile(Profile::Strict),
            Engine::secret_scan_with_profile_and_packs(Profile::Strict, Vec::new()),
        ] {
            let result = engine.mask(Input::text(raw), &config);
            assert!(!result.masked.contains("hunter2XyzAbc123"));
            assert!(result.masked.contains("Data Source=x;"));
            assert!(result.masked.ends_with(";Encrypt=True"));
            assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
        }
    }

    #[test]
    fn json_appsettings_connection_string_is_masked_and_recoverable() {
        use crate::policy::Profile;
        use crate::{restore, Config, Engine, Input, Kind};
        let raw = r#"{"ConnectionStrings":{"DefaultConnection":"Server=x;Initial Catalog=y;User ID=u;Password=hunter2XyzAbc123;Encrypt=True"}}"#;
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Json,
                data: raw.to_string(),
            },
            &Config::insecure_testing(),
        );
        assert!(!result.masked.contains("hunter2XyzAbc123"));
        assert!(result
            .masked
            .contains("Server=x;Initial Catalog=y;User ID=u;Password="));
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn generated_placeholder_is_left_opaque() {
        use crate::policy::Profile;
        use crate::{Config, Engine, Input};
        let engine = Engine::with_profile(Profile::Strict);
        let config = Config::insecure_testing();
        let first = engine.mask(Input::text("Password=syntheticSecretValue"), &config);
        let handle = first
            .masked
            .strip_prefix("Password=")
            .expect("fixture should produce one generated placeholder");
        let connection = format!("Server=x;Password={handle};Encrypt=True");
        let second = engine.mask(Input::text(&connection), &config);
        assert_eq!(second.masked, connection);
    }
}
