//! Temporary, explicitly scoped compatibility coverage, not a replacement for
//! CredSweeper. Each case needs an issue and regression fixtures. Remove a case
//! once the engine integration passes those fixtures without this detector.
//!
//! #1400: semicolon-delimited connection-string `Password`/`Pwd` fields. This
//! does not claim an upstream CredSweeper defect or implement the entire DB
//! connection-string grammar.

use super::Detector;
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

pub struct PentectTempParser;

impl Detector for PentectTempParser {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let mut out = Vec::new();
        let mut offset = 0;
        for line in view.text().split_inclusive('\n') {
            if line.contains(';') {
                connection_passwords(view, line, offset, &mut out);
            }
            offset += line.len();
        }
        out
    }
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
