use super::Detector;
use crate::model::{ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;
use data_encoding::{BASE64URL, BASE64URL_NOPAD};
use regex::Regex;
use std::sync::LazyLock;

#[derive(Default)]
pub struct JwtDetector;

static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[^A-Za-z0-9_.-])(eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)(?:$|[^A-Za-z0-9_.-])",
    )
    .expect("JWT regex compiles")
});

impl Detector for JwtDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        JWT.captures_iter(view.text())
            .filter_map(|captures| {
                let candidate = captures.get(1)?;
                valid_compact_jwt(candidate.as_str()).then(|| Span {
                    range: view.to_raw(ByteRange::new(candidate.start(), candidate.end())),
                    category: Category::Secret,
                    label: "JSON_WEB_TOKEN".to_string(),
                    confidence: Confidence::High,
                    source: DetectorId::Rule,
                })
            })
            .collect()
    }
}

fn valid_compact_jwt(value: &str) -> bool {
    const MAX_COMPACT_JWT_BYTES: usize = 24_003;
    if value.len() > MAX_COMPACT_JWT_BYTES {
        return false;
    }
    let mut parts = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(header) = decode_json_object(header) else {
        return false;
    };
    if !header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|algorithm| !algorithm.is_empty())
    {
        return false;
    }
    if decode_json_object(payload).is_none() {
        return false;
    }
    signature.is_empty() || decode_base64url(signature).is_some_and(|bytes| !bytes.is_empty())
}

fn decode_json_object(value: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    serde_json::from_slice::<serde_json::Value>(&decode_base64url(value)?)
        .ok()?
        .as_object()
        .cloned()
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .or_else(|_| BASE64URL.decode(value.as_bytes()))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn detect(text: &str) -> Vec<Span> {
        let region = region(text);
        JwtDetector.detect(&NormalizedView::build(&region, text))
    }

    #[test]
    fn detects_jwt_with_only_application_defined_claims() {
        let token = concat!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJ1c2VyIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwiYWRtaW4iOnRydWV9.",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        let spans = detect(token);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].range, ByteRange::new(0, token.len()));
        assert_eq!(spans[0].label, "JSON_WEB_TOKEN");
    }

    #[test]
    fn rejects_lookalikes_and_five_part_jwe() {
        for value in [
            "eyJungle.abcdefghijklmnop.abcdefghijklmnop",
            "eyJhbGciOiJIUzI1NiJ9.not-json.abcdefghijklmnop",
            "eyJhbGciOiJIUzI1NiJ9.e30.one.two.three",
            "aaa.bbb.ccc",
        ] {
            assert!(detect(value).is_empty(), "{value}");
        }
    }
}
