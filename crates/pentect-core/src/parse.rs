use crate::json;
use crate::model::*;

/// Turns raw input into value regions. Injected per `Kind`; the engine falls
/// back to whole-input plaintext when no parser matches or one returns None.
pub trait Parser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>>;
}

pub struct TextParser;

impl Parser for TextParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        Some(vec![Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: None,
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        }])
    }
}

pub struct JsonParser;

impl Parser for JsonParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        json::parse_json_regions(raw)
    }
}
