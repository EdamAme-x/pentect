//! パイプライン編成（REF.md §5）と公開 API（境界 A, §15）。

use crate::detect::DetectorSet;
use crate::merge::merge;
use crate::model::*;
use crate::policy::{Action, Policy};
use crate::recovery::Recovery;
use crate::render::render;
use crate::sweep::identity_sweep;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// マスク設定（REF.md §15.1）。`key` は同一性ハッシュの HMAC 鍵（§11.2）。
/// 鍵生成・keyfile I/O は adapter 責務（core は明示フィールドで受けるだけ）。
#[derive(Clone, Debug)]
pub struct Config {
    pub key: [u8; 32],
    pub locale: String,
}

impl Config {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, locale: "en".into() }
    }
    /// テスト/デモ用の固定鍵。**本番不可**（adapter が CSPRNG 鍵を供給, REF.md §11.2）。
    pub fn insecure_testing() -> Self {
        Self::new([7u8; 32])
    }
}

/// 原値を含まない要約（REF.md §14-5）。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub masked_count: usize,
}

/// `recovery` は local-only。`MaskResult` 自体は serde 派生しない（§14-5）。
pub struct MaskResult {
    pub masked: String,
    pub recovery: Recovery,
    pub spans: Vec<Span>,
    pub summary: Summary,
}

pub fn mask(input: Input, config: &Config) -> MaskResult {
    let ir = parse(input);
    mask_ir(ir, config)
}

/// core primitive（REF.md §15.1, §17.5）。adapter は同じ IR を作って渡せる。
pub fn mask_ir(ir: Ir, config: &Config) -> MaskResult {
    let detectors = DetectorSet::builtin();
    let policy = Policy::default();

    // Detect
    let mut spans = Vec::new();
    for region in &ir.regions {
        spans.extend(detectors.run(region, &ir.raw));
    }

    // Policy.classify（slice 1 は Mask のみ残す）
    spans.retain(|s| matches!(policy.classify(s), Action::Mask(_)));

    // Merge → 同一性 sweep → Render
    let merged = merge(spans, &ir.protected);
    let swept = identity_sweep(&ir.raw, merged, &ir.protected);
    let rendered = render(&ir.raw, &config.key, swept.clone());

    let summary = Summary { masked_count: rendered.map.len() };
    MaskResult {
        masked: rendered.masked,
        recovery: Recovery { map: rendered.map },
        spans: swept,
        summary,
    }
}

/// slice 1 parser: Text/Json を単一 PlainText region に。既存 placeholder を protected に。
fn parse(input: Input) -> Ir {
    let raw = input.data;
    let protected = scan_placeholders(&raw);
    let ctx = Context {
        path: None,
        key: None,
        kind: RegionKind::PlainText,
        format: input.kind,
    };
    let regions = vec![Region {
        span: ByteRange::new(0, raw.len()),
        ctx,
    }];
    Ir { raw, regions, protected }
}

/// render が出す厳密形 `<<LABEL_hhhhhhhhhhhhhhhh>>`（16 lowercase hex）を冪等性のため凍結。
fn scan_placeholders(raw: &str) -> Vec<ByteRange> {
    let re = Regex::new(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}>>").expect("placeholder regex compiles");
    re.find_iter(raw)
        .map(|m| ByteRange::new(m.start(), m.end()))
        .collect()
}
