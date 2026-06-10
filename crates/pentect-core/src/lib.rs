//! # pentect-core
//!
//! 機密を含むテキストを、ローカルで可逆なプレースホルダへ「翻訳」するマスキング中核。
//! 設計の一次資料は `sandbox/REF.md`（統合仕様書 v1.0）。
//!
//! パイプライン（REF.md §5）: Input → IR → Detect → Policy.classify → Merge
//! → 同一性 sweep → Render → MaskResult。
//!
//! ## slice 1 のスコープ（正直に）
//! - 経路は **Text のみ**（Json も単一 PlainText region として扱う。構造保存=valid-JSON は
//!   region 抽出が入る slice 2 で）。
//! - 検出器 = `rule`（高信頼ベンダ規則）+ `entropy`（不透明 blob）。
//! - 粒度は whole-value のみ（URL_STRUCTURED / EMAIL_SPLIT は後続）。
//! - 検出は raw region 上で直接（正規化検出ビュー/OffsetMap は後続。identity 正規化 `n_id`
//!   は placeholder/同一性で既に使用）。
//!
//! 保証している不変条件（REF.md §14、`tests/invariants.rs`）: 可逆 / 冪等 / 決定的 /
//! 全域同一性（survivor ゼロ）/ collision ゼロ。

pub mod detect;
pub mod merge;
pub mod model;
pub mod normalize;
pub mod pipeline;
pub mod placeholder;
pub mod policy;
pub mod recovery;
pub mod render;
pub mod sweep;

pub use model::{ByteRange, Category, Confidence, Input, Kind, Span};
pub use pipeline::{mask, mask_ir, Config, MaskResult, Summary};
pub use recovery::{restore, Recovery, RestoreError};

/// UI / audit 用の要約（原値を含まない、REF.md §14-5）。
pub fn explain(result: &MaskResult) -> Summary {
    result.summary.clone()
}
