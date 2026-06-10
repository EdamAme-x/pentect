//! 中核データモデル（REF.md §4）。slice 1 は契約を最小実装。

use serde::{Deserialize, Serialize};

/// 型ラベル（将来 SmolStr）。`^[A-Z][A-Z0-9_]*$` を想定（render が保証）。
pub type Label = String;

/// raw 内の byte 範囲（char 境界整列）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
    /// 半開区間の重なり判定。
    pub fn overlaps(&self, o: &ByteRange) -> bool {
        self.start < o.end && o.start < self.end
    }
    pub fn contains(&self, o: &ByteRange) -> bool {
        self.start <= o.start && o.end <= self.end
    }
}

/// provenance タグ（REF.md §4.1）。slice 1 の builtin parser は Text/Json のみ。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Text,
    Json,
    Har,
    Curl,
    Markdown,
    Other(String),
}

#[derive(Clone, Debug)]
pub struct Input {
    pub kind: Kind,
    pub data: String,
}

impl Input {
    pub fn text(s: impl Into<String>) -> Self {
        Self { kind: Kind::Text, data: s.into() }
    }
}

/// 4 軸 + catch-all（REF.md §4.3, §17.1）。細かい型は `Span.label` に押し込む。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Secret,
    Identifier,
    Endpoint,
    Pii,
    Other,
}

impl Category {
    /// Merge 優先度（REF.md §8.2 P3.3）: Secret > Pii > Identifier > Endpoint > Other。
    pub fn priority(self) -> u8 {
        match self {
            Category::Secret => 4,
            Category::Pii => 3,
            Category::Identifier => 2,
            Category::Endpoint => 1,
            Category::Other => 0,
        }
    }
}

/// 宣言順で Low < Medium < High（Ord 派生）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    PlainText,
    JsonValue,
    Header,
    Cookie,
    Url,
    Body,
}

/// 検出・Policy が読む read-only 文脈（REF.md §4.2）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Context {
    pub path: Option<String>,
    pub key: Option<String>,
    pub kind: RegionKind,
    pub format: Kind,
}

/// 「値（content）」の範囲 + 文脈。構造文字は含まない。
#[derive(Clone, Debug)]
pub struct Region {
    pub span: ByteRange,
    pub ctx: Context,
}

/// IR = raw + regions + protected（REF.md §4.2）。
#[derive(Clone, Debug)]
pub struct Ir {
    pub raw: String,
    pub regions: Vec<Region>,
    /// 既存 placeholder の不可侵範囲（冪等性、REF.md §18.5）。
    pub protected: Vec<ByteRange>,
}

/// Detector の出力単位（REF.md §4.2）。range は常に raw の絶対 byte 範囲。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Span {
    pub range: ByteRange,
    pub category: Category,
    pub label: Label,
    pub confidence: Confidence,
    pub source: String,
}
