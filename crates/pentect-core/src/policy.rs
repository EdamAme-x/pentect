//! Policy（REF.md §9）。slice 1 は既定の per-span 分類のみ（deny/allow/when は slice 2+）。

use crate::model::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Granularity {
    Full,
    HashOnly,
    // URL_STRUCTURED / EMAIL_SPLIT は slice 2。
}

#[derive(Clone, Debug)]
pub enum Action {
    Mask(Option<Granularity>),
    Keep,
    Warn,
    Drop,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {}

impl Policy {
    /// REF.md §17.2 core 既定 = Mask（strict; 迷ったら隠す）。
    /// per-span・他 span を見ない（順序非依存, REF.md §9.1）。
    pub fn classify(&self, _span: &Span) -> Action {
        Action::Mask(None)
    }
}
