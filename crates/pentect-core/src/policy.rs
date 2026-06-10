use crate::model::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Granularity {
    Full,
    HashOnly,
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
    /// Default policy: mask every candidate. Per-span and order-independent.
    pub fn classify(&self, _span: &Span) -> Action {
        Action::Mask(None)
    }
}
