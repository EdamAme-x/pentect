use crate::model::Span;

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

/// Decides what to do with each detected span. Injected into the engine.
/// Per-span and order-independent: it never looks at other spans.
pub trait Policy {
    fn classify(&self, span: &Span) -> Action;
}

/// Default policy: mask every candidate (strict).
pub struct MaskAll;

impl Policy for MaskAll {
    fn classify(&self, _span: &Span) -> Action {
        Action::Mask(None)
    }
}
