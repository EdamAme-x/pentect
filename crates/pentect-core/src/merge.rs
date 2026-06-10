//! Merger（REF.md §8）: overlap の唯一の所有者。
//! slice 1 = Mask span のみの prov_tier 順 貪欲非重複化（gov_tier/deny-immunity は slice 2）。

use crate::model::*;

/// 入力の Mask 候補 span 群 → 非重複の確定集合。
pub fn merge(mut spans: Vec<Span>, protected: &[ByteRange]) -> Vec<Span> {
    // protected と交差する候補は除去（placeholder は不可侵, REF.md §18.5）。空 span も除去。
    spans.retain(|s| {
        !s.range.is_empty() && !protected.iter().any(|p| p.overlaps(&s.range))
    });

    // prov_tier 順（REF.md §8.2 P3）: confidence desc → 大きい方（containment）→
    // category priority desc → 決定的 tiebreak (source, start, end) asc。
    spans.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.range.len().cmp(&a.range.len()))
            .then(b.category.priority().cmp(&a.category.priority()))
            .then(a.source.cmp(&b.source))
            .then(a.range.start.cmp(&b.range.start))
            .then(a.range.end.cmp(&b.range.end))
    });

    let mut accepted: Vec<Span> = Vec::new();
    for s in spans {
        if accepted.iter().all(|a| !a.range.overlaps(&s.range)) {
            accepted.push(s);
        }
    }
    accepted.sort_by_key(|s| s.range.start);
    accepted
}
