//! グローバル同一性スイープ（REF.md §13）: 最適化ではなく **correctness**。
//! 「ある値を1箇所で隠したが別箇所に生で残る」= 部分漏洩を閉じる（不変条件 §14-6）。
//!
//! slice 1 は prong (b)（代表の raw bytes を全域リテラル検索）。prong (a)（各 region の
//! N_id ビュー上のマッチ）は検出ビュー/OffsetMap と共に slice 2。

use crate::model::*;
use crate::normalize::n_id;
use std::collections::BTreeMap;

pub fn identity_sweep(raw: &str, accepted: Vec<Span>, protected: &[ByteRange]) -> Vec<Span> {
    // identity = n_id(value) ごとに代表（最小 offset）を選ぶ。
    let mut rep: BTreeMap<String, Span> = BTreeMap::new();
    for s in &accepted {
        let val = &raw[s.range.start..s.range.end];
        let id = n_id(val);
        rep.entry(id)
            .and_modify(|e| {
                if s.range.start < e.range.start {
                    *e = s.clone();
                }
            })
            .or_insert_with(|| s.clone());
    }

    let mut all = accepted.clone();
    for r in rep.values() {
        let needle = &raw[r.range.start..r.range.end];
        if needle.is_empty() {
            continue;
        }
        let mut from = 0usize;
        while let Some(pos) = raw[from..].find(needle) {
            let abs = from + pos;
            let range = ByteRange::new(abs, abs + needle.len());
            from = abs + needle.len();
            let clash = all.iter().any(|a| a.range.overlaps(&range))
                || protected.iter().any(|p| p.overlaps(&range));
            if !clash {
                all.push(Span {
                    range,
                    category: r.category,
                    label: r.label.clone(),
                    confidence: r.confidence,
                    source: "sweep".to_string(),
                });
            }
        }
    }

    all.sort_by_key(|s| s.range.start);
    all
}
