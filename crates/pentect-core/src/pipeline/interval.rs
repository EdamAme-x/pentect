use crate::model::ByteRange;

/// Small interval index for non-overlapping ranges sorted by start.
#[derive(Clone, Debug, Default)]
pub(super) struct RangeIndex {
    ranges: Vec<ByteRange>,
}

impl RangeIndex {
    pub(super) fn new(mut ranges: Vec<ByteRange>) -> Self {
        ranges.retain(|r| !r.is_empty());
        ranges.sort_by_key(|r| (r.start, r.end));
        Self { ranges }
    }

    pub(super) fn overlaps(&self, range: &ByteRange) -> bool {
        if range.is_empty() {
            return false;
        }
        let idx = self.ranges.partition_point(|r| r.start < range.end);
        idx > 0 && self.ranges[idx - 1].overlaps(range)
    }

    pub(super) fn insert(&mut self, range: ByteRange) {
        if range.is_empty() {
            return;
        }
        let idx = self.ranges.partition_point(|r| r.start < range.start);
        self.ranges.insert(idx, range);
    }

    pub(super) fn overlapping(&self, range: &ByteRange) -> Vec<ByteRange> {
        if range.is_empty() {
            return Vec::new();
        }
        let mut idx = self.ranges.partition_point(|r| r.end <= range.start);
        let mut out = Vec::new();
        while let Some(r) = self.ranges.get(idx) {
            if r.start >= range.end {
                break;
            }
            if r.overlaps(range) {
                out.push(*r);
            }
            idx += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_real_overlaps() {
        let idx = RangeIndex::new(vec![ByteRange::new(2, 5), ByteRange::new(8, 10)]);
        assert!(idx.overlaps(&ByteRange::new(4, 6)));
        assert!(!idx.overlaps(&ByteRange::new(5, 8)));
        assert!(idx.overlaps(&ByteRange::new(9, 12)));
    }

    #[test]
    fn overlapping_returns_sorted_intersections() {
        let idx = RangeIndex::new(vec![
            ByteRange::new(0, 2),
            ByteRange::new(4, 6),
            ByteRange::new(8, 10),
        ]);
        assert_eq!(
            idx.overlapping(&ByteRange::new(1, 9)),
            vec![
                ByteRange::new(0, 2),
                ByteRange::new(4, 6),
                ByteRange::new(8, 10)
            ]
        );
    }
}
