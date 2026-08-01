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

    pub(super) fn contains(&self, range: &ByteRange) -> bool {
        if range.is_empty() {
            return false;
        }
        let idx = self.ranges.partition_point(|r| r.start <= range.start);
        idx > 0 && self.ranges[idx - 1].contains(range)
    }

    pub(super) fn insert(&mut self, range: ByteRange) {
        if range.is_empty() {
            return;
        }
        let idx = self.ranges.partition_point(|r| r.start < range.start);
        self.ranges.insert(idx, range);
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
    fn contains_requires_full_containment() {
        let idx = RangeIndex::new(vec![ByteRange::new(2, 5), ByteRange::new(8, 12)]);
        assert!(idx.contains(&ByteRange::new(3, 5)));
        assert!(idx.contains(&ByteRange::new(8, 12)));
        assert!(!idx.contains(&ByteRange::new(1, 3)));
        assert!(!idx.contains(&ByteRange::new(4, 9)));
        assert!(!idx.contains(&ByteRange::new(12, 12)));
    }
}
