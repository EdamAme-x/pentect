use regex::Regex;

/// Spares structured-but-benign values (UUIDs, hash digests, git SHAs) from
/// context-free over-masking. It only ever retracts a candidate, and the engine
/// only applies it to context-free spans, so it can never suppress an anchored
/// secret (a benign-shaped value under a sensitive key is still masked).
pub trait OverMaskGuard {
    fn benign(&self, value: &str) -> bool;
}

pub struct ShapeGuard {
    uuid: Regex,
    hex_digest: Regex,
    git_sha: Regex,
}

impl ShapeGuard {
    pub fn builtin() -> Self {
        let r = |p: &str| Regex::new(p).expect("guard regex compiles");
        Self {
            uuid: r("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
            // md5/sha1/sha256/sha512 digest lengths.
            hex_digest: r("^(?i)[0-9a-f]{32}$|^(?i)[0-9a-f]{40}$|^(?i)[0-9a-f]{64}$|^(?i)[0-9a-f]{128}$"),
            git_sha: r("^[0-9a-f]{7,40}$"),
        }
    }
}

impl OverMaskGuard for ShapeGuard {
    fn benign(&self, value: &str) -> bool {
        self.uuid.is_match(value) || self.hex_digest.is_match(value) || self.git_sha.is_match(value)
    }
}

/// Guard that spares nothing: the `--aggressive` escape hatch.
pub struct NoGuard;

impl OverMaskGuard for NoGuard {
    fn benign(&self, _value: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spares_known_shapes() {
        let g = ShapeGuard::builtin();
        assert!(g.benign("550e8400-e29b-41d4-a716-446655440000")); // uuid
        assert!(g.benign("356a192b7913b04c54574d18c28d46e6395428ab")); // sha1
        assert!(g.benign("5f4dcc3b5aa765d61d8327deb882cf99")); // md5
        assert!(!g.benign("AKIAIOSFODNN7EXAMPLE")); // real secret shape
        assert!(!NoGuard.benign("550e8400-e29b-41d4-a716-446655440000"));
    }
}
