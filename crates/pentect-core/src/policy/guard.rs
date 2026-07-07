/// Spares structured-but-benign values (UUIDs, hash digests, git SHAs) from
/// context-free over-masking. It only ever retracts a candidate, and the engine
/// only applies it to context-free spans, so it can never suppress an anchored
/// secret (a benign-shaped value under a sensitive key is still masked).
pub trait OverMaskGuard: Send + Sync {
    fn benign(&self, value: &str) -> bool;
}

pub struct ShapeGuard;

impl ShapeGuard {
    pub fn builtin() -> Self {
        Self
    }
}

impl OverMaskGuard for ShapeGuard {
    fn benign(&self, value: &str) -> bool {
        is_uuid(value) || is_hex_digest(value) || is_git_sha(value) || is_local_path(value)
    }
}

fn is_uuid(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}

fn is_hex_digest(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64 | 128) && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn is_git_sha(value: &str) -> bool {
    (7..=40).contains(&value.len())
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn is_local_path(value: &str) -> bool {
    let b = value.as_bytes();
    if b.iter().any(|&c| matches!(c, b'\r' | b'\n')) {
        return false;
    }
    if b.len() >= 4 && b[0].is_ascii_alphabetic() && b[1] == b':' && is_sep(b[2]) {
        return true;
    }
    if b.starts_with(b"~") {
        return has_tilde_home_prefix(b);
    }
    if !b.starts_with(b"/") {
        return false;
    }
    path_prefix_rest(b, &[b"home", b"users", b"var/home", b"export/home"])
        .is_some_and(|rest| !rest.is_empty())
        || mnt_drive_prefix_rest(b).is_some_and(|rest| !rest.is_empty())
        || slash_drive_users_prefix_rest(b).is_some_and(|rest| !rest.is_empty())
}

fn has_tilde_home_prefix(b: &[u8]) -> bool {
    if b.len() < 4 || b[0] != b'~' {
        return false;
    }
    let Some(sep) = b[1..].iter().position(|&c| c == b'/') else {
        return false;
    };
    let name = &b[1..1 + sep];
    !name.is_empty()
        && !name.iter().any(|&c| {
            matches!(c, b'/' | b'\\' | b'\r' | b'\n' | b'"' | b'\'') || c.is_ascii_whitespace()
        })
        && b.get(1 + sep + 1).is_some()
}

fn path_prefix_rest<'a>(b: &'a [u8], prefixes: &[&[u8]]) -> Option<&'a [u8]> {
    for prefix in prefixes {
        if b.len() > prefix.len() + 2
            && b[0] == b'/'
            && eq_ascii_ci(&b[1..1 + prefix.len()], prefix)
        {
            let sep = 1 + prefix.len();
            if b[sep] == b'/' {
                return Some(&b[sep + 1..]);
            }
        }
    }
    None
}

fn mnt_drive_prefix_rest(b: &[u8]) -> Option<&[u8]> {
    if b.len() > 7 && eq_ascii_ci(&b[..5], b"/mnt/") && b[5].is_ascii_alphabetic() && b[6] == b'/' {
        return Some(&b[7..]);
    }
    None
}

fn slash_drive_users_prefix_rest(b: &[u8]) -> Option<&[u8]> {
    if b.len() > 9
        && b[0] == b'/'
        && b[1].is_ascii_alphabetic()
        && b[2] == b'/'
        && eq_ascii_ci(&b[3..8], b"users")
        && b[8] == b'/'
    {
        return Some(&b[9..]);
    }
    None
}

fn is_sep(b: u8) -> bool {
    matches!(b, b'/' | b'\\')
}

fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

/// Guard that spares nothing: the `--aggressive` escape hatch. Internal — callers
/// select it via `Engine::with_profile_unguarded`, not by naming the type.
pub(crate) struct NoGuard;

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
        assert!(g.benign(r"C:\Users\Public\Downloads\file.txt")); // local path
        assert!(g.benign("/Users/Shared/cache/file.txt")); // local path
        assert!(g.benign("/var/home/alice/.config/app.toml")); // local path
        assert!(g.benign("~alice/src/main.rs")); // local path
        assert!(!g.benign("AKIAIOSFODNN7EXAMPLE")); // real secret shape
        assert!(!NoGuard.benign("550e8400-e29b-41d4-a716-446655440000"));
    }
}
