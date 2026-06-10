use pentect_core::{mask, restore, Config, Input, Kind, Recovery};
use proptest::prelude::*;

fn mask_text(s: &str) -> (String, Recovery) {
    let cfg = Config::insecure_testing();
    let r = mask(Input { kind: Kind::Text, data: s.to_string() }, &cfg);
    (r.masked, r.recovery)
}

const CORPUS: &[&str] = &[
    "",
    "hello world no secrets",
    "token: sk-ABCDEFGHIJKLMNOPQRSTUVWX done",
    "aws AKIAIOSFODNN7EXAMPLE here",
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjo0Mn0.abcDEFghiJKLmnoPQRstuVWxyz tail",
    "mail alice@example.com and again alice@example.com",
    "github ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 end",
    "日本語のテキスト no secret",
];

#[test]
fn reversible() {
    for &x in CORPUS {
        let (masked, rec) = mask_text(x);
        let back = restore(&masked, &rec).unwrap();
        assert_eq!(back, x, "reversible failed for {x:?} (masked={masked:?})");
    }
}

#[test]
fn idempotent() {
    let cfg = Config::insecure_testing();
    for &x in CORPUS {
        let r1 = mask(Input { kind: Kind::Text, data: x.to_string() }, &cfg);
        let r2 = mask(Input { kind: Kind::Text, data: r1.masked.clone() }, &cfg);
        assert_eq!(r2.masked, r1.masked, "idempotent failed for {x:?}");
    }
}

#[test]
fn deterministic() {
    for &x in CORPUS {
        let (a, _) = mask_text(x);
        let (b, _) = mask_text(x);
        assert_eq!(a, b, "deterministic failed for {x:?}");
    }
}

// Same value masks to one placeholder, and no plaintext occurrence survives.
#[test]
fn global_identity_no_survivor() {
    let x = "id alice@example.com mid alice@example.com end";
    let (masked, rec) = mask_text(x);
    assert!(!masked.contains("alice@example.com"), "survivor remained: {masked}");
    assert_eq!(rec.map.len(), 1, "same value must map to one placeholder: {masked}");
}

// Distinct values map to distinct placeholders.
#[test]
fn distinct_values_distinct_placeholders() {
    let x = "a AKIAIOSFODNN7EXAMPLE b AKIA0000000000000000 c";
    let (masked, rec) = mask_text(x);
    assert_eq!(rec.map.len(), 2, "two distinct AKIDs -> two placeholders: {masked}");
}

// Bytes outside a masked value are left untouched.
#[test]
fn non_masked_bytes_unchanged() {
    let x = "prefix sk-ABCDEFGHIJKLMNOPQRSTUVWX suffix";
    let (masked, _) = mask_text(x);
    assert!(masked.starts_with("prefix "), "{masked}");
    assert!(masked.ends_with(" suffix"), "{masked}");
}

proptest! {
    // Charset excludes `<` and `>` to avoid injecting placeholder syntax.
    #[test]
    fn prop_reversible(s in "[a-zA-Z0-9 @._:/-]{0,200}") {
        let (masked, rec) = mask_text(&s);
        let back = restore(&masked, &rec).unwrap();
        prop_assert_eq!(back, s);
    }

    #[test]
    fn prop_deterministic(s in "[a-zA-Z0-9 @._:/-]{0,200}") {
        let (a, _) = mask_text(&s);
        let (b, _) = mask_text(&s);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_idempotent(s in "[a-zA-Z0-9 @._:/-]{0,200}") {
        let (m1, _) = mask_text(&s);
        let (m2, _) = mask_text(&m1);
        prop_assert_eq!(m2, m1);
    }
}
