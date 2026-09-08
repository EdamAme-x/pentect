use std::collections::HashMap;

use pentect_core::{scan_recovery_views, Recovery, RecoveryViewKind};

const VALUE_HANDLE: &str = "<<VALUE_0123456789abcdef>>";
const VALUE_BASE64_HANDLE: &str = "<<VALUE_0123456789abcdef|base64>>";
const AAAA_HANDLE: &str = "<<AAAA_KEY_fedcba9876543210>>";
const AAAA_BASE64_HANDLE: &str = "<<AAAA_KEY_fedcba9876543210|base64>>";

fn collision_recovery() -> Recovery {
    Recovery::seal(
        HashMap::from([
            (VALUE_HANDLE.to_string(), "\0\0\0".to_string()),
            (AAAA_HANDLE.to_string(), "stable-token".to_string()),
        ]),
        &[0x5a; 32],
    )
}

#[test]
fn derived_short_value_does_not_corrupt_a_known_handle() {
    let recovery = collision_recovery();

    // Three NUL bytes encode to "AAAA", which is also part of another known
    // handle's label. Known opaque handles must remain byte-identical.
    assert_eq!(recovery.remask_views(AAAA_HANDLE), AAAA_HANDLE);
    assert_eq!(
        recovery.remask_views(AAAA_BASE64_HANDLE),
        AAAA_BASE64_HANDLE
    );
    assert_eq!(recovery.remask_views(VALUE_HANDLE), VALUE_HANDLE);
    assert_eq!(
        recovery.remask_views(VALUE_BASE64_HANDLE),
        VALUE_BASE64_HANDLE
    );
}

#[test]
fn collision_safe_remasking_is_idempotent_and_still_masks_values() {
    let recovery = collision_recovery();
    let input =
        format!("stable-token AAAA {AAAA_HANDLE} {AAAA_BASE64_HANDLE} {VALUE_BASE64_HANDLE}");
    let expected = format!(
        "{AAAA_HANDLE} {VALUE_BASE64_HANDLE} {AAAA_HANDLE} {AAAA_BASE64_HANDLE} {VALUE_BASE64_HANDLE}"
    );

    let remasked = recovery.remask_views(&input);
    assert_eq!(remasked, expected);
    assert_eq!(recovery.remask_views(&remasked), remasked);
}

#[test]
fn streaming_remasking_matches_batch_at_every_split_point() {
    let recovery = collision_recovery();
    let input = format!("prefix/{AAAA_BASE64_HANDLE}/suffix");
    let expected = input.as_bytes();

    for split in 0..=input.len() {
        let mut remasker = recovery.stream_remasker_with_views();
        let mut output = remasker.push_text(&input.as_bytes()[..split]);
        output.extend(remasker.push_text(&input.as_bytes()[split..]));
        output.extend(remasker.finish());
        assert_eq!(output, expected, "split point {split}");
    }
}

#[test]
fn emitted_pentect_prefixed_handle_supports_raw_and_base64_views() {
    let handle = "<<PENTECT_API_KEY_0011223344556677>>";
    let base64_handle = "<<PENTECT_API_KEY_0011223344556677|base64>>";
    let recovery = Recovery::seal(
        HashMap::from([(handle.to_string(), "synthetic-token".to_string())]),
        &[0x33; 32],
    );

    let scanned = scan_recovery_views(base64_handle).expect("emitted handle must scan");
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0].handle, handle);
    assert_eq!(scanned[0].kind, RecoveryViewKind::Base64);
    assert_eq!(
        recovery.resolve_with_views(handle).unwrap(),
        "synthetic-token"
    );
    assert_eq!(
        recovery.resolve_with_views(base64_handle).unwrap(),
        "c3ludGhldGljLXRva2Vu"
    );
}
