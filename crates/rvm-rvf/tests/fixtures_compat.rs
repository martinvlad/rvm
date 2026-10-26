//! Compatibility against bytes produced by the RuVector writers (project Ofer
//! P0, ADR-160). The fixtures are checked in; `tests/fixtures/README.md` records
//! exactly how they were generated.

use rvm_rvf::{
    verify, walk, walk_container, RvfError, VerifyOptions, ROOT_PAGE_MAGIC, ROOT_PAGE_SIZE,
};

const FORGE: &[u8] = include_bytes!("fixtures/forge-signed-root-page.rvf");
const FORGE_PUBKEY_HEX: &str = include_str!("fixtures/forge-signed-root-page.pubkey.hex");
const LEGACY: &[u8] = include_bytes!("fixtures/rvstore-legacy.rvf");

fn pubkey() -> [u8; 32] {
    let h = FORGE_PUBKEY_HEX.trim();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn forge_container_walks_and_reports_the_root_page() {
    let w = walk_container(FORGE).expect("forge container must walk");
    let page = w.root_page.expect("root page must be reported");
    assert_eq!(page.len(), ROOT_PAGE_SIZE);
    assert_eq!(page.end, FORGE.len());
    assert_eq!(
        &FORGE[page.start..page.start + 4],
        &ROOT_PAGE_MAGIC.to_le_bytes()
    );
    // One signed WASM segment plus the root MANIFEST segment.
    assert_eq!(w.segments.len(), 2);
    let exec: Vec<_> = w.segments.iter().filter(|s| s.is_executable()).collect();
    assert_eq!(exec.len(), 1);
    assert!(exec[0].is_signed());
    // Every segment ends before the page; the page is not misread as one.
    assert!(w.segments.iter().all(|s| s.payload.end <= page.start));
    assert_eq!(walk(FORGE).unwrap(), w.segments);
}

#[test]
fn forge_container_verifies_with_the_forge_key() {
    let opts = VerifyOptions::with_trusted_keys(vec![pubkey()]);
    let report = verify(FORGE, &opts).expect("well-formed");
    assert!(report.ok, "failures: {:?}", report.failures());
    assert_eq!(report.executables.len(), 1);
    assert_eq!(report.byte_length as usize, FORGE.len());
}

#[test]
fn forge_container_with_unknown_key_fails_verification_not_parsing() {
    let report = verify(FORGE, &VerifyOptions::default()).expect("well-formed");
    assert!(!report.ok);
}

#[test]
fn a_stripped_root_page_walks_identically_and_has_no_page() {
    let stripped = &FORGE[..FORGE.len() - ROOT_PAGE_SIZE];
    let w = walk_container(stripped).unwrap();
    assert!(w.root_page.is_none());
    assert_eq!(w.segments, walk(FORGE).unwrap());
}

#[test]
fn corrupting_the_root_page_magic_makes_it_trailing_garbage() {
    // Without the magic the 4096 bytes are not a recognised page, so they are
    // neither a segment nor zero padding: rejected, never silently ignored.
    let mut bytes = FORGE.to_vec();
    let at = bytes.len() - ROOT_PAGE_SIZE;
    bytes[at] ^= 0xff;
    assert!(walk(&bytes).is_err());
}

/// The CURRENT `rvf-runtime` `RvfStore` writes a legacy dialect: segments are
/// not padded to the 64-byte alignment the shared v1 wire format requires, and
/// they carry no 64-byte-aligned successor header. rvm-rvf deliberately
/// REJECTS it. Converging the dialect is RuVector's job (RuVector ADR-354);
/// this test pins today's behavior so a silent change in either repo is caught.
/// When ADR-354 lands, replace this fixture with the canonical one exported
/// by RuVector and flip the assertion.
#[test]
fn legacy_rvstore_dialect_is_rejected_with_a_clear_error() {
    assert_eq!(
        LEGACY.len() % 64,
        841 % 64,
        "fixture is the unpadded legacy file"
    );
    assert_ne!(LEGACY.len() % 64, 0, "legacy files are not 64-byte aligned");
    // Segment 0 parses, but the writer put segment 1 at the unpadded offset
    // 162 while the v1 reader looks for it at the next 64-byte boundary, 192,
    // and finds no magic there.
    let err = walk(LEGACY).expect_err("legacy dialect must be rejected");
    assert_eq!(err, RvfError::BadMagic);
    // The error renders to a human-readable reason.
    assert!(!format!("{err}").is_empty());
    assert!(verify(LEGACY, &VerifyOptions::default()).is_err());
}
