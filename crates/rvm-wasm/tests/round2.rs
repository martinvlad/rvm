//! Round-2 probes for the new ModulePolicy limits (branch feat/ofer-review-rvm).
mod common;
use common::corpus::wat;
use rvm_wasm::{Limit, ModuleError, ModulePolicy, StreamingModuleValidator};

fn verdict(p: &ModulePolicy, m: &[u8], split: usize) -> Result<(), ModuleError> {
    let mut v = StreamingModuleValidator::new(p.clone());
    for c in m.chunks(split.max(1)) {
        v.push(c)?;
    }
    v.finish().map(|_| ())
}

#[test]
fn new_limits_hold_under_every_split() {
    let p = ModulePolicy::default();
    let cases: Vec<(&str, String, Option<Limit>)> = vec![
        ("table at limit", "(module (table 65536 funcref))".into(), None),
        ("table over", "(module (table 65537 funcref))".into(), Some(Limit::TableElements)),
        ("imported table over", "(module (import \"a\" \"t\" (table 70000 funcref)))".into(), Some(Limit::TableElements)),
        ("table w/ max huge but initial small", "(module (table 1 4000000000 funcref))".into(), None),
        ("two tables, second over", "(module (table 1 funcref) (table 99999 funcref))".into(), Some(Limit::TableElements)),
        (
            "globals over",
            format!("(module {})", "(global i32 (i32.const 0))".repeat(10_001)),
            Some(Limit::Globals),
        ),
        (
            "data segs over",
            format!("(module (memory 1 1) {})", "(data (i32.const 0) \"\")".repeat(10_001)),
            Some(Limit::DataSegments),
        ),
        (
            "elem segs over",
            format!("(module (table 1 funcref) {})", "(elem (i32.const 0) func)".repeat(10_001)),
            Some(Limit::ElementSegments),
        ),
    ];
    let mut p2 = p.clone();
    p2.imports = rvm_wasm::ImportPolicy::AllowAll;
    for (name, src, want) in cases {
        let m = wat(&src);
        for split in [1usize, 3, 17, m.len()] {
            let r = verdict(&p2, &m, split);
            match (&want, &r) {
                (None, Ok(())) => {}
                (Some(l), Err(ModuleError::LimitExceeded(g))) if l == g => {}
                _ => panic!("{name} split {split}: {r:?}"),
            }
        }
    }
}

/// Table64 / memory64 are off, so a 64-bit table limit cannot be smuggled.
#[test]
fn table_initial_size_cannot_be_hidden_in_a_leb_overlong_form() {
    let mut m = vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
    // table section: 1 table, funcref, limits flag 0, initial = 70000 as a 5-byte LEB
    m.extend_from_slice(&[4, 9, 1, 0x70, 0, 0xF0, 0xA2, 0x84, 0x80, 0x00]);
    let r = verdict(&ModulePolicy::default(), &m, 1);
    assert!(matches!(r, Err(ModuleError::LimitExceeded(Limit::TableElements)) | Err(ModuleError::Invalid { .. })), "{r:?}");
}
