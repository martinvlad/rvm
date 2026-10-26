//! Differential and adversarial tests for `StreamingModuleValidator` (P11).
//!
//! The reference verdict is `wasmparser::Validator::validate_all` on the full
//! buffer with the same feature set.

mod common;
use common::corpus::{bad_modules, policy_cases, valid_modules, wat};
use proptest::prelude::*;
use rvm_wasm::{
    wasm_features, AllowedImport, ImportPolicy, ModuleError, ModulePolicy,
    StreamingModuleValidator, ValidatedModule,
};

fn reference_ok(bytes: &[u8]) -> bool {
    wasmparser::Validator::new_with_features(wasm_features())
        .validate_all(bytes)
        .is_ok()
}

fn run_chunks(
    policy: &ModulePolicy,
    bytes: &[u8],
    cuts: &[usize],
) -> Result<ValidatedModule, ModuleError> {
    let mut v = StreamingModuleValidator::new(policy.clone());
    let mut last = 0;
    for &c in cuts.iter().chain(std::iter::once(&bytes.len())) {
        let c = c.min(bytes.len());
        if c < last {
            continue;
        }
        v.push(&bytes[last..c])?;
        last = c;
    }
    v.finish()
}

fn one_byte(policy: &ModulePolicy, bytes: &[u8]) -> Result<ValidatedModule, ModuleError> {
    let cuts: Vec<usize> = (1..bytes.len()).collect();
    run_chunks(policy, bytes, &cuts)
}

#[test]
fn corpus_is_what_we_claim() {
    for (name, m) in valid_modules() {
        assert!(reference_ok(&m), "{name} must be valid for wasmparser");
    }
    for (name, m) in bad_modules() {
        assert!(!reference_ok(&m), "{name} must be rejected by wasmparser");
    }
}

fn assert_all_splits_agree(name: &str, bytes: &[u8]) {
    let policy = ModulePolicy::permissive();
    let want = reference_ok(bytes);
    // One shot.
    assert_eq!(
        run_chunks(&policy, bytes, &[]).is_ok(),
        want,
        "{name}: one shot"
    );
    // Exhaustive 1-byte pushes.
    assert_eq!(
        one_byte(&policy, bytes).is_ok(),
        want,
        "{name}: 1-byte pushes"
    );
    // Every two-chunk split.
    for cut in 0..=bytes.len() {
        assert_eq!(
            run_chunks(&policy, bytes, &[cut]).is_ok(),
            want,
            "{name}: split at {cut}"
        );
    }
}

#[test]
fn valid_modules_accepted_under_every_split() {
    for (name, m) in valid_modules() {
        assert_all_splits_agree(name, &m);
        let out = run_chunks(&ModulePolicy::permissive(), &m, &[]).unwrap();
        assert_eq!(out.byte_len(), m.len() as u64, "{name}");
    }
}

#[test]
fn malformed_modules_rejected_under_every_split() {
    for (name, m) in bad_modules() {
        assert_all_splits_agree(name, &m);
    }
}

#[test]
fn validated_module_reports_counts() {
    let m = wat(r#"(module (import "env" "f" (func)) (func (export "a")) (func (export "b")))"#);
    let out = run_chunks(&ModulePolicy::permissive(), &m, &[]).unwrap();
    assert_eq!(out.import_count(), 1);
    assert_eq!(out.export_count(), 2);
    assert_eq!(out.function_count(), 2);
}

// ---------------------------------------------------------------- policy

#[test]
fn policy_violations_are_rejected_under_every_split_and_valid_without_policy() {
    for (name, bytes, policy, want) in policy_cases() {
        assert!(reference_ok(&bytes), "{name}: wasmparser accepts it");
        assert!(
            run_chunks(&ModulePolicy::permissive(), &bytes, &[]).is_ok(),
            "{name}"
        );
        assert_eq!(
            one_byte(&policy, &bytes).unwrap_err(),
            want,
            "{name}: 1-byte"
        );
        assert_eq!(
            run_chunks(&policy, &bytes, &[]).unwrap_err(),
            want,
            "{name}: one shot"
        );
        for cut in 0..=bytes.len() {
            let got = run_chunks(&policy, &bytes, &[cut]).unwrap_err();
            assert_eq!(got, want, "{name}: split at {cut}");
        }
    }
}

#[test]
fn allowed_imports_pass_the_policy() {
    let m = wat(r#"(module (import "env" "ok" (func)) (import "wasi" "x" (func)))"#);
    let policy = ModulePolicy {
        imports: ImportPolicy::Allowlist(vec![
            AllowedImport {
                module: "env".into(),
                name: Some("ok".into()),
            },
            AllowedImport {
                module: "wasi".into(),
                name: None,
            },
        ]),
        ..ModulePolicy::default()
    };
    assert!(one_byte(&policy, &m).is_ok());
}

#[test]
fn imports_are_checked_as_soon_as_the_import_section_completes() {
    let m = wat(r#"(module (import "env" "forbidden" (func)) (func) (func))"#);
    let import_end = {
        // header(8) + type section + import section; find by pushing bytes.
        let mut v = StreamingModuleValidator::new(ModulePolicy::default());
        let mut at = None;
        for (i, b) in m.iter().enumerate() {
            match v.push(std::slice::from_ref(b)) {
                Err(ModuleError::ForbiddenImport { .. }) => {
                    at = Some(i);
                    break;
                }
                Err(e) => panic!("unexpected {e:?}"),
                Ok(_) => {}
            }
        }
        at.expect("forbidden import must be refused before the module ends")
    };
    assert!(
        import_end < m.len() - 4,
        "refused at byte {import_end} of {}",
        m.len()
    );
}

#[test]
fn rejected_module_yields_no_validated_module_and_stays_poisoned() {
    let (_, bad) = bad_modules().remove(12); // an ordering violation
    let mut v = StreamingModuleValidator::new(ModulePolicy::permissive());
    let err = v.push(&bad).unwrap_err();
    // Poisoned: further pushes (even of nothing useful) repeat the error...
    assert_eq!(v.push(&[0]).unwrap_err(), err);
    assert_eq!(v.push(&[]).unwrap_err(), err);
    // ...and finish() cannot produce a ValidatedModule.
    assert_eq!(v.finish().unwrap_err(), err);

    // A policy rejection is final too, even if the rest of the bytes are fine.
    let m = wat("(module (memory 1 1000))");
    let mut v = StreamingModuleValidator::new(ModulePolicy {
        max_memory_pages: 10,
        ..ModulePolicy::default()
    });
    assert!(v.push(&m).is_err());
    assert!(v.finish().is_err());
}

#[test]
fn finish_without_enough_bytes_is_an_error() {
    let m = wat("(module (func))");
    for cut in 0..m.len() {
        let mut v = StreamingModuleValidator::new(ModulePolicy::permissive());
        let _ = v.push(&m[..cut]);
        // The 8-byte header alone is a valid empty module; every other proper
        // prefix of this module is a truncation.
        assert_eq!(
            v.finish().is_ok(),
            reference_ok(&m[..cut]),
            "prefix of {cut} bytes"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_splits_match_the_reference(
        pick in 0usize..1000,
        cuts in prop::collection::vec(any::<u16>(), 0..12),
    ) {
        let mut all = valid_modules();
        all.extend(bad_modules());
        let (name, bytes) = &all[pick % all.len()];
        let mut cuts: Vec<usize> = cuts.iter().map(|c| *c as usize % (bytes.len() + 1)).collect();
        cuts.sort_unstable();
        let got = run_chunks(&ModulePolicy::permissive(), bytes, &cuts);
        prop_assert_eq!(got.is_ok(), reference_ok(bytes), "{} cuts {:?}", name, cuts);
    }

    #[test]
    fn random_byte_flips_match_the_reference(
        pick in 0usize..1000,
        flips in prop::collection::vec((any::<u16>(), any::<u8>()), 1..4),
        cuts in prop::collection::vec(any::<u16>(), 0..6),
    ) {
        let all = valid_modules();
        let (name, orig) = &all[pick % all.len()];
        let mut bytes = orig.clone();
        for (at, val) in &flips {
            let i = *at as usize % bytes.len();
            bytes[i] ^= *val | 1;
        }
        let mut cuts: Vec<usize> = cuts.iter().map(|c| *c as usize % (bytes.len() + 1)).collect();
        cuts.sort_unstable();
        let got = run_chunks(&ModulePolicy::permissive(), &bytes, &cuts);
        prop_assert_eq!(got.is_ok(), reference_ok(&bytes), "{} cuts {:?}", name, cuts);
    }
}
