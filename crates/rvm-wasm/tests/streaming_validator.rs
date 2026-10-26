//! Differential and adversarial tests for `StreamingModuleValidator` (P11).
//!
//! The reference verdict is `wasmparser::Validator::validate_all` on the full
//! buffer with the same feature set.

mod common;
use common::*;
use proptest::prelude::*;
use rvm_wasm::{
    wasm_features, AllowedImport, ImportPolicy, Limit, ModuleError, ModulePolicy,
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

fn wat(s: &str) -> Vec<u8> {
    wat::parse_str(s).expect("valid wat")
}

fn valid_modules() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", wat("(module)")),
        (
            "add",
            wat(r#"(module (func (export "add") (param i32 i32) (result i32)
                 local.get 0 local.get 1 i32.add))"#),
        ),
        (
            "locals_memory_data",
            wat(r#"(module (memory 1 4) (data (i32.const 0) "hello")
                 (func (export "f") (param i32) (result i32) (local i64 f32)
                   local.get 0 i32.load)
                 (func (export "g") (result i32) i32.const 7))"#),
        ),
        (
            "bulk_memory_datacount",
            wat(r#"(module (memory 1 2) (data $d "abcd")
                 (func (export "init") (memory.init $d (i32.const 0) (i32.const 0) (i32.const 4))))"#),
        ),
        (
            "import_and_start",
            wat(r#"(module (import "env" "log" (func $log (param i32)))
                 (func $s i32.const 1 call $log) (start $s))"#),
        ),
        (
            "table_elem_global",
            wat(
                r#"(module (table 2 funcref) (global (mut i32) (i32.const 3))
                 (func $a) (elem (i32.const 0) $a) (export "g" (global 0)))"#,
            ),
        ),
        ("custom_section", {
            let mut m = wat("(module (func))");
            m.extend(section(0, &[1, b'n', 1, 2, 3]));
            m
        }),
        ("synthetic_small", synthetic_module(4096)),
    ]
}

/// Malformed or invalid modules: wasmparser rejects every one of these.
fn bad_modules() -> Vec<(&'static str, Vec<u8>)> {
    let ty = section(1, &vec_of(&[type_i32_i32()]));
    let func1 = section(3, &vec_of(&[vec![0]]));
    let ok_code = section(10, &vec_of(&[body(&[0x20, 0])]));
    let mut v = vec![
        ("empty_input", vec![]),
        ("short_header", vec![0, 0x61, 0x73]),
        ("bad_magic", vec![1, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
        ("bad_version", vec![0, 0x61, 0x73, 0x6d, 2, 0, 0, 0]),
        ("component_header", vec![0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0]),
        ("truncated_section_header", {
            let mut m = HEADER.to_vec();
            m.push(1);
            m
        }),
        ("truncated_section_body", {
            let mut m = HEADER.to_vec();
            m.extend([1, 10, 1, 0x60]);
            m
        }),
        ("leb_too_long", {
            let mut m = HEADER.to_vec();
            m.extend([1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);
            m
        }),
        ("leb_overlong_fifth_byte", {
            let mut m = HEADER.to_vec();
            m.extend([1, 0xff, 0xff, 0xff, 0xff, 0x7f]);
            m
        }),
        ("huge_declared_section", {
            let mut m = HEADER.to_vec();
            m.extend([11, 0xff, 0xff, 0xff, 0xff, 0x0f, 0, 0, 0]);
            m
        }),
        ("unknown_section_id", module(&[section(14, &[0])])),
        (
            "tag_section_without_exceptions",
            module(&[section(13, &[0])]),
        ),
        (
            "order_function_before_type",
            module(&[func1.clone(), ty.clone()]),
        ),
        ("duplicate_type_section", module(&[ty.clone(), ty.clone()])),
        (
            "duplicate_memory_section",
            module(&[
                section(5, &vec_of(&[vec![0, 1]])),
                section(5, &vec_of(&[vec![0, 1]])),
            ]),
        ),
        (
            "function_without_code",
            module(&[ty.clone(), func1.clone()]),
        ),
        (
            "code_without_function",
            module(&[ty.clone(), ok_code.clone()]),
        ),
        (
            "function_code_count_mismatch",
            module(&[
                ty.clone(),
                section(3, &vec_of(&[vec![0], vec![0]])),
                section(10, &vec_of(&[body(&[0x20, 0])])),
            ]),
        ),
        (
            "data_count_mismatch",
            module(&[
                section(5, &vec_of(&[vec![0, 1]])),
                section(12, &leb(2)),
                section(
                    11,
                    &vec_of(&[{
                        let mut d = vec![0u8, 0x41, 0, 0x0b];
                        d.extend(leb(1));
                        d.push(7);
                        d
                    }]),
                ),
            ]),
        ),
        ("data_count_without_data", module(&[section(12, &leb(1))])),
        (
            "invalid_body_stack_underflow",
            module(&[
                ty.clone(),
                func1.clone(),
                section(10, &vec_of(&[body(&[0x6a])])), // i32.add on empty stack
            ]),
        ),
        (
            "invalid_body_unknown_opcode",
            module(&[
                ty.clone(),
                func1.clone(),
                section(10, &vec_of(&[body(&[0xff])])),
            ]),
        ),
        (
            "invalid_body_missing_end",
            module(&[
                ty.clone(),
                func1.clone(),
                section(
                    10,
                    &vec_of(&[{
                        let b = vec![0u8, 0x20, 0x00];
                        let mut o = leb(b.len() as u32);
                        o.extend(b);
                        o
                    }]),
                ),
            ]),
        ),
        (
            "invalid_body_wrong_result",
            module(&[
                ty.clone(),
                func1.clone(),
                section(10, &vec_of(&[body(&[])])), // returns nothing, type wants i32
            ]),
        ),
        (
            "invalid_type_index",
            module(&[
                section(3, &vec_of(&[vec![5]])),
                section(10, &vec_of(&[body(&[])])),
            ]),
        ),
        (
            "memory_min_above_max",
            module(&[section(5, &vec_of(&[vec![1, 5, 2]]))]),
        ),
        (
            "too_many_locals_for_wasmparser",
            module(&[
                ty.clone(),
                func1.clone(),
                section(
                    10,
                    &vec_of(&[{
                        let mut b = leb(1);
                        b.extend(leb(60_000));
                        b.push(0x7f);
                        b.extend([0x20, 0, 0x0b]);
                        let mut o = leb(b.len() as u32);
                        o.extend(b);
                        o
                    }]),
                ),
            ]),
        ),
        ("code_count_huge_short_data", {
            let mut m = HEADER.to_vec();
            m.extend(ty.clone());
            m.extend(func1.clone());
            m.extend([10, 6, 0xff, 0xff, 0xff, 0xff, 0x0f]);
            m
        }),
        ("trailing_garbage", {
            let mut m = wat("(module (func))");
            m.push(0xee);
            m
        }),
    ];
    // Every truncation of a valid module is itself a rejected stream.
    let full = wat(
        r#"(module (memory 1) (func (export "f") (result i32) i32.const 1)
                        (data (i32.const 0) "x"))"#,
    );
    for cut in [9, 12, 20, full.len() - 1] {
        if cut < full.len() {
            v.push(("truncated_valid_module", full[..cut].to_vec()));
        }
    }
    v
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

fn policy_cases() -> Vec<(&'static str, Vec<u8>, ModulePolicy, ModuleError)> {
    let mut cases = Vec::new();
    let base = || ModulePolicy {
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    };

    let imp = wat(r#"(module (import "env" "forbidden" (func)) (import "env" "ok" (func)))"#);
    cases.push((
        "forbidden_import_denyall",
        imp.clone(),
        ModulePolicy {
            imports: ImportPolicy::DenyAll,
            ..base()
        },
        ModuleError::ForbiddenImport { index: 0 },
    ));
    cases.push((
        "forbidden_import_allowlist",
        imp.clone(),
        ModulePolicy {
            imports: ImportPolicy::Allowlist(vec![AllowedImport {
                module: "env".into(),
                name: Some("ok".into()),
            }]),
            ..base()
        },
        ModuleError::ForbiddenImport { index: 0 },
    ));
    cases.push((
        "forbidden_import_predicate",
        imp,
        ModulePolicy {
            imports: ImportPolicy::Predicate(|i| i.name == "forbidden"),
            ..base()
        },
        ModuleError::ForbiddenImport { index: 1 },
    ));

    let body300 = module(&[
        section(1, &vec_of(&[vec![0x60, 0, 0]])),
        section(3, &vec_of(&[vec![0]])),
        section(10, &vec_of(&[body(&vec![0x01; 300])])), // 300 nops
    ]);
    cases.push((
        "oversized_function_body",
        body300,
        ModulePolicy {
            max_function_body_bytes: 64,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::FunctionBodyBytes),
    ));
    cases.push((
        "memory_max_above_policy",
        wat("(module (memory 1 1000))"),
        ModulePolicy {
            max_memory_pages: 100,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::MemoryPages),
    ));
    cases.push((
        "memory_without_max",
        wat("(module (memory 1))"),
        ModulePolicy {
            max_memory_pages: 100,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::MemoryPages),
    ));
    cases.push((
        "imported_memory_max_above_policy",
        wat(r#"(module (import "env" "m" (memory 1 1000)))"#),
        ModulePolicy {
            max_memory_pages: 100,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::MemoryPages),
    ));
    cases.push((
        "too_many_locals_policy",
        wat("(module (func (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))"),
        ModulePolicy {
            max_locals: 8,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::Locals),
    ));
    cases.push((
        "too_many_functions",
        wat("(module (func) (func) (func))"),
        ModulePolicy {
            max_functions: 2,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::Functions),
    ));
    cases.push((
        "too_many_types",
        wat("(module (type (func)) (type (func (param i32))) (type (func (param i64))))"),
        ModulePolicy {
            max_types: 2,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::Types),
    ));
    cases.push((
        "too_many_exports",
        wat(r#"(module (func) (export "a" (func 0)) (export "b" (func 0)))"#),
        ModulePolicy {
            max_exports: 1,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::Exports),
    ));
    cases.push((
        "too_many_imports",
        wat(r#"(module (import "e" "a" (func)) (import "e" "b" (func)))"#),
        ModulePolicy {
            max_imports: 1,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::Imports),
    ));
    let big = synthetic_module(8192);
    cases.push((
        "module_bytes",
        big.clone(),
        ModulePolicy {
            max_module_bytes: 4096,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::ModuleBytes),
    ));
    cases.push((
        "section_bytes",
        big,
        ModulePolicy {
            max_section_bytes: 64,
            ..base()
        },
        ModuleError::LimitExceeded(Limit::SectionBytes),
    ));
    cases
}

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
