//! Adversarial-review repros (branch feat/ofer-review-rvm). Ids match
//! review-rvm-report.md.

mod common;
use common::corpus::{bad_modules, valid_modules, wat};
use rvm_wasm::{
    validate_module, wasm_features, ModuleError, ModulePolicy, StreamingModuleValidator,
};

fn reference_ok(bytes: &[u8]) -> bool {
    wasmparser::Validator::new_with_features(wasm_features())
        .validate_all(bytes)
        .is_ok()
}

fn stream_ok(policy: &ModulePolicy, bytes: &[u8], cuts: &[usize]) -> bool {
    let mut v = StreamingModuleValidator::new(policy.clone());
    let mut last = 0;
    for &c in cuts.iter().chain(std::iter::once(&bytes.len())) {
        let c = c.min(bytes.len());
        if c < last {
            continue;
        }
        if v.push(&bytes[last..c]).is_err() {
            return false;
        }
        last = c;
    }
    v.finish().is_ok()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// RW-01: the default policy bounds table size, globals, data segments and
/// element segments, as it already bounded memory pages.
#[test]
fn rw01_default_policy_bounds_tables_globals_data_and_elements() {
    let huge_table = wat("(module (table 10000000 funcref))");
    assert!(huge_table.len() < 40);
    assert!(!stream_ok(&ModulePolicy::default(), &huge_table, &[]));
    assert!(stream_ok(&ModulePolicy::permissive(), &huge_table, &[]));
    let imported = wat("(module (import \"env\" \"t\" (table 10000000 funcref)))");
    let allow = ModulePolicy {
        imports: rvm_wasm::ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    };
    assert!(!stream_ok(&allow, &imported, &[]));
    // A modest table still passes.
    assert!(stream_ok(
        &ModulePolicy::default(),
        &wat("(module (table 64 funcref))"),
        &[]
    ));

    let p = |f: fn(&mut ModulePolicy)| {
        let mut p = ModulePolicy::default();
        f(&mut p);
        p
    };
    let globals = wat(
        "(module (global i32 (i32.const 1)) (global i32 (i32.const 2)) (global i32 (i32.const 3)))",
    );
    assert!(stream_ok(&p(|p| p.max_globals = 3), &globals, &[]));
    assert!(!stream_ok(&p(|p| p.max_globals = 2), &globals, &[]));
    let data = wat("(module (memory 1 2) (data (i32.const 0) \"a\") (data (i32.const 8) \"b\"))");
    assert!(stream_ok(&p(|p| p.max_data_segments = 2), &data, &[]));
    assert!(!stream_ok(&p(|p| p.max_data_segments = 1), &data, &[]));
    let elems =
        wat("(module (table 4 funcref) (func $f) (elem (i32.const 0) $f) (elem (i32.const 1) $f))");
    assert!(stream_ok(&p(|p| p.max_element_segments = 2), &elems, &[]));
    assert!(!stream_ok(&p(|p| p.max_element_segments = 1), &elems, &[]));
    // The verdict does not depend on how the bytes are split.
    for m in [&huge_table, &globals, &data, &elems] {
        let cuts: Vec<usize> = (1..m.len()).collect();
        assert_eq!(
            stream_ok(&ModulePolicy::default(), m, &cuts),
            stream_ok(&ModulePolicy::default(), m, &[])
        );
    }
}

/// RW-02: documented mismatch - the cheap framing check accepts a tag section
/// (and a module the real validator refuses). Only the buffered path relies on
/// the framing check alone.
#[test]
fn rw02_framing_accepts_what_the_validator_refuses() {
    let mut m = vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
    m.extend_from_slice(&[13, 1, 0]); // tag section, count 0
    assert!(validate_module(&m).is_ok());
    let mut v = StreamingModuleValidator::new(ModulePolicy::permissive());
    let r = v.push(&m).and_then(|_| v.finish());
    assert!(matches!(r, Err(ModuleError::Invalid { .. })), "{r:?}");
}

/// Probe: mutation fuzz of the corpus, random chunk splits, permissive policy.
/// The streaming verdict must equal wasmparser's whole-buffer verdict.
#[test]
fn probe_mutated_modules_agree_with_wasmparser_under_hostile_splits() {
    let mut seeds: Vec<Vec<u8>> = valid_modules().into_iter().map(|(_, m)| m).collect();
    seeds.extend(bad_modules().into_iter().map(|(_, m)| m));
    let mut rng = Rng(0x00C0_FFEE_1234_5678);
    let policy = ModulePolicy::permissive();
    let mut accepted = 0u32;
    let mut disagreements: Vec<Vec<u8>> = Vec::new();
    for iter in 0..60_000u32 {
        let mut m = seeds[rng.below(seeds.len())].clone();
        for _ in 0..1 + rng.below(4) {
            match rng.below(7) {
                0 if !m.is_empty() => {
                    let i = rng.below(m.len());
                    m[i] ^= 1 << rng.below(8);
                }
                1 if !m.is_empty() => {
                    let i = rng.below(m.len());
                    m[i] = rng.next() as u8;
                }
                2 => {
                    let l = m.len();
                    m.truncate(rng.below(l + 1));
                }
                3 => {
                    let at = rng.below(m.len() + 1);
                    let extra: Vec<u8> = (0..rng.below(8)).map(|_| rng.next() as u8).collect();
                    m.splice(at..at, extra);
                }
                4 => {
                    // append another section / second module / garbage
                    let pick = seeds[rng.below(seeds.len())].clone();
                    if rng.below(2) == 0 {
                        m.extend_from_slice(&pick[8.min(pick.len())..]);
                    } else {
                        m.extend_from_slice(&pick);
                    }
                }
                5 if m.len() > 9 => {
                    // blow up a size byte after a section id
                    let i = 8 + rng.below(m.len() - 8);
                    m[i] = 0xFF;
                }
                _ => {
                    m.push(rng.next() as u8);
                }
            }
        }
        let want = reference_ok(&m);
        let mut cuts: Vec<usize> = (0..rng.below(6)).map(|_| rng.below(m.len() + 1)).collect();
        if iter % 5 == 0 {
            cuts = (1..m.len()).collect(); // one byte at a time
        }
        cuts.sort_unstable();
        let got = stream_ok(&policy, &m, &cuts);
        if want {
            accepted += 1;
        }
        if got != want {
            disagreements.push(m);
            if disagreements.len() >= 5 {
                break;
            }
        }
    }
    assert!(
        accepted > 50,
        "mutations never reached a valid module: {accepted}"
    );
    assert!(
        disagreements.is_empty(),
        "streaming != wasmparser on {} inputs, e.g. {:02x?}",
        disagreements.len(),
        disagreements[0]
    );
}

/// Probe: with the DEFAULT (restrictive) policy, acceptance must imply
/// acceptance under the permissive policy, and the verdict must not depend on
/// the split.
#[test]
fn probe_default_policy_is_split_independent_and_never_looser() {
    let seeds: Vec<Vec<u8>> = valid_modules().into_iter().map(|(_, m)| m).collect();
    let mut rng = Rng(0xFEED_FACE_CAFE_BEEF);
    let strict = ModulePolicy {
        max_module_bytes: 300,
        max_section_bytes: 120,
        max_function_body_bytes: 40,
        max_locals: 8,
        ..ModulePolicy::default()
    };
    for _ in 0..30_000 {
        let mut m = seeds[rng.below(seeds.len())].clone();
        for _ in 0..rng.below(3) {
            if !m.is_empty() {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
        }
        let whole = stream_ok(&strict, &m, &[]);
        let bytewise: Vec<usize> = (1..m.len()).collect();
        let split = stream_ok(&strict, &m, &bytewise);
        let mut cuts: Vec<usize> = (0..rng.below(5)).map(|_| rng.below(m.len() + 1)).collect();
        cuts.sort_unstable();
        let rand_split = stream_ok(&strict, &m, &cuts);
        assert_eq!(whole, split, "split-dependent verdict {m:02x?}");
        assert_eq!(whole, rand_split, "split-dependent verdict {m:02x?}");
        if whole {
            assert!(reference_ok(&m), "policy accepted what wasmparser refuses");
        }
    }
}
