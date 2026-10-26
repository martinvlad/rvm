//! Peak allocation of the streaming validator is bounded by policy, not by
//! declared sizes. Single test function: the counting allocator is global.

mod common;
use common::*;
use peak_alloc::PeakAlloc;
use rvm_wasm::{ImportPolicy, Limit, ModuleError, ModulePolicy, StreamingModuleValidator};

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

fn policy(max_section: usize) -> ModulePolicy {
    ModulePolicy {
        max_module_bytes: 64 * 1024 * 1024,
        max_section_bytes: max_section,
        max_function_body_bytes: 4096,
        max_functions: 10_000_000,
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    }
}

/// Peak bytes allocated above the level at entry while running `f`.
fn peak_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = PEAK.current_usage();
    PEAK.reset_peak_usage();
    let r = f();
    (r, PEAK.peak_usage().saturating_sub(base))
}

#[test]
fn peak_allocation_is_bounded_by_policy() {
    const SECTION: usize = 16 * 1024;
    // Generous allowance for wasmparser's own per-module state and the Vec
    // doubling slack; the point is that it is independent of declared sizes.
    const OVERHEAD: usize = 96 * 1024;
    // 1. A section that declares ~4 GiB and then trickles bytes: refused as
    //    soon as the declaration is read; nothing proportional is allocated.
    //    Once by the module-size bound, once (module bound lifted) by the
    //    section bound.
    let mut lie = HEADER.to_vec();
    lie.extend([11, 0xff, 0xff, 0xff, 0xff, 0x0f]);
    lie.extend(std::iter::repeat(0u8).take(100_000));
    for (module_max, want) in [
        (64 * 1024 * 1024, Limit::ModuleBytes),
        (usize::MAX / 2, Limit::SectionBytes),
    ] {
        let (res, peak) = peak_during(|| {
            let mut v = StreamingModuleValidator::new(ModulePolicy {
                max_module_bytes: module_max,
                ..policy(SECTION)
            });
            let mut out = Ok(());
            for chunk in lie.chunks(1) {
                if let Err(e) = v.push(chunk) {
                    out = Err(e);
                    break;
                }
            }
            out
        });
        assert_eq!(res, Err(ModuleError::LimitExceeded(want)));
        assert!(peak < 8 * 1024, "declared-size lie allocated {peak} bytes");
    }

    // 2. Same lie for a function body inside the code section.
    let mut lie = HEADER.to_vec();
    lie.extend(section(1, &vec_of(&[type_i32_i32()])));
    lie.extend(section(3, &vec_of(&[vec![0]])));
    lie.extend([10, 0xff, 0xff, 0xff, 0xff, 0x0f, 1]);
    lie.extend([0xff, 0xff, 0xff, 0xff, 0x0f]); // body size ~4 GiB
    lie.extend(std::iter::repeat(0u8).take(100_000));
    let (res, peak) = peak_during(|| {
        let mut v = StreamingModuleValidator::new(ModulePolicy {
            max_module_bytes: usize::MAX / 2,
            ..policy(SECTION)
        });
        lie.chunks(7).try_for_each(|c| v.push(c).map(|_| ()))
    });
    assert!(
        res.is_err(),
        "oversized declared code section must be refused"
    );
    assert!(peak < 8 * 1024, "body-size lie allocated {peak} bytes");

    // 3. A 1 MiB valid module of small functions, pushed in odd-sized chunks:
    //    peak is far below the module size (no whole-module buffering).
    let big = synthetic_module(1024 * 1024);
    let (res, streaming) = peak_during(|| {
        let mut v = StreamingModuleValidator::new(policy(256 * 1024));
        for c in big.chunks(997) {
            v.push(c)?;
        }
        v.finish()
    });
    let ok = res.expect("valid module");
    assert_eq!(ok.byte_len(), big.len() as u64);
    assert!(
        streaming < big.len() / 4 + OVERHEAD,
        "streaming peak {streaming} not far below module size {}",
        big.len()
    );

    // 4. Buffered reference for contrast: the whole-buffer validator keeps all
    //    function bodies queued, so its peak scales with the module.
    let (_, buffered) = peak_during(|| {
        wasmparser::Validator::new_with_features(rvm_wasm::wasm_features())
            .validate_all(&big)
            .unwrap()
    });
    assert!(
        streaming < buffered,
        "streaming {streaming} should be below buffered {buffered}"
    );

    // 5. A legitimate section at the policy bound is buffered within the
    //    stated allowance (1-byte pushes: worst case for the buffer).
    //    wasmparser stores ~250 B per type, so the validator state is bounded by
    //    `max_types`, which policy also caps: allow 1 KiB per permitted type.
    let n_types = SECTION / 5 - 4;
    let items: Vec<Vec<u8>> = (0..n_types).map(|_| type_i32_i32()).collect();
    let ty = section(1, &vec_of(&items));
    assert!(ty.len() <= SECTION);
    let m = module(&[ty]);
    let run = |max_types: u32| {
        peak_during(|| {
            let mut v = StreamingModuleValidator::new(ModulePolicy {
                max_types,
                ..policy(SECTION)
            });
            for b in m.chunks(1) {
                v.push(b)?;
            }
            v.finish()
        })
    };
    let (res, section_peak) = run(n_types as u32);
    res.expect("type-heavy module");
    let bound = 2 * (SECTION + 8) + 1024 * n_types + OVERHEAD;
    assert!(
        section_peak <= bound,
        "section-bound peak {section_peak} > {bound}"
    );
    // The same bytes under a tighter type cap are refused before the types
    // are materialised, so the validator state never reaches the large figure.
    let (res, capped_peak) = run(100);
    assert_eq!(res.unwrap_err(), ModuleError::LimitExceeded(Limit::Types));
    assert!(
        capped_peak <= 2 * (SECTION + 8) + OVERHEAD,
        "capped peak {capped_peak}"
    );
    eprintln!("alloc peaks: 1MiB streaming={streaming} buffered={buffered} section={section_peak} capped={capped_peak}");
}
