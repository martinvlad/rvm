//! The module corpus shared by the streaming-validator tests (`rvm-wasm`) and
//! the stream end-to-end tests (`rvm-launch`): valid modules, malformed
//! modules wasmparser rejects, and modules that are valid but break a policy.
#![allow(dead_code)]

use super::*;
use rvm_wasm::{AllowedImport, ImportPolicy, Limit, ModuleError, ModulePolicy};

pub fn wat(s: &str) -> Vec<u8> {
    wat::parse_str(s).expect("valid wat")
}

pub fn valid_modules() -> Vec<(&'static str, Vec<u8>)> {
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
pub fn bad_modules() -> Vec<(&'static str, Vec<u8>)> {
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

pub fn policy_cases() -> Vec<(&'static str, Vec<u8>, ModulePolicy, ModuleError)> {
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
