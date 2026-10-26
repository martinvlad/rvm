//! Shared module builders for the streaming-validator tests and bench.
#![allow(dead_code)]

pub mod corpus;

pub const HEADER: [u8; 8] = [0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];

pub fn leb(mut v: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

pub fn section(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut s = vec![id];
    s.extend(leb(payload.len() as u32));
    s.extend_from_slice(payload);
    s
}

pub fn module(sections: &[Vec<u8>]) -> Vec<u8> {
    let mut m = HEADER.to_vec();
    for s in sections {
        m.extend_from_slice(s);
    }
    m
}

/// Vector: count then items.
pub fn vec_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = leb(items.len() as u32);
    for i in items {
        v.extend_from_slice(i);
    }
    v
}

/// `(func (param i32) (result i32))`
pub fn type_i32_i32() -> Vec<u8> {
    vec![0x60, 1, 0x7f, 1, 0x7f]
}

/// A function body (size-prefixed) with no locals and the given code (without `end`).
pub fn body(code: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8]; // zero local declarations
    b.extend_from_slice(code);
    b.push(0x0b);
    let mut out = leb(b.len() as u32);
    out.extend(b);
    out
}

/// A synthetic module of about `target` bytes: one type, many small functions
/// (24-byte bodies), one memory, one export. Valid for wasmparser.
pub fn synthetic_module(target: usize) -> Vec<u8> {
    // body: local.get 0; i32.const k; i32.add   x4  = 20 bytes + locals(1) + end(1) + size(1)
    let n = ((target.saturating_sub(64)) / 26).max(1);
    let mut code_payload = leb(n as u32);
    for i in 0..n {
        let mut code = Vec::new();
        for r in 0..4u8 {
            code.extend_from_slice(&[0x20, 0x00, 0x41, ((i as u8).wrapping_add(r)) & 0x3f, 0x6a]);
        }
        // Net stack effect: each rep leaves one value; drop three to keep one result.
        code.extend_from_slice(&[0x1a, 0x1a, 0x1a]);
        code_payload.extend(body(&code));
    }
    let func_payload = {
        let mut v = leb(n as u32);
        v.extend(std::iter::repeat(0u8).take(n));
        v
    };
    module(&[
        section(1, &vec_of(&[type_i32_i32()])),
        section(3, &func_payload),
        section(5, &vec_of(&[vec![1, 1, 1]])), // memory min 1 max 1
        section(
            7,
            &vec_of(&[{
                let mut e = leb(1);
                e.push(b'f');
                e.extend([0u8, 0u8]);
                e
            }]),
        ),
        section(10, &code_payload),
    ])
}
