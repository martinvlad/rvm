//! Writes the compat fixtures with the RuVector writers.
//! Usage: `gen <out-dir>`; prints the sha256-free summary the README records.
use ed25519_dalek::SigningKey;
use rvf_runtime::{RvfOptions, RvfStore};
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: gen <out-dir>"));
    std::fs::create_dir_all(&out).unwrap();

    // (a) Forge-authored, signed, with the trailing 4096-byte Level-0 root page.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let wasm = b"\0asm\x01\0\0\0".to_vec();
    let c = rvf_forge_core::author::ContainerBuilder::new()
        .segment(rvf_types::SegmentType::Wasm, wasm)
        .sign_with(key.clone())
        .build()
        .unwrap();
    std::fs::write(out.join("forge-signed-root-page.rvf"), &c.bytes).unwrap();
    std::fs::write(
        out.join("forge-signed-root-page.pubkey.hex"),
        hex(&key.verifying_key().to_bytes()),
    )
    .unwrap();

    // (b) Legacy dialect: a file written by the current rvf-runtime RvfStore.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.rvf");
    let mut o = RvfOptions::default();
    o.dimension = 4;
    let mut s = RvfStore::create(&p, o).unwrap();
    let v: Vec<Vec<f32>> = (0..10).map(|i| vec![i as f32; 4]).collect();
    let refs: Vec<&[f32]> = v.iter().map(|x| x.as_slice()).collect();
    let ids: Vec<u64> = (0..10).collect();
    s.ingest_batch(&refs, &ids, None).unwrap();
    s.close().unwrap();
    let bytes = std::fs::read(&p).unwrap();
    std::fs::write(out.join("rvstore-legacy.rvf"), &bytes).unwrap();
    println!(
        "forge: {} bytes; rvstore-legacy: {} bytes",
        c.bytes.len(),
        bytes.len()
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
