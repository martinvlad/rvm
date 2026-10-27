#![allow(dead_code)]
//! Shared builders for the stream end-to-end tests.

use rvm_host::Placement;
use rvm_launch::{SessionError, StreamSession};
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder, StreamBundle};
use rvm_rvf::stream::StreamPolicy;
use rvm_rvf::testkit::{signed_segment_with, unsigned_segment, unsigned_segment_with, TestKeypair};
use rvm_rvf::{VerifyOptions, CAPABILITY_DECLARATION_KEY};
use rvm_types::PartitionId;
use rvm_wasm::{ImportPolicy, ModulePolicy};

pub const PLACEMENT: Placement = Placement::new(PartitionId::new(1), 0, 16);

pub fn kp() -> TestKeypair {
    TestKeypair::deterministic(11)
}

pub fn opts() -> VerifyOptions {
    VerifyOptions::with_trusted_keys(vec![kp().public])
}

pub fn base_policy() -> ModulePolicy {
    ModulePolicy {
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    }
}

pub fn noise(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// A package: capabilities, the signed module (SHAKE-256 checksum, the only
/// kind the stream path accepts for an executable), bulk data, a manifest.
pub fn package_body(module: &[u8], caps: &str, algo: u8) -> Vec<u8> {
    let meta = format!("{CAPABILITY_DECLARATION_KEY}={caps}");
    let mut d = unsigned_segment(0x07, meta.as_bytes(), 1);
    d.extend(signed_segment_with(0x10, module, 2, &kp(), algo));
    d.extend(unsigned_segment_with(0x01, &noise(9_000), 3, 2));
    d.extend(unsigned_segment(0x05, b"root", 4));
    d
}

pub fn builder(chunk_log2: u8, order: Order) -> StreamBuilder {
    let mut b = StreamBuilder::new([0x5A; 32]);
    b.chunk_log2 = chunk_log2;
    b.order = order;
    b.stages = if order == Order::Stage {
        Stages::ByType
    } else {
        Stages::Flat
    };
    b
}

pub struct Streamed<'k> {
    pub session: StreamSession<'k>,
    pub bundle: StreamBundle,
}

pub fn stream<'k>(keys: &'k [[u8; 32]], bundle: StreamBundle, base: ModulePolicy) -> Streamed<'k> {
    let mut policy = StreamPolicy::unpinned_insecure(keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    Streamed {
        session: StreamSession::new(policy, opts(), base),
        bundle,
    }
}

pub fn run_all(s: &mut Streamed<'_>) -> Result<(), SessionError> {
    for f in &s.bundle.frames.clone() {
        s.session.push(f)?;
    }
    Ok(())
}

/// Re-read the persisted `body` to confirm an `Unverifiable` identity.
pub fn confirm(s: &mut Streamed<'_>, body: &[u8]) {
    s.session
        .finish_identity(|off, buf| {
            let at = off as usize;
            buf.copy_from_slice(&body[at..at + buf.len()]);
            true
        })
        .expect("identity confirms");
}
