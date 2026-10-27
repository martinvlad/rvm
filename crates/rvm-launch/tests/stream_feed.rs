//! RV-06: the session's incremental entry applies the descriptor-derived frame
//! size limit before buffering, and gives the same verdict as whole-frame push
//! under any split.

mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use peak_alloc::PeakAlloc;
use rvm_launch::{SessionError, SessionEvent, SessionState};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::StreamError;
use stream_common::*;

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

fn extra_peak<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = PEAK.current_usage();
    PEAK.reset_peak_usage();
    let r = f();
    (r, PEAK.peak_usage().saturating_sub(base))
}

#[test]
fn feed_applies_the_signed_size_limit_before_buffering_and_matches_push() {
    let module = wasm_common::synthetic_module(20_000);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let body = package_body(&module, "clock", 2);
    let bundle = b.build(&body).unwrap();

    // 1. Any split of the byte stream gives the verdict whole-frame push gives.
    let stream_bytes: Vec<u8> = bundle.frames.concat();
    for split in [1usize, 7, 64, 1000, 4096, stream_bytes.len()] {
        let mut s = stream(&keys, bundle.clone(), base_policy());
        let mut events = Vec::new();
        for piece in stream_bytes.chunks(split) {
            s.session.feed(piece, |r| events.push(r)).unwrap();
        }
        assert_eq!(s.session.state(), SessionState::Complete, "split {split}");
        assert_eq!(events.last(), Some(&Ok(SessionEvent::Complete)));
        assert!(s.session.take_module(2).is_ok());
    }

    // 2. A hostile size lie after a good descriptor costs (almost) nothing.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    s.session.feed(&bundle.frames[0], |_| {}).unwrap();
    let name = "4 GiB chunk";
    let mut frame = vec![1u8];
    frame.extend_from_slice(&1u64.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&u32::MAX.to_le_bytes());
    let (r, extra) = extra_peak(|| s.session.feed(&frame, |_| {}));
    assert_eq!(
        r.err(),
        Some(SessionError::Stream(
            rvm_rvf::stream::AdmissionError::Stream(StreamError::FrameSizeLie)
        )),
        "{name}"
    );
    assert!(extra < 1024, "{name} cost {extra} bytes");
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert!(
        s.session.take_obligation().is_some(),
        "authenticated poison owes"
    );

    // 3. A 4 GiB descriptor claim before any descriptor.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    let mut lie = vec![0u8];
    lie.extend_from_slice(&u32::MAX.to_le_bytes());
    let (r, extra) = extra_peak(|| s.session.feed(&lie, |_| {}));
    assert!(r.is_err());
    assert!(extra < 1024, "descriptor claim cost {extra} bytes");
    assert!(
        s.session.take_obligation().is_none(),
        "nothing was authenticated"
    );

    // 4. After completion, more bytes are refused and the state is unchanged.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    s.session.feed(&stream_bytes, |_| {}).unwrap();
    assert_eq!(s.session.state(), SessionState::Complete);
    assert!(s.session.feed(&[1, 2, 3], |_| {}).is_err());
    assert_eq!(s.session.state(), SessionState::Complete);
    assert!(s.session.take_module(2).is_ok());
}
