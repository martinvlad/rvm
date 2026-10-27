//! Round-2 review probes for rvm-rvf (branch feat/ofer-review-rvm).

mod common;

use common::{builder, noise, opts, run_bundle};
use rvm_rvf::stream::builder::{Order, Span};
use rvm_rvf::stream::StreamState;
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{verify, CheckKind, DetailCode, Outcome, ROOT_PAGE_MAGIC, RvfError};

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82F6_3B78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn level0_page() -> [u8; 4096] {
    let mut p = [0u8; 4096];
    p[..4].copy_from_slice(&ROOT_PAGE_MAGIC.to_le_bytes());
    p[4..6].copy_from_slice(&1u16.to_le_bytes());
    let c = crc32c(&p[..0xFFC]);
    p[0xFFC..].copy_from_slice(&c.to_le_bytes());
    p
}

/// RF-01b DEFECT (Low-Medium, residual): the stricter page test is
/// attacker-satisfiable. The CRC is not a secret, so anyone who controls the
/// last 4096 payload bytes of a segment can embed a "valid" page there. The
/// buffered walk then still cuts the body inside the segment and refuses it,
/// while the signed table lets the stream carry it.
#[test]
fn rf01b_a_crafted_valid_page_inside_a_payload_still_splits_the_verdicts() {
    let mut body = unsigned_segment(0x05, b"root", 1);
    let first_len = body.len();
    let mut payload = noise(8_000, 5);
    let total = first_len + 64 + 8_000;
    let at = (total - 4096) - (first_len + 64);
    payload[at..at + 4096].copy_from_slice(&level0_page());
    body.extend(unsigned_segment(0x07, &payload, 2));
    assert_eq!(body.len(), total);
    assert_eq!(verify(&body, &opts()).unwrap_err(), RvfError::PayloadOutOfBounds);

    let b = builder(12, Order::File);
    let spans = [
        Span { seg_id: 1, seg_type: 0x05, start: 0, end: first_len, uncompressed: 0 },
        Span { seg_id: 2, seg_type: 0x07, start: first_len, end: total, uncompressed: 0 },
    ];
    let bundle = b.build_spans(&body, &spans);
    let keys = [b.public_key()];
    let run = run_bundle(&bundle, &keys, &opts());
    assert_eq!(run.state, StreamState::Complete);
}

/// The other direction: a genuine page appended after real segments is hidden
/// from the walk (by design). Check the stream and the buffered verdict agree
/// when the page is last and when the descriptor omits the pseudo-entry.
#[test]
fn rf01c_page_handling_other_direction() {
    let mut body = unsigned_segment(0x05, b"root", 1);
    let seg_end = body.len();
    body.extend_from_slice(&level0_page());
    let buffered = verify(&body, &opts()).expect("page recognised");
    assert_eq!(buffered.segment_count, 1);

    // Descriptor WITHOUT the 0xFE pseudo-entry: the trailing 4096 bytes are
    // then presented as an ordinary segment and must be refused.
    let b = builder(12, Order::File);
    let spans = [
        Span { seg_id: 1, seg_type: 0x05, start: 0, end: seg_end, uncompressed: 0 },
        Span { seg_id: 2, seg_type: 0x07, start: seg_end, end: body.len(), uncompressed: 0 },
    ];
    let bundle = b.build_spans(&body, &spans);
    let keys = [b.public_key()];
    let run = run_bundle(&bundle, &keys, &opts());
    assert_ne!(run.state, StreamState::Complete);

    // A page with a bad CRC: both refuse.
    let mut bad = unsigned_segment(0x05, b"root", 1);
    let mut p = level0_page();
    p[100] ^= 1;
    bad.extend_from_slice(&p);
    assert!(verify(&bad, &opts()).is_err());
}

fn profile_record(meta: &[&[u8]]) -> Option<Outcome> {
    let mut body = Vec::new();
    for (i, m) in meta.iter().enumerate() {
        body.extend(unsigned_segment_with(0x07, m, 10 + i as u64, 2));
    }
    body.extend(unsigned_segment(0x05, b"root", 1));
    let r = verify(&body, &opts()).unwrap();
    r.records
        .iter()
        .find(|r| r.check == CheckKind::StreamProfile)
        .map(|r| r.outcome)
}

#[test]
fn probe_profile_line_parsing() {
    let yes = Some(Outcome::Fail);
    assert_eq!(profile_record(&[b"rvm.stream_profile=required"]), yes);
    assert_eq!(profile_record(&[b"a=b\r\nrvm.stream_profile=required\r\n"]), yes);
    assert_eq!(profile_record(&[b"\0\nrvm.stream_profile=1"]), yes);
    assert_eq!(profile_record(&[b"\xFF\xFE\nrvm.stream_profile=required"]), yes);
    assert_eq!(profile_record(&[b"x", b"rvm.stream_profile=required"]), yes);
    let mut big = vec![b'a'; 3 << 20];
    big.extend_from_slice(b"\nrvm.stream_profile=required");
    assert_eq!(profile_record(&[&big]), yes);
    // Not recognised: no '=', leading space, NUL before key on the same line,
    // CR-only separator. The capability parser treats these identically.
    assert_eq!(profile_record(&[b"rvm.stream_profile"]), None);
    assert_eq!(profile_record(&[b" rvm.stream_profile=required"]), None);
    assert_eq!(profile_record(&[b"\0rvm.stream_profile=required"]), None);
    assert_eq!(profile_record(&[b"x\rrvm.stream_profile=required"]), None);
}

#[test]
fn probe_pinned_identity_policy() {
    let mut body = unsigned_segment(0x07, b"rvm.stream_profile=required", 2);
    body.extend(unsigned_segment(0x05, b"root", 1));
    // permit flag without a pin is not enough
    let mut o = opts();
    o.permit_buffered_stream_profile = true;
    let r = verify(&body, &o).unwrap();
    assert!(r.first_failure(CheckKind::StreamProfile).is_some());
    // with the pin it is
    let o2 = o.clone().expect_identity(rvm_rvf::sha256(&body));
    let r = verify(&body, &o2).unwrap();
    assert!(r.first_failure(CheckKind::StreamProfile).is_none());
    // require_pinned_identity
    let mut o3 = opts();
    o3.require_pinned_identity = true;
    let r = verify(&body, &o3).unwrap();
    let f = r.first_failure(CheckKind::Identity).unwrap();
    assert_eq!(f.detail, DetailCode::IdentityNotPinned);
}

mod vec_mut {
    use rvm_rvf::stream::{FrameReader, StreamAdmission, StreamPolicy};
    use rvm_rvf::VerifyOptions;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
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

    /// The final shared vectors (sha256 e442f865...) through the mutation
    /// harness: raw frames and reader-split, overflow checks on in debug.
    #[test]
    fn probe_final_vectors_mutation() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("vectors/rvsd-v1-vectors.json")).unwrap();
        let key: [u8; 32] = hex(v["test_only_key"]["public_key_hex"].as_str().unwrap()).try_into().unwrap();
        let keys = [key];
        let mut rng = Rng(0xABCD_EF01_2345_6789);
        let mut ran = 0;
        for st in v["streams"].as_array().unwrap() {
            let frames: Vec<Vec<u8>> =
                st["frames"].as_array().unwrap().iter().map(|f| hex(f["hex"].as_str().unwrap())).collect();
            for _ in 0..1500 {
                let mut fr = frames.clone();
                for _ in 0..1 + rng.below(3) {
                    let i = rng.below(fr.len());
                    match rng.below(7) {
                        0 if !fr[i].is_empty() => {
                            let l = fr[i].len();
                            fr[i][rng.below(l)] ^= 1 << rng.below(8);
                        }
                        1 => {
                            let l = fr[i].len();
                            fr[i].truncate(rng.below(l + 1));
                        }
                        2 if fr.len() > 1 => {
                            fr.remove(i);
                        }
                        3 => {
                            let f = fr[i].clone();
                            fr.insert(i, f);
                        }
                        4 => {
                            let j = rng.below(fr.len());
                            fr.swap(i, j);
                        }
                        5 => {
                            for off in [1usize, 5, 9, 13] {
                                if fr[i].len() >= off + 4 && rng.below(2) == 0 {
                                    let x = [0xFFFF_FFFFu32, 0x8000_0000, 0, 1][rng.below(4)];
                                    fr[i][off..off + 4].copy_from_slice(&x.to_le_bytes());
                                }
                            }
                        }
                        _ => fr[i].push(rng.next() as u8),
                    }
                }
                let r = catch_unwind(AssertUnwindSafe(|| {
                    let mk = || {
                        let mut p = StreamPolicy::unpinned_insecure(&keys);
                        p.size = rvm_rvf::SizePolicy::permissive();
                        StreamAdmission::new(p, VerifyOptions::default())
                    };
                    let mut a = mk();
                    for f in &fr {
                        let _ = a.push(f);
                    }
                    let mut a = mk();
                    let all: Vec<u8> = fr.concat();
                    let mut rd = FrameReader::new();
                    let mut at = 0;
                    while at < all.len() {
                        let end = (at + 1 + rng.below(300)).min(all.len());
                        if rd.feed(&mut a, &all[at..end], |_| {}).is_err() {
                            break;
                        }
                        at = end;
                    }
                }));
                assert!(r.is_ok(), "panic");
                ran += 1;
            }
        }
        assert!(ran >= 4000, "{ran}");
    }
}
