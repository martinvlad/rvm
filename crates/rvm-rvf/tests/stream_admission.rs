//! P10: the streamed and the buffered paths apply one rule set.
//!
//! For every body in the corpus, fed as a stream in file order and in stage
//! order, at segment and 4 KiB chunk granularity: the stream completes with a
//! report equal to `verify(body)`, or both refuse the body.

mod common;

use common::{builder, corpus, opts, run_bundle};
use rvm_rvf::stream::builder::{Order, Span};
use rvm_rvf::stream::StreamState;
use rvm_rvf::{verify, CheckKind, DetailCode, Outcome, VerifyOptions};

const FORGE: &[u8] = include_bytes!("fixtures/forge-signed-root-page.rvf");
const FORGE_PUBKEY_HEX: &str = include_str!("fixtures/forge-signed-root-page.pubkey.hex");

fn forge_key() -> [u8; 32] {
    let h = FORGE_PUBKEY_HEX.trim();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn assert_same(name: &str, body: &[u8], opts: &VerifyOptions, chunk_log2: u8, order: Order) {
    let b = builder(chunk_log2, order);
    let bundle = b.build(body).unwrap_or_else(|e| panic!("{name}: {e}"));
    let keys = [b.public_key()];
    let run = run_bundle(&bundle, &keys, opts);
    let ctx = format!("{name} chunk_log2={chunk_log2:#x} order={order:?}");
    assert_eq!(
        run.state,
        StreamState::Complete,
        "{ctx}: {:?}",
        run.first_error
    );
    let streamed = run.report.expect("report at Complete");
    let mut buffered = verify(body, opts).expect("corpus bodies are well-formed");
    // The one intended difference: how a stream-profiled package arrived.
    for r in &mut buffered.records {
        if r.check == CheckKind::StreamProfile {
            assert_eq!(r.detail, DetailCode::StreamProfileDowngrade, "{ctx}");
            r.outcome = Outcome::Pass;
            r.detail = DetailCode::StreamProfileSatisfied;
        }
    }
    buffered.ok = !buffered.records.iter().any(|r| r.outcome == Outcome::Fail);
    assert_eq!(streamed, buffered, "{ctx}");
}

#[test]
fn stream_and_buffered_reports_are_equal_for_the_whole_corpus() {
    let opts = opts();
    for (name, body) in corpus() {
        for chunk_log2 in [0xFF, 12] {
            for order in [Order::File, Order::Stage] {
                assert_same(name, &body, &opts, chunk_log2, order);
            }
        }
    }
}

#[test]
fn the_corpus_contains_both_accepted_and_refused_packages() {
    let opts = opts();
    let ok: Vec<_> = corpus()
        .into_iter()
        .map(|(n, b)| (n, verify(&b, &opts).unwrap().ok))
        .collect();
    assert!(ok.iter().any(|(_, o)| *o), "{ok:?}");
    assert!(ok.iter().filter(|(_, o)| !*o).count() >= 6, "{ok:?}");
}

#[test]
fn a_real_ruvector_forge_package_streams_to_the_same_report() {
    let opts = VerifyOptions::with_trusted_keys(vec![forge_key()]);
    for chunk_log2 in [0xFF, 12] {
        // The fixture's executable uses the writer's checksum; if it is the
        // weak one the stream path must refuse it, and the test says so.
        let b = builder(chunk_log2, Order::File);
        let bundle = b.build(FORGE).unwrap();
        let keys = [b.public_key()];
        let run = run_bundle(&bundle, &keys, &opts);
        let buffered = verify(FORGE, &opts).unwrap();
        assert!(buffered.ok);
        if run.state == StreamState::Complete {
            assert_eq!(run.report.unwrap(), buffered);
        } else {
            let (_, err) = run.first_error.expect("refused with a reason");
            panic!("forge fixture refused on the stream path: {err}");
        }
    }
}

/// Cut a body at the segment boundaries of its intact walk.
fn spans_of(body: &[u8]) -> Vec<Span> {
    let segs = rvm_rvf::walk(body).unwrap();
    segs.iter()
        .enumerate()
        .map(|(i, s)| Span {
            seg_id: s.header.segment_id,
            seg_type: s.header.seg_type,
            start: s.offset,
            end: segs.get(i + 1).map_or(body.len(), |n| n.offset),
            uncompressed: 0,
        })
        .collect()
}

#[test]
fn a_malformed_container_is_refused_by_both_paths() {
    // Each mutation yields authentic-but-malformed bytes: the descriptor is
    // signed over them, so only the segment rules can refuse.
    type Mutate = fn(&mut Vec<u8>);
    let cases: [(&str, Mutate); 5] = [
        ("payload length past its segment", |b| {
            b[128 + 0x10..128 + 0x18].copy_from_slice(&(1u64 << 20).to_le_bytes());
        }),
        ("payload length over the format maximum", |b| {
            b[128 + 0x10..128 + 0x18].copy_from_slice(&u64::MAX.to_le_bytes());
        }),
        ("bad segment magic", |b| b[128] ^= 0xFF),
        ("signed flag without a footer", |b| {
            // Segment 3 (vectors) is unsigned; mark it SIGNED.
            let at = rvm_rvf::walk(b).unwrap()[2].offset;
            b[at + 6] |= 0x04;
        }),
        ("non-zero bytes after the last segment", |b| {
            let n = b.len();
            b.extend_from_slice(&[0u8; 64]);
            b[n + 5] = 1;
        }),
    ];
    for (name, mutate) in cases {
        let mut body = common::good_body();
        let spans = spans_of(&body);
        mutate(&mut body);
        let buffered = verify(&body, &opts());
        assert!(buffered.is_err(), "{name}: verify must refuse, got ok");
        for chunk_log2 in [0xFF, 12] {
            let b = builder(chunk_log2, Order::File);
            // Trailing garbage extends the last span.
            let mut spans = spans.clone();
            if let Some(last) = spans.last_mut() {
                last.end = body.len();
            }
            let bundle = b.build_spans(&body, &spans);
            let run = run_bundle(&bundle, &[b.public_key()], &opts());
            assert_ne!(run.state, StreamState::Complete, "{name}");
            assert!(run.report.is_none(), "{name}");
            assert!(
                run.failure.is_some() || matches!(run.state, StreamState::Poisoned(_)),
                "{name}: a refusal must say why"
            );
        }
    }
}

#[test]
fn stream_profile_is_refused_by_the_buffered_loader_unless_permitted() {
    let body = corpus()
        .into_iter()
        .find(|(n, _)| *n == "declares-stream-profile")
        .unwrap()
        .1;
    let report = verify(&body, &opts()).unwrap();
    assert!(!report.ok);
    let rec = report
        .records
        .iter()
        .find(|r| r.check == CheckKind::StreamProfile)
        .unwrap();
    assert_eq!(rec.outcome, Outcome::Fail);
    assert_eq!(rec.detail, DetailCode::StreamProfileDowngrade);

    let mut permitted = opts();
    permitted.permit_buffered_stream_profile = true;
    let report = verify(&body, &permitted).unwrap();
    assert!(report.ok, "{:?}", report.failures());
    let rec = report
        .records
        .iter()
        .find(|r| r.check == CheckKind::StreamProfile)
        .unwrap();
    assert_eq!(rec.detail, DetailCode::StreamProfilePermitted);

    // Streamed, the same package is admitted without any special permission.
    let b = builder(12, Order::File);
    let bundle = b.build(&body).unwrap();
    let run = run_bundle(&bundle, &[b.public_key()], &opts());
    assert!(run.report.unwrap().ok);
}

#[test]
fn a_package_without_the_declaration_is_unchanged_by_the_downgrade_rule() {
    let report = verify(&common::good_body(), &opts()).unwrap();
    assert!(report.ok);
    assert!(report
        .records
        .iter()
        .all(|r| r.check != CheckKind::StreamProfile));
}
