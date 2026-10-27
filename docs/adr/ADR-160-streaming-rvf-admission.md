# ADR-160: Streaming RVF admission and incremental module validation (project Ofer)

**Status**: Proposed
**Date**: 2026-10-26
**Authors**: Claude Code
**Supersedes**: None
**Related**: ADR-132, ADR-134, ADR-140, ADR-149, ADR-155; RuVector ADR-284, ADR-287, ADR-353 (RVF Stream Descriptor), ADR-354

---

## Context

ADR-155 admits an RVF package only after the whole container is in memory (`rvm_rvf::verify(&[u8])`), and keeps `MAX_MODULE_SIZE` (1 MiB) as an executor backstop because streaming validation is "future work tracked under RuVector ADR-287" (still Proposed). RuVector ADR-353 now specifies how bytes are authenticated while they arrive: a signed stream descriptor commits to every byte of an unchanged RVF body; chunks are released only after their hash matches.

Project Ofer's research established facts this ADR must respect (verified in code, 2026-10-26):

- `rvm-wasm::validate_module` checks the 8-byte header and section framing only. There is no wasmparser, wasmi or wasmtime dependency anywhere in the workspace.
- `Instance::start` admits bytes and marks an agent slot `Running`; **no code is executed**. `rvm-ffi`, `rvm-node`, `rvm-policy` and `rvm-state`, named by ADR-284 and ADR-287, do not exist.
- `rvm-rvf` restates the RVF wire format instead of depending on `rvf-wire`, so a wire change is a two-repo change.
- `rvm_rvf::walk` rejects a container that ends in a 4096-byte `RVM0` root page (as `rvf-forge-core` produces), and rejects files written by `rvf-runtime` (ADR-354).

## Decision

1. **Interop first (P0).** `rvm-rvf::walk` recognizes a trailing Level-0 root page. A compatibility test runs against checked-in fixture bytes produced by the RuVector writers (`RvfStore` and `rvf-forge-core`). Streaming work does not count as done until this is green.
2. **`rvm-rvf::stream::StreamVerifier`.** `no_std`, `alloc` only where bounded by the verified descriptor, push-style. It implements ADR-353 sections 1 to 6: descriptor verification, exact-next-chunk rule, per-chunk SHA-256 leaf check, per-segment state, `Complete`/`Suspended`/`Poisoned`. Because this crate restates the format, it is kept in step with `rvf-wire` by shared known-answer vectors (`rvsd-v1-vectors.json`, generated in RuVector), not by a code dependency.
3. **One rule set.** The existing `verify(&[u8])` becomes a thin wrapper that feeds the stream verifier in file order and yields the same `VerificationReport`, so whole-buffer and streaming admission cannot disagree. A differential test enforces it.
4. **Incremental module validation.** `rvm-wasm::StreamingModuleValidator` wraps `wasmparser` (`default-features = false`, `validate`, `no_std`) as a push parser fed only with chunks the verifier has released. Limits (function body size, locals, type, import and export counts, memory maximum) come from a `ModulePolicy` derived from signed policy. `MAX_MODULE_SIZE` stays as the default backstop, not the mechanism (ADR-155 section 4). Imports are reconciled with the declared capability set as soon as the import section completes; each code entry is validated as it arrives; whole-module checks (function count equals code count, data count) run at the end.
5. **Start only from verified, validated, complete bytes.** `rvm-launch::Instance::start_verified(VerifiedModule)` requires: segment `SegmentVerified`, validator finished without error, and the existing length plus SHA-256 identity match (`accepts_wasm`). The module is copied once into partition-private memory; the transport buffer is never trusted after hand-off.
6. **Witnesses.** `DescriptorVerified`, `DescriptorRejected(reason)`, `SegmentVerified(seg_id, root)`, `StreamPoisoned(seg_id, chunk_index, reason)` are emitted through the existing witness path for pass and fail alike. `Poisoned` revokes granted capabilities (epoch bump), terminates instances started from the stream, and drops derived state.
7. **No downgrade.** A package that declares a stream profile is refused by the buffered loader unless signed policy permits it. Executables must carry a SHA-256-grade commitment; `checksum_algo` 0 and 1 are not accepted as authenticity.

## What this ADR does not do

It does not add an execution engine. RVM still does not run WASM instructions; "start" means admission and slot activation. Time-to-first-instruction on RVM is therefore not measurable. Benchmarks report a labeled host proxy (time from first byte to validator completion plus instantiation in a host engine, run outside RVM) and say so. Choosing and integrating an engine (wasmi or wasmtime) is a separate decision and is out of scope.

It does not boot the bare-metal kernel under QEMU (no `aarch64-unknown-none` target installed in the research environment); that remains unverified.

## Acceptance

- P0: fixtures from both RuVector producers verify in `rvm-rvf`.
- Shared vectors: descriptor decode, signature, leaf and table hashes, and verifier events match RuVector byte for byte.
- Adversarial properties from ADR-353 hold for `StreamVerifier` (bit flips, truncation at every offset, frame permutation, replay, splice, size lies with an allocation bound).
- Differential: `verify(&[u8])` and the stream verifier agree on accept/reject and on `VerifiedExecutable` identities, fed in file order and in stage order.
- WASM: a corpus of malformed modules gets the same verdict from the streaming validator, under arbitrary chunk splits, as `wasmparser::Validator` on the full buffer; no executable memory is allocated for a rejected module.
- `Instance::start_verified` is unreachable before verification and validation; mutating the transport buffer after hand-off does not change instance bytes.
- The new code builds for a `no_std` target (`thumbv8m.main-none-eabihf` is installed in the reference environment).

## Consequences

Positive: bounded memory, early rejection, one rule set for buffered and streamed admission. Negative: `wasmparser` joins the trusted computing base for admission; mitigated by authenticate-before-parse and by re-validation inside any future engine (never `new_unchecked`).

## Implementation notes and amendments (rvm-rvf stream, rvm-launch session)

Written when the code landed on `feat/ofer-rvm-stream`; where this section and
the Decision above disagree, this section records what was built and why.

1. **Item 3 ("`verify(&[u8])` becomes a thin wrapper over the stream verifier")
   is not implemented, and cannot be as written.** `StreamVerifier`
   authenticates bytes against a signed descriptor; `verify` applies the
   ADR-155 loading rules (root manifest, signed executables, content hashes,
   size policy, capability mapping) to a container that, in the legacy case,
   has no descriptor at all. A body with a valid descriptor but an unsigned
   executable stream-*completes* and `verify`-rejects. What was built instead:
   both paths build their `VerificationReport` through one function
   (`rvm_rvf::report::build_report`), the stream feeding it facts computed
   incrementally (`StreamAdmission`, `SegmentChecker`) and `verify` feeding it
   facts read from a buffer. The differential test
   (`tests/stream_admission.rs`) asserts that for every corpus body, in file
   order and stage order, at segment and 4 KiB chunk granularity, the streamed
   report equals `verify(body)` record for record (including a real RuVector
   forge package), and that malformed containers are refused by both.
   One intended difference: a stream-profiled package records
   `StreamProfileSatisfied` where the buffered loader records
   `StreamProfileDowngrade`. The stream's descriptor prefilter sums
   `stored_len` per class while `verify` sums `payload_length`, so a stream is
   never admitted that `verify` would refuse on size, but a package at the very
   edge of a class budget can be refused by the stream and accepted by `verify`.
2. **Item 5 timing.** `StreamSession::take_module` yields a `VerifiedModule`
   only when the stream is `Complete`, admission passed **and the identity is
   verified**. It is not available as soon as the module's own segment
   verifies: the capability mapping and the root-manifest rule are
   package-level facts. Stage ordering therefore bounds memory and gives early
   rejection but does not yet let a component start before the rest of the
   package arrives. Early start of a verified component is future work.
3. **Item 5 placement.** `StreamSession` and `VerifiedModule` live in
   `rvm-launch`: the session must name `rvm-rvf`, `rvm-wasm` and `Instance`;
   `rvm-host` sits below `Instance`. `Instance::start_verified` moves the
   module into the instance's own storage; start is admission and slot
   activation only.
4. **Item 6 poison effects (revised after review RV-01, RV-02, RV-09).**
   There is no global capability epoch bump. A session that installs a
   package's capabilities (`install_capabilities`, built on
   `CapabilityMapping::install_tracked`, which returns the `(index,
   generation)` handles) remembers them, and a poisoned session issues one
   `#[must_use] PoisonObligation` (`take_obligation`) naming exactly those
   handles and the instances it started. Instances remember a **per-session
   id** (a process-unique counter, not derived from anything the transport
   controls), not the descriptor hash, so a session cannot reach another
   tenant that streams the same package. A poison before any descriptor was
   authenticated issues no obligation: the session is dead and nothing else is
   touched. Because identity must be verified before anything is granted
   (item 8) and `Complete` is terminal, a session that has granted something
   cannot currently be poisoned afterwards; the obligation is the contract an
   early-start extension must discharge, and `PoisonObligation::for_session`
   lets a host register installs it made by other means.
5. **Item 7 declaration.** A stream-profiled package carries a `META` line
   `rvm.stream_profile=required` (read as bytes, so non-UTF-8 junk cannot hide
   it). It cannot carry the descriptor hash: the descriptor commits to the
   body, so a body containing its own descriptor hash would be circular. The
   binding is the descriptor's `rvf_identity`, which covers the line.
   `VerifyOptions::permit_buffered_stream_profile` is the explicit permission,
   and **only takes effect with a pinned `expected_identity`**. The line is
   unsigned, so anyone who can change the bytes can strip it (review RV-08); a
   host whose policy is "packages are stream-delivered" sets
   `VerifyOptions::require_pinned_identity`, which makes the buffered loader
   refuse any package not pinned by identity. The residual, stated plainly: an
   unpinned buffered package is by definition unauthenticated as to its stream
   profile. Closing it fully needs the package contract (ADR-155 section 5) to
   carry the declaration outside the body.
6. **Behaviour taken from the shared vectors (RuVector ADR-353 clarified,
   vectors sha256 `e442f865…bb33`).**
   - Identity is checked over released bytes only while chunks arrive in file
     order. A stage-ordered stream ends in `CompleteUnverified`; `Complete`
     always means the identity is confirmed. `finish_identity(read_at)` moves
     `CompleteUnverified` to `Complete` or `Poisoned`.
   - `Complete`, `CompleteUnverified`, `Suspended` and `Rejected` are never
     turned into `Poisoned` by a later frame or a reader-level size lie; any
     frame after completion is refused with `StreamBadState`.
   - The identity check runs before the final chunk is released.
   - A chunk whose `requires_mask` stages are not verified is a counted fault.
   - `rvf_identity` must be zero when `identity_present` is clear; entry
     `flags` must be zero; stage requirements must be acyclic; the root-page
     pseudo-entry (`0xFE`) must be last, exactly 4096 bytes, `uncompressed_len`
     0, and its first chunk must begin with the root magic.
   - `checksum_algo` 0 or 1 on an executable or index segment poisons the
     stream. This is the only place the rule applies (RF-04): the buffered
     loader keeps accepting those segments because their authenticity there is
     the segment signature, whereas on the stream path the SHA-256 leaf already
     authenticates the bytes and the weak checksum would only be a parser
     input. `hash.rs` documents algorithm 1 as the writer default, so every
     default-written executable is refused on the stream path; publishers of
     streamed executables use algorithm 2. Algorithms 3 and 4..255 verify
     with XXH3 as before.
   - Duplicates: a chunk with an index below the next expected one whose bytes
     hash to the verified leaf is **ignored** (not a fault) and counted
     against `max_duplicate_frames` (default `4 * total chunks + 64`, then
     `StreamDuplicateFlood` 0x081A); with different bytes it is a leaf-mismatch
     fault. A byte-identical repeated descriptor is ignored; a different one
     is a fault. A replayed authentic frame therefore cannot poison a stream
     (RV-02). Chunk tables are retained for the life of the stream (cap
     `max_table_bytes`, default 64 MiB, a counted fault) so a duplicate can be
     checked.
   - An epoch pin is `(epoch, descriptor_hash, signer_key_id)`, keyed by
     `file_id`, and constrains only descriptors from that signer.
7. **Witness (revised after RV-04, RV-05).** Stream events use the existing
   record path with new `CheckKind` values (`StreamDescriptor`,
   `StreamSegment`, `StreamPoisoned`, `StreamComplete`, `StreamModule`,
   `StreamFault`) and the numeric reason in `aux[6..8]`. Counted faults, a
   failed `finish_identity` and reader-level poison are witnessed. For a
   package refused after `Complete` the failing `VerificationRecord`s of the
   report are written (as `emit_report` does for the buffered path), and the
   session writes `StreamComplete` only once the package is admitted.
   Admission-level poisons keep their real reason through local codes
   `0x0F00..` (`SegmentMalformed`, `SegmentMismatch`, `IdentityRequired`,
   `TooManyOpenSegments`, `ClockRequired`); these are RVM-local, not
   RuVector `ErrorCode` values.
8. **Identity gates everything (RV-03).** Until the identity is verified the
   session exposes no `VerifiedModule`, no `VerifiedPackage`, and
   `install_capabilities` refuses. A pinned `expected_identity` is checked
   against the descriptor's claim, so it is only as strong as the verification
   of that claim.
9. **Replay protection is a choice, and the pin is recorded after admission
   (RV-07).** `StreamPolicy::new(keys, ReplayProtection)` has no default;
   `unpinned_insecure` is the visibly insecure spelling. `ReplayProtection::Store`
   uses a `PinStore` (reference: `MemoryPinStore`; a production host persists
   it). A descriptor with `expires_ns` set is refused (`ClockRequired`) when the
   policy is pinned but has no trusted clock. The session records
   `(epoch, descriptor_hash, signer)` exactly once, when the stream is
   `Complete`, its identity is verified and the package passed admission; a
   cut, poisoned or refused stream never moves the pin.
10. **Size lies and the session (RV-06).** `StreamSession::feed` /
    `feed_witnessed` drive a `FrameReader` with the limits the signed
    descriptor implies, so a hostile size claim is refused before a payload
    byte is buffered (allocator-counting test: under 1 KiB). `push` takes an
    already-buffered frame and cannot apply the limit.
11. **Root page (RF-01).** `split_root_page` no longer triggers on the magic
    alone: the trailing 4096 bytes must be a structurally valid Level-0 page
    (`RVM0` magic, version 1, signature length within the buffer, CRC32C of
    bytes `0..0xFFC` at `0xFFC`). The RuVector shared fixtures with a page
    (`forge_signed_rvm0.rvf`, `runtime_signed_wire.rvf`) satisfy it. This is
    stricter than `rvf-forge-core`'s magic-only split; a writer whose page
    carries no valid CRC is no longer split off by the buffered path. A payload
    that contains a *complete valid* Level-0 page at `len - 4096` is still
    indistinguishable from a page by the buffered walk (the stream path is not
    affected: the descriptor cuts the segments).
12. **Smaller changes.** A segment header may not claim a larger
    `uncompressed_len` than the signed entry (RF-03).
    `discard_derived_state` on a live stream poisons it instead of leaving a
    later panic (RF-02). `ModulePolicy` bounds table elements, globals, data
    segments and element segments (RW-01).
13. **Frame ownership (RV-10).** Confirmed that a frame is hashed in place and
    then read again by the segment checker, the metadata copy and the module
    validator. In safe Rust those are the same bytes (a `&[u8]` cannot be
    mutated while borrowed); the guarantee ends at an FFI or shared-memory
    boundary, where the caller must copy into verifier-owned memory first. No
    extra copy is made on the safe path.
14. **Replay protection, round 2 (RV2-01, RV2-02).** Pins are keyed by
    `(signer_key_id, file_id)`: a second trusted signer publishing the same
    `file_id` has its own pin and can neither displace nor bypass another's
    (the reference does the same: an `EpochPin` applies only to its signer and
    `file_id`, and its descriptor hash is mandatory). `PinStore::advance` is a
    compare-and-set: it moves a pin only from the value the caller just checked
    against, and never backwards. The check is no longer only at descriptor
    arrival: the session re-checks the pin when the identity is verified (a
    session that began at epoch 4 and finished after epoch 5 was pinned fails
    with `SessionError::Replay(StaleEpoch)` and a failing witness record), and
    `take_module` checks again (`take_module_witnessed` writes the record).
    **The RuVector reference must also:** key its pin lookup by signer as well
    as file id (it already filters by signer), re-run the epoch comparison when
    a stream completes and before releasing anything derived from it, and
    expose a compare-and-set pin update.
15. **`finish_identity` re-verifies (RV2-03).** It no longer trusts the
    persisted body: it reads it through `read_at` in 64 KiB pieces, checks
    **every chunk against the signed leaf and table commitments**, and only
    then compares `SHA-256` with `rvf_identity`. A descriptor that claims
    another body's hash is therefore not confirmed by supplying that body. The
    claim `rvf_identity` is itself a signer assertion; `expected_identity`
    pins it to the package the host meant. **The reference must also** verify
    the persisted bytes against the commitments in its `finish_identity`.
16. **Obligations (RV2-05).** `PoisonObligation::for_session` is crate-private
    and only `take_obligation` issues one. Discharge sweeps derived
    capabilities through the table's `parent_index` links (a slot records its
    parent's index but not its generation; the sweep runs at once, before a
    slot can be reused). Session ids come from a 32-bit process counter and
    wrap after 2^32 sessions; a target without 64-bit atomics cannot do better.
    Pre-descriptor reader poison is witnessed with an all-zero binding, which
    marks it unauthenticated (RV2-04).
17. **Root page, round 2 (RF-01b).** A valid-looking trailing page is only a
    guess, and its CRC is public. The buffered walk now splits the page off
    only when the segments tile exactly up to it; if the split walk fails the
    whole buffer is walked instead. A real page always starts on a segment
    boundary, so the split walk succeeds for it; a "page" crafted inside a
    payload makes the split walk fail and falls back, so both paths cut the body
    the same way. This replaces the proposed check of the page's own
    `l1_manifest_*` fields, which an attacker can also set (they are public
    values), with a rule that does not depend on any attacker-settable field.
    When a descriptor is available `verify_with_descriptor` cuts the buffer at
    the signed table and needs no guess. The differential test
    (`stream_admission`, `round2::rf01b…`) covers both the heuristic and the
    descriptor case. The residual: a body with no descriptor and a crafted
    payload engineered so that *both* the split and the whole walk succeed with
    different segmentations; the whole-buffer rules (segment alignment, no
    gaps) leave no such layout that we know of, but there is no proof.
18. **Optimization pass (measured, 2026-10-26, Ryzen 9 9950X, 32 threads,
    release, load average 2-4, median of 7 with [min-max]).** Tools: manual
    timers and an allocator-counting run (`examples/alloc_count.rs`); `perf` is
    not permitted here (`perf_event_paranoid`).
    - **Identity hash (file order), `parallel-identity` feature (off by
      default, needs `std`, `no_std` builds do not compile it).** The second
      SHA-256 pass (running identity) runs on a worker thread fed copies of the
      chunks through a queue of 4. Same digest, same verdicts; the digest is
      complete before the final chunk is released. Chunks over 1 MiB and bodies
      under 4 MiB are hashed inline. Verifier at 64 KiB chunks: 1.35 [1.31-1.36]
      to 2.44 [2.31-2.48] GB/s (+81%); at 1 MiB: 1.36 to 2.52 (+85%);
      admission 1.31 to 2.35, session 1.31 to 2.25-2.34; segment-granular
      (M1) unchanged (chunks exceed the bound). Peak memory unchanged at 256 MiB
      (3.6 to 3.7 MiB). Host proxy, file order, unthrottled: module ready
      54.0 to 33.4 ms (buffered 28.5). The cost is a thread and a copy per
      chunk; the memory bound is kept by the queue limit.
    - **SHA-256 backend.** Already hardware: 2.7 GB/s raw (SHA-NI via
      `cpufeatures`, no feature needed); the portable path would be about
      0.4 GB/s. No gain available.
    - **Copies/allocations.** The push path allocates 0.1 (verifier), 0.4
      (admission), 1.6 (session) times per MiB; nothing avoidable except the
      module copy the session must keep. The byte reader (`feed`) allocated a
      new buffer per frame and grew it by doubling: 8716 allocations and 190 MB
      for 64 MiB at 1500-byte splits; it now reserves the admitted size once and
      reuses the buffer: 104 allocations, 1.17 MB, throughput 1.13 [1.01-1.14]
      to 1.18 [1.16-1.18] GB/s (+4%, inside the noise bar; kept for the 160x
      reduction in allocation).
    - **Module validator.** 195 MB/s streamed against 183 MB/s whole-buffer
      `wasmparser`: the wrapper adds nothing measurable; the time is
      wasmparser's function-body validation. No gain.
    - **`finish_identity`.** 1.32 [1.31-1.32] GB/s on a 256 MiB body (two
      SHA-256 passes, 4103 `read_at` calls of 64 KiB); `read_at` buffer size
      does not matter (16 KiB 1.32, 64 KiB 1.28-1.32, 256 KiB 1.31, 1 MiB 1.24
      within noise). With `parallel-identity`: 2.19 [2.13-2.24] GB/s. In
      stage order the confirmation is part of the time to a startable module:
      host proxy, stage order, unthrottled, 80.2 ms (buffered 28.5), 61.4 ms
      with the feature; at 1 Gbit/s 591 ms against 567 buffered.
    - **Honest summary of B3/B4/B5 now:** memory 3.6 MiB against 258.6 MiB
      (unchanged); verifier 1.35 GB/s default, 2.4-2.5 GB/s with
      `parallel-identity`; module-ready unthrottled is still slower than the
      buffered path in file order (33-54 ms against 28.5) and in stage order
      (61-80 ms), and equal or better only when the link is the bottleneck
      (file order, 1 Gbit/s: 540 against 567 ms).
19. **Round 3 and vectors `9d331d28…` (RV3-01, F4-05).** The identity worker
    thread is joined as soon as the stream is poisoned, completes, suspends
    (the running state is handed back and hashing continues inline on resume) or
    the running hash becomes infeasible, and is not started when the descriptor's
    stages are not in body order (stage-ordered delivery is expected out of file
    order). A worker that dies makes the identity unverifiable, never verified.
    Chunk tables are now **freed when their segment finishes**, so retained
    table memory is bounded by the open segments (`max_table_bytes`). A late
    chunk of a finished multi-chunk segment cannot be checked any more: it is
    counted against `max_duplicate_frames`, never released, and reported as
    `Event::Unverified` (not a fault, not a poison); a repeat of a finished
    single-chunk segment is still verified (the leaf is in the descriptor entry)
    and reported as `Duplicate`. Because finished tables are gone,
    `finish_identity` rebuilds each segment's leaf list from the persisted bytes
    (32 bytes per chunk, one segment at a time) and compares it with the signed
    chunk-table hash, which is the same commitment.
