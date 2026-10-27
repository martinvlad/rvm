# Adversarial review: project Ofer, rvm side (branch feat/ofer-streaming @ fae20cc)

Reviewer worktree: /data/scratch/ofer-wt/review-rvm (branch feat/ofer-review-rvm). Only the three repro files are committed:
`crates/rvm-launch/tests/review_findings.rs`, `crates/rvm-rvf/tests/review_findings.rs`, `crates/rvm-wasm/tests/review_findings.rs`.
Tests named `rvNN_/rfNN_/rwNN_` PASS when the defect is present (they assert the bad behaviour). `probe_*` tests are robustness probes.
Local workspace workaround (dropping 4 members from the root Cargo.toml) is uncommitted.

Bottom line: the core cryptographic path (descriptor decode, signature, leaf/table commitments, exact-next-chunk rule, WASM validator) held up against everything I could throw at it. I found no way to release, validate or start bytes that the trusted signer did not commit to. The defects are at the integration layer: pre-authentication poisoning with global side effects, the identity check being optional in stage order, missing witnesses on the most important failure, and fail-open defaults for replay/expiry.

## Findings

### RV-01  High  [test]  Unauthenticated frame poisons a session; documented effect is a GLOBAL capability epoch bump
- Code: `rvm-launch/src/stream_session.rs:413-419` (`revoke_capabilities` -> `caps.increment_epoch()`), `rvm-rvf/src/stream/verifier.rs:304-307` (first frame not a descriptor => `poison`), `:219-230` (`fault` poisons once faults > budget 4).
- Test: `rv01_unauthenticated_frame_poisons_and_global_epoch_bump_revokes_bystander`. A 4-byte junk frame, no key, no knowledge of the package: session Poisoned (descriptor_hash = [0;32], i.e. before any authentication); `revoke_capabilities` then makes an unrelated partition's capability fail `verify_p1`.
- Impact: anyone who can inject one frame on any stream link can force revocation of every capability in the manager (including other partitions'). It is acknowledged in ADR-160 amendment 4 as "global", but the ADR does not accept it as a DoS vector, and the trigger is pre-auth. Revocation is caller-invoked, so the severity depends on the host honouring the documented "Poisoned => revoke" contract, which the ADR mandates.
- Fix: do not offer a global bump as the poison effect; require `install` to return handles (the note in the doc comment) and revoke only those; never treat a pre-descriptor poison (descriptor_hash all zero) as grounds for revocation or termination; poisoning from unauthenticated transport faults should kill the session, not trigger host-wide effects.

### RV-02  High  [test]  Replaying authentic frames poisons the stream, and poison terminates other tenants' instances
- Code: `stream_session.rs:440` (`i.stream_origin() == Some(&origin)` selects by descriptor hash only), `verifier.rs:219-230`.
- Test: `rv02_replaying_authentic_frames_poisons_and_terminates_other_tenants`. An on-path attacker forges nothing: it duplicates one genuine chunk frame 5 times (fault budget 4). Session A is Poisoned; `A.terminate_instances` then terminates tenant B's Running instance that merely runs the same package (same descriptor hash) from a separate, clean session.
- Impact: cross-tenant DoS amplification from a duplicated frame; indistinguishable from a benign retransmit storm. Fix: key the termination on the session identity (a per-session nonce stored in `Instance` by `start_verified`), not the descriptor hash; consider (a tradeoff, since it trades the poison DoS for replay/bandwidth abuse) not counting exact duplicates of already-verified chunks against the budget. The per-session nonce is the stronger fix.

### RV-03  Medium  [test]  Stage-ordered delivery completes, hands out a startable module, and passes an identity pin without the identity ever being verified
- Code: `rvm-rvf/src/stream/admission.rs:355-362` (`finish_report` accepts `Unverifiable`), `stream_session.rs:297-310` (`on_complete`), `:354-` (`take_module` does not look at identity status). `grep identity_status|Unverifiable rvm-launch/src` finds only a doc comment: the session exposes no accessor.
- Test: `rv03_unverifiable_identity_still_yields_startable_module_and_passes_identity_pin`. Descriptor signed with `rvf_identity = [0x99;32]` (not the body hash), delivered in stage order, host pins `expected_identity = [0x99;32]`: `report.ok == true`, `take_module` succeeds, `start_verified` reaches Running, and nothing ever called `finish_identity`. File order catches the same lie (existing test), so the control is order-dependent.
- Impact: the SHA-256 identity binding (ADR-155) is the only thing that stops a trusted signer from claiming another package's identity; the `Unverifiable` case turns it into an unenforced, un-queryable obligation, and the report's `rvf_identity` is the signer's claim. Realistic attacker: `StreamPolicy.trusted_keys` (descriptor signer) and `VerifyOptions.trusted_keys` (segment signer) are separate trust sets, so the case that bites is a compromised or malicious descriptor key (for example a mirror operator that signs descriptors) wrapped around authentic publisher-signed segments. Not Critical because it needs that key, but it defeats `expected_identity` pinning and package-contract binding.
- Fix: make `take_module` fail with a typed error unless identity is `Verified`, or have `finish_identity` return the witness that `take_module` requires; expose the status on the session.

### RV-04  Medium  [test]  The most important failure path writes no failing witness
- Code: `stream/witness.rs:212-243` (`StreamComplete` pass emitted whenever admission built a report), `stream_session.rs:297-310` (`on_complete` -> `PackageRefused` emits nothing).
- Test: `rv04_package_refused_after_complete_emits_no_failure_witness`: unsigned executable, authentic bytes, `push_witnessed` throughout: the log holds pass records (SegmentVerified, StreamComplete) and zero Fail records; session ends Failed/`PackageRefused`.
- Impact: contradicts ADR-160 item 6 ("pass and fail alike") and leaves a log that says "stream complete: pass" for a package that was refused (unsigned/untrusted-signature executable, missing root manifest, size policy, capability mapping). The per-check `VerificationRecord`s exist in the report but are never emitted. Fix: emit the report's failing records (as `emit_report` does for buffered `verify`) and a `PackageRefused` record before returning the error; emit `StreamComplete` only after `on_complete` passes.

### RV-05  Low  [test]  Counted faults, `finish_identity` poison and reader-level poison are unwitnessed
- Code: `witness.rs:243` (`Err(_) => {}`), `stream_session.rs:392-` (`finish_identity` has no log parameter), `frame.rs` (`v.poison` from the reader).
- Test: `rv05_counted_faults_are_not_witnessed` (three hash-mismatch refusals, zero records).
- Impact: up to `fault_budget` tampered frames per stream leave no audit trail; an identity-mismatch poison that should terminate a running instance is invisible. Also: admission-level poisons (`Malformed`, `IdentityRequired`, `TooManyOpenSegments`) are all recorded with reason `TableInvalid` (`admission.rs:241`), losing the cause.

### RV-06  Medium  [trace: empty grep + private field]  The session API cannot apply the size-lie control
- Code: `rvm-launch` never references `FrameReader`, `FrameTarget` or `frame_payload_limit` (grep is empty); `StreamSession::admission` is private so a caller cannot build a `FrameReader` over it.
- Impact: `StreamSession::push(&[u8])` takes a fully buffered frame, so the limit that `FrameReader::admit` derives from the signed descriptor (the allocator-counting guarantee, ADR-353 section 4) is unreachable for the only high-level consumer. An integrator has to buffer an unauthenticated frame of unknown size before the session sees it. Fix: add `StreamSession::feed(bytes)` using `FrameReader`, or expose `frame_payload_limit`.

### RV-07  Medium  [trace]  Replay, expiry and policy-hash protection are fail-open by default and nothing records the pin
- Code: `stream/mod.rs:126-128` (`epoch_pin: None, now_ns: None, expected_policy_hash: None`). `EpochPin` is only ever consumed (`descriptor.rs:353-360`); `grep EpochPin` outside tests finds the type, the lookup type and the policy field, no store or update.
- Impact: with `StreamPolicy::new(keys)` (what `stream_bench` and the tests use) an old epoch is accepted, `expires_ns` is ignored, and an equal-epoch conflict is accepted. Whether the caller persists the highest accepted `(epoch, descriptor_hash)` after `Complete` is entirely unspecified; if it pins at `DescriptorVerified` instead, a cut stream advances the pin. Fix: make pin store/update a required part of `StreamSession` (take a `&mut dyn PinStore`), updated only on `Complete`; make `now_ns` required when any descriptor sets `expires_ns`.

### RV-08  Low (ADR-160 amendment 5 residual)  [trace]  Downgrade by stripping the profile line
- Code: `report.rs:104-117` (`declares_stream_profile`), ADR-160 amendment 5.
- The profile declaration is an unsigned `META` line; the buffered loader trusts it only if the container is pinned by `expected_identity`, which `VerifyOptions` does not require. A network attacker (not only a careless publisher) who strips the line or the META segment turns a stream-profiled package into a plain buffered package that `verify` accepts. Same for any non-UTF-8 META (`from_utf8` failure => "not declared"). What stripping gains: buffered delivery has no `file_id`/`epoch` binding, so an old but validly signed version becomes loadable where the stream path (once RV-07's pin is wired) would refuse it; I found no other gain, since signatures and content hashes are still checked. Real fix is the one the ADR names (package contract carries the declaration).

### RF-01  Low-Medium  [test]  Root-page heuristic splits the stream and buffered verdicts (differential claim is false)
- Code: `rvm-rvf/src/container.rs:99-114` (`split_root_page`: magic at exactly `len-4096`, no other check).
- Test: `rf01_rvm0_inside_a_payload_splits_stream_and_buffered_verdicts`. Body = manifest + one META segment whose payload happens to contain `RVM0` at body offset `len-4096`. `verify(body)` returns `Err(PayloadOutOfBounds)`; the stream, whose signed table cuts the segments correctly, reaches Complete with a report. The ADR-160 differential test cannot see this because its builder uses `walk_container` to choose the cuts.
- Impact: the buffered loader refuses (availability) valid packages whose content collides with the magic; an attacker who controls bytes in a publisher's payload can make the package unloadable on the buffered path only. No path found that makes the buffered walk accept more than the stream (hiding a segment inside the "page" is possible only for bytes after a real `RVM0` page, which neither path interprets). Fix: require the page magic plus a structural check (for example a trailing-page length/crc field) or let the descriptor, not a magic probe, define the page in both paths.

### RF-02  Low  [test]  Public `discard_derived_state` on a live stream causes a later index panic
- Code: `admission.rs:232-238`, `:312` (`self.done[entry_idx] = ...`). Test `rf02_...` (catch_unwind confirms). Misuse of a `pub` method, but the failure mode is a panic in no_std hypervisor code. Make it `pub(crate)` or have it poison.

### RF-03  Low  [trace]  Header `uncompressed_len` never compared with the signed entry
- Code: grep shows `uncompressed` is read only by the builder; `descriptor.rs:401` bounds the entry value only. A segment whose own header claims a larger `uncompressed_len` than the signed entry passes; any future decompressor that trusts the header bypasses the policy bound.

### RF-04  Info  [trace]  Weak-checksum rule: spec-compliant but inconsistent
- `chunk.rs:141` rejects algo 0 and 1 only for executable and index types at chunk 0. hash.rs documents algo 1 as the RuVector writer default, so every default-written executable is refused on the stream path and accepted on the buffered path (documented, tested). Algo 3 ("HMAC-SHAKE reserved") and 4..255 pass and are verified with XXH3. Authenticity still comes from the SHA-256 leaf, so no integrity impact.

### RW-01  Low (hardening)  [test]  No table-size limit in `ModulePolicy`
- Test `rw01_default_policy_accepts_a_ten_million_entry_table`: `(table 10000000 funcref)` (under 40 bytes) passes the default policy while a 2000-page memory is refused. When an engine exists it must allocate ~80 MB. Also no limits on globals, data segments, elements.

### RW-02  Not exploitable  [test]  Tag-section mismatch
- Test `rw02_framing_accepts_what_the_validator_refuses`. The framing check accepts a tag section; the validator rejects it (WASM2). The only consumers of the framing check alone are the buffered `Instance::start`, which is the weaker path anyway; the stream path always runs the validator first, and `start_verified` re-runs framing on the accepted bytes (the validator's accept set is a subset of what framing accepts; 4 M mutated modules found no counterexample). Not an admission bypass.

### RV-09  Low  [trace]  Poison effects are advisory
- After `finish_identity` fails nothing terminates the already-started instance until the caller calls `terminate_instances`; `revoke_capabilities` likewise. Consider returning an obligation the caller must discharge.

### RV-10  Suspicion (not demonstrated)  [suspicion]  Frames are re-read after hashing
- ADR-353 section 7 says "verify from a verifier-owned buffer (never a shared/mmap'd transport buffer)". The leaf hash is computed in place (`chunk.rs`), then the same slice is read again by `SegmentChecker::push`, by the `meta` copy (`admission.rs:298`), by `validator.push(payload)` and `bytes.extend_from_slice(payload)` (`stream_session.rs:283-284`). With a concurrently mutable frame buffer (DMA, shared memory) the hashed, validated and copied bytes can differ. Executables are saved by the signature (SHAKE of the copied bytes is in the report) and by the final `executable.matches` SHA-256, but unsigned META (capability declarations) is not. Safe Rust prevents mutation while `&[u8]` is held, so this is only a contract issue for FFI callers; document it or copy the frame first.

## Attack classes tried with no finding

| Class | How hard I tried | Result |
|---|---|---|
| Truncation, reorder/duplicate/insert, mid-stream substitution, splice | Read verifier.rs/chunk.rs line by line; ran existing P1-P6 on armv7 under qemu (also my review_findings suite, 5/5 pass there); 12 000 frame mutations + 30 000 re-signed hostile descriptors (debug build, overflow checks on) through `StreamAdmission` and `FrameReader` with random splits; cargo-fuzz `frame_machine` 150 s (4 M execs) and `descriptor_decode` (330 k execs) | no panic, no early Complete, nothing unsigned released |
| Signature / trust | `verify_strict`, key id loop tries every matching trusted key, reserved sig_alg/hash_alg bytes rejected, signature checked before expiry/epoch/table | sound |
| Descriptor size-lie / allocation | `seg_count`, `table_len`, exact length, `descriptor_len` checked_mul, `max_pending_table_bytes`, per-frame limits from the signed table; `with_capacity` only after exact-length proof | sound (existing allocator-counting tests plus my reading); one policy-dependent exposure: segment-granular profile lets the reader buffer a whole segment (default cap 1 GiB) before its hash can be checked |
| u64->usize on 32-bit | armv7-unknown-linux-gnueabihf under qemu-arm-static: stream_vectors, stream_admission, stream_adversarial and my review tests pass; thumbv8m.main-none-eabihf `cargo check` for rvm-rvf, rvm-wasm (alloc), rvm-launch passes | no truncation found at default policy. `align_up(sat(end))` (segment.rs) and `FrameReader::admit` (`header.len() + payload as usize`) would overflow only if a policy raises `max_segment_bytes` to about 4 GiB on a 32-bit target |
| Panics from attacker bytes | grep of all indexing/`expect` in stream/, plus the mutation harnesses | only RF-02 (API misuse) |
| VerifiedModule forgery / TOCTOU after hand-off | constructor and fields are `pub(crate)`, no Clone, no raw-bytes path; `start_verified` moves the Vec, re-checks identity equality and `accepts_wasm` | sound; the first copy is the Vec in the session, not partition memory |
| Stream-profile downgrade through the buffered loader | `verify` fails `StreamProfile` unless `permit_buffered_stream_profile`; `VerifiedPackage::from_report` refuses failed reports | sound for packages that carry the line (see RV-08) |
| Streaming validator vs wasmparser | `probe_mutated_modules_agree_with_wasmparser_under_hostile_splits` run at 3 M mutated modules (flips, truncations, insertions, appended sections or whole modules, blown-up sizes) with random and byte-at-a-time splits against `Validator::validate_all` under WASM2; restrictive-policy split-independence over 1 M; policy acceptance implies wasmparser acceptance | zero disagreements. Import list is checked once and wasmparser rejects a second import section; poisoned validator replays the same error and `finish` returns it |
| Root page | walk_container vs stream pseudo-entry, trailing zero tail, last-segment truncated padding | only RF-01 |

## Not checked
- RuVector-side implementation of the shared vectors (only ran this repo's consumers of the JSON).
- Bare-metal boot or QEMU of the hypervisor; thumbv8m was compile-checked only.
- 32-bit behaviour with a policy that permits segments of 2-4 GiB.
- cargo-fuzz was run only on the two existing targets, which exercise the verifier, not `StreamAdmission`/`StreamSession`; my mutation tests cover those at far lower volume.
- wasmparser 0.243 internals (trusted as the reference).
- Witness ring overflow by session flooding (host policy).

---

# Round 2 (target: feat/ofer-streaming @ 92ff6cf, merged into feat/ofer-review-rvm)

Vectors: `rvsd-v1-vectors.json` sha256 e442f865...bb33 confirmed. Full `cargo test --release` of rvm-rvf, rvm-launch, rvm-wasm is green on the merged tree. New repros: `crates/rvm-launch/tests/round2.rs`, `crates/rvm-rvf/tests/round2.rs`, `crates/rvm-wasm/tests/round2.rs`; new cargo-fuzz target `crates/rvm-rvf/fuzz/fuzz_targets/admission_session.rs` (seeds in `fuzz/seeds/admission_session`). The implementer's inverted tests are kept as `review_findings.rs`; my round-1 originals are in git history (d1a07b9).

## Round-1 originals rerun against 92ff6cf

| Original | Result on new code |
|---|---|
| rv01-rv05 (launch) | do not compile (`revoke_capabilities`, `terminate_instances`, single-arg `StreamPolicy::new` removed). Semantic ports (`r1_*` in launch round2.rs): all fixed behaviour holds |
| rf01 (rvf) | no longer reproduces with a bare `RVM0` magic (fails as intended); **still reproduces with a crafted valid page, see RF-01b** |
| rf02 | no longer reproduces (`discard_derived_state` poisons) |
| rw01 | no longer reproduces (table limit) |
| rw02 | still passes, by design (framing vs validator), not a defect |
| probes (mutation, 12k frames + 30k re-signed descriptors; 3M wasm mutations) | still pass, no panic, no disagreement |

## Round-1 fixes: do they hold

| Id | Verdict | Bypass attempts |
|---|---|---|
| RV-01 | closed | pre-auth junk owes no obligation (`take_obligation` is None unless the poison is authenticated); no global bump API remains. An on-path attacker can still kill its own session post-descriptor with a wrong-length frame, which is inherent |
| RV-02 | closed | 6 replayed authentic chunks are `Duplicate`, not faults; the flood cap fires after 89 duplicates on the small test stream (4*chunks+64) and only poisons that session; discharge of A's obligation leaves tenant B Running |
| RV-03 | closed for the original path | stage-order lie: `take_module`, `package()`, `install_capabilities` refuse until `finish_identity`; second `finish_identity` errors without disturbing state; wrong body poisons. Residual: RV2-03 |
| RV-04/05 | closed | failing report records, per-fault `StreamFault` records and `finish_identity_witnessed` verified in `r1_refusals_and_faults_are_witnessed`. Residual: RV2-04 |
| RV-06 | closed | `feed`/`feed_witnessed` pass every split (1, 7, 64, 1000, 4096, whole) and a 4 GiB size lie costs under 1 KiB (existing test; my fuzz target feeds with two split patterns and asserts the same verdict) |
| RV-07 | partially closed | the API forces a choice and the pin is recorded only after verified completion (cut and unconfirmed streams record nothing: `r2_pin_not_recorded_for_cut_or_unconfirmed_streams`). But see RV2-01 and RV2-02 |
| RV-08 | closed as designed | `permit_buffered_stream_profile` needs a pin; `require_pinned_identity` is opt-in (default off, so the default buffered loader is still unpinned) |
| RV-09 | closed (type), moot in practice | see RV2-05 |
| RV-10 | documented only | frame-ownership rule added to `stream/mod.rs`; FFI callers must still copy |
| RF-02, RF-03, RW-01 | closed | header `uncompressed_len` larger than the entry is a mismatch poison; table/global/data/element limits enforced under every split (`new_limits_hold_under_every_split`, including an overlong-LEB table size) |
| RF-01 | **not closed for an adversary**, RF-01b | |
| RF-04 | unchanged | still only 0/1 on executable/index |

## New findings

### RV2-01  Medium  [test]  A second trusted signer wipes another signer's pin, reopening rollback
- Code: `rvm-rvf/src/stream/pin.rs` (`MemoryPinStore::record` keeps one slot per `file_id`; a higher epoch from any signer replaces it), `stream/descriptor.rs` (pin is applied only if `p.signer_key_id == h.signer_key_id`).
- Test: `r2_pin_slot_is_overwritten_by_a_second_trusted_signer_reopening_rollback`. Signer A completes epoch 9 (pin A/9); sanity: A's epoch 3 is refused. Signer B (also in `trusted_keys`) completes the same `file_id` at epoch 10: pin becomes B/10. A's epoch 3 now completes and `take_module` succeeds. The reverse works too (a B pin makes A's descriptors unpinned).
- Impact: replay protection is only as strong as the weakest trusted key; one compromised or merely second publisher key nullifies every other lineage sharing a `file_id`. Needs a key in the trust set, hence Medium.
- Fix: key the store by `(signer_key_id, file_id)`, or keep per-signer maxima; do not let a pin for another signer displace one.

### RV2-02  Medium  [test]  The pin is not re-checked at completion (check-then-act race)
- Code: `descriptor.rs` (lookup at descriptor time only), `stream_session.rs maybe_record_pin` (record at completion, `record` silently ignores a lower epoch but the completion is already admitted).
- Test: `r2_pin_is_not_rechecked_at_completion_so_two_sessions_race_to_a_rollback`. Session S4 receives its (valid) epoch-4 descriptor first; S5 completes and pins 5; S4's remaining frames arrive and S4 reaches Complete, `take_module` returns the epoch-4 module after epoch 5 was installed.
- Impact: an attacker that can interleave deliveries (a mirror serving an old version slowly) defeats rollback protection across concurrent sessions.
- Fix: re-run the pin comparison in `promote`/`maybe_record_pin` before `package` and modules become available; make `record` return whether it was accepted and refuse otherwise.

### RV2-03  Low  [test]  `finish_identity` trusts `read_at`; confirming bytes are not bound to streamed bytes
- Code: `verifier.rs finish_identity` hashes what `read_at` returns.
- Test: `r2_finish_identity_does_not_bind_the_confirming_bytes_to_the_streamed_bytes`. A descriptor claims `sha256(B0)`, a different body `B` is streamed in stage order; the host's `read_at` answers with `B0`; identity becomes Verified and `take_module` returns the module from `B`.
- Impact: needs a rogue descriptor signer plus a host whose persisted store is not what it streamed; it moves trust to the persistence layer. Fix: while reading, also check each chunk against the signed leaf commitments (the verifier already holds them), so the confirming bytes must equal the streamed bytes.

### RV2-04  Low  [test]  Reader-level poison before the descriptor is not witnessed
- Code: `rvm-launch/src/stream_target.rs Witnessed::poison` (`if let Some(b) = binding_of(...)`).
- Test: `r2_feed_witnessed_does_not_record_a_preauth_reader_poison`: `feed_witnessed` with an unknown frame type poisons the session and writes zero records (`push_witnessed` uses a fallback binding and does record it). Fix: use the same fallback binding.

### RV2-05  Low  [test]  Obligation mechanics
- Code: `stream_obligation.rs discharge` removes root slots with `CapabilityTable::remove`; `for_session` is `pub`; `session_id` is a process-global `AtomicU32` (sequential, public via `session_id()`, wraps after 2^32).
- Test: `r2_discharge_leaves_derived_children_and_for_session_is_forgeable`. A capability inserted with `insert_derived(parent = revoked root)` stays valid after discharge, and a forged `PoisonObligation::for_session(other_id, ..)` terminates another session's Running instance.
- Impact: bounded. A completed session cannot be poisoned from outside (`r2_completed_session_cannot_be_poisoned_externally`: `FrameTarget::poison` is a no-op after Complete), and nothing is installed or started before Complete with a verified identity, so a real obligation never carries handles or instances today; it is a type with nothing to owe. A dropped obligation (`must_use` is a lint only) loses nothing for that reason. If the design ever lets caps be installed earlier, cascade through the derivation tree and make ids unguessable and 64-bit.

### RF-01b  Low-Medium  [test]  The stricter page test is attacker-satisfiable
- Code: `container.rs is_level0_page` (magic, version 1, `u16@0x96 <= 3688`, CRC32C of `[..0xFFC]`).
- Test: `rf01b_a_crafted_valid_page_inside_a_payload_still_splits_the_verdicts`. CRC32C is public, so a party controlling the last 4096 payload bytes of a segment embeds a "valid" page: `verify` returns `PayloadOutOfBounds`, the stream (table cuts correctly) reaches Complete. The other direction is clean (`rf01c`: a page with a bad CRC is refused by both; a descriptor with no `0xFE` entry makes the stream refuse a trailing real page).
- Fix: let the descriptor decide in both paths (feed the buffered walker the signed table when one exists) or add a MAC-like binding; otherwise document that the differential claim holds only for non-adversarial payload content.

### Info
- `StreamSession::report()` and `VerifiedPackage::from_report` remain reachable before identity confirmation; a caller can build a package from the unconfirmed report (the session's own gates are sound).
- `ReplayProtection::Unpinned` and `MemoryPinStore` (volatile, `RefCell`: a re-entrant interrupt would panic on `borrow_mut`) are what a quick integration will pick; a reboot drops all pins.
- `install_capabilities` is not idempotent (a second call duplicates grants).
- Entry `flags != 0` is now rejected although ADR-353 says reserved flags are "carried verbatim"; check this against RuVector producers.
- Error codes: 0x0F00..0x0F04 appear nowhere in RuVector `rvf-types` error.rs, are unique, and fit the `aux[6..8]` u16; 0x0818 stays reserved.

## Rechecked sound (round 2)
- Duplicate rule: a repeat with different bytes is a `ChunkHashMismatch` fault, a wrong-length repeat is a size-lie poison, an identical descriptor is ignored and a different one is a fault; faults interleaved with 20 duplicates each still poison after the budget; the flood cap is finite so a stream cannot be kept alive indefinitely with duplicates.
- `CompleteUnverified`/`finish_identity` gating: no path to `take_module`, `package()` or `install_capabilities` without Verified; Complete cannot be re-poisoned by late frames or by `FrameTarget::poison`.
- Profile-line parsing as bytes: CRLF, NUL-prefixed lines, non-UTF-8 prefixes, two META segments and a 3 MiB META all detect the line; no-`=`, leading-space, NUL-before-key and CR-only forms are not detected, exactly as the capability parser treats them. `permit_buffered_stream_profile` needs a pin; `require_pinned_identity` fails an unpinned buffered load.
- WASM limits: split-independent for tables (including imported and overlong-LEB), globals, data and element segment counts; 3M mutated modules vs wasmparser and 1M restrictive-policy cases, no disagreement.
- Shared vectors through mutation: 6 000 mutated streams from the vector file (raw and reader-split, debug build with overflow checks), no panic.
- Fuzzing: new `admission_session` target (edit scripts over authentic signed streams in file/stage order and chunk 0xFF/12, plus re-signed hostile descriptors; two split patterns; asserts split-independent state and module, and that any module handed out is byte-identical to the signed one): 1.48M execs in 241 s, no crash or assertion. armv7 (qemu) passes stream_vectors, stream_admission, stream_terminal and both round2 suites; thumbv8m check passes for rvm-launch.

## Not checked (round 2)
- Real concurrency (the pin store is single-threaded `RefCell`; RV2-02 is shown with interleaved sessions on one thread).
- Persistence of pins across reboot (no implementation).
- RuVector-side producers for the new entry-flags rule and the Level-0 page layout beyond the fixtures.
- The fuzz target's coverage plateaued near 1700 edges; deeper structure-aware mutation of the chunk-table frames was not attempted.

---

# Round 3 (optimize)

Scope: `git diff 32a5900..ce80826` (parallel-identity worker, feed buffer reuse, host-proxy stage-order fix, finish_identity via IdentityTracker). Branch feat/ofer-review-rvm, merged with origin/feat/ofer-streaming (ce80826). Local-only workspace workaround (root Cargo.toml/Cargo.lock) not committed. Repros: `crates/rvm-rvf/tests/review_round3.rs` (feature-gated, run with `--features "testkit parallel-identity" -- --test-threads=1`), fuzz target `crates/rvm-rvf/fuzz/fuzz_targets/identity_worker.rs` (+ 3 small seeds).

## Findings

No critical, high or medium findings.

### RV3-01  Low  [test]  The identity worker thread outlives poison and completion
- Code: `src/stream/ident.rs` (`Worker` is only stopped by `Drop` of the tracker); `verifier.rs install` spawns it at descriptor acceptance; nothing sets `self.identity = None` on Complete / Poisoned / Rejected-after-install / Suspended.
- Test: `rv3_01_worker_thread_outlives_poison_and_completion` (8 poisoned verifiers keep 8 threads until dropped; all joined on drop, thread count returns to base).
- Impact: a host that keeps poisoned or finished sessions (obligations, reports) holds one parked thread per session whose signed descriptor commits to a body >= 4 MiB. Needs a trusted signer, so it is resource hygiene, not an attacker primitive. Stage order spawns a worker too although the identity becomes infeasible at the first out-of-order chunk (thread and a few copied chunks wasted; info).
- Fix: drop the tracker (or only its worker) when the state becomes terminal (`Complete*`, `Poisoned`); spawn lazily on the first in-order chunk.

### RV3-02  Info  Memory bound is stated for 64 KiB chunks only
- ADR-160 item 18 says peak memory is unchanged (3.6 -> 3.7 MiB). That holds at 64 KiB chunks. The bound is `(QUEUE + 2) * chunk` copies (4 queued, 1 in the worker, 1 being copied), so up to about 6 MiB extra at the 1 MiB cut-off; still bounded, backpressure is a `sync_channel(4)` and a dead worker makes `send` fail instead of blocking (no deadlock path found). Suggest stating the formula.

### RV3-03  Info  Worker death degrades to `CompleteUnverified`, not an error
- `ident.rs update` sets `feasible = false` when `send` fails; `completion_status` maps a `None` digest to `Unverifiable`. This is fail-closed for admission: `take_module` requires `Verified` and a caller recovers with `finish_identity`. Worth a line in the ADR: a File-order stream can end `CompleteUnverified` after an OS-level thread failure. I could not inject a worker death without editing the implementation (Sha-256 `update` cannot panic; the only exits are channel closure and a panic in `clone`/alloc), so this path is verified by reading only.

### RV3-04  Info  Stale round-2 repro files do not build or pass after the round-2 fixes
- `crates/rvm-rvf/tests/review_round2.rs::rf01b...` now fails (`verify` rejects nothing: RF-01b was fixed in 9862b21) and `crates/rvm-launch/tests/review_round2.rs`, `crates/rvm-wasm/tests/{review_findings,round2}.rs` no longer compile against the fixed API (`PoisonObligation::for_session`, `ModulePolicy` re-exports; rvm-wasm needs `--features std`). The implementer's inverted `round2.rs` files cover the same behaviour and pass. Not a product defect; delete or invert my old files before using `cargo test --all-targets` as a gate.

### Info
- `FrameReader::feed` now does `reserve_exact(total - len)` as soon as a header is admitted. The size is bounded by `max_descriptor_bytes` (1 MiB default) before the descriptor is verified and by the signed max chunk afterwards, so the amplification (header -> allocation) is at most 1 MiB per session before authentication; previously growth was proportional to bytes actually received. Allocation failure aborts (`reserve_exact`, not `try_reserve`).
- Feature unification: any workspace member enabling `rvm-rvf/parallel-identity` turns the thread on for every consumer in that build. Only the host-proxy and my fuzz crate do today.

## Rechecked and found sound (how hard)
- Worker vs `completion_status`/`take_module`/`finish_identity` (read every line of ident.rs, chunk.rs, verifier.rs): `digest()` sends a `Snapshot` after every queued `Data` on the same FIFO channel, so the digest includes every chunk including the final one before `Complete` is set; the final chunk is released only after `completion_status` returns, and the only error between `update` and release is a poison, so no hashed-but-unreleased chunk can coexist with a live stream. Only leaf-verified, in-order bytes reach the worker (`admit_chunk` precedes the update; out-of-order sets `feasible=false`). Tests: `identity_verdicts_do_not_depend_on_where_the_identity_hash_runs` (implementer), `clone_at_the_end_and_lie_detection`, 3 byte flips and a read failure in `finish_identity_with_a_worker_confirms_and_refuses`.
- Worker death/panic: `send`/`recv` errors become `feasible=false`/`None` -> `Unverifiable`; never `Verified`. No mutex anywhere (no poisoning); the snapshot reply channel has capacity 1 so the worker never blocks; `Drop` closes the sender then joins (drains at most 4 chunks); `finish_identity` early returns drop the tracker the same way. Read-only (see RV3-03).
- Thread spawn failure: `Builder::spawn(..).ok()` -> inline hashing. Shown for real with `ulimit -u 1` (`spawn_failure_falls_back_to_inline`: 1 thread in the process, Verified for the truth, IdentityMismatch for the lie).
- clone() mid-stream: a clone takes a snapshot of the hasher and continues inline with no shared state; clones and original are independent, dropping the original or a clone mid-stream does not disturb the others (`clone_mid_stream_is_independent`, clones at 1/3, 2/3, end-1).
- Feed buffer reuse: `need` is reset before `push_frame`, `clear()` after; every read is bounded by `target - len`; the reader is per session and refuses all input once Poisoned/terminal, so stale bytes cannot reach another session or frame. Reader vs `push` equivalence at splits 65536, 4093, 70001 (`probe_reader_with_worker_matches_push`).
- Default and no_std unaffected: all threaded code is `cfg(feature = "parallel-identity")`, which implies `std`; `cargo check -p rvm-rvf --no-default-features` and `--target thumbv8m.main-none-eabihf` pass.
- Stage-order negative result (80 ms vs 28.5 ms buffered): host-proxy now calls `finish_identity` (full chunk-wise re-verification against the signed leaves plus identity hash) before `take_module`, and `take_module` itself demands `Verified`; the slower number is the honest cost of two extra passes, not a hidden shortcut. The proxy's `read_at` copies from the in-memory body, so device read latency is not in that number (the same is true of the buffered baseline).
- Tests run (release): rvm-rvf default and with `parallel-identity`: all pass except the stale RF-01b file (RV3-04); rvm-launch lib + review_findings/round2/stream_*: pass in both configurations; rvm-wasm (`--features std`): pass. round3 tests: 8/8 pass with `--test-threads=1` (running them in parallel makes the thread-count test flaky; documented in the file header). Mutation campaign (`probe_worker_mutation_campaign`, 20 s, both orders, 5 MiB bodies): no panic, deterministic verdicts, Complete only with the exact signed bytes.
- Fuzz `identity_worker`, 121 s, parallel-identity on: 9 991 execs (82 exec/s, 5 MiB body, 64 KiB chunks), cov 2299 / ft 3977, no crash, no race assertion. Worker coverage measured in the harness (thread-count delta after `DescriptorVerified`; counter bumped twice per exec because each input runs twice): the worker was live in about 82% of runs and about 22% of runs reached Complete with it (4 136 of 19 000 runs).

## Not checked (round 3)
- Real multi-threaded stress (many verifiers on many threads, clone from another thread); the worker is exercised only from one producer thread at a time.
- Worker death (see RV3-03) and a deliberately slow worker's memory peak: argued from the code, not measured.
- Performance claims (1.35 -> 2.4 GB/s, 80 vs 61 ms): not re-measured; host-proxy not run (separate workspace, needs network for wasmi).
- armv7/qemu and wasm32 runs of the new code were not repeated; only the thumbv8m no_std check.
