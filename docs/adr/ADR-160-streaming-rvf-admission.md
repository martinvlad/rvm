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
