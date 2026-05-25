# Production TSS TODO

This file tracks the work required before this repository can be treated as a
production-grade TSS library.

Current status from local inspection:

- `go test ./...` passes.
- `cggmp21/secp256k1` is still explicitly experimental.
- Protocol payloads still use JSON in multiple state machines.
- `docs/paillier-zk-proofs.md` states that the Paillier/ZK proof layer is not
  production-audited.

References:

- [RFC 9591: The Flexible Round-Optimized Schnorr Threshold Protocol](https://www.rfc-editor.org/rfc/rfc9591)
- [IACR ePrint 2021/060: CGGMP21](https://eprint.iacr.org/2021/060)

## Non-Negotiable Rules

- Do not read, copy, port, or derive code from public TSS implementations in Go
  or any other language.
- It is acceptable to use papers, RFCs, standards, and public test vectors or
  test scenarios.
- Do not preserve prior-format fallback paths while moving toward the
  production target. Existing conversion code for retired wire shapes must be
  removed rather than supported.
- CGGMP21 applies only to ECDSA over secp256k1. Ed25519 must stay on the
  FROST-style EdDSA path.
- Do not remove the experimental warning from `cggmp21/secp256k1` until the full
  Paillier MtA/ZK CGGMP21 signing path exists and has completed independent
  review.
- Never place private shares, nonces, Paillier private-key material, presign
  secret material, or raw secret-bearing payloads in blame evidence, logs,
  errors, examples, or docs.

## P0: Complete CGGMP21 Paillier/MtA/ZK and Identifiable Abort

### Goal

Replace the current unaudited Paillier/ZK proof shells with a production-grade
CGGMP21 proof set and make identifiable abort behavior complete enough for
review.

### Detailed Process

1. Build a protocol checklist directly from the CGGMP21 paper for keygen,
   presign, online signing, MtA/MtAwc, proof statements, public inputs,
   witnesses, transcript inputs, and abort-identification requirements.
2. Compare that checklist against the current `internal/zk/paillier` proof
   inventory: `ModulusProof`, `EncScalarProof`, `EncRangeProof`, and
   `MTAResponseProof`.
3. Replace proof shells whose statement is weaker than CGGMP21 requires. Do not
   keep shell proofs under production names.
4. Rework transcript and challenge domains so every proof binds:
   protocol name, version, session id, threshold, ordered participant set,
   ordered signer set when applicable, sender, receiver, proof kind, Paillier
   public key, ciphertexts, curve commitments, and all public statement data.
5. Recheck MtA/MtAwc equations for both `delta = k * gamma` and `chi = k * x`
   paths. Document every protocol equation near the implementation.
6. Ensure each attributable verification failure returns `ProtocolError` with
   `Blame.Parties` and deterministic `Blame.Evidence`, except duplicate/replay
   handling.
7. Add evidence verification coverage for malformed Paillier key material,
   invalid proof bytes, transcript mismatch, MtA response mismatch, malformed
   delta broadcast, malformed online partial, and final aggregate verification
   failure.
8. Keep the `ExperimentalSecurityNotice` attached to CGGMP21 artifacts until the
   implementation and proof set have completed independent cryptographic review.

### Acceptance Criteria

- `1-of-1`, `2-of-3`, and `3-of-5` CGGMP21 signing scenarios succeed.
- Tampering with Paillier public keys, Paillier proofs, encrypted nonce proofs,
  MtA responses, round-1 echoes, round-3 deltas, online partials, or aggregate
  signatures fails closed.
- Attributable CGGMP21 failures include deterministic public blame evidence.
- Blame evidence contains only public inputs or hashes of confidential inputs.
- No secret scalar, nonce, presign secret, or Paillier private-key material can
  appear in evidence, logs, formatted errors, examples, or docs.
- `go test -race ./...` and `golangci-lint run` pass.
- The experimental warning remains until independent review is complete.

## P0: Convert Protocol Payloads and Nested Key Material to Strict TLV

### Goal

Remove JSON from transcript-bound and secret-bearing protocol payloads. All
protocol messages and nested cryptographic records should use deterministic,
exact-field TLV encodings.

### Detailed Process

1. Define fixed TLV type ids and exact field sets for all CGGMP21 payloads:
   keygen commitments, keygen shares, presign round 1, presign round 2, presign
   round 3, and online signing partials.
2. Convert `internal/mta` start and response messages to canonical binary
   payloads. Their nested proof bytes must remain exact proof records, not ad hoc
   byte blobs with ambiguous shape.
3. For every decoder, require exact field sets, strictly increasing tags, no
   duplicate tags, no trailing bytes, canonical scalar encodings, canonical point
   encodings, and minimal positive integer encodings.
4. Replace tests that mutate JSON payload structs with tests that mutate TLV
   fields and raw bytes.
5. Update `docs/wire.md` with the complete wire inventory and the exact
   production rule: no automatic fallback and no proof-conversion helper.

### Acceptance Criteria

- Protocol packages no longer use JSON to encode or decode secret-bearing or
  transcript-bound payloads.
- `rg "encoding/json|json.Marshal|json.Unmarshal"` in protocol packages returns
  only allowed public diagnostic encodings, if any.
- All new payload decoders have fuzz tests.
- Wrong type id, wrong field set, duplicate field, unsorted field, trailing
  bytes, malformed scalar, malformed point, and non-minimal integer encodings
  are rejected.
- `docs/wire.md` lists every production TLV record.
- `go test -race ./...` and `golangci-lint run` pass.

## P0: Harden Secret-Material Lifecycle and Misuse Resistance

### Goal

Reduce the risk of leaking key shares, nonces, Paillier private keys, or presign
material through APIs, memory lifetime, logs, formatted errors, tests, or
default encoders.

### Detailed Process

1. Review every exported struct that contains secret-bearing bytes, including
   key shares, presigns, Paillier private keys, nonce state, and session state.
2. Move long-lived secret fields behind opaque types or unexported fields where
   the public API can remain practical.
3. Prevent secret-bearing structs from being accidentally JSON-marshaled by
   default. Prefer explicit `MarshalBinary` methods with clear security docs.
4. Add `Destroy` or close-style methods for keygen, presign, and signing
   sessions that clear local scalar, nonce, and Paillier private-key bytes.
5. Clear temporary byte slices when they hold secret material and no longer need
   to survive. Document where Go `big.Int` or compiler behavior limits reliable
   zeroization.
6. Review all errors, test failures, examples, and docs for accidental secret
   formatting.
7. Add tests proving `Destroy` clears stored byte slices and does not corrupt
   public metadata needed for diagnostics.

### Acceptance Criteria

- `rg "json:\\\".*secret|fmt\\..*Secret|%x.*Secret"` has no unsafe hits.
- Secret-bearing types do not expose default JSON representations.
- Destroy tests cover key shares, presigns, and session-local secret material.
- Docs clearly state what the library can and cannot guarantee about memory
  zeroization in Go.
- `go test -race ./...` and `golangci-lint run` pass.

## P1: Align FROST Ed25519 with RFC 9591

### Goal

Move the Ed25519 implementation from "FROST-style" toward behavior that is
traceable to RFC 9591 and reviewable as FROST Ed25519.

### Detailed Process

1. Build a checklist from RFC 9591 for the Ed25519 ciphersuite: context string,
   nonce commitment shape, binding factor, group commitment, challenge,
   Lagrange coefficient usage, partial verification, aggregation, and signature
   encoding.
2. Compare each checklist item against `frost/ed25519` keygen and signing.
3. Update domain separation and transcript labels so all signing inputs are
   explicit and documented.
4. Add public test vectors or public test scenarios from standards or papers
   where available. Do not derive code from public TSS implementations.
5. Add tests for wrong signer set, wrong session id, malformed nonce commitment,
   malformed partial scalar, duplicate/replayed messages, and bad partial blame.
6. Update docs and examples so the public surface describes exact FROST behavior
   rather than an underspecified "style" when the implementation is ready.

### Acceptance Criteria

- Produced signatures are accepted by `crypto/ed25519.Verify`.
- RFC-derived vectors or scenarios pass.
- `1-of-1`, `2-of-3`, and `3-of-5` FROST signing scenarios pass.
- All protocol equations and domain-separation choices have useful comments and
  matching docs.
- `go test -race ./...` and `golangci-lint run` pass.

## P1: Implement Resharing, Proactive Refresh, and Presign Safety Strategy

### Goal

Add production key-lifecycle capabilities without weakening the protocol
boundary or allowing presign misuse.

### Detailed Process

1. Design FROST resharing for threshold changes and participant-set changes.
   Bind all new shares to a fresh transcript and public commitment set.
2. Design CGGMP21 resharing and proactive refresh with Paillier/ZK material
   updated or revalidated as required by the final protocol checklist.
3. Ensure refreshed shares cannot be mixed with old shares in signing sessions.
4. Bind CGGMP21 presigns to signer set, key transcript, presign session id, and
   any derivation context needed by additive-shift signing.
5. Define persistent presign-consumption behavior so reuse is rejected after
   process restart, not only in memory.
6. Add executable examples showing normal resharing, proactive refresh, and
   presign lifecycle usage.

### Acceptance Criteria

- Old shares cannot sign under a new refresh transcript.
- Mixed old/new shares fail closed with attributable errors when possible.
- Presign reuse is rejected before any second online partial can leave the
  process, including after persistence and reload.
- Public examples cover the supported lifecycle.
- `go test -race ./...` and `golangci-lint run` pass.

## P1: Tighten API, State Machines, and Transport-Neutral Integration Contract

### Goal

Make misuse harder for integrators while keeping the library transport-neutral.

### Detailed Process

1. Require inbound envelopes to carry transcript hashes. Do not treat missing
   transcript hash as acceptable in production protocol sessions.
2. Document that authenticated sender identity must come from the external
   transport and must match `Envelope.From` before the state machine handles a
   message.
3. Normalize protocol errors so wrong session, wrong round, wrong sender, wrong
   recipient, wrong payload type, duplicate message, malformed payload, and
   verification failure are distinguishable and stable.
4. Confirm every state transition is monotonic: completed, consumed, or aborted
   sessions must not accept additional messages that alter state.
5. Add tests for session state after completion, duplicate after completion,
   wrong recipient after completion, and retrying after attributable abort.
6. Keep networking, storage encryption, retries, peer authentication, and KMS
   integration outside this repository. Document the exact caller contract.

### Acceptance Criteria

- Wrong session, round, sender, recipient, payload type, transcript, malformed
  scalar, malformed point, duplicate, and replay cases fail closed.
- Duplicate/replay failures do not create blame evidence.
- Attributable verification failures do create deterministic public evidence.
- `docs/security.md` contains a production integration checklist.
- `go test -race ./...` and `golangci-lint run` pass.

## P1: Expand Tests, Fuzzing, Race Checks, Lint, and Audit Gates

### Goal

Turn the current functional tests into release gates suitable for a
security-sensitive cryptographic library.

### Detailed Process

1. Add full state-machine fuzzers for FROST and CGGMP21 message delivery,
   including malformed payloads, wrong ordering, duplicates, and dropped
   messages.
2. Add adversarial scheduler tests that permute valid envelope delivery order
   while preserving protocol constraints.
3. Add concurrency and race tests around session APIs that callers may use from
   multiple goroutines, or explicitly document APIs as not goroutine-safe.
4. Add boundary threshold tests for minimum participant sets, maximum practical
   tested participant sets, invalid threshold values, and repeated party ids.
5. Add golden encoding tests for every public binary record and every production
   protocol payload.
6. Add CI gates for `go test -race ./...`, fuzz smoke tests, `golangci-lint run`,
   and exported-doc comment checks.
7. Do not rely on `golangci-lint run --fix` as a release gate. Formatting and
   lint fixes should be committed deliberately.

### Acceptance Criteria

- Race, lint, fuzz smoke, and doc checks are release-blocking.
- New API, wire-format, or protocol behavior changes require matching docs and
  executable examples.
- Golden tests fail on accidental wire-format drift.
- Fuzzers cover all production payload decoders.
- `go test -race ./...` and `golangci-lint run` pass.

## P2: Finish Release Documentation, Audit Scope, and Version Strategy

### Goal

Define exactly when this repository can make production claims and how those
claims are communicated.

### Detailed Process

1. Update `README.md`, `docs/security.md`, `docs/wire.md`,
   `docs/cggmp21-secp256k1.md`, `docs/frost-ed25519.md`, and
   `docs/architecture.md` after each P0/P1 protocol or wire-format change.
2. Maintain a release checklist covering threat model, caller responsibilities,
   unsupported features, test commands, fuzz commands, lint commands, and audit
   status.
3. Document the external cryptographic audit scope for CGGMP21, Paillier/ZK,
   identifiable abort, FROST/RFC 9591 conformance, and wire-format canonicality.
4. Keep `ExperimentalSecurityNotice` until the final CGGMP21 implementation and
   audit results justify removing it.
5. Ensure every exported identifier has a Go doc comment starting with the
   identifier name.

### Acceptance Criteria

- The README accurately distinguishes reviewed production behavior from
  unsupported or unaudited behavior.
- Audit scope and unresolved risks are explicit.
- All exported identifiers pass `doccheck_test.go`.
- Final release candidates pass `go test -race ./...` and `golangci-lint run`.

## General Handoff Checklist for Substantial Changes

- Update docs for any API, wire-format, or protocol behavior change.
- Add or refresh executable examples when public behavior changes.
- Add tests for success paths: `1-of-1`, `2-of-3`, and `3-of-5`.
- Add tests for duplicate/replayed messages, malformed scalar or point payloads,
  wrong session id, wrong signer set, signature verification failure, and blame
  attribution when applicable.
- Run `go test -race ./...`.
- Run `golangci-lint run`.
