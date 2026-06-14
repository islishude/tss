# AGENTS.md

This repository is a Go threshold-signature library under module `github.com/islishude/tss`.

The codebase is security-sensitive. Treat protocol logic, wire formats, transcript construction, proof domains, key-share handling, and presign handling as consensus/security boundaries, not ordinary application code.

For testing rules, required invariants, test tiers, fuzzing, golden vectors, and crash/restart expectations, read [`docs/testing-rules.md`](docs/testing-rules.md) before adding or changing tests.

## Non-Negotiable Rules

- Do not read, copy, port, or derive code from public TSS implementations in Go or any other language.
- Papers, RFCs, standards, and public test vectors or test scenarios are acceptable references.
- Keep protocol boundaries explicit:
  - `cggmp21/secp256k1` is threshold ECDSA over secp256k1.
  - `frost/ed25519` is FROST-style EdDSA over Ed25519.
- Do not preserve retired wire shapes with compatibility shims. Remove retired conversion paths instead of adding fallback decoding.
- Do not add `v2`, `v3`, or other compatibility versions for wire formats, proofs, or challenge labels before production readiness. There is no legacy production data to preserve.
- Never use `math/big.Int.Exp` with a secret exponent. Secret-exponent modular exponentiation must go through `internal/paillier/paillierct`.
- Secret scalars must use `internal/secret.Scalar`. Do not expose secret scalars through `String()`, variable-length `Bytes()`, `BigInt()`, JSON, logs, panic messages, or formatted errors.
- Never place private shares, nonces, Paillier private-key material, MtA secrets, presign secrets, or other witness material in `BlameEvidence`, logs, test failure messages, or public error strings.
- CGGMP21 presigns are one-use objects. A presign must not be reusable across digests, sessions, signer sets, key shares, BIP32 paths, serialization round trips, shallow copies, restarts, or concurrent calls.

## Minimal Local Checks

Prefer the smallest command that validates the code you changed.

```sh
# Fast feedback for ordinary changes.
make check

# Broader fast feedback before a PR.
make ci

# Formatting and module hygiene.
gofmt -w changed-go-files

# Formatting markdowns and json files
npx -y prettier -w file/dir/glob

# Apply source-modifying fixes, formatting, and module tidy
make fix-all
```

Use heavier checks only when the changed area justifies them or the task explicitly asks for them:

```sh
# Full protocol flows.
make test-integration

# Production-parameter crypto smoke tests.
make test-slowcrypto

# Race-sensitive protocol or presign changes.
make test-race
```

Do not run stress, long fuzzing, production-parameter, or race suites by default. Use them deliberately.

## Architecture Map

- Root package `tss`: session IDs, party IDs, envelopes, envelope guards, replay handling, blame evidence, errors, and reference storage-encryption helpers.
- `frost/ed25519`: dealerless FROST-style Ed25519 DKG, signing, partial verification, aggregation, refresh, reshare, and non-hardened HD derivation.
- `cggmp21/secp256k1`: CGGMP21-style threshold ECDSA keygen, presign, online signing, refresh, reshare, non-hardened BIP32 derivation, and evidence verification.
- `internal/wire`: strict canonical TLV encoding for envelopes, key shares, presign records, MtA messages, Paillier keys, and proof payloads.
- `internal/transcript`: canonical labeled SHA-256 transcript builder for domain-separated hashing across all protocol packages.
- `internal/secret`: fixed-length secret scalar representation.
- `internal/paillier`: Paillier primitives, key generation, encryption, decryption, and homomorphic operations.
- `internal/paillier/paillierct`: constant-time modular exponentiation for secret-exponent paths.
- `internal/mta`: Paillier MtA helpers for CGGMP21 presign/sign flows.
- `internal/zk/*`: zero-knowledge proofs used by CGGMP21 and related primitives.
- `internal/shamir`: Shamir sharing and interpolation.
- `internal/curve/*`: curve-specific scalar, point, commitment, and signature helpers.
- `internal/testutil`/`internal/testharness`: shared test helpers, deterministic readers, party/session factories, mutation helpers, assertions, fixtures, and reduced-parameter test controls.
- `internal/testvectors`: canonical test vector files. `wire/v1/` holds binary golden vectors (wire format compatibility contracts) for envelope, FROST, CGGMP21, and ZK proofs. `protocol/` holds JSON cross-implementation vectors for FROST Ed25519 and CGGMP21 secp256k1 full protocol flows. All golden tests and vector generation/verification tests reference this directory. Regenerate with `UPDATE_GOLDEN=1` (binary) or `-tags=vectorgen` (JSON). See `internal/testvectors/README.md` for the full command reference.

## Coding Rules

- Keep files focused on one responsibility. Split code when protocol flow, serialization, validation, and storage concerns start mixing.
- Prefer protocol-local helpers over broad abstractions. Introduce shared helpers only when they centralize an invariant used by multiple packages.
- Add Go doc comments for every exported identifier. Comments must start with the identifier name. internal comments should explain intent, constraints, assumptions, or edge cases.
- Comment protocol equations, transcript construction, domain separation, and security-sensitive shortcuts. Avoid comments that merely restate the code.
- Fail closed on malformed or unexpected input. Wrong session, protocol, version, round, sender, recipient, signer set, threshold, transcript hash, payload type, scalar, point, proof, or encoding must return an error.
- Reject duplicate, replayed, equivocated, out-of-order, or cross-session messages unless a protocol phase explicitly buffers them. Buffered messages must be revalidated before use.
- Do not accept non-canonical wire encodings. Duplicate tags, trailing bytes, non-minimal integers, oversized fields, wrong type IDs, and missing required fields must be rejected.
- Keep domain separation explicit. Challenges, transcript hashes, commitments, proof statements, and signature shares must bind all relevant context.

## Documentation Rules

- Update `docs/*.md` when behavior, API, wire format, security assumptions, lifecycle requirements, or storage expectations change.
- Update [`docs/testing-rules.md`](docs/testing-rules.md) when adding a new test tier, invariant class, protocol phase, or shared test harness pattern.
- Add or update executable examples when the public API changes.
- Keep security notes precise. Do not claim production audit, constant-time behavior, zeroization guarantees, or crash safety unless the code and tests support the claim.
