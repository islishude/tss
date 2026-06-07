# AGENTS.md

This repository contains a Go TSS library under module `github.com/islishude/tss`.

## Non-Negotiable Constraints

- Do not read, copy, port, or derive code from public TSS implementations in Go or any other language.
- It is acceptable to use papers, RFCs, standards, and public test vectors or test scenarios.
- Keep the protocol boundary honest: CGGMP21 applies to ECDSA/secp256k1; Ed25519 uses FROST-style EdDSA.
- Do not preserve prior-format fallback paths while moving toward the production target. Existing conversion code for retired wire shapes must be removed rather than supported.
- Do not introduce backward-compatibility versioning (v2, v3, etc.) for wire formats, proofs, or challenge labels before production-readiness. There is no legacy data to be compatible with. Use v1 and evolve it in place.
- Never use `math/big.Int.Exp` when the exponent is a secret (`λ`, `μ`, `b` in MtA). All secret-exponent modular exponentiation must go through `internal/paillier/paillierct` (`filippo.io/bigmod`).
- Secret scalars must use `secret.Scalar` (fixed-length bytes). Never expose them via `String()`, variable-length `Bytes()`, `BigInt()`, or JSON.

## Useful Commands

Use `make` targets for common operations:

```sh
# Default: fast unit tests (Tier 0, < 30s)
make test

# Tier 0 + Tier 1: fast unit + small-param crypto (< 2m)
make test-fast

# Tier 2: integration tests with full keygen/presign/sign (< 10m)
make test-integration

# Tier 3: production security-parameter smoke tests (< 45m)
make test-slowcrypto

# Tier 4: stress tests with count=10 (3h)
make test-stress

# Race detector across all packages
make test-race

# PR-ready check: build + vet + lint + format + tidy + test-fast
make ci

# Full suite: ci + integration + slowcrypto + race + stress
make nightly

# Build, test-fast, vet, lint (default)
make all

# Run linter with auto-fix
make lint-fix

# Format go and markdown files
make format

# Modernize Go code
make fix

# List all targets
make help
```

Run `make test` after each change for fast feedback. Use `make ci` before pushing a PR.

## Architecture Map

- Root package `tss`: transport-neutral session ids, envelopes, errors, blame evidence, common interfaces, session-id generation, and reference storage-encryption helpers.
- `frost/ed25519`: dealerless FROST-style Ed25519 DKG, two-round signing, partial verification, Ed25519-compatible aggregation, and resharing.
- `cggmp21/secp256k1`: CGGMP21-style threshold ECDSA keygen, presign, online signing, resharing, proactive refresh, BIP32 HD derivation, RefreshScheduler, and evidence verification.
- `internal/shamir`: Shamir sharing and interpolation over caller-provided prime-order fields.
- `internal/curve/edwards25519`: Ed25519 scalar/point helpers and commitment verification.
- `internal/curve/secp256k1`: SEC 2 curve constants, point operations, ECDSA helpers.
- `internal/fiat`: fiat-crypto generated constant-time arithmetic for secp256k1 scalar/field and ed25519 scalar.
- `internal/mta`: Paillier MtA product-share helpers for CGGMP21-style signing (Start/Respond/Finish). `Respond` and `Finish` accept the prover's Paillier key and the verifier's Ring-Pedersen parameters for `Πaff-g` proof construction and verification.
- `internal/paillier`: Paillier public-key primitives (encrypt, decrypt, homomorphic ops, key generation). Secret fields (`Lambda`, `Mu`) use `secret.Scalar`, not `*big.Int`. Decrypt uses constant-time `c^λ mod n²` via `paillierct` with ciphertext blinding.
- `internal/paillier/paillierct`: constant-time modular exponentiation via `filippo.io/bigmod`. Used by `Decrypt` (with ciphertext blinding) and MtA `Respond` (`c^b mod n²`, without blinding — the ZK proof verifies the exact ciphertext relationship).
- `internal/secret`: fixed-length `Scalar` type; no `String()`, `BigInt()`, variable-length `Bytes()`, or JSON.
- `internal/testutil`: shared test helpers — deterministic readers, session/party factories, wire mutation utilities, protocol-error assertions, cached Paillier fixtures, and security-parameter overrides. Used by both Tier 0 (fast) and Tier 2 (integration) tests.
- `internal/wire`: strict TLV encoding for binary envelopes, key shares, presign records, MtA messages, Paillier keys, and all proof payloads.
- `internal/zk/paillier`: ZK proof types — `ModulusProof` (Πmod), `RingPedersenProof` (Πprm), `EncProof` (Πenc, Paillier encryption in range), `AffGProof` (Πaff-g, MtA affine operation), `LogStarProof` (Πlog*, discrete-log equality in range). Current protocol flows use Πmod, Πprm, Πenc, Πaff-g, and Πlog*. Legacy proof types (Π^Enc, Π^mta, Π^log) are present for MtA Start but rejected everywhere else.
- `internal/zk/schnorr`: Schnorr proof-of-knowledge primitive over secp256k1.

## Coding Rules

- Keep files small and organized around one responsibility. Split code when a file starts mixing unrelated concerns or becomes difficult to scan.
- Prefer shared utility packages over hand-rolled helpers to keep invariants centralized
- Prefer small, protocol-local helpers over broad abstractions.
- Keep message decoding fail-closed: wrong session, round, sender, recipient, duplicate message, malformed scalar/point, or transcript mismatch must error.
- Preserve deterministic `MarshalBinary` / `UnmarshalBinary` behavior for key-share types.
- Do not add JSON fallback to binary decoders; use migration helpers separately if legacy data is ever needed.
- Preserve deterministic `BlameEvidence` encoding; never place private shares, nonces, or Paillier private-key material in blame evidence.
- CGGMP21 verification failures that can identify a sender or signer set should populate `ProtocolError.Blame.Evidence` unless the failure is duplicate/replay handling.
- Add Go doc comments for every new exported identifier; comments must start with the identifier name so `doccheck_test.go` can enforce them.
- Add comments around protocol equations, transcript/domain separation, and security-sensitive shortcuts.
- When adding API, wire-format, or protocol behavior, update the relevant `docs/*.md` file and add or refresh an executable example when the public surface changes.
- Avoid comments that restate the line; explain why the check or formula exists.
- Prefer inline comments at call sites that explain the intent (e.g., the invariant being checked), even when the callee has its own doc comment. Inline comments keep the reader in flow and prevent information loss when refactoring.
- Never log or format secret scalar, nonce, or key-share bytes.
- `math/big.Int.Exp` is acceptable only for public-exponent paths: encryption (`g^m`, `r^n`), public proof verification, test vectors, and key generation. For secret-exponent paths (`c^λ mod n²`, `encA^b mod N²`), always use `internal/paillier/paillierct`.
- All inputs to `paillierct` must be fixed-length big-endian encodings. Never use `lambda.BitLen()`, `lambda.Bytes()` (variable-length), or any `VarTime`-suffixed `bigmod` functions.
- Ciphertext blinding (`c' = c * r^n mod n²`) is required in `Paillier.Decrypt`. Do not apply blinding in MtA `Respond` — the ZK proof verifies the exact ciphertext relationship.

## Test Architecture

Tests are organized into 5 tiers, separated by build tags and `testing.Short()` guards:

| Tier  | Build Tag               | Command                 | Content                                                                                             |
| ----- | ----------------------- | ----------------------- | --------------------------------------------------------------------------------------------------- |
| **0** | (none)                  | `make test`             | Wire TLV, state machine, malformed input, domain construction, blame evidence. No crypto keygen.    |
| **1** | (none, `Short()` guard) | `make test-fast`        | Small-param proof correctness (512/1024-bit Paillier), MtA correctness.                             |
| **2** | `integration`           | `make test-integration` | Full keygen→presign→sign, replay/duplicate, BIP32, refresh, reshare. 768-bit Paillier via TestMain. |
| **3** | `slowcrypto`            | `make test-slowcrypto`  | 3072-bit Paillier, production SecurityParams, 3-of-5 flows.                                         |
| **4** | `stress`                | `make test-stress`      | `-count=10`, race detector, long fuzz runs.                                                         |

- **Tier 0 files** must NOT use Paillier keygen, full CGGMP keygen, or full presign. They test input/output, state machine, and wire/security boundaries.
- **Tier 1 files** use reduced crypto params. Every test must check `testing.Short()` and skip when set.
- **Tier 2 files** have `//go:build integration` and use reduced (768-bit) Paillier via `TestMain`. They cover protocol integration: keygen, presign, sign, refresh, reshare, BIP32.
- **Tier 3 files** have `//go:build slowcrypto` and use production 3072-bit Paillier. Smoke coverage only.
- **Tier 4 files** have `//go:build stress` and run with `-count=10` or `-race`. Nightly only.

Shared test helpers live in `internal/testutil` (public) and `cggmp21/secp256k1/helpers_test.go` (package-private).

## Testing Expectations

When changing protocol behavior, add or update tests for:

- success paths for `1-of-1`, `2-of-3`, and `3-of-5`;
- duplicate/replayed messages;
- malformed scalar/point payloads;
- incorrect session id or signer set;
- signature verification failure and blame attribution when applicable;
- proof verification failures (wrong domain, wrong public key, malformed commitment/response);
- presign consumption and nonce-reuse guards;
- reshare and refresh flows preserving the group public key.

Place fast unit tests in Tier 0 (`_test.go` files without build tags). Put integration flows in Tier 2 (`//go:build integration`). Use Tier 3 (`//go:build slowcrypto`) for production-parameter smoke coverage.
