# Test Vectors

This directory is the **single canonical location** for all test vectors: binary wire-format golden files and JSON cross-implementation protocol vectors. Previously these were scattered across per-package `testdata/` directories.

## Structure

```
wire/v1/                          — binary golden vectors (wire format stability)
  envelope/   1 file               — Envelope.golden
  frost/      5 files              — KeyShare, KeygenCommitmentsPayload, KeygenSharePayload,
                                     NonceCommitmentPayload, SignPartialPayload
  cggmp21/    5 files              — KeyShare, KeygenSharePayload, Presign,
                                     PresignRound3Payload, SignPartialPayload
  zk/         10 files             — ModulusProof, RingPedersenParams, RingPedersenProof,
                                     EncryptionProof, MTAResponseProof, LogProof,
                                     EncProof, AffGProof, LogStarProof, SchnorrProof

protocol/                           — JSON cross-implementation vectors (protocol flows)
  frost-ed25519/       1 file      — frost_ed25519_vectors.json
  cggmp21-secp256k1/   1 file      — cggmp21_secp256k1_vectors.json
```

**Total: 21 binary wire vectors + 2 JSON protocol vectors = 23 files.**

## Golden Files (`wire/v1/`)

Binary golden files are compatibility contracts. Every `.golden` file encodes a single wire-format object as a hex string. They are validated by `golden_test.go` files in each protocol package.

### Regeneration

To regenerate **all** binary golden vectors after a wire format change:

```sh
# Tier 0 + Tier 1 golden tests (envelope, FROST, ZK)
UPDATE_GOLDEN=1 go test -run 'TestGolden' -count=1 . ./frost/ed25519 ./internal/zk/paillier ./internal/zk/schnorr

# Tier 2 golden tests (CGGMP21 — requires full keygen/presign)
UPDATE_GOLDEN=1 go test -tags=integration -run 'TestGolden' -count=1 ./cggmp21/secp256k1
```

Or regenerate a single file:

```sh
UPDATE_GOLDEN=1 go test -run 'TestGoldenKeyShare$' -count=1 ./frost/ed25519
```

### Verification

Golden tests read the `.golden` file, compare it against a freshly marshaled object, and verify round-trip + trailing-byte rejection:

```sh
go test -run 'TestGolden' ./...
go test -tags=integration -run 'TestGolden' ./cggmp21/secp256k1
```

### Versioning

Files are versioned by directory (`v1`, `v2`, ...). When a wire format change is intentional:

1. Create a new `v2/` directory tree.
2. Copy `v1/` vectors as the starting point (or regenerate fresh).
3. Update `golden_test.go` references to `v2/`.
4. **Never modify `v1/` vectors in place** — they remain as the prior-format compatibility contract.

## Protocol Vectors (`protocol/`)

JSON files for cross-implementation verification. Each file is a JSON array of test cases containing deterministic keygen parameters, key share encodings, group public keys, and (for FROST) message/signature pairs or (for CGGMP21) presign encodings and signatures.

### FROST Ed25519 (`frost_ed25519_vectors.json`)

Each case:

- `threshold`, `n`, `parties` — keygen parameters
- `seed` — hex-encoded 32-byte ChaCha8 seed (deterministic keygen)
- `group_public_key` — hex-encoded public key
- `keygen_shares` — array of hex-encoded key share TLV encodings
- `message` — hex-encoded message bytes
- `signers` — array of party IDs for signing
- `signature` — hex-encoded 64-byte Ed25519 signature (`R || z`)

FROST vectors are **deterministic**: re-running keygen with the same seed always produces the same group public key and key share encodings. Signatures are non-deterministic (fresh random nonces per sign call); the stored signature is verified for validity but fresh sign calls produce different signatures.

### CGGMP21 secp256k1 (`cggmp21_secp256k1_vectors.json`)

Each case:

- `threshold`, `n`, `parties` — keygen parameters
- `seed` — documentation only (CGGMP21 uses `crypto/rand` for Schnorr proof nonces)
- `group_public_key` — hex-encoded public key
- `keygen_shares` — array of hex-encoded key share TLV encodings
- `presigns` — array of hex-encoded presign TLV encodings
- `digest` — hex-encoded 32-byte SHA-256 digest
- `signature` — object with `r` and `s` hex-encoded 32-byte scalars

CGGMP21 vectors are **non-deterministic**: keygen and signing use `crypto/rand.Reader` for Schnorr proof nonces. The vector file acts as a format regression check — verifying that stored TLV encodings decode, validate, round-trip, and produce verifiable signatures.

### Generation

Generate fresh JSON protocol vectors:

```sh
# Method 1: vectorgen build tag (generates full keygen + presign + sign vectors)
go test -run 'TestGenerateVectors$' -tags='vectorgen' -count=1 ./frost/ed25519 ./cggmp21/secp256k1

# Method 2: GENERATE_VECTORS env var (CGGMP21 only, requires integration tag)
GENERATE_VECTORS=1 go test -run 'TestGenerateCGGMP21Vectors' -tags='integration' -count=1 ./cggmp21/secp256k1
```

The `vectorgen` build-tag method is the primary path. `GENERATE_VECTORS=1` is provided as an alternative for regenerating CGGMP21 vectors within the integration test workflow without needing the `vectorgen` tag.

### Verification

Verify stored vectors against the library implementation:

```sh
# FROST — verifies seed → keygen consistency and signature validity
go test -run 'CrossImplementation' -count=1 ./frost/ed25519

# CGGMP21 — verifies TLV decode/validate/round-trip and signature verification
go test -tags=integration -run 'CrossImplementation' -count=1 ./cggmp21/secp256k1
```

## All Regeneration Commands (one-shot)

```sh
# 1. Binary golden vectors (wire format)
UPDATE_GOLDEN=1 go test -run 'TestGolden' -count=1 . ./frost/ed25519 ./internal/zk/paillier ./internal/zk/schnorr
UPDATE_GOLDEN=1 go test -tags=integration -run 'TestGolden' -count=1 ./cggmp21/secp256k1

# 2. JSON protocol vectors (cross-implementation)
go test -run 'TestGenerateVectors$' -tags='vectorgen' -count=1 ./frost/ed25519 ./cggmp21/secp256k1
# Alternative: CGGMP21 only, without vectorgen tag
GENERATE_VECTORS=1 go test -run 'TestGenerateCGGMP21Vectors' -tags='integration' -count=1 ./cggmp21/secp256k1

# 3. Verify everything
go test -run 'TestGolden|CrossImplementation' -count=1 ./...
go test -tags=integration -run 'TestGolden|CrossImplementation' -count=1 ./cggmp21/secp256k1
```

## Adding New Vectors

1. **Binary wire vector**: Add the marshal call to the appropriate `golden_test.go`, run `UPDATE_GOLDEN=1` to generate, then verify without the flag.
2. **JSON protocol vector**: Add a test case to the `vectorgen_test.go` array, run with `-tags=vectorgen`, then verify with the cross-implementation test.
3. Use deterministic RNG with fixed seeds for reproducibility.
4. Document the seed, parameters, and expected invariants in a comment header.
