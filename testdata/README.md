# Test Vectors

This directory contains JSON test vectors for cross-implementation verification of the TSS library.

## Format

Each file is a JSON array of test cases. Every test case includes:

- `description`: human-readable test description
- `threshold`: signing threshold
- `n`: total number of participants (keygen) or signers (signing)
- `parties`: array of party IDs (1-indexed)
- `seed`: hex-encoded 32-byte seed. For FROST Ed25519 this is the deterministic ChaCha8 seed used for keygen and signing. CGGMP21 secp256k1 vectors include the seed for documentation but are non-deterministic (Schnorr proofs use `crypto/rand`).
- `group_public_key`: hex-encoded public key for the group
- `keygen_shares`: array of hex-encoded key share TLV encodings

### FROST Ed25519 (`frost_ed25519_vectors.json`)

Each case additionally includes:

- `message`: hex-encoded message bytes
- `signers`: array of party IDs for signing
- `signature`: hex-encoded 64-byte Ed25519 signature (`R || z`). Signatures are non-deterministic (random nonces); the stored signature is verified for validity against the group public key and message, but fresh sign calls will produce different signatures.

FROST vectors are deterministic: re-running keygen with the same seed always produces the same group public key and key share encodings. Signatures are non-deterministic because each sign call uses fresh random nonces.

### CGGMP21 secp256k1 (`cggmp21_secp256k1_vectors.json`)

Each case additionally includes:

- `presigns`: array of hex-encoded presign TLV encodings
- `digest`: hex-encoded 32-byte SHA-256 digest
- `signature`: object with `r` and `s` hex-encoded 32-byte scalars

CGGMP21 vectors are non-deterministic: keygen and signing use `crypto/rand.Reader` for Schnorr proof nonces. The vector file acts as a format regression check — verifying that stored TLV encodings decode, validate, round-trip, and produce verifiable signatures.

## Generation

Regenerate vector files with:

```sh
go test -run TestGenerateVectors -tags=vectorgen ./...
```

This runs the `vectorgen` build-tag tests that produce fresh `frost_ed25519_vectors.json` and `cggmp21_secp256k1_vectors.json`.

## Verification

Run against the library implementation:

```sh
go test -run CrossImplementationVectors ./...
```

For FROST, this regenerates key shares from the seed, compares against stored encodings, and verifies that both a fresh signature and the stored signature are valid against the group public key. For CGGMP21, this verifies that stored encodings decode, validate, round-trip, and that stored signatures verify against group public keys.
