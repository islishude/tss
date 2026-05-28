# Test Vectors

This directory contains JSON test vectors for cross-implementation verification of the TSS library.

## Format

Each file is a JSON array of test cases. Every test case includes:

- `description`: human-readable test description
- `threshold`: signing threshold
- `n`: total number of participants (keygen) or signers (signing)
- `parties`: array of party IDs (1-indexed)
- `seed`: hex-encoded 32-byte deterministic seed used for randomness

### FROST Ed25519 (`frost_ed25519_vectors.json`)

Each case includes DKG outputs and signing results:

- `group_public_key`: hex-encoded 32-byte Ed25519 public key
- `keygen_shares`: array of hex-encoded key share TLV encodings
- `message`: hex-encoded message bytes
- `signers`: array of party IDs for signing
- `signature`: hex-encoded 64-byte Ed25519 signature (`R || z`)

### CGGMP21 secp256k1 (`cggmp21_secp256k1_vectors.json`)

Each case includes keygen and signing outputs:

- `group_public_key`: hex-encoded 33-byte compressed secp256k1 public key
- `keygen_shares`: array of hex-encoded key share TLV encodings
- `presigns`: array of hex-encoded presign TLV encodings
- `digest`: hex-encoded 32-byte SHA-256 digest
- `signature`: object with `r` and `s` hex-encoded 32-byte scalars

## Generation

Vectors are generated from deterministic ChaCha8-based randomness seeded from `seed`.
Regenerate with:

```sh
go test -run TestGenerateVectors -tags=vectorgen ./...
```

## Verification

Run against the library implementation:

```sh
go test -run TestCrossImplementationVectors ./...
```
