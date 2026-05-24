# Architecture

This module is a transport-neutral threshold-signature library. The public API is split by protocol family:

- `github.com/islishude/tss`: shared session ids, envelopes, algorithm identifiers, key-share/signature interfaces, protocol errors, and blame evidence.
- `github.com/islishude/tss/frost/ed25519`: dealerless FROST-style Ed25519 DKG and two-round signing.
- `github.com/islishude/tss/cggmp21/secp256k1`: experimental CGGMP21-style secp256k1 threshold ECDSA keygen, presign, online signing, and evidence verification.
- `internal/wire`: strict TLV encoding used by binary envelope, key-share, and presign records.
- `internal/curve`, `internal/shamir`, `internal/paillier`, `internal/mta`, and `internal/zk`: protocol-local cryptographic helpers. Curve scalar and field wrappers use committed fiat-crypto generated arithmetic under `internal/fiat`.

## Transport Model

All protocol APIs return `tss.Envelope` values. The library does not open sockets, retry messages, authenticate peers, encrypt payloads, or persist state. Integrators must provide authenticated delivery, confidentiality for envelopes with `ConfidentialRequired`, reliable ordering, and replay protection.

`Envelope.ValidateBasic` is the first fail-closed boundary. It checks protocol name, version, session id, transcript hash, and sender membership before package-specific state machines decode payloads.

## Key-Share Lifecycle

Keygen state machines produce algorithm-specific `KeyShare` records. `MarshalBinary` is deterministic and uses canonical TLV encoding for the share record. Secret material is not encrypted by this package; callers must encrypt persisted shares when needed and call `Destroy` when practical.

CGGMP21 key shares include Paillier private material, proof data, and optional HD chain-code material needed by the signing path. Old CGGMP21 shares without Paillier/ZK fields can be decoded as records, but `StartPresign` rejects them and requires rerunning keygen. Old GG20 wire identifiers are rejected.

## Signing Lifecycle

FROST Ed25519 signs in two online rounds: nonce commitments, then partial signatures. Aggregation verifies each partial before producing a 64-byte Ed25519 signature compatible with `crypto/ed25519.Verify`.

CGGMP21 secp256k1 separates offline presign from online signing. Presign records contain local one-use `k_i` and `chi_i` values and must not be shared. `StartSignDigest` marks a presign consumed before producing any outbound online signing message. `StartSignDigestWithOptions` can apply a caller-provided additive public-key shift during online signing.

## Public vs Internal

The public packages expose state-machine APIs and deterministic encoding. Internal packages are intentionally narrow helpers for curve arithmetic, sharing, Paillier, MtA, and proof binding. They are documented because protocol reviewers need to understand their invariants, but they are not stable public API.
