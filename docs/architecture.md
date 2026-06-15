# Architecture

This module is a transport-neutral threshold-signature library. The public API is split by protocol family:

- `github.com/islishude/tss`: shared session ids, envelopes, algorithm identifiers, key-share/signature interfaces, protocol errors, and blame evidence.
- `github.com/islishude/tss/frost/ed25519`: dealerless FROST-style Ed25519 DKG and two-round signing.
- `github.com/islishude/tss/cggmp21/secp256k1`: CGGMP21-style secp256k1 threshold ECDSA keygen, presign, online signing, key refresh, resharing, BIP32 HD derivation, and evidence verification.
- `internal/wire`: strict TLV encoding used by binary envelope, key-share, and presign records.
- `internal/curve`, `internal/shamir`, `internal/paillier`, `internal/paillier/paillierct`, `internal/secret`, `internal/mta`, and `internal/zk`: protocol-local cryptographic helpers. `paillierct` wraps constant-time `c^λ mod n²` via `filippo.io/bigmod`. `secret.Scalar` is a fixed-length secret type that rejects JSON and variable-length encoding. Curve scalar and field wrappers use committed fiat-crypto generated arithmetic under `internal/fiat`.
- `internal/zk/signprep`: CGGMP21 signprep proof (Πsignprep) proving that a signer's published KPoint and ChiPoint during presign round 3 are correctly derived from its private nonce and signing key contribution, bound to the presign transcript.

## Transport Model

Protocol start APIs return outbound `tss.Envelope` values. Inbound handlers
accept `tss.InboundEnvelope`, which integrators construct by calling
`OpenEnvelope(raw, ReceiveInfo, ...)` after authenticating the peer and
classifying the actual channel protection. The library does not open sockets,
retry messages, authenticate peers, encrypt payloads, or persist state.
Integrators must provide authenticated delivery, confidentiality for
secret-bearing envelopes, reliable ordering, broadcast certificates where
required by `PolicySet`, and replay protection via `ReplayCache`.

`EnvelopeGuard.Validate` is the first fail-closed boundary after opening. It
checks protocol name, version, session id, sender membership, transport
authentication, identity binding, delivery mode, confidentiality policy,
broadcast consistency, and replay before package-specific state machines decode
payloads.

## Key-Share Lifecycle

Keygen state machines produce algorithm-specific `KeyShare` records. `MarshalBinary` is deterministic and uses canonical TLV encoding for the share record. Secret material is not encrypted by this package; callers must encrypt persisted shares when needed and call `Destroy` when practical.

CGGMP21 key shares include Paillier private material, Ring-Pedersen parameters/proofs, proof data, and optional HD chain-code material needed by the signing path. Old CGGMP21 shares without current Paillier/ZK fields are rejected and require rerunning keygen. Old GG20 wire identifiers are rejected.

## Signing Lifecycle

FROST Ed25519 signs in two online rounds: nonce commitments, then partial signatures. Aggregation verifies each partial before producing a 64-byte Ed25519 signature accepted by `crypto/ed25519.Verify`.

CGGMP21 secp256k1 separates offline presign from online signing. Presign records contain local one-use `k_i` and `chi_i` values and must not be shared. `NewPresignPlan` binds key id, chain id, derivation path, policy domain, message domain, signer set, and key metadata before nonce generation. `NewSignPlan` binds the presign, message, low-S policy, and durable attempt policy; `StartSign` verifies the plan against the key and presign, constructs a candidate partial locally, then calls `CommitSignAttempt` as the only durable linearization point before returning the envelope. A committed, outcome-unknown, or possibly sent presign can only resume the same immutable attempt; delivery ACKs/certificates and final signature visibility are persisted as separate durable state on that attempt.

## Public vs Internal

The public packages expose state-machine APIs and deterministic encoding. Internal packages are intentionally narrow helpers for curve arithmetic, sharing, Paillier, MtA, and proof binding. They are documented because protocol reviewers need to understand their invariants, but they are not stable public API.
