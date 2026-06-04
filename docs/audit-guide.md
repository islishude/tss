# Cryptographic Audit Guide

This document maps the active ZK proof surface for independent review. The
`cggmp21/secp256k1` package name is retained, but the Paillier proof baseline is
the CGGMP24 revision for Πmod and Ring-Pedersen Πprm.

## Proof Inventory

| Proof                      | Wire Type                         | Code Location                                                               |
| -------------------------- | --------------------------------- | --------------------------------------------------------------------------- |
| Πmod (`ModulusProof`)      | `zk.paillier.modulus-proof`       | `internal/zk/paillier/proofs.go` `ProveModulus` / `VerifyModulus`           |
| Πprm (`RingPedersenProof`) | `zk.paillier.ring-pedersen-proof` | `internal/zk/paillier/proofs.go` `ProveRingPedersen` / `VerifyRingPedersen` |
| Πenc (`EncProof`)          | `zk.paillier.enc-proof`           | `internal/zk/paillier/enc.go` `ProveEnc` / `VerifyEnc`                      |
| Πaff-g (`AffGProof`)       | `zk.paillier.aff-g-proof`         | `internal/zk/paillier/affg.go` `ProveAffG` / `VerifyAffG`                   |
| Πlog\* (`LogStarProof`)    | `zk.paillier.logstar-proof`       | `internal/zk/paillier/logstar.go` `ProveLogStar` / `VerifyLogStar`          |
| Schnorr proof              | `zk.schnorr.proof`                | `internal/zk/schnorr/schnorr.go`                                            |

Legacy proof types (v1) `EncryptionProof` (Π^Enc), `MTAResponseProof` (Π^mta), and `LogProof` (Π^log) remain in `proofs.go` for the MtA Start broadcast path but are rejected everywhere else.

## Review Focus

- Every proof verifier performs structural validation before algebraic checks.
- Πmod must derive all `y_i` values from the verifier transcript and must reject
  any non-exact round count or extra proof fields.
- Paillier ciphertexts must be in `Z*_{N²}` and Ring-Pedersen elements must be in
  `Z*_N` before proof equations are evaluated.
- Πenc, Πaff-g, and Πlog\* proofs require Ring-Pedersen commitments to hide
  integer witnesses; commitment nonces are sampled from the configured
  `SecurityParams` ranges.
- Verifier range checks (z1 ∈ ±2^(EncRange+1), z3 ∈ ±(N · 2^(EncRange+1)), etc.)
  must precede algebraic equation checks.
- secp256k1 points must be compressed canonical points and never infinity.
- Presigns are bound to `PresignContext` and cannot be consumed under a different
  key id, chain id, derivation path, policy domain, or message domain.
- Raw digest signing is only available through full interactive signing
  (`SignDigestInteractive`); persisted presigns use `StartSign` with a
  context-bound message.

See [paillier-zk-proofs.md](paillier-zk-proofs.md) for proof statements,
transcript inputs, and verifier checks.
