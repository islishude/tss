# Cryptographic Audit Guide

This document maps the active ZK proof surface for independent review. The
`cggmp21/secp256k1` package name is retained, but the Paillier proof baseline is
the CGGMP24 revision for Πmod and Ring-Pedersen Πprm.

## Proof Inventory

| Proof                      | Wire Type                         | Code Location                                                               |
| -------------------------- | --------------------------------- | --------------------------------------------------------------------------- |
| Πmod (`ModulusProof`)      | `zk.paillier.modulus-proof`       | `internal/zk/paillier/proofs.go` `ProveModulus` / `VerifyModulus`           |
| Πprm (`RingPedersenProof`) | `zk.paillier.ring-pedersen-proof` | `internal/zk/paillier/proofs.go` `ProveRingPedersen` / `VerifyRingPedersen` |
| ΠEnc (`EncryptionProof`)   | `zk.paillier.encryption-proof`    | `internal/zk/paillier/proofs.go` `ProveEncryption` / `VerifyEncryption`     |
| Πmta (`MTAResponseProof`)  | `zk.paillier.mta-response-proof`  | `internal/zk/paillier/proofs.go` `ProveMTAResponse` / `VerifyMTAResponse`   |
| Πlog (`LogProof`)          | `zk.paillier.log-proof`           | `internal/zk/paillier/proofs.go` `ProveLog` / `VerifyLog`                   |
| Schnorr proof              | `zk.schnorr.proof`                | `internal/zk/schnorr/schnorr.go`                                            |

## Review Focus

- Every proof verifier performs structural validation before algebraic checks.
- Πmod must derive all `y_i` values from the verifier transcript and must reject
  any non-exact round count or extra proof fields.
- Paillier ciphertexts must be in `Z*_{N²}` and Ring-Pedersen elements must be in
  `Z*_N` before proof equations are evaluated.
- secp256k1 points must be compressed canonical points and never infinity.
- Presigns are bound to `PresignContext` and cannot be consumed under a different
  key id, chain id, derivation path, policy domain, or message domain.
- Raw digest signing is only available through full interactive signing
  (`SignDigestInteractive`); persisted presigns use `StartSign` with a
  context-bound message.

See [paillier-zk-proofs.md](paillier-zk-proofs.md) for proof statements,
transcript inputs, and verifier checks.
