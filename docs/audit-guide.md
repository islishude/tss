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

The retired `EncryptionProof`, `MTAResponseProof`, and `LogProof` types and
wire decoders have been removed. Round 1 uses per-verifier `EncProof` (`Πenc`);
there is no legacy proof fallback.

## Review Focus

- Every proof verifier performs structural validation before algebraic checks.
- Πmod must derive all `y_i` values from the verifier transcript and must reject
  any non-exact round count or extra proof fields.
- Paillier ciphertexts must be in `Z*_{N²}` and Ring-Pedersen elements must be in
  `Z*_N` before proof equations are evaluated.
- `SecurityParams.MinPaillierBits` is enforced for both Paillier public moduli
  and Ring-Pedersen auxiliary moduli before verifier equations run.
- Πenc, Πaff-g, and Πlog\* proofs require Ring-Pedersen commitments to hide
  integer witnesses; commitment nonces are sampled from the configured
  `SecurityParams` ranges.
- Schnorr witnesses and challenges use fixed-width secp256k1 scalar arithmetic;
  `internal/zk/schnorr` contains no `math/big` boundary.
- Paillier witnesses, randomness, masks, Ring-Pedersen lambda, private factors,
  and MtA openings use `secret.Scalar` or `secret.SignedInt`. Public moduli,
  ciphertexts, challenges, and proof responses remain `big.Int`.
- Verifier range checks (z1 ∈ ±2^(EncRange+1), z3 ∈ ±(N · 2^(EncRange+1)), etc.)
  must precede algebraic equation checks.
- secp256k1 points must be compressed canonical points and never infinity.
- Presigns are bound to `tss.SigningContext`/`PresignContext` and cannot be consumed under a different
  key id, chain id, derivation path, policy domain, or message domain.
- Reshare receiver Paillier/Ring-Pedersen proofs and final reshare key-share
  proofs bind the canonical `ResharePlan.Digest()` so receiver material cannot
  be replayed across old/new party sets, thresholds, chain codes, or dealer sets.
- Raw digest signing is not exposed through a public convenience API; persisted
  presigns use `StartSign` with a context-bound message.

See [paillier-zk-proofs.md](paillier-zk-proofs.md) for proof statements,
transcript inputs, and verifier checks.
