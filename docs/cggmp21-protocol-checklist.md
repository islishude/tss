# CGGMP secp256k1 Protocol Checklist

This checklist tracks the active `cggmp21/secp256k1` implementation. The package
name is historical; the Paillier proof layer uses CGGMP24 Πmod and
Ring-Pedersen Πprm semantics.

## Keygen, Refresh, Reshare

| Requirement                                                                        | Code Location                                                              | Status |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------ |
| Generate Paillier safe-prime modulus `N=pq` with `p≡q≡3 mod 4`                     | `internal/paillier`, `keygen.go`, `refresh.go`, `reshare.go`               | DONE   |
| Prove and verify CGGMP24 Πmod with `w` and exactly 128 verifier-derived rounds     | `internal/zk/paillier/proofs.go`                                           | DONE   |
| Generate, store, and verify Ring-Pedersen `(N,s,t)` parameters and Πprm            | `internal/zk/paillier/proofs.go`, `keygen.go`, `refresh.go`, `reshare.go`  | DONE   |
| Generate `T=τ²`, `S=T^λ` and require public Jacobi `+1` for both bases             | `internal/zk/paillier/ring_pedersen.go`                                    | DONE   |
| Prove receiver-specific Πfac and enforce `2^Ell < p,q < 2^Ell sqrt(N)`             | `internal/zk/paillier/factor.go`, keygen/refresh/reshare handlers          | DONE   |
| Persist and revalidate every remote Πfac against the local verifier parameters     | `keyshare.go`, lifecycle completion paths                                  | DONE   |
| Reject mismatched Ring-Pedersen modulus vs Paillier public key                     | `types.go`, protocol receive handlers                                      | DONE   |
| Bind keygen/refresh/reshare transcripts to Paillier keys and Ring-Pedersen records | `keygen.go`, `refresh.go`, `reshare.go`                                    | DONE   |
| Prove share-to-verification-share discrete-log equality with Πlog\*                | `keygen.go`, `refresh.go`, `reshare.go`, `internal/zk/paillier/logstar.go` | DONE   |
| Preserve group secret in party-set-changing reshare with Lagrange-weighted dealers | `reshare.go`, `internal/shamir`                                            | DONE   |
| Source new Paillier/Ring-Pedersen material from the new receiver set               | `reshare.go`                                                               | DONE   |
| Accept reshare Πfac before receiver broadcast and reject a later key conflict      | `reshare.go`, `reshare_round1.go`                                          | DONE   |
| Store only canonical TLV key-share records with no legacy proof fallback           | `encoding.go`, `payload_encoding.go`                                       | DONE   |

## Proof Verifier Policy

| Requirement                                                                                | Code Location                                 | Status |
| ------------------------------------------------------------------------------------------ | --------------------------------------------- | ------ |
| Structural validation before algebraic comparison                                          | `internal/zk/paillier/proofs.go`              | DONE   |
| Reject non-canonical scalar responses and wrong-width Paillier integers                    | `internal/zk/paillier/proofs.go`              | DONE   |
| Reject Paillier ciphertexts outside `Z*_{N²}`                                              | `internal/paillier`, `internal/zk/paillier`   | DONE   |
| Reject invalid Ring-Pedersen parameters outside `Z*_N`                                     | `ValidateRingPedersenParams`                  | DONE   |
| Reject malformed secp256k1 points before challenge derivation                              | `internal/zk/paillier`, `internal/zk/schnorr` | DONE   |
| Domain separate every active proof tag and bind curve/version/domain/statement/commitments | `proofTranscript`, `domain.go`                | DONE   |

## Presign And Signing

| Requirement                                                                     | Code Location                                        | Status |
| ------------------------------------------------------------------------------- | ---------------------------------------------------- | ------ |
| Bind presigns to `tss.SigningContext`/`PresignContext` before nonce generation  | `NewPresignPlan` + `StartPresign`                    | DONE   |
| Bind key id, chain id, derivation path, policy domain, and message domain       | `presignContextHash`, `Presign` TLV                  | DONE   |
| Move BIP32 path resolution into presign creation                                | `preparePresignContext`, `tryEmitRound3`             | DONE   |
| Reject online signing under mismatched context, path, or derived key before use | `StartSign`                                          | DONE   |
| Mark presign consumed before emitting online partial                            | `startSignDigestBound`                               | DONE   |
| Avoid raw digest signing with persisted presigns                                | no public raw-digest signing helper; use `StartSign` | DONE   |
| Reject early identification without committing its replay slot                  | `guard.go`, sign/presign handlers                    | DONE   |
| Verify built-in identification evidence from authenticated public context       | `identification_portable.go`, `evidence.go`          | DONE   |
| Bind sign replay inputs and fit portable evidence at the 16-signer limit        | `identification_portable.go`, evidence size tests    | DONE   |

## Negative Tests

| Scenario                                                                               | Test Location                                                    |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Πmod Jacobi, round count, missing equations, invalid `Z*_N` elements, extra fields     | `internal/zk/paillier/proofs_test.go`                            |
| Invalid Ring-Pedersen params, response bounds, wrong transcript/party/domain           | `internal/zk/paillier/proofs_test.go`, `encoding_test.go`        |
| Πfac canonical wire, field mutation, context replay, response bounds, small-factor key | `internal/zk/paillier/factor*_test.go`, `payload_limits_test.go` |
| Invalid ciphertexts, malformed points, non-canonical responses                         | `internal/zk/paillier/proofs_test.go`                            |
| MtA proof domain binds presign context                                                 | `domain_test.go`                                                 |
| MtA additive masks use EllPrime-width fixed secret integers                            | `internal/mta/helpers_test.go`                                   |
| SignPrep binds ordered round-2 payload commitments                                     | `integration_presign_adversary_test.go`                          |
| Round1 Πlog\* binds EncK to KPoint; SignPrep binds delta and sigma MtA equations       | `domain_test.go`, `internal/zk/signprep/correctness_test.go`     |
| Presign reuse across key id, chain id, derivation path, policy domain, message domain  | `presign_policy_test.go`                                         |
| Early identification retry and portable evidence verification/mutation                 | `guard_test.go`, `integration_identification_test.go`            |
