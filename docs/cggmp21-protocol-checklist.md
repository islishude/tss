# CGGMP secp256k1 Protocol Checklist

This checklist tracks the active `cggmp21/secp256k1` implementation. The package
name is historical; the Paillier proof layer uses CGGMP24 Πmod and
Ring-Pedersen Πprm semantics.

## Keygen, Refresh, Reshare

| Requirement                                                                        | Code Location                                                             | Status |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------ |
| Generate Paillier safe-prime modulus `N=pq` with `p≡q≡3 mod 4`                     | `internal/paillier`, `keygen.go`, `refresh.go`, `reshare.go`              | DONE   |
| Prove and verify CGGMP24 Πmod with `w` and exactly 128 verifier-derived rounds     | `internal/zk/paillier/proofs.go`                                          | DONE   |
| Generate, store, and verify Ring-Pedersen `(N,s,t)` parameters and Πprm            | `internal/zk/paillier/proofs.go`, `keygen.go`, `refresh.go`, `reshare.go` | DONE   |
| Reject mismatched Ring-Pedersen modulus vs Paillier public key                     | `types.go`, protocol receive handlers                                     | DONE   |
| Bind keygen/refresh/reshare transcripts to Paillier keys and Ring-Pedersen records | `keygen.go`, `refresh.go`, `reshare.go`                                   | DONE   |
| Prove share-to-verification-share discrete-log equality with Πlog                  | `keygen.go`, `refresh.go`, `reshare.go`                                   | DONE   |
| Store only canonical TLV key-share records with no legacy proof fallback           | `encoding.go`, `payload_encoding.go`                                      | DONE   |

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

| Requirement                                                                         | Code Location                                                | Status |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------ | ------ |
| Bind presigns to `PresignContext` before nonce generation                           | `StartPresignWithContext`                                    | DONE   |
| Bind key id, chain id, derivation path, policy domain, and message domain           | `presignContextHash`, `Presign` TLV                          | DONE   |
| Move BIP32 additive shift into presign creation                                     | `preparePresignContext`, `tryEmitRound3`                     | DONE   |
| Reject online signing under a mismatched context or additive shift before consuming | `StartSign`                                                  | DONE   |
| Mark presign consumed before emitting online partial                                | `startSignDigestBound`                                       | DONE   |
| Avoid raw digest signing with persisted presigns                                    | public API; `SignDigestInteractive` is full-interactive only | DONE   |

## Negative Tests

| Scenario                                                                              | Test Location                                             |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Πmod Jacobi, round count, missing equations, invalid `Z*_N` elements, extra fields    | `internal/zk/paillier/proofs_test.go`                     |
| Invalid Ring-Pedersen params, response bounds, wrong transcript/party/domain          | `internal/zk/paillier/proofs_test.go`, `encoding_test.go` |
| Invalid ciphertexts, malformed points, non-canonical responses                        | `internal/zk/paillier/proofs_test.go`                     |
| MtA proof domain binds presign context                                                | `domain_test.go`                                          |
| Presign reuse across key id, chain id, derivation path, policy domain, message domain | `presign_policy_test.go`                                  |
