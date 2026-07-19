# CGGMP21 secp256k1 Protocol Checklist

This checklist tracks the active `cggmp21/secp256k1` implementation against the
bundled 2024 paper. `DONE` means the repository contains the implementation and
tests; it is not an audit or production-readiness claim.

## Figure 6: Key Generation

| Requirement                                                                      | Code location                                              | Status |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------ |
| Commit `rho_i`, `X_i`, Schnorr first message, and decommitment before reveal     | `paper_keygen.go`, `paper_keygen_figure6.go`               | DONE   |
| Commit the chain-code contribution in round 1 and reveal it only at confirmation | `paper_keygen_figure6.go`, `keygen_confirmation_verify.go` | DONE   |
| Reject a wrong or equivocated round-1 opening before state mutation              | `paper_keygen_figure6.go`, `paper_keygen_payload.go`       | DONE   |
| Derive the common XOR coin from every accepted opening                           | `paper_keygen_figure6.go`                                  | DONE   |
| Finalize Schnorr with the exact committed first message and common coin          | `paper_keygen_figure6.go`, `internal/zk/schnorr`           | DONE   |
| Enter Figure 7/F.1 before exposing a sign-ready `KeyShare`                       | `paper_keygen.go`, `paper_auxiliary_state.go`              | DONE   |

## Figure 7 and Appendix F.1

| Requirement                                                                                           | Code location                                                                 | Status |
| ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------ |
| Generate Paillier `N` and auxiliary `Nhat` with separate local key-generation calls                   | `auxiliary_setup.go`, `internal/zk/paillier/ring_pedersen.go`                 | DONE   |
| Destroy auxiliary factors and trapdoor after preparing public parameters and `Πprm`                   | `auxiliary_setup.go`, `internal/zk/paillier/ring_pedersen.go`                 | DONE   |
| Reject `N == Nhat` and enforce both production modulus floors                                         | `paper_auxiliary_payload.go`, `internal/zk/paillier`                          | DONE   |
| Commit all public setup, polynomial, DH, RID, and proof material before reveal                        | `paper_auxiliary_primitives.go`, `paper_auxiliary_payload.go`                 | DONE   |
| Verify `Πprm`, `Πmod`, and receiver-specific `Πfac` under bound domains                               | `paper_auxiliary_state.go`, `internal/zk/paillier`                            | DONE   |
| Use degree `t-1` Shamir polynomials for repository threshold `t`                                      | `epoch_shamir.go`, `paper_auxiliary_state.go`                                 | DONE   |
| Derive non-zero collision-free identifiers with bounded `H(SID,RID,party,counter)` rejection sampling | `epoch_context.go`, `epoch_context_test.go`                                   | DONE   |
| Encrypt polynomial evaluations with authenticated pairwise DH masks                                   | `paper_auxiliary_primitives.go`, `paper_auxiliary_state.go`                   | DONE   |
| Restrict DH exponent disclosure to the dedicated accusation record                                    | `paper_auxiliary_failure.go`, `paper_auxiliary_payload.go`                    | DONE   |
| Bind the complete epoch and require target-holder confirmation before output                          | `epoch_context.go`, `keygen_confirmation.go`, `keygen_confirmation_verify.go` | DONE   |

## Figure 8: Presigning

| Requirement                                                                   | Code location                                               | Status |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------- | ------ |
| Publish `K_i,G_i,Y_i,A_i,B_i` and verifier-specific `Πenc-elg` proofs         | `presign_round1.go`, `internal/zk/paillier/enc_elg.go`      | DONE   |
| Bind the accepted canonical public round-1 view into every recipient proof    | `presign_round1.go`, `paper_presign_domains.go`             | DONE   |
| Prove `Gamma_i` with `Πelog` and both pairwise affine paths with `Πaff-g`     | `presign_round2.go`, `internal/mta`, `internal/zk/paillier` | DONE   |
| Interpret decrypted affine masks as centered signed integers before reduction | `internal/mta/finish.go`                                    | DONE   |
| Publish `delta_i,Delta_i,S_i` with the Figure 8 `Πelog` relation              | `presign_round3.go`, `internal/zk/paillier/elog.go`         | DONE   |
| Verify both aggregate equations independently before producing an artifact    | `presign_round3.go`, `paper_presign_artifact.go`            | DONE   |
| Reject zero `delta` or invalid ECDSA nonce as an unattributed burned run      | `presign_round3.go`, `paper_presign_artifact.go`            | DONE   |
| Persist only normalized `(Gamma,kTilde_i,chiTilde_i,DeltaTilde,STilde)`       | `paper_presign_artifact.go`, `sign.go`, `encoding.go`       | DONE   |

## Figure 9: Failed Nonce or Chi

| Requirement                                                             | Code location                                     | Status |
| ----------------------------------------------------------------------- | ------------------------------------------------- | ------ |
| Enter only after one Figure 8 aggregate equation fails                  | `figure9.go`, `presign_round3.go`                 | DONE   |
| Publish the aggregated ciphertext and a setup-less `Πdec`               | `figure9.go`, `internal/zk/paillier/dec.go`       | DONE   |
| Publish one setup-less `Πaff-g*` per peer over canonical MtA views      | `figure9.go`, `internal/zk/paillier/affg_star.go` | DONE   |
| Attribute the first invalid proof to its authenticated sender           | `figure9.go`, `evidence.go`                       | DONE   |
| Return an unblamed invariant if all proofs verify but the alert remains | `figure9.go`, `figure9_integration_test.go`       | DONE   |

## Figure 10: Signing

| Requirement                                                                      | Code location                              | Status |
| -------------------------------------------------------------------------------- | ------------------------------------------ | ------ |
| Compute `sigma_i = kTilde_i*m + r*chiTilde_i`                                    | `online_sign_lifecycle.go`                 | DONE   |
| Check every authenticated partial with `Gamma^sigma_i=DeltaTilde_i^m STilde_i^r` | `online_sign_transition.go`                | DONE   |
| Attribute an invalid partial directly without another proof phase                | `online_sign_transition.go`, `evidence.go` | DONE   |
| Sum verified partials and normalize only the final signature to low-S            | `online_sign_session.go`, `low_s_test.go`  | DONE   |

## Durable Lifecycle

| Requirement                                                                                               | Code location                                                                    | Status |
| --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------ |
| Install the first confirmed keygen/import share before a store-backed protocol start                      | `tssrun/lifecycle.go`, `example_integration_helpers_test.go`                     | DONE   |
| Load the exact current generation and validate canonical key material before start                        | `lifecycle_keyshare.go`, `presign_round1.go`                                     | DONE   |
| Acquire a generation-bound presign lease before releasing initial envelopes                               | `presign_round1.go`, `tssrun/lifecycle.go`                                       | DONE   |
| Atomically persist an available presign and finish its lease                                              | `presign_lifecycle.go`, `tssrun/lifecycle.go`, `tssrun/conformance/lifecycle.go` | DONE   |
| Expose only a public persisted descriptor after successful presign commit                                 | `presign_runtime.go`, `presign_runtime_integration_test.go`                      | DONE   |
| Treat a store error after an attempted atomic commit as an outcome requiring authoritative reconciliation | `presign_lifecycle.go`, `tssrun/file_lifecycle_test.go`                          | DONE   |
| Atomically claim availability and persist exact intent and outbox                                         | `online_sign_lifecycle.go`, `sign_attempt_coordinator.go`                        | DONE   |
| Reconcile unknown outcomes only with the exact attempt query                                              | `online_sign_lifecycle.go`, `tssrun/lifecycle.go`                                | DONE   |
| Fence refresh/reshare cutover and burn source-epoch available presigns                                    | `tssrun/lifecycle.go`, `tssrun/conformance/lifecycle.go`                         | DONE   |
| Install a non-hardened child as a distinct lineage after fresh Figure 7/F.1                               | `child_derivation.go`, `child_derivation_plan.go`                                | DONE   |

## Security Profile and Negative Coverage

| Requirement                                                                               | Code location                                                              | Status |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------ |
| Default `(Ell,EllPrime,Epsilon,ChallengeBits)=(256,1280,512,256)`                         | `internal/zk/paillier/params.go`                                           | DONE   |
| Enforce the 3072-bit floor separately for Paillier and auxiliary moduli                   | `internal/zk/paillier`, `paper_auxiliary_payload.go`                       | DONE   |
| Use bounded rejection sampling for canonical non-zero field and modulus challenges        | `internal/zk/challenge`, `internal/zk/paillier/modulus.go`                 | DONE   |
| Reject malformed points, ciphertext non-members, range violations, and wrong domains      | `internal/zk/paillier/` proof-specific tests                               | DONE   |
| Reject wrong epoch, RID, plan, sender, recipient, committee, or signer set                | protocol state-transition and integration tests                            | DONE   |
| Reject early, duplicate, conflicting, replayed, and out-of-order payloads without effects | `presign_state_transition_integration_test.go`, lifecycle transition tests | DONE   |
| Keep Figure 7 accusation records and Figure 9 evidence public-only where required         | `paper_auxiliary_state_test.go`, `figure9_integration_test.go`             | DONE   |

## Review Gaps

- Independent cryptographic review of the Paillier, range-proof, and
  accountability implementations is still required.
- Validation rejects `N == Nhat` but does not explicitly check
  `gcd(N,Nhat) == 1` or prove independent factor generation to peers.
- Active `Πenc-elg`, `Πelog`, `Πaff-g*`, and `Πdec` encoders have canonical
  round-trip and mutation tests, but do not yet have standalone committed
  `internal/testvectors/wire/v1/zk/*.golden` records. Protocol vectors and wire
  goldens for enclosing records do not replace that proof-level audit evidence.
- The repository transport, persistence, and threshold-extension bindings are
  outside the paper's exact protocol model and require separate review.
- Reference file and memory stores are not production durability or key
  management.

The canonical committed evidence roots are
`internal/testvectors/protocol/cggmp21-secp256k1/`,
`internal/testvectors/fixtures/cggmp21-secp256k1/`, and
`internal/testvectors/wire/v1/cggmp21/`. Test-tier ownership and commands live in
[`testing-rules.md`](testing-rules.md) and the `Makefile`; this checklist does
not duplicate that command matrix.
