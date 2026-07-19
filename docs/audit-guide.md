# Cryptographic Audit Guide

This is the review entry point for `cggmp21/secp256k1`. It identifies the
active implementation surface and the evidence to inspect; it does not restate
every proof equation. The only protocol baseline used by this repository is the
bundled 2024 revision of [`cggmp21.pdf`](cggmp21.pdf). The implementation is not
independently audited or production ready.

## Review Order

1. Read [`cggmp21-secp256k1.md`](cggmp21-secp256k1.md) for the operational and
   lifecycle contract.
2. Compare Figures 6-10 and Appendix F.1 with
   [`cggmp21-paper-mapping.md`](cggmp21-paper-mapping.md).
3. Review proof relations, transcript inputs, ranges, and constant-time
   boundaries in [`paillier-zk-proofs.md`](paillier-zk-proofs.md).
4. Review secret handling and one-use presign requirements in
   [`security.md`](security.md), then the durable coverage contracts in
   [`testing-invariants.md`](testing-invariants.md).
5. Inspect canonical record ownership in [`wire.md`](wire.md) and committed
   evidence under `internal/testvectors`.

The mapping and proof notes are authoritative for protocol and proof detail.
This guide intentionally links to them instead of maintaining a second set of
relations or wire-type tables.

## Active Cryptographic Surface

| Phase               | Active relation or boundary                                            | Primary source                                                                                                                                               |
| ------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Figure 6            | Commit-ahead secp256k1 Schnorr                                         | `cggmp21/secp256k1/paper_keygen_figure6.go`, `internal/zk/schnorr/schnorr.go`                                                                                |
| Figure 7            | Ring-Pedersen `Pi_prm`                                                 | `cggmp21/secp256k1/auxiliary_setup.go`, `internal/zk/paillier/ring_pedersen.go`                                                                              |
| Figure 7            | Paillier `Pi_mod` and recipient-specific `Pi_fac`                      | `cggmp21/secp256k1/paper_auxiliary_state.go`, `internal/zk/paillier/modulus.go`, `internal/zk/paillier/factor.go`                                            |
| Figure 7/F.1        | Polynomial Schnorr proofs and authenticated DH share masks             | `cggmp21/secp256k1/paper_auxiliary_state.go`, `cggmp21/secp256k1/paper_auxiliary_primitives.go`                                                              |
| Figure 8 round 1    | Recipient-specific `Pi_enc-elg`                                        | `cggmp21/secp256k1/presign_round1.go`, `internal/zk/paillier/enc_elg.go`                                                                                     |
| Figure 8 rounds 2-3 | `Pi_elog`, pairwise `Pi_aff-g`, and MtA integer handling               | `cggmp21/secp256k1/presign_round2.go`, `cggmp21/secp256k1/presign_round3.go`, `internal/mta`, `internal/zk/paillier/elog.go`, `internal/zk/paillier/affg.go` |
| Figure 9            | Setup-less `Pi_aff-g*` and `Pi_dec` accountability                     | `cggmp21/secp256k1/figure9.go`, `internal/zk/paillier/affg_star.go`, `internal/zk/paillier/dec.go`                                                           |
| Figure 10           | Direct normalized-partial equation                                     | `cggmp21/secp256k1/online_sign_transition.go`, `cggmp21/secp256k1/paper_presign_artifact.go`                                                                 |
| Lifecycle           | Generation validation, leases, atomic presign/sign commit, and cutover | `cggmp21/secp256k1/presign_lifecycle.go`, `cggmp21/secp256k1/online_sign_lifecycle.go`, `tssrun/lifecycle.go`                                                |

`EncProof`, `LogStarProof`, `MulProof`, and `MulStarProof` remain internal
primitives, but they are not substitutes for the active Figure 8/9 relations.
`LogStarProof` is used by the temporary reshare handoff. Ed25519 Schnorr belongs
to the FROST package and is outside this CGGMP21 audit scope.

## Questions That Need Explicit Review

- **Proof composition.** The code identifies its `Pi_mod` and `Pi_prm`
  constructions as CGGMP24-style while placing them in the bundled CGGMP21
  schedule. Verify the concrete relations and composition; the label is not an
  independent conformance claim.
- **Context schedule.** Early Figure 6 records and Figure 7 `Pi_prm` are created
  before RID or `EpochID` exists. Verify their available run/plan/party bindings
  and the later final-transcript and auxiliary-digest coverage. Do not require
  nonexistent future context or overlook later coverage.
- **Recipient separation.** `Pi_fac`, `Pi_enc-elg`, and `Pi_aff-g` statements are
  recipient-specific. Check that changing the recipient or auxiliary setup
  invalidates the proof and that broadcast statements do not invent a direct
  recipient.
- **Integer semantics.** Check proof bounds before equations, ciphertext and
  Ring-Pedersen membership, fixed-width signed encodings, and centered Paillier
  plaintext conversion before curve-order reduction.
- **Secret exponentiation.** Paillier private decryption must use
  `(*paillierct.PrivateModExp).ExpSecretBlinded`; MtA secret scalar exponents
  must use `paillierct.ExpCT`. This limited boundary is not a whole-program
  constant-time claim.
- **Accountability.** Figure 7 may reveal a DH exponent only in its dedicated
  authenticated decryption-error accusation. Figure 9 publishes public MtA
  transcript views and proofs, never witnesses or factors. Figure 10 attributes
  a bad authenticated partial directly and has no later proof phase.
- **One-use durability.** Keygen/import output must be installed with
  `LifecycleStore.InstallInitialGeneration` before store-backed work. Verify
  atomic available-presign commit, sign-attempt claim/outbox commit, unknown
  outcome recovery, refresh/reshare fencing, source-presign burning, and child
  lineage installation.
- **Repository extensions.** Authenticated envelopes, canonical TLV, Appendix
  F.1 threshold adaptation, dynamic identifiers, chain-code commit/reveal,
  durable lifecycle, reshare handoff, and child derivation extend the paper's
  exact protocol model and require their own analysis.

## Evidence and Commands

The `Makefile` is the command source of truth; run `make help` before selecting
additional suites. A documentation or audit change should normally preserve:

```sh
make check
make test-integration
make vectors-verify-all
```

Use `make test-slowcrypto` for the production-parameter Paillier/ZK smoke path,
and `make fuzz-smoke` when a decoder or reject path changes. Test tiers and
durable coverage ownership are defined in
[`testing-rules.md`](testing-rules.md) and
[`testing-invariants.md`](testing-invariants.md), not in this guide.

Relevant committed evidence includes:

- `internal/testvectors/protocol/cggmp21-secp256k1/`;
- `internal/testvectors/fixtures/cggmp21-secp256k1/`;
- `internal/testvectors/wire/v1/cggmp21/`; and
- `internal/testvectors/wire/v1/zk/`.

These vectors and tests are implementation evidence, not a formal proof or an
independent audit.

## Open Review Gaps

- The Paillier/ZK layer, Fiat-Shamir composition, concrete range analysis, and
  Figure 9 accountability path still require independent cryptographic review.
- The two local modulus roles use separate key-generation calls and equality
  rejection, but validation does not explicitly check cross-modulus GCD or prove
  independent factor generation to peers.
- `Pi_enc-elg`, `Pi_elog`, `Pi_aff-g*`, and `Pi_dec` have canonical round-trip
  and mutation tests but no standalone committed ZK golden record yet.
- File and memory lifecycle stores are reference implementations, not
  production durability, encryption-at-rest, KMS, or HSM designs.
- Secret cleanup is best effort in Go and is not a memory-forensic zeroization
  guarantee.
- Production deployment additionally requires reviewed randomness, transport,
  database transactions, key management, authorization, and recovery
  operations.
