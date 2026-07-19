# Test Inventory

This inventory records the current test-suite shape by package, build tag, and
invariant group. Use it to locate existing coverage before moving, merging, or
removing tests; file counts alone do not justify deletion.

Stable policy lives in [`testing-rules.md`](testing-rules.md); normative
behavioral coverage lives in [`testing-invariants.md`](testing-invariants.md).

Snapshot date: 2026-07-19.

## Repository Snapshot

Commands used:

```sh
rg --files -g '*_test.go'
rg -n '^func Test' -g '*_test.go'
rg -n '^func Fuzz' -g '*_test.go'
rg -n '^func Benchmark' -g '*_test.go'
rg -n '^func Example' -g '*_test.go'
rg -n '^//go:build ' -g '*_test.go'
```

| Metric                 | Count |
| ---------------------- | ----: |
| Test files             |   278 |
| `Test*` functions      |  1321 |
| `Fuzz*` functions      |    10 |
| `Benchmark*` functions |    15 |
| `Example*` functions   |    21 |

## Build Tags

| Build tag                    | Files | Intended tier   | Cleanup status                                                                                                     |
| ---------------------------- | ----: | --------------- | ------------------------------------------------------------------------------------------------------------------ |
| untagged                     |   210 | Tier 0          | Keep only fast deterministic unit, wire, guard, replay, state-machine, fail-closed, domain, and copy-safety tests. |
| `tier1`                      |    19 | Tier 1          | Keep reduced-parameter crypto, cached-fixture validation, and local primitive/property checks.                     |
| `integration`                |    40 | Tier 2          | Keep full lifecycle, HD lifecycle, adversarial delivery, restart, and recovery tests.                              |
| `integration \|\| vectorgen` |     1 | Shared helper   | Only helper-only files needed by both integration and generator code may use this shape.                           |
| `slowcrypto`                 |     5 | Tier 3          | Keep narrow production-parameter smoke tests.                                                                      |
| `vectorgen`                  |     3 | generation only | Keep only `TestGenerate*` entry points used by `internal/testvectors/cmd/tvgen`.                                   |

## Package Hotspots

| Package                | Test files | `Test*` functions | Primary invariants                                                                                                       |
| ---------------------- | ---------: | ----------------: | ------------------------------------------------------------------------------------------------------------------------ |
| `cggmp21/secp256k1`    |         92 |               316 | CGGMP21 keygen, presign, online sign, refresh, reshare, HD/BIP32, one-use presigns, restart, blame, wire/golden vectors. |
| `frost/ed25519`        |         48 |               224 | FROST keygen, sign, refresh, reshare, HD, domain separation, copy-safety, vectors.                                       |
| `.`                    |         25 |               207 | Envelope guards, configs, replay, clone/copy safety, redaction, storage helpers.                                         |
| `internal/wire`        |         16 |               162 | Canonical TLV encoding, tag grammar, limits, duplicate/trailing/malformed rejection.                                     |
| `internal/zk/paillier` |         36 |               121 | Reduced and production-parameter proof correctness, tamper rejection, transcript binding.                                |
| `internal/mta`         |         10 |                29 | MtA correctness, proof binding, reduced-parameter integration with Paillier.                                             |

## Placement Notes

The normative tier definitions are in
[`testing-rules.md`](testing-rules.md). The current inventory has two notable
placement constraints:

- CGGMP21 tests that construct complete Figure 8/9 exchanges, run an
  authoritative persistence lifecycle, or reconstruct and sign with imported
  shares are Tier 2 even when they use reduced cryptographic parameters.
- Canonical validation of committed reduced-parameter key-share fixtures is
  Tier 1; helper code that loads those fixtures remains untagged so every tier
  can reuse it without widening test selection.

## CGGMP21 Presign and Lifecycle Coverage

The current split follows Figure 8/9/10 invariants and the unified lifecycle
boundary. Delete or merge a test only after the inventory can point to an equal
or stronger assertion.

| Invariant bucket                        | Current files                                                                                                     | Required shape                                                                                                                                                                |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Normalized Figure 8 artifact and codecs | `paper_presign_artifact_test.go`, `encoding_test.go`, golden/vector tests                                         | Preserve exact tuple validation, canonical decode/re-encode, tamper rejection, and public binding.                                                                            |
| State transitions and reject paths      | `presign_state_transition_integration_test.go`, `integration_presign_adversary_test.go`, `adversary_test.go`      | Assert wrong round, duplicate, equivocation, cross-epoch, wrong-plan, malformed proof, and no unsafe mutation/effects.                                                        |
| Figure 9 attributable abort             | `figure9_limits_test.go`, `figure9_integration_test.go`                                                           | Cover bounded decode, `Pi_dec`, setup-less `Pi_aff-g*`, authenticated evidence, and terminal failure with no available presign.                                               |
| Available-presign commit                | `presign_available_persistence_test.go`, `presign_lifecycle_store_test.go`, `presign_runtime_integration_test.go` | Prove side-effect-free encoding, atomic lease completion, canonical slot identity, burn/conflict behavior, and public-only completion descriptors.                            |
| Figure 10 attempt claim and recovery    | `crash_recovery_test.go`, `concurrency_test.go`, `state_transition_test.go`, `low_s_test.go`                      | Keep exact outbox recovery, outcome-unknown reconciliation, delivery/completion separation, conflicting concurrent claims, direct partial verification, and low-S completion. |
| Generation and plan binding             | `lifecycle_plan_integration_test.go`, `lifecycle_test.go`, `presign_context_test.go`, `presign_identity_test.go`  | Bind key ID, generation, epoch, signer set, presign ID, empty-path context, plan digest, and security profile.                                                                |
