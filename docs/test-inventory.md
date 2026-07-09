# Test Inventory

This inventory is the working map for test-suite cleanup. It records the
current shape of the repository by package, build tag, invariant group, and
runtime tier so future removals can be justified by invariant coverage rather
than file count.

Snapshot date: 2026-07-09, after the initial tier/tag cleanup and CGGMP21
presign file split.

## Repository Snapshot

Commands used:

```sh
rg --files -g '*_test.go'
rg -n '^func Test' -g '*_test.go'
rg -n '^func Fuzz' -g '*_test.go'
rg -n '^func Benchmark' -g '*_test.go'
rg -n '^func Example' -g '*_test.go'
```

| Metric                 | Count |
| ---------------------- | ----: |
| Test files             |   224 |
| `Test*` functions      |  1149 |
| `Fuzz*` functions      |     4 |
| `Benchmark*` functions |    15 |
| `Example*` functions   |    19 |

## Build Tags

| Build tag                    | Files | Intended tier   | Cleanup status                                                                                                     |
| ---------------------------- | ----: | --------------- | ------------------------------------------------------------------------------------------------------------------ |
| untagged                     |   167 | Tier 0          | Keep only fast deterministic unit, wire, guard, replay, state-machine, fail-closed, domain, and copy-safety tests. |
| `tier1`                      |    14 | Tier 1          | Keep reduced-parameter crypto and local primitive/property checks.                                                 |
| `integration`                |    35 | Tier 2          | Keep full lifecycle, HD lifecycle, adversarial delivery, restart, and recovery tests.                              |
| `integration \|\| vectorgen` |     1 | Shared helper   | Only helper-only files needed by both integration and generator code may use this shape.                           |
| `slowcrypto`                 |     4 | Tier 3          | Keep narrow production-parameter smoke tests.                                                                      |
| `vectorgen`                  |     3 | generation only | Keep only `TestGenerate*` entry points used by `internal/testvectors/cmd/tvgen`.                                   |

## Package Hotspots

| Package                | Test files | `Test*` functions | Primary invariants                                                                                                       |
| ---------------------- | ---------: | ----------------: | ------------------------------------------------------------------------------------------------------------------------ |
| `cggmp21/secp256k1`    |         75 |               327 | CGGMP21 keygen, presign, online sign, refresh, reshare, HD/BIP32, one-use presigns, restart, blame, wire/golden vectors. |
| `frost/ed25519`        |         39 |               167 | FROST keygen, sign, refresh, reshare, HD, domain separation, copy-safety, vectors.                                       |
| `.`                    |         23 |               208 | Envelope guards, configs, replay, clone/copy safety, redaction, storage helpers.                                         |
| `internal/wire`        |         16 |               162 | Canonical TLV encoding, tag grammar, limits, duplicate/trailing/malformed rejection.                                     |
| `internal/zk/paillier` |         26 |                82 | Reduced and production-parameter proof correctness, tamper rejection, transcript binding.                                |
| `internal/mta`         |          7 |                22 | MtA correctness, proof binding, reduced-parameter integration with Paillier.                                             |

## Tier Decisions

- Tier 0 is for local invariants that do not need a full protocol lifecycle.
- Tier 1 is for reduced-parameter crypto and proof coverage that is still cheap
  enough for normal local feedback.
- Tier 2 is for full protocol lifecycles, HD lifecycles, adversarial delivery,
  restart/recovery, and any test that needs multiple protocol phases to make the
  assertion meaningful.
- Tier 3 remains production-parameter smoke coverage only.
- `vectorgen` is not a tier. It is only the build tag for generator entry points
  selected by `tvgen`.

## CGGMP21 Presign Pilot

Use `.agents/test-audit-cggmp21-presign.md` as the seed audit for the first
cleanup pass. The goal is to split by invariant first and delete later only when
coverage is demonstrably stronger elsewhere.

| Invariant bucket                    | Current files                                                                       | Target shape                                                                                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Codec and golden/vector contracts   | `encoding_test.go`, `vector_test.go`, golden tests                                  | Keep. Do not change wire bytes or committed vectors during cleanup.                                                                          |
| Handle lifecycle and one-use claims | `integration_presign_test.go`, `sign_attempt_test.go`                               | Keep at least one strong assertion for original, cloned, shallow-copied, restored, burned, and serialized presigns.                          |
| SignAttempt store semantics         | `integration_presign_test.go`, `sign_attempt_test.go`                               | Table-drive conflict, corrupt load, outcome-unknown, missing store, delivery, completion, and durable replay cases where setup is identical. |
| Restart and resume                  | `integration_presign_test.go`                                                       | Keep exact outbox replay, delivery-complete resume, completion durability, and committed-attempt recovery.                                   |
| Burn and concurrency                | `integration_presign_test.go`                                                       | Keep restored-copy burn, burn-after-commit, same-intent idempotence, and conflicting concurrent starts.                                      |
| Tamper and blame                    | `integration_presign_test.go`, `integration_adversary_test.go`, `adversary_test.go` | Keep fail-closed errors and blame attribution. Merge only overlapping setup/assertions.                                                      |
| Round-trip recovery handles         | `integration_presign_test.go`, `vector_test.go`                                     | Keep until one-use serialized-handle behavior is covered by a narrower test plus vector decode/encode contracts.                             |

## Rollout Order

1. Fix tier and generator semantics before deleting tests.
2. Split broad protocol files by invariant bucket.
3. Merge duplicate setup with table-driven cases.
4. Downgrade tests whose invariant can be exercised in a lower tier without
   weakening realism.
5. Delete only after the inventory can point to a stronger remaining assertion.

## Follow-Up Areas

- Move FROST full lifecycle, HD lifecycle, refresh, and reshare flows to
  `integration` while keeping local state transition, encoding, domain, and
  copy-safety tests untagged.
- Table-drive root package clone/config/broadcast tests while preserving
  copy-safety, redaction, and fail-closed assertions.
- Keep `internal/wire` high coverage, but group tests by codec feature instead
  of adding catch-all files.
- Keep ZK and Paillier tier boundaries intact. Merge same-setup proof and
  tamper cases without downgrading production-parameter smoke tests.
