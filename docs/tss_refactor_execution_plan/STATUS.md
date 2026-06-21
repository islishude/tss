# Refactor Status Tracker

This file is the single progress ledger for the staged protocol-state-machine refactor.

Update this file at the end of every phase or PR. Keep phase files mostly stable; record actual progress, deviations, and follow-up items here.

## Legend

| Status        | Meaning                                                |
| ------------- | ------------------------------------------------------ |
| `not-started` | No implementation work has begun.                      |
| `in-progress` | Implementation is underway.                            |
| `blocked`     | Work cannot continue without a decision or dependency. |
| `review`      | Implementation is complete and waiting for review.     |
| `done`        | Merged or otherwise accepted.                          |
| `deferred`    | Intentionally postponed.                               |

## Phase summary

| Phase | File                                | Status      | Owner | Branch / PR        | Notes                                                                                                                                  |
| ----: | ----------------------------------- | ----------- | ----- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
|    00 | `00-baseline-and-invariants.md`     | review      | Codex | `refactor-session` | Added non-secret snapshot helpers and no-mutation baseline tests; malformed CGGMP keygen payload abort behavior recorded as follow-up. |
|    01 | `01-local-helpers.md`               | review      | Codex | `refactor-session` | Added package-local slot, partyTable, cleanupStack, and minimal transition/effects helpers in both protocol packages.                  |
|    02 | `02-frost-sign.md`                  | in-progress | Codex | `refactor-session` | Local partial emission and aggregation now use prepare/commit helpers; handler transition/context-state wrapper work remains.          |
|    03 | `03-frost-keygen.md`                | not-started |       |                    |                                                                                                                                        |
|    04 | `04-frost-reshare-refresh.md`       | not-started |       |                    |                                                                                                                                        |
|    05 | `05-cggmp-keygen.md`                | not-started |       |                    |                                                                                                                                        |
|    06 | `06-cggmp-presign.md`               | not-started |       |                    |                                                                                                                                        |
|    07 | `07-cggmp-online-sign-and-store.md` | not-started |       |                    |                                                                                                                                        |
|    08 | `08-readiness-and-cleanup.md`       | not-started |       |                    |                                                                                                                                        |

## Current decisions

| Decision                                                                           | Status  | Resolution                                                                                    |
| ---------------------------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------- |
| Whether helpers remain package-local or move to `internal`                         | open    | Start package-local. Revisit after Phase 06.                                                  |
| Whether counters are removed or retained as debug-only invariants during migration | open    | Retain temporarily if needed; remove in Phase 08.                                             |
| Whether `Presign.id()` changes in this refactor series                             | open    | Prepare for change in Phase 07; implement separately if public/durable behavior needs review. |
| Whether FROST and CGGMP transition interfaces must be identical                    | decided | No. Keep protocol-local. Similar shape, not shared abstraction.                               |

## Open risks

| Risk                                            | Impact | Mitigation                                                                | Status |
| ----------------------------------------------- | ------ | ------------------------------------------------------------------------- | ------ |
| Go toolchain mismatch prevents local tests      | High   | Run with Go version required by `go.mod`; record exact command output.    | open   |
| Refactor accidentally changes wire encoding     | High   | Add golden/canonical wire tests where touched.                            | open   |
| Refactor changes duplicate-message behavior     | Medium | Add duplicate-idempotence tests before changing handlers.                 | open   |
| Cleanup tests cannot observe secret destruction | Medium | Use test-only hooks, fake owner wrappers, or observable prepared objects. | open   |

## Completion log

Append entries in reverse chronological order.

### 2026-06-21 — Phase 02 — FROST sign prepare/commit partial

- Status changed from: `not-started`
- Status changed to: `in-progress`
- Branch / PR: `refactor-session`
- Summary: Split FROST local partial emission into `prepareLocalPartial` and `commitLocalPartial`, so marshal/envelope failures no longer write the local partial, set `partialSent`, or clear local nonces before commit. Split aggregate completion into `prepareAggregate` and `commitAggregate`, so verification failures do not write `signature` or set `completed`. Added tests for commitment plan-hash rejection, local partial prepare failure, and aggregate failure.
- Tests run:
  - `go test ./frost/ed25519 -run 'Test.*Sign|Test.*Plan|Test.*Reject|Test.*Duplicate|TestSession' -count=1`
- Deviations from phase plan: This is a partial Phase 02 checkpoint. Immutable context/state wrappers and explicit build/apply transition objects for commitment and partial handlers are not complete yet.
- Follow-up items:
  - Add `frostSignContext`, `frostSignResources`, and `frostSignState` wrappers or equivalent mirror checks.
  - Move commitment and partial handler logic into explicit build/apply transition functions.
  - Extend snapshot tests to malformed partial scalar, conflicting partial, duplicate idempotence, and successful full signing flow under the new transition path.

### 2026-06-21 — Phase 01 — package-local protocol helpers

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Added package-local `slot`, `partyTable`, `cleanupStack`, and minimal `sessionTransition`/`sessionEffects` helpers to both `frost/ed25519` and `cggmp21/secp256k1`. Added helper tests for optional state, deterministic party-table lookup/iteration/predicates, cleanup LIFO/disarm/idempotence, and transition/effects shape. Helpers remain package-local after this phase; the `internal` move decision remains deferred until patterns are proven through later phases.
- Tests run:
  - `go test ./frost/ed25519 -run 'TestSession' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'TestSession' -count=1`
  - `go test ./frost/ed25519 -run 'Test.*Invariant|Test.*Reject|Test.*Duplicate|TestSession' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'Test.*Invariant|Test.*Reject|Test.*Duplicate|TestSession' -count=1`
- Deviations from phase plan: None.
- Follow-up items:
  - Introduce helper usage only inside the phase-specific handler refactors.
  - Revisit whether any helper should move to `internal` after Phase 06, as planned.

### 2026-06-21 — Phase 00 — baseline snapshots and no-mutation tests

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Added package-local, non-secret session snapshots for FROST sign/keygen/reshare-refresh and CGGMP keygen/presign/online sign. Added focused reject-path no-mutation invariant tests for each required protocol family without changing production protocol logic.
- Tests run:
  - `go test ./frost/ed25519 -run 'Test.*Invariant|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'Test.*Invariant|Test.*Reject|Test.*Duplicate' -count=1`
- Deviations from phase plan: CGGMP keygen uses a guard-level wrong-round reject for the passing no-mutation baseline. A malformed CGGMP keygen commitments payload currently aborts the session and clears local state; that behavior was observed during Phase 00 and should be addressed in Phase 05 when keygen handlers are made transactional.
- Follow-up items:
  - Add deeper malformed-payload no-mutation assertions as the relevant handlers move to prepare/commit transitions.
  - Expand duplicate idempotence assertions with snapshots during each phase-specific handler refactor.

### YYYY-MM-DD — Phase XX — short title

- Status changed from: `not-started`
- Status changed to: `in-progress`
- Branch / PR:
- Summary:
- Tests run:
- Deviations from phase plan:
- Follow-up items:
