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

| Phase | File                                | Status      | Owner | Branch / PR | Notes |
| ----: | ----------------------------------- | ----------- | ----- | ----------- | ----- |
|    00 | `00-baseline-and-invariants.md`     | not-started |       |             |       |
|    01 | `01-local-helpers.md`               | not-started |       |             |       |
|    02 | `02-frost-sign.md`                  | not-started |       |             |       |
|    03 | `03-frost-keygen.md`                | not-started |       |             |       |
|    04 | `04-frost-reshare-refresh.md`       | not-started |       |             |       |
|    05 | `05-cggmp-keygen.md`                | not-started |       |             |       |
|    06 | `06-cggmp-presign.md`               | not-started |       |             |       |
|    07 | `07-cggmp-online-sign-and-store.md` | not-started |       |             |       |
|    08 | `08-readiness-and-cleanup.md`       | not-started |       |             |       |

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

### YYYY-MM-DD — Phase XX — short title

- Status changed from: `not-started`
- Status changed to: `in-progress`
- Branch / PR:
- Summary:
- Tests run:
- Deviations from phase plan:
- Follow-up items:
