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

| Phase | File                                | Status | Owner | Branch / PR        | Notes                                                                                                                                  |
| ----: | ----------------------------------- | ------ | ----- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
|    00 | `00-baseline-and-invariants.md`     | review | Codex | `refactor-session` | Added non-secret snapshot helpers and no-mutation baseline tests; malformed CGGMP keygen payload abort behavior recorded as follow-up. |
|    01 | `01-local-helpers.md`               | review | Codex | `refactor-session` | Kept package-local cleanup and transition/effects helpers; unused slot and partyTable prototypes were removed in Phase 08.             |
|    02 | `02-frost-sign.md`                  | review | Codex | `refactor-session` | Commitment and partial handlers now build validated transitions before apply; local emission and aggregation use prepare/commit.       |
|    03 | `03-frost-keygen.md`                | review | Codex | `refactor-session` | Start, pending-share, and final-share ownership are staged; commitment/share/confirmation handlers use validated transitions.          |
|    04 | `04-frost-reshare-refresh.md`       | review | Codex | `refactor-session` | Explicit mode/role, shared dealer preparation, validated transitions, and staged completion now cover reshare and refresh.             |
|    05 | `05-cggmp-keygen.md`                | review | Codex | `refactor-session` | Round1 and confirmation transitions plus staged start/pending/final ownership now cover CGGMP keygen.                                  |
|    06 | `06-cggmp-presign.md`               | review | Codex | `refactor-session` | Round1/2/3 transitions, atomic local outputs, staged final Presign, readiness predicates, and constructor cleanup are implemented.     |
|    07 | `07-cggmp-online-sign-and-store.md` | review | Codex | `refactor-session` | Online partials and final aggregation are transition-based; durable claim/load/delivery/complete/burn are coordinator-owned.           |
|    08 | `08-readiness-and-cleanup.md`       | review | Codex | `refactor-session` | Removed presign counters and unused helper scaffolding, documented handler contracts, and passed CI, integration, and race matrices.   |

## Current decisions

| Decision                                                                           | Status   | Resolution                                                                                     |
| ---------------------------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| Whether helpers remain package-local or move to `internal`                         | decided  | Keep cleanup and transition helpers package-local; remove unused slot/partyTable prototypes.   |
| Whether counters are removed or retained as debug-only invariants during migration | decided  | Removed CGGMP presign counters; readiness derives from accepted per-party state.               |
| Whether `Presign.id()` changes in this refactor series                             | deferred | Keep current bytes behind `presignHandle`; persisted non-secret UID is a separate wire change. |
| Whether FROST and CGGMP transition interfaces must be identical                    | decided  | No. Keep protocol-local. Similar shape, not shared abstraction.                                |

## Open risks

| Risk                                            | Impact | Mitigation                                                                | Status |
| ----------------------------------------------- | ------ | ------------------------------------------------------------------------- | ------ |
| Go toolchain mismatch prevents local tests      | High   | Run with Go version required by `go.mod`; record exact command output.    | closed |
| Refactor accidentally changes wire encoding     | High   | Add golden/canonical wire tests where touched.                            | closed |
| Refactor changes duplicate-message behavior     | Medium | Add duplicate-idempotence tests before changing handlers.                 | closed |
| Cleanup tests cannot observe secret destruction | Medium | Use test-only hooks, fake owner wrappers, or observable prepared objects. | closed |

## Completion log

Append entries in reverse chronological order.

### 2026-06-21 — Phase 08 — readiness, cleanup, documentation, and final matrix

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Removed all five observational CGGMP presign round counters so readiness is derived only from accepted per-party state. Removed the unused `slot` and `partyTable` migration prototypes from both protocol packages while retaining the production-used cleanup stack and transition/effects interface. Lowered methods on internal helper types so they do not create accidental exported API surface. Audited handler ordering and prepared-object ownership, documented the transaction contract in architecture, testing, and protocol docs, and updated the malformed-presign lifecycle integration test to distinguish non-mutating malformed rejection from terminal equivocation.
- Tests run:
  - `go test ./frost/ed25519 -run 'Test.*Sign|Test.*Keygen|Test.*Reshare|Test.*Refresh|Test.*Invariant|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'Test.*Keygen|Test.*Presign|Test.*Sign|Test.*Attempt|Test.*Invariant|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test ./frost/ed25519 -count=1`
  - `go test ./cggmp21/secp256k1 -count=1`
  - `make check`
  - `make ci`
  - `make test-integration`
  - `make test-race`
  - `git diff --check`
- Deviations from phase plan: Phase statuses remain `review` rather than `done` because the branch has not been merged or explicitly accepted. No temporary context/state mirror fields were introduced in earlier phases, so there were none to remove. The current secret-derived `Presign.id()` remains unchanged; Phase 07 added a narrow handle boundary for a separately reviewed persisted non-secret UID migration.
- Follow-up items:
  - Review and merge the complete refactor series.
  - Treat a persisted non-secret presign UID as a separate wire/storage design change with vectors and migration review.

### 2026-06-21 — Phase 07 — CGGMP online sign and durable coordinator

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Routed online sign partials through a validated build/apply transition and split final ECDSA aggregation into prepare and commit stages. Final signature preparation is now testable without any store. Extracted `signAttemptCoordinator` as the only caller of durable claim, load/resume, delivery, completion, and burn operations; `SignSession` no longer stores a raw `SignAttemptStore` or timeout. Added `presignHandle` as the future identity integration point while preserving existing `Presign.id()` bytes and wire behavior. Durable completion still precedes signature visibility, and accepted final partials remain available for idempotent `RetryCompletion` after store failure.
- Tests run:
  - `go test ./cggmp21/secp256k1 -run 'TestCGGMP21OnlineSign|TestSignAttemptCoordinator' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'Test.*Sign|Test.*Attempt|Test.*Resume|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test -tags=integration ./cggmp21/secp256k1 -run 'TestThresholdECDSA_(SignAttemptCompletionSurvivesRestart|SignAttemptCompletionIsDurableBeforeVisible|BurnPresignBlocksRestoredCopies|BurnPresignAfterCommitPreservesResume|SignAttemptStoreSerializesIntents|StartSignRequiresSignAttemptStore)$' -count=1`
  - `go test ./cggmp21/secp256k1 -count=1`
- Deviations from phase plan: Kept the existing `SignSession` fields as the single online state owner instead of adding duplicate context/state mirrors. `signPartialPayload.S` was already a fixed-width `internal/secret.Scalar`, so no wire change was needed. `Presign.id()` itself was intentionally not changed.
- Follow-up items:
  - Complete Phase 08 by removing presign counters and unused migration helpers.
  - Keep the non-secret presign UID redesign separate from this structural refactor.

### 2026-06-21 — Phase 06 — CGGMP presign transactional rounds

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Refactored all CGGMP presign rounds into transactional boundaries. Round1 payload/proof pairing verifies before acceptance. Round2 verification returns owned alpha material and local round2 preparation stages all beta shares and envelopes before commit. Round3 remote material is transition-owned, local round3 output stages delta, signprep material, envelope, and base presign, and final completion installs a separately staged Presign. Added derived readiness predicates and cleanup-safe `StartPresign` ownership. Fixed a ciphertext alias where destroying `StartOpening` could clear the accepted round1 `EncK`; round1 now clones the public ciphertext before destroying the witness.
- Tests run:
  - `go test ./cggmp21/secp256k1 -run 'TestCGGMP21Presign(Round1PlanHashRejectDoesNotMutate|Round1DeferredVerificationFailureDoesNotAcceptPayload|Round2MalformedRejectDoesNotMutate|Round2VerificationFailureDoesNotWriteAlphaShares|Round2PrepareFailureDoesNotWriteBetaShares|Round3MalformedRejectDoesNotMutate|Round3PrepareDoesNotMutateAndDestroysStagedSecrets|Round3VerificationFailureDoesNotWriteVerifyShare|CompletionPrepareDoesNotMutateAndDestroysFinalPresign|DerivedReadinessMatchesCounters)$|TestCGGMP21PreparedPresignStartDestroyClearsOwnedState' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'Test.*Presign|Test.*SignPrep|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test ./cggmp21/secp256k1 -count=1`
- Deviations from phase plan: Kept the existing ordered `parties` state as the single owner instead of introducing a second mirrored state object. Existing counters remain for migration assertions, but readiness now derives from per-party state.
- Follow-up items:
  - Begin Phase 07 by extracting online partial transition/aggregation from durable attempt coordination.
  - Remove now-observational presign counters in Phase 08 after final audit.

### 2026-06-21 — Phase 05 — CGGMP keygen transitions and staged ownership

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Routed CGGMP keygen public commitments/proofs, confidential shares, and confirmations through typed build/apply transitions. Malformed commitment payloads no longer abort and clear a live session. Centralized `StartKeygen` cleanup for Paillier private material, local shares, polynomial coefficients, chain code, and outbound payloads. Split pending and final key-share construction into staged prepare/commit paths that destroy secret scalars and cloned Paillier private keys unless ownership commits.
- Tests run:
  - `go test ./cggmp21/secp256k1 -run 'TestCGGMP21Keygen(MalformedCommitmentRejectDoesNotMutate|CommitmentBuildDoesNotMutate|InvalidProofBuildDoesNotMutate|ShareBuildOwnsAndClearsDecodedSecret|PendingPrepareDoesNotMutateAndDestroysStagedSecrets|FinalPrepareFailureDoesNotInstallKeyShare)$|TestCGGMP21PreparedKeygenStartDestroyClearsOwnedState' -count=1`
  - `go test ./cggmp21/secp256k1 -run 'Test.*Keygen|Test.*Confirmation' -count=1`
  - `go test ./cggmp21/secp256k1 -count=1`
  - `make check`
- Deviations from phase plan: Kept the existing `KeygenSession` field layout as the single state owner rather than adding temporary context/state mirrors. Invalid-message errors no longer abort solely because they carry public blame; cryptographic verification errors still abort according to the existing lifecycle policy.
- Follow-up items:
  - Begin Phase 06 with presign round1 transitions and remove mutation from deferred verification.
  - Revisit the package-wide verification-abort policy only if later phase tests require a stricter non-mutating reject contract.

### 2026-06-21 — Phase 04 — FROST reshare and refresh transitions

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Replaced implicit `refreshMode` and `isRecipient` booleans with explicit reshare mode and role values for dealer-only, recipient-only, and dealer-recipient sessions. Unified reshare and refresh dealer startup behind one cleanup-safe prepared constructor. Routed commitment and confidential share handling through build/apply transitions, and split completion into staged preparation and commit so an uncommitted new key share is destroyed on failure.
- Tests run:
  - `go test ./frost/ed25519 -run 'TestFROSTReshare(ModeAndRoleAreExplicit|CommitmentBuildDoesNotMutate|ShareBuildOwnsAndClearsDecodedSecret|DealerOnlyRejectsInboundShareWithoutMutation|RejectsShareFromNonDealerWithoutMutation|DealerOnlyCompletionNeedsOnlyCommitments|CompletionPrepareDoesNotMutateAndDestroysStagedShare)$|TestFROSTPreparedReshareDealerStartDestroyClearsOwnedState' -count=1`
  - `go test ./frost/ed25519 -run 'Test.*Reshare|Test.*Refresh|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test ./frost/ed25519 -count=1`
  - `make check`
- Deviations from phase plan: Kept the existing `ReshareSession` data fields as the single state owner rather than introducing temporary context/state mirrors. Mode/role and prepared ownership objects provide the required invariants without dual writes.
- Follow-up items:
  - Begin Phase 05 with the malformed CGGMP keygen commitment abort identified in Phase 00.
  - Reuse the FROST transition and staged key-share patterns locally without introducing a cross-package framework.

### 2026-06-21 — Phase 03 — FROST keygen transitions and staged ownership

- Status changed from: `not-started`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Routed FROST keygen commitments, confidential shares, and confirmations through explicit build/apply transitions. Fixed the commitment path so an invalid chain-code commitment cannot leave accepted commitments behind. Added cleanup-safe ownership for `StartKeygen`, pending key-share preparation, and final key-share preparation; staged secret shares and key shares are destroyed unless commit transfers ownership.
- Tests run:
  - `go test ./frost/ed25519 -run 'TestFROSTKeygen(CommitmentBuildDoesNotMutate|InvalidChainCodeCommitRejectDoesNotMutate|ShareBuildOwnsAndClearsDecodedSecret|PendingPrepareDoesNotMutateAndDestroysStagedShare|FinalPrepareFailureDoesNotInstallKeyShare)$' -count=1`
  - `go test ./frost/ed25519 -run 'Test.*Keygen|Test.*Confirmation|Test.*Reject|Test.*Duplicate' -count=1`
  - `go test ./frost/ed25519 -count=1`
  - `make check`
- Deviations from phase plan: Kept the existing `KeygenSession` field layout as the single state owner instead of adding temporary context/state mirrors. The new transition and prepared-object boundaries provide the planned mutation and ownership guarantees without dual writes.
- Follow-up items:
  - Begin Phase 04 by making FROST reshare/refresh mode and role explicit.
  - Preserve staged final-share construction when refactoring reshare completion.

### 2026-06-21 — Phase 02 — FROST sign handler transitions

- Status changed from: `in-progress`
- Status changed to: `review`
- Branch / PR: `refactor-session`
- Summary: Routed FROST commitment and partial handling through explicit build/apply transitions. Transition build performs guard and signer policy checks, canonical decode, plan binding, duplicate/conflict checks, and partial cryptographic verification whenever the complete commitment context is available. Only transition apply writes accepted commitments or partials and returns effects. The earlier prepare/commit boundaries for local partial emission and aggregate completion remain authoritative.
- Tests run:
  - `go test ./frost/ed25519 -run 'TestFROSTSign(CommitmentBuildDoesNotMutate|PartialBuildDoesNotMutate|MalformedPartialRejectDoesNotMutate|CommitmentPlanHashRejectDoesNotMutate|LocalPartialPrepareFailureDoesNotCommit|AggregateFailureDoesNotCommit)$' -count=1`
  - `go test ./frost/ed25519 -run 'TestFROST(IgnoresDuplicateCommitment|RejectsConflictingCommitment|IgnoresDuplicatePartial|RejectsConflictingPartial)$|TestSignBlameEvidenceBindsBadPartialPayload|TestSignOutOfOrderPartialsWaitForCommitments|TestRFC9591Ed25519SigningVector' -count=1`
  - `go test ./frost/ed25519 -run 'Test.*Sign|Test.*Plan|Test.*Reject|Test.*Duplicate|TestSession' -count=1`
  - `go test ./frost/ed25519 -count=1`
  - `make check`
- Deviations from phase plan: Did not add duplicated `frostSignContext`, `frostSignResources`, or `frostSignState` mirror fields. Existing `SignSession` fields remain the single state owner, while package-local transitions provide the transaction boundary. This avoids temporary dual writes and leaves any later physical field grouping as a non-behavioral cleanup.
- Follow-up items:
  - Begin Phase 03 with `StartKeygen` ownership cleanup and transactional commitment/share handling.
  - Preserve the transition build/apply shape when later consolidating session field ownership.

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
