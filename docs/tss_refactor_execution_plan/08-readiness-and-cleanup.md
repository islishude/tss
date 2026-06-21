# Phase 08 — Readiness, Cleanup, Documentation, and Final Test Matrix

## Objective

Finish the structural refactor by removing temporary compatibility scaffolding, consolidating readiness predicates, updating documentation, and running the final test matrix.

## Scope

This phase spans both packages:

```text
frost/ed25519
cggmp21/secp256k1
```

Focus areas:

1. Remove or freeze old counters.
2. Remove temporary mirror fields introduced during migration.
3. Ensure readiness is derived from state.
4. Ensure cleanup paths use explicit ownership helpers.
5. Update documentation.
6. Run final test suite.

## Step-by-step implementation

### Step 08.1 — Remove or demote manual counters

In CGGMP presign, eliminate or demote fields such as:

```go
round1Count
round1ProofCount
round1VerifiedCount
round2Count
round3Count
```

Preferred replacement:

```go
func (st *cggmpPresignState) allRound1PayloadsAccepted() bool
func (st *cggmpPresignState) allRound1ProofsAccepted() bool
func (st *cggmpPresignState) allRound1Verified() bool
func (st *cggmpPresignState) allRound2Accepted() bool
func (st *cggmpPresignState) allRound3Accepted() bool
```

If counters are temporarily retained for debug assertions, they must not drive protocol progression.

### Step 08.2 — Remove migration mirror fields

During phases 02–07, old and new state fields may coexist. Remove the old fields once each protocol has fully migrated.

Checklist:

- No stale map mirrors.
- No stale `haveX` booleans where `slot[T]` is authoritative.
- No duplicate completed/pending flags.
- No duplicate party-index maps.
- No transition commit writes both old and new state.

### Step 08.3 — Consolidate cleanup ownership

Audit all prepare objects and session constructors.

Every secret-bearing staged object must satisfy one of these patterns:

```go
prepared, err := prepareX(...)
if err != nil {
    return err
}
defer prepared.Destroy()

commitX(prepared)
prepared.MarkCommitted()
```

or:

```go
cleanup := newCleanupStack()
defer cleanup.Run()

// add cleanup callbacks as each secret-bearing object is created

cleanup.Disarm()
```

Search targets:

```sh
grep -R "Destroy()" frost/ed25519 cggmp21/secp256k1
grep -R "defer .*Destroy" frost/ed25519 cggmp21/secp256k1
grep -R "BigInt()" cggmp21/secp256k1 internal/curve/secp256k1
```

Record any remaining intentional exceptions in `STATUS.md`.

### Step 08.4 — Ensure handler structure is uniform

Every public protocol handler should visibly follow:

```text
validate inbound -> build transition -> commit transition -> return effects
```

Audit these entry points:

```text
frost/ed25519: HandleSignMessage
frost/ed25519: HandleKeygenMessage
frost/ed25519: HandleReshareMessage / refresh handlers

cggmp21/secp256k1: HandleKeygenMessage
cggmp21/secp256k1: HandlePresignMessage
cggmp21/secp256k1: HandleSignMessage / ResumeSign path
```

### Step 08.5 — Documentation updates

Update:

```text
docs/architecture.md
docs/testing-rules.md
docs/frost-ed25519.md
docs/cggmp21-secp256k1.md
```

Add or update a section describing the handler invariant:

```text
decode -> policy validate -> cryptographic verify -> transition prepare -> commit -> effects
```

Document:

- reject paths must not mutate state;
- prepared secret material must be destroyed unless committed;
- duplicate identical messages are idempotent or explicitly documented otherwise;
- conflicting duplicates are verification/equivocation errors;
- emission is atomic with respect to state mutation;
- state readiness should be derived from per-party slots or bitsets, not naked counters.

### Step 08.6 — Final test matrix

Run the narrow tests first:

```sh
go test ./frost/ed25519 -run 'Test.*Sign|Test.*Keygen|Test.*Reshare|Test.*Refresh|Test.*Invariant|Test.*Reject|Test.*Duplicate'
go test ./cggmp21/secp256k1 -run 'Test.*Keygen|Test.*Presign|Test.*Sign|Test.*Attempt|Test.*Invariant|Test.*Reject|Test.*Duplicate'
```

Then package tests:

```sh
go test ./frost/ed25519
go test ./cggmp21/secp256k1
```

Then full checks according to repository testing policy:

```sh
make check
```

If touched concurrency, locking, session lifecycle, or durable store code:

```sh
make test-race
```

If touched protocol full flows:

```sh
make test-integration
```

Record exact commands and results in `STATUS.md`.

## Required final audit checklist

- [ ] No handler mutates state before transition commit.
- [ ] No prepare object with secret material lacks cleanup.
- [ ] No local partial/beta/delta/presign output is committed before envelope construction succeeds.
- [ ] No readiness decision depends on stale counters.
- [ ] No temporary mirror fields remain.
- [ ] FROST sign/keygen/reshare tests pass.
- [ ] CGGMP keygen/presign/sign tests pass.
- [ ] Documentation reflects the new internal protocol-handler contract.
- [ ] `STATUS.md` is fully updated.

## Acceptance criteria

- All planned phases are marked `done` or intentionally `deferred` in `STATUS.md`.
- Final test matrix has been recorded.
- Documentation has been updated.
- No known cleanup/mutation/counter migration gaps remain untracked.
