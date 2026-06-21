# Phase 07 — Refactor CGGMP Online Sign and Durable Store Coordination

## Objective

Decouple CGGMP online signing from durable sign-attempt storage and presign consumption tracking.

Priority issues:

1. Online partial verification and aggregation should be testable without a file-backed durable store.
2. Durable attempt claim/burn/update behavior should be testable without cryptographic aggregation logic.
3. This phase should prepare the codebase for a future `Presign.id()` redesign that uses non-secret per-presign uniqueness rather than secret-derived material.

## Target files

Likely files:

```text
cggmp21/secp256k1/online_sign.go
cggmp21/secp256k1/sign.go
cggmp21/secp256k1/sign_attempt.go
cggmp21/secp256k1/sign_attempt_file_store.go
```

Recommended new files:

```text
cggmp21/secp256k1/online_sign_context_state.go
cggmp21/secp256k1/online_sign_transition.go
cggmp21/secp256k1/sign_attempt_coordinator.go
cggmp21/secp256k1/online_sign_state_transition_test.go
cggmp21/secp256k1/sign_attempt_coordinator_test.go
```

## Proposed structure

### Immutable signing context

```go
type cggmpSignContext struct {
    self      tss.PartyID
    sessionID tss.SessionID
    signers   tss.PartySet

    digestHash []byte
    planHash   []byte

    keyBinding     []byte
    presignBinding []byte
    presignID      []byte

    limits Limits
}
```

### Online sign state machine

```go
type signPartial struct {
    scalar secp.Scalar // Prefer fixed scalar representation over *big.Int.
    envelope tss.Envelope
}

type cggmpSignPeerState struct {
    partial slot[signPartial]
}

type cggmpSignState struct {
    peers partyTable[cggmpSignPeerState]

    completed bool
    aborted   bool
    signature []byte
}
```

### Attempt coordinator

```go
type signAttemptCoordinator struct {
    store SignAttemptStore
    attempt *SignAttempt
    presignID []byte
}
```

Coordinator responsibilities:

- claim presign attempt
- persist base envelope
- update delivery state
- burn attempt
- complete attempt
- reload/resume attempt

State machine responsibilities:

- validate partial payloads
- verify partial signatures
- aggregate final signature
- verify final signature
- produce completion effect

## Step-by-step implementation

### Step 07.1 — Introduce online sign state/context wrappers

- Create `cggmpSignContext` from existing sign session construction.
- Create `cggmpSignState` from existing partial maps and completion flags.
- Keep old fields temporarily if needed.

### Step 07.2 — Replace `*big.Int` partial state with fixed scalar representation

This phase should align with the earlier safety finding that secret scalar material should not be converted into `*big.Int` unless there is a narrow audited bridge.

Preferred:

```go
type signPartialPayload struct {
    S secp.Scalar
}
```

or fixed 32-byte canonical scalar representation.

If immediate wire/API change is too large, create an internal conversion boundary and record the remaining risk in `STATUS.md`.

### Step 07.3 — Transition for partial messages

Add:

```go
type acceptSignPartialTx struct {
    from tss.PartyID
    partial signPartial
    duplicate bool
}
```

Build validates:

1. envelope guard
2. confidential/broadcast policy as required
3. payload type and round
4. canonical decode
5. plan hash / session / digest binding
6. signer membership
7. scalar validity
8. duplicate/equivocation
9. cryptographic partial verification

Commit writes partial slot and invokes aggregate prepare/commit if ready.

### Step 07.4 — Split final signature aggregation

Add:

```go
func (s *SignSession) prepareFinalSignature() (*preparedFinalSignature, error)
func (s *SignSession) commitFinalSignature(p *preparedFinalSignature) signEffects
```

Prepare:

- checks all required partials
- verifies all partials if not already verified
- aggregates final signature
- verifies final signature

Commit:

- writes final signature
- sets completed
- returns completion effect to attempt coordinator

### Step 07.5 — Extract sign-attempt coordinator

Add:

```go
type signAttemptCoordinator struct {
    store SignAttemptStore
    attempt *SignAttempt
    presignID []byte
}

func (c *signAttemptCoordinator) Claim(...) error
func (c *signAttemptCoordinator) PersistBaseEnvelope(...) error
func (c *signAttemptCoordinator) MarkDelivered(...) error
func (c *signAttemptCoordinator) Burn(...) error
func (c *signAttemptCoordinator) Complete(...) error
```

`SignSession` should call coordinator methods, but online cryptographic state should not directly manipulate file paths or store metadata.

### Step 07.6 — Prepare for non-secret presign identity

Do not necessarily change `Presign.id()` in this phase unless the team decides to include it.

Add abstraction:

```go
type PresignHandle []byte
```

or keep `[]byte` but route through a method that can later change implementation.

Document intended direction:

- `Presign.id()` should eventually use non-secret per-presign uniqueness, such as a persisted 32-byte `presignUID`.
- Store integrity should rely on AEAD/MAC or recomputable transcript, not secret-derived public identifiers.

## Required tests

Add tests in:

```text
cggmp21/secp256k1/online_sign_state_transition_test.go
cggmp21/secp256k1/sign_attempt_coordinator_test.go
```

Test cases:

1. Invalid partial does not mutate online sign state.
2. Conflicting partial does not mutate state.
3. Duplicate identical partial is idempotent according to existing policy.
4. Aggregation failure does not set completed or write signature.
5. Successful aggregation works without a file store.
6. Durable claim failure does not mutate online sign state.
7. Durable delivery update failure is handled according to existing policy and recorded in tests.
8. Burn behavior is isolated in coordinator tests.
9. Resume path validates the same key/presign/security binding as start path.
10. If scalar representation changes, wire/canonical tests prove compatibility expectations.

## Suggested test commands

```sh
go test ./cggmp21/secp256k1 -run 'Test.*Sign|Test.*Attempt|Test.*Resume|Test.*Reject|Test.*Duplicate'
```

## Acceptance criteria

- Online sign partial state is independent of durable store internals.
- Durable attempt coordination has focused tests.
- Partial handling is transition-based.
- Aggregation is prepare/commit based.
- Future non-secret presign identity change has a clean integration point.
- Full CGGMP signing tests pass.
