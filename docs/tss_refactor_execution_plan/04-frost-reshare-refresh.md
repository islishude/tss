# Phase 04 — Refactor `frost/ed25519` Reshare and Refresh

## Objective

Refactor FROST reshare and refresh so that role/mode logic is explicit and completion is transactional.

Priority issues:

1. The same session type currently covers true reshare, refresh, dealer-only, recipient-only, and dealer-recipient roles.
2. Role invariants are implicit in booleans and nil checks.
3. Completion creates a new share and should destroy it on every pre-commit failure.

## Target files

Likely files:

```text
frost/ed25519/reshare.go
frost/ed25519/reshare_completion.go
frost/ed25519/refresh_runner.go
```

Recommended new files:

```text
frost/ed25519/reshare_context_state.go
frost/ed25519/reshare_transition.go
frost/ed25519/reshare_prepare_commit.go
frost/ed25519/reshare_state_transition_test.go
```

## Proposed structure

### Mode and role

```go
type frostReshareMode uint8

const (
    frostReshareModeReshare frostReshareMode = iota
    frostReshareModeRefresh
)

type frostReshareRole uint8

const (
    frostReshareRoleDealerOnly frostReshareRole = iota
    frostReshareRoleRecipientOnly
    frostReshareRoleDealerAndRecipient
)
```

### Immutable context

```go
type frostReshareContext struct {
    self         tss.PartyID
    sessionID    tss.SessionID
    oldParties   tss.PartySet
    newParties   tss.PartySet
    newThreshold int

    oldPublicKey []byte
    chainCode    []byte
    planHash     []byte
    limits       Limits

    mode frostReshareMode
    role frostReshareRole
}
```

### State

```go
type frostResharePeerState struct {
    commitments slot[reshareCommitments]
    share       slot[*secret.Scalar]
}

type frostReshareState struct {
    dealers partyTable[frostResharePeerState]

    completed bool
    aborted   bool
    newShare  *KeyShare
}
```

## Step-by-step implementation

### Step 04.1 — Introduce explicit mode and role

- Compute mode and role during session construction.
- Replace scattered `refreshMode`, `isRecipient`, `oldKey != nil`, `newParties.Contains(self)` checks with context methods.

Suggested methods:

```go
func (c frostReshareContext) IsDealer() bool
func (c frostReshareContext) IsRecipient() bool
func (c frostReshareContext) RequiresInboundShares() bool
func (c frostReshareContext) RequiresOutboundShares() bool
```

### Step 04.2 — Unify dealer start preparation

Add:

```go
func prepareReshareDealerStart(...) (*preparedReshareDealerStart, error)
```

This function should cover both:

- true reshare, where the constant term is derived from the old secret and Lagrange coefficient;
- refresh, where the constant term is zero.

Prepared object should own:

- polynomial scalars
- staged own share
- outbound confidential share payloads
- outbound envelopes

Destroy must clear any staged secret-bearing values unless committed.

### Step 04.3 — Transition for commitment messages

Add:

```go
type acceptReshareCommitmentsTx struct {
    from tss.PartyID
    commitments reshareCommitments
    duplicate bool
}
```

Build validates:

1. envelope guard
2. broadcast policy
3. sender is old-party dealer
4. plan hash
5. threshold and commitment count
6. duplicate/equivocation

Commit writes only the commitment slot.

### Step 04.4 — Transition for share messages

Add:

```go
type acceptReshareShareTx struct {
    from tss.PartyID
    share *secret.Scalar
    duplicate bool
}
```

Build validates:

1. envelope guard
2. confidential recipient policy
3. local party is a recipient
4. sender is old-party dealer
5. canonical decode
6. plan hash
7. scalar validity
8. duplicate/equivocation

Build owns decoded share until commit. Reject cleanup must destroy it.

### Step 04.5 — Split completion

Add:

```go
func (s *ReshareSession) maybePrepareReshareCompletion() (*preparedReshareCompletion, error)
func (s *ReshareSession) commitReshareCompletion(p *preparedReshareCompletion)
```

Prepared object:

```go
type preparedReshareCompletion struct {
    newShare *KeyShare
    dealerOnlyComplete bool

    committed bool
}

func (p *preparedReshareCompletion) Destroy() {
    if p.committed {
        return
    }
    if p.newShare != nil {
        p.newShare.Destroy()
    }
}
```

Dealer-only prepare:

- wait for all dealer commitments
- aggregate public commitments
- verify group public key preservation
- do not create a new share

Recipient prepare:

- wait for all dealer commitments and all recipient shares
- verify every dealer share against commitments
- aggregate new secret
- create new `KeyShare`
- validate new share
- verify group public key preservation

Commit:

- install new share if recipient
- set completed
- clear temporary secret-bearing state

## Required tests

Add tests in:

```text
frost/ed25519/reshare_state_transition_test.go
```

Test cases:

1. Invalid commitment does not mutate state.
2. Conflicting commitment does not mutate state.
3. Invalid share does not mutate state and destroys staged share.
4. Share from non-dealer is rejected without mutation.
5. Share to non-recipient is rejected without mutation.
6. Dealer-only completion does not require inbound shares.
7. Recipient completion requires all required shares.
8. Failed share verification aborts and clears received secret shares.
9. Completion failure destroys staged new share.
10. Refresh preserves group public key.
11. True reshare preserves group public key.
12. Successful existing reshare/refresh tests remain unchanged.

## Suggested test commands

```sh
go test ./frost/ed25519 -run 'Test.*Reshare|Test.*Refresh|Test.*Reject|Test.*Duplicate'
```

## Acceptance criteria

- Mode and role are explicit in context.
- Commitment/share handlers do not mutate before validation.
- Completion is prepare/commit based.
- New share is destroyed on pre-commit failure.
- Dealer-only and recipient behavior are clearly separated.
- Full reshare and refresh tests pass.
