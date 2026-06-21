# Phase 03 — Refactor `frost/ed25519` Keygen

## Objective

Refactor FROST keygen to make commitment handling, share handling, confirmation handling, pending key share creation, and finalization transactional and auditable.

Priority issues:

1. `StartKeygen` must clean up local polynomial, local shares, and staged session-owned secrets on any error after session construction.
2. Commitment/share/confirmation handlers must not mutate state before validation is complete.
3. Pending and final key share creation must be atomic and cleanup-safe.

## Target files

Likely files:

```text
frost/ed25519/keygen.go
frost/ed25519/keygen_completion.go
frost/ed25519/keygen_confirm.go
```

Recommended new files:

```text
frost/ed25519/keygen_context_state.go
frost/ed25519/keygen_transition.go
frost/ed25519/keygen_prepare_commit.go
frost/ed25519/keygen_state_transition_test.go
```

## Proposed structure

### Immutable context

```go
type frostKeygenContext struct {
    self      tss.PartyID
    sessionID tss.SessionID
    parties   tss.PartySet
    threshold int
    planHash  []byte
    limits    Limits
}
```

### Resources

```go
type frostKeygenResources struct {
    ownPoly     []*fed.Scalar
    ownMessages []tss.Envelope
}
```

Resources own local secret-bearing values before they are committed into a final `KeyShare`.

### State

```go
type frostKeygenPeerState struct {
    commitments     slot[keygenCommitments]
    share           slot[*secret.Scalar]
    chainCode       slot[[]byte]
    chainCodeCommit slot[[]byte]
    confirmation    slot[*KeygenConfirmation]
}

type frostKeygenState struct {
    peers partyTable[frostKeygenPeerState]

    pending   *KeyShare
    keyShare  *KeyShare
    completed bool
    aborted   bool
}
```

## Step-by-step implementation

### Step 03.1 — Split `StartKeygen` into prepare and commit

Add:

```go
func prepareKeygenStart(...) (*preparedKeygenStart, error)
```

Suggested object:

```go
type preparedKeygenStart struct {
    ctx       frostKeygenContext
    resources frostKeygenResources
    state     frostKeygenState

    out []tss.Envelope

    committed bool
}

func (p *preparedKeygenStart) Destroy() {
    if p.committed {
        return
    }
    clearScalars(p.resources.ownPoly)
    clearEnvelopePayloads(p.resources.ownMessages)
    if p.state.pending != nil {
        p.state.pending.Destroy()
    }
    if p.state.keyShare != nil {
        p.state.keyShare.Destroy()
    }
}
```

`StartKeygen` should only create and return the session after all fallible start work succeeds or after ownership is transferred.

### Step 03.2 — Transition for commitment messages

Add:

```go
type acceptKeygenCommitmentsTx struct {
    from tss.PartyID
    commitments keygenCommitments
    chainCodeCommit []byte
    duplicate bool
}
```

Build must validate:

1. envelope guard
2. broadcast policy
3. round and payload type
4. canonical decode
5. plan hash
6. sender membership
7. commitment count and threshold consistency
8. chain code commitment length
9. duplicate/equivocation behavior

Only commit may write:

```go
peer.commitments = someSlot(commitments)
peer.chainCodeCommit = someSlot(bytes.Clone(chainCodeCommit))
```

### Step 03.3 — Transition for share messages

Add:

```go
type acceptKeygenShareTx struct {
    from tss.PartyID
    share *secret.Scalar
    duplicate bool
}
```

Build must validate:

1. confidential recipient policy
2. sender membership
3. canonical decode
4. plan hash
5. scalar validity
6. duplicate/equivocation

Build owns the decoded secret share until commit. On reject, the share must be destroyed.

### Step 03.4 — Transition for confirmation messages

Add:

```go
type acceptKeygenConfirmationTx struct {
    from tss.PartyID
    confirmation *KeygenConfirmation
    canonical []byte
    duplicate bool
}
```

Build must validate:

1. broadcast policy
2. sender membership
3. canonical decode
4. plan hash / transcript binding
5. duplicate/equivocation
6. confirmation structural limits

Commit writes confirmation slot only after all checks pass.

### Step 03.5 — Split pending key share creation

Add:

```go
func (s *KeygenSession) maybePreparePendingKeyShare() (*preparedPendingKeyShare, error)
func (s *KeygenSession) commitPendingKeyShare(p *preparedPendingKeyShare) keygenEffects
```

Prepared object:

```go
type preparedPendingKeyShare struct {
    share *KeyShare
    confirmation *KeygenConfirmation
    confirmationEnv tss.Envelope

    committed bool
}

func (p *preparedPendingKeyShare) Destroy() {
    if p.committed {
        return
    }
    if p.share != nil {
        p.share.Destroy()
    }
}
```

Prepare performs:

- readiness check
- dealer share verification
- local secret aggregation
- group commitment aggregation
- verification share construction
- transcript construction
- `KeyShare` construction
- `KeyShare` validation
- confirmation construction
- confirmation marshal
- confirmation envelope construction

Commit performs:

- install `pending`
- store local confirmation
- return confirmation envelope effect

### Step 03.6 — Split finalization

Add:

```go
func (s *KeygenSession) maybePrepareFinalKeyShare() (*preparedFinalKeyShare, error)
func (s *KeygenSession) commitFinalKeyShare(p *preparedFinalKeyShare)
```

Prepare performs:

- collect confirmations
- verify confirmation set
- aggregate chain code
- clone pending key share
- apply final transcript/confirmations
- validate final key share

Commit performs:

- destroy old pending share
- install final key share
- clear intermediate secret-bearing state
- set completed

## Required tests

Add tests in:

```text
frost/ed25519/keygen_state_transition_test.go
```

Test cases:

1. Invalid chain-code commitment length does not write commitments.
2. Malformed commitment payload does not mutate state.
3. Conflicting commitments do not mutate state.
4. Malformed share does not mutate state.
5. Conflicting share destroys decoded staged share and does not mutate state.
6. Confirmation mismatch does not write confirmation slot.
7. Pending key share prepare failure destroys staged `KeyShare`.
8. Finalization failure does not install final `keyShare`.
9. `StartKeygen` envelope failure cleans local polynomial and staged outbound secret payloads.
10. Successful full keygen flow remains unchanged.

## Suggested test commands

```sh
go test ./frost/ed25519 -run 'Test.*Keygen|Test.*Confirmation|Test.*Reject|Test.*Duplicate'
```

## Acceptance criteria

- `StartKeygen` has a single cleanup-safe prepare/commit path.
- Keygen message handlers do not mutate before full validation.
- Pending `KeyShare` is destroyed on all pre-commit failures.
- Final `KeyShare` installation is atomic.
- Reject-path and duplicate tests pass.
- Full keygen tests pass.
