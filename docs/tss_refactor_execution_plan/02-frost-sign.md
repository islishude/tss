# Phase 02 — Refactor `frost/ed25519` Signing

## Objective

Refactor FROST signing so that inbound handlers and local partial emission follow a transaction-oriented structure:

```text
decode -> policy validate -> crypto verify -> prepare transition -> commit -> effects
```

The highest-priority issue is making local partial emission atomic: the local partial must not be written to session state before the partial envelope has been successfully constructed.

## Target files

Likely files:

```text
frost/ed25519/sign.go
frost/ed25519/sign_round1.go
frost/ed25519/sign_round2.go
```

Recommended new files:

```text
frost/ed25519/sign_context_state.go
frost/ed25519/sign_transition.go
frost/ed25519/sign_prepare_commit.go
frost/ed25519/sign_state_transition_test.go
```

## Proposed structure

### Immutable context

```go
type frostSignContext struct {
    self        tss.PartyID
    sessionID   tss.SessionID
    signers     tss.PartySet
    planHash    []byte
    contextHash []byte
    limits      Limits

    verificationKey []byte
}
```

All handler logic should read binding fields from this context instead of reaching into scattered session fields.

### Resources

```go
type frostSignResources struct {
    key        *KeyShare
    message    []byte
    derivation *tss.DerivationResult

    dNonce      *secret.Scalar
    eNonce      *secret.Scalar
    deltaScalar *fed.Scalar
}
```

Rules:

- Resources own secret-bearing values.
- Resources must expose `Destroy` / `clearNonceScalars` style methods.
- Resource cleanup should not be duplicated across handlers.

### State

```go
type frostSignPeerState struct {
    commitment slot[nonceCommitment]
    partial    slot[*fed.Scalar]
    partialEnv slot[tss.Envelope]
}

type frostSignState struct {
    peers partyTable[frostSignPeerState]

    commitMessage slot[tss.Envelope]
    partialSent   bool
    completed     bool
    aborted       bool
    signature     []byte
}
```

## Step-by-step implementation

### Step 02.1 — Introduce context/state wrappers without changing behavior

- Add `frostSignContext`, `frostSignResources`, `frostSignState`.
- Populate them in `StartSign` or equivalent constructor.
- Keep old fields temporarily if needed.
- Add assertions/tests to ensure old and new state mirror each other if both exist temporarily.

### Step 02.2 — Introduce sign transitions

Add transitions:

```go
type acceptNonceCommitmentTx struct {
    from       tss.PartyID
    commitment nonceCommitment
    duplicate  bool
}

type acceptPartialTx struct {
    from      tss.PartyID
    partial   *fed.Scalar
    envelope  tss.Envelope
    duplicate bool
}
```

Each transition should have:

```go
Apply(st *frostSignState) (signEffects, error)
CleanupOnReject()
MarkCommitted()
```

### Step 02.3 — Refactor commitment handling

Build function:

```go
func (s *SignSession) buildAcceptNonceCommitmentTx(env tss.InboundEnvelope) (*acceptNonceCommitmentTx, error)
```

Build must perform:

1. envelope guard validation
2. round and payload type check
3. canonical decode
4. plan hash validation
5. sender membership check
6. duplicate/equivocation check

Build must not mutate session state.

Commit must:

- write the commitment slot
- invoke `maybePrepareLocalPartial` if readiness is reached
- return outbound partial envelope effect if one was prepared and committed

### Step 02.4 — Refactor partial handling

Build function:

```go
func (s *SignSession) buildAcceptPartialTx(env tss.InboundEnvelope) (*acceptPartialTx, error)
```

Build must perform:

1. envelope guard validation
2. round and payload type check
3. canonical decode
4. plan hash validation
5. sender membership check
6. scalar validation
7. duplicate/equivocation check
8. cryptographic partial verification if enough commitment context exists

Commit must:

- write partial slot
- write partial envelope slot if needed for evidence/replay
- invoke aggregate prepare/commit when all partials are present

### Step 02.5 — Split local partial emission

Add:

```go
func (s *SignSession) prepareLocalPartial() (*preparedSignPartial, error)
func (s *SignSession) commitLocalPartial(p *preparedSignPartial) signEffects
```

Prepared object:

```go
type preparedSignPartial struct {
    z       *fed.Scalar
    env     tss.Envelope
    payload []byte

    committed bool
}

func (p *preparedSignPartial) Destroy() {
    if p.committed {
        return
    }
    if p.z != nil {
        p.z.Set(fed.NewScalar())
    }
    clear(p.payload)
}
```

Prepare performs all expensive and fallible work:

- readiness check
- group commitment computation
- rho/challenge computation
- local scalar partial computation
- payload marshal
- envelope construction

Prepare must not:

- write `s.partials[self]`
- set `partialSent`
- clear nonces
- return an envelope to the caller directly

Commit performs:

- write local partial
- store local partial envelope if required
- set `partialSent`
- clear nonce scalars
- mark prepared object committed
- return outbound envelope effect

### Step 02.6 — Split aggregation

Add:

```go
func (s *SignSession) prepareAggregate() (*preparedAggregateSignature, error)
func (s *SignSession) commitAggregate(p *preparedAggregateSignature)
```

Prepare:

- checks all partials are present
- verifies every partial
- computes final signature
- verifies final signature
- returns signature bytes

Commit:

- writes `signature`
- sets `completed`
- clears intermediate secret-bearing resources if any remain

## Required tests

Add tests in:

```text
frost/ed25519/sign_state_transition_test.go
```

Test cases:

1. Invalid commitment plan hash does not mutate state.
2. Malformed commitment payload does not mutate state.
3. Conflicting commitment does not mutate state.
4. Duplicate identical commitment is idempotent according to existing policy.
5. Invalid partial plan hash does not mutate state.
6. Malformed partial scalar does not mutate state.
7. Conflicting partial does not mutate state.
8. Local partial marshal/envelope failure does not:
   - set `partialSent`
   - write local partial
   - clear local nonces
9. Aggregate failure does not:
   - set `completed`
   - write final signature
10. Successful full signing flow remains unchanged.

## Suggested test commands

```sh
go test ./frost/ed25519 -run 'Test.*Sign|Test.*Plan|Test.*Reject|Test.*Duplicate'
```

## Acceptance criteria

- `HandleSignMessage` no longer mutates state before transition commit.
- Local partial emission is atomic.
- Aggregation is prepare/commit based.
- Reject-path snapshot tests pass.
- Full FROST signing tests pass.
- No public API changes unless explicitly recorded in `STATUS.md`.
