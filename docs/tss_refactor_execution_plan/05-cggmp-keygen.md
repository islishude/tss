# Phase 05 — Refactor `cggmp21/secp256k1` Keygen

## Objective

Apply the transition-oriented structure to CGGMP keygen after the FROST pattern has been proven.

Priority issues:

1. `StartKeygen` must clean up Paillier private key, local secret share, and session-owned resources on all post-construction failures.
2. Keygen handlers must not mutate state before complete validation.
3. `KeyShare` construction and finalization must be atomic and cleanup-safe.

## Target files

Likely files:

```text
cggmp21/secp256k1/keygen.go
cggmp21/secp256k1/keygen_round1.go
cggmp21/secp256k1/keygen_completion.go
cggmp21/secp256k1/keygen_confirm.go
```

Recommended new files:

```text
cggmp21/secp256k1/keygen_context_state.go
cggmp21/secp256k1/keygen_transition.go
cggmp21/secp256k1/keygen_prepare_commit.go
cggmp21/secp256k1/keygen_state_transition_test.go
```

## Proposed structure

### Immutable context

```go
type cggmpKeygenContext struct {
    self      tss.PartyID
    sessionID tss.SessionID
    parties   tss.PartySet
    threshold int
    planHash  []byte
    limits    Limits

    securityParams SecurityParams
}
```

### Resources

```go
type cggmpKeygenResources struct {
    paillierPrivateKey *paillier.PrivateKey
    localSecretShare   *secret.Scalar
    // Any other local secret or staged proof resources.
}
```

### State

Use a package-local `partyTable` and typed slots for commitments, shares, confirmations, and proof-bearing artifacts.

```go
type cggmpKeygenPeerState struct {
    commitments slot[keygenCommitmentsPayload]
    share       slot[*secret.Scalar]
    confirmation slot[*KeygenConfirmation]
    // ring/paillier proof-related public artifacts as typed slots.
}

type cggmpKeygenState struct {
    peers partyTable[cggmpKeygenPeerState]

    pending   *KeyShare
    keyShare  *KeyShare
    completed bool
    aborted   bool
}
```

## Step-by-step implementation

### Step 05.1 — Split `StartKeygen` into prepare and commit

Add:

```go
func prepareCGGMPKeygenStart(...) (*preparedCGGMPKeygenStart, error)
```

Prepared object owns:

- Paillier private key
- local secret share
- local proof material
- outbound confidential payloads
- outbound envelopes
- staged session state

Destroy must call:

- `paillierPrivateKey.Destroy()`
- local secret scalar destroy
- pending/final `KeyShare.Destroy()` if staged
- clear any secret payload buffers

### Step 05.2 — Transition for round1 commitments and public proof artifacts

Build function validates:

1. envelope guard
2. broadcast policy
3. round and payload type
4. canonical decode
5. plan hash
6. sender membership
7. limits
8. proof structural validity
9. duplicate/equivocation behavior

Commit writes only typed slots after validation succeeds.

### Step 05.3 — Transition for confidential share messages

Build validates:

1. envelope guard
2. confidential recipient policy
3. canonical decode
4. plan hash
5. sender membership
6. scalar validity
7. proof or commitment binding if applicable
8. duplicate/equivocation

Decoded secret share ownership belongs to the transition until commit.

### Step 05.4 — Split pending key share creation

Add:

```go
func (s *KeygenSession) maybePreparePendingKeyShare() (*preparedCGGMPPendingKeyShare, error)
func (s *KeygenSession) commitPendingKeyShare(p *preparedCGGMPPendingKeyShare) keygenEffects
```

Prepared object:

```go
type preparedCGGMPPendingKeyShare struct {
    share *KeyShare
    confirmation *KeygenConfirmation
    confirmationEnv tss.Envelope

    committed bool
}

func (p *preparedCGGMPPendingKeyShare) Destroy() {
    if p.committed {
        return
    }
    if p.share != nil {
        p.share.Destroy()
    }
}
```

Prepare performs all fallible work, including:

- share verification
- public key aggregation
- transcript construction
- `KeyShare` construction
- proof domain construction
- confirmation creation
- confirmation envelope creation

Commit installs pending share and confirmation.

### Step 05.5 — Split finalization

Add:

```go
func (s *KeygenSession) maybePrepareFinalKeyShare() (*preparedCGGMPFinalKeyShare, error)
func (s *KeygenSession) commitFinalKeyShare(p *preparedCGGMPFinalKeyShare)
```

Prepare verifies all confirmations and returns a staged final share.

Commit:

- destroys/replaces pending share
- installs final share
- clears intermediate resources
- sets completed

## Required tests

Add tests in:

```text
cggmp21/secp256k1/keygen_state_transition_test.go
```

Test cases:

1. Invalid round1 payload does not mutate state.
2. Invalid proof artifact does not mutate state.
3. Invalid confidential share destroys staged secret and does not mutate state.
4. Conflicting commitment/share/confirmation does not mutate state.
5. `StartKeygen` envelope failure destroys Paillier private key and local share.
6. Pending `KeyShare` prepare failure destroys staged share and cloned Paillier key.
7. Finalization failure does not install final share.
8. Successful full keygen remains unchanged.

## Suggested test commands

```sh
go test ./cggmp21/secp256k1 -run 'Test.*Keygen|Test.*Confirmation|Test.*Reject|Test.*Duplicate'
```

## Acceptance criteria

- `StartKeygen` cleanup is centralized and covers session-owned resources.
- Keygen handlers are transition-based.
- Secret-bearing decoded shares are destroyed on reject.
- Pending/final `KeyShare` installation is atomic.
- Full CGGMP keygen tests pass.
