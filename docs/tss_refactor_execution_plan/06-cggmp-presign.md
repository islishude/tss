# Phase 06 — Refactor `cggmp21/secp256k1` Presign

## Objective

Refactor CGGMP presign round handling into transactional prepare/commit phases.

This is the most complex part of the series and should be split into multiple pull requests if needed.

Priority issues:

1. Round1 public/proof deferred verification should not mutate state before verification succeeds.
2. Round2 MtA verification should be pure and return verified material, not write directly into peer state.
3. Round2 local emission must not write beta shares before payloads and envelopes are successfully constructed.
4. Round3 local emission must destroy staged `delta`, `chi`, signprep proof material, and final `Presign` on every pre-commit failure.
5. Round readiness should eventually stop relying on manually maintained counters.

## Target files

Likely files:

```text
cggmp21/secp256k1/sign.go
cggmp21/secp256k1/presign_round1.go
cggmp21/secp256k1/presign_round2.go
cggmp21/secp256k1/presign_round3.go
cggmp21/secp256k1/presign_plan.go
```

Recommended new files:

```text
cggmp21/secp256k1/presign_context_state.go
cggmp21/secp256k1/presign_transition.go
cggmp21/secp256k1/presign_prepare_commit.go
cggmp21/secp256k1/presign_state_transition_test.go
```

## Proposed structure

### Immutable context

```go
type cggmpPresignContext struct {
    self       tss.PartyID
    sessionID  tss.SessionID
    signers    tss.PartySet
    planHash   []byte
    contextHash []byte

    keygenTranscriptHash []byte
    partiesHash          []byte
    derivationBinding    []byte

    securityParams SecurityParams
    limits         Limits
}
```

### Resources

```go
type cggmpPresignResources struct {
    keyShare *KeyShare

    paillierPrivateKey *paillier.PrivateKey
    kShare             *secret.Scalar
    gamma              *secret.Scalar
    xBar               *secret.Scalar

    startOpening *mta.StartOpening
}
```

### State

```go
type cggmpPresignPeerState struct {
    round1 cggmpPresignRound1State
    round2 cggmpPresignRound2State
    round3 cggmpPresignRound3State
    mta    cggmpPresignMTAState
}

type cggmpPresignRound1State struct {
    payload  slot[presignRound1Payload]
    proof    slot[presignRound1ProofRecord]
    verified bool
}

type cggmpPresignState struct {
    peers partyTable[cggmpPresignPeerState]

    round2Sent bool
    round3Sent bool
    completed  bool
    aborted    bool

    presign *Presign
}
```

## PR split recommendation

### PR 06A — Round1 transition

Add transitions:

```go
type acceptPresignRound1PayloadTx struct {
    from tss.PartyID
    payload presignRound1Payload
    verifyResult *round1VerifyResult
    duplicate bool
}

type acceptPresignRound1ProofTx struct {
    from tss.PartyID
    proof presignRound1ProofPayload
    proofEnvelope tss.Envelope
    verifyResult *round1VerifyResult
    duplicate bool
}
```

Build must:

1. validate envelope guard
2. validate broadcast policy
3. validate payload type and round
4. canonical decode
5. validate plan/context/session binding
6. validate sender membership
7. check duplicate/equivocation
8. if counterpart public/proof exists, perform cryptographic verification before returning tx

Commit writes payload/proof and verified flag only after build succeeds.

### PR 06B — Round2 transition and local emission

Change `finishRound2` into a pure verifier:

```go
func verifyPresignRound2(...) (*round2VerifiedMaterial, error)
```

Verified material:

```go
type round2VerifiedMaterial struct {
    alphaDelta *secret.Scalar
    alphaSigma *secret.Scalar
    committed bool
}

func (m *round2VerifiedMaterial) Destroy() { ... }
func (m *round2VerifiedMaterial) TakeAlphaDelta() *secret.Scalar { ... }
func (m *round2VerifiedMaterial) TakeAlphaSigma() *secret.Scalar { ... }
```

Add transition:

```go
type acceptPresignRound2Tx struct {
    from tss.PartyID
    payload presignRound2Payload
    material *round2VerifiedMaterial
    duplicate bool
}
```

Commit writes round2 payload and takes ownership of alpha shares.

Split local round2 emission:

```go
func (s *PresignSession) preparePresignRound2Outputs() (*preparedPresignRound2Outputs, error)
func (s *PresignSession) commitPresignRound2Outputs(p *preparedPresignRound2Outputs) presignEffects
```

Prepared object owns beta shares until commit.

Commit writes beta shares, sets `round2Sent`, and returns envelopes.

### PR 06C — Round3 transition and local completion

Add transition:

```go
type acceptPresignRound3Tx struct {
    from tss.PartyID
    payload presignRound3Payload
    verifyShare signVerifyShare
    duplicate bool
}
```

Split local round3 emission:

```go
func (s *PresignSession) preparePresignRound3Output() (*preparedPresignRound3Output, error)
func (s *PresignSession) commitPresignRound3Output(p *preparedPresignRound3Output) presignEffects
```

Prepared object owns:

- `deltaSecret`
- `chiShare`
- local verify share
- signprep proof
- round3 envelope
- final staged `Presign`

Destroy must clean every uncommitted secret-bearing value.

Commit:

- writes local round3 state
- installs final `Presign`
- sets `round3Sent`
- marks completed when appropriate
- returns outbound envelope effect

## Derived readiness predicates

Add readiness helpers before deleting counters:

```go
func (st *cggmpPresignState) allRound1PayloadsAccepted() bool
func (st *cggmpPresignState) allRound1ProofsAccepted() bool
func (st *cggmpPresignState) allRound1Verified() bool
func (st *cggmpPresignState) allRound2Accepted() bool
func (st *cggmpPresignState) allRound3Accepted() bool
```

Initially, compare derived readiness to existing counters in tests. Remove counters later in Phase 08.

## Required tests

Add tests in:

```text
cggmp21/secp256k1/presign_state_transition_test.go
```

Test cases:

1. Round1 payload invalid plan hash does not mutate state.
2. Round1 proof invalid plan hash does not mutate state.
3. Round1 deferred proof verification failure does not leave payload/proof partially accepted.
4. Round2 malformed payload does not mutate state.
5. Round2 MtA verification failure does not write alpha shares.
6. Round2 local emit marshal/envelope failure does not write beta shares or set `round2Sent`.
7. Round3 malformed payload does not mutate state.
8. Round3 verification failure does not write verify share.
9. Round3 local emit failure destroys staged `delta`, `chi`, proof material, and `Presign`.
10. Duplicate identical messages are idempotent according to existing policy.
11. Conflicting duplicates do not mutate state.
12. Derived readiness matches counters while counters still exist.
13. Successful full presign flow remains unchanged.

## Suggested test commands

```sh
go test ./cggmp21/secp256k1 -run 'Test.*Presign|Test.*SignPrep|Test.*Reject|Test.*Duplicate'
```

## Acceptance criteria

- Round1 deferred verification no longer mutates before verification succeeds.
- Round2 verification is pure and returns owned material.
- Round2 local emission is atomic.
- Round3 local emission is cleanup-safe and atomic.
- Derived readiness predicates exist and are tested against counters.
- Full CGGMP presign tests pass.
