# Phase 00 — Baseline Snapshots and Invariant Tests

## Objective

Create test infrastructure before changing production code. The purpose is to make unsafe reject-path mutation, partial emission, cleanup gaps, and duplicate-message behavior visible.

This phase should not perform the structural refactor yet.

## Scope

Add test-only helpers and baseline tests for:

- `frost/ed25519` signing
- `frost/ed25519` keygen
- `frost/ed25519` reshare / refresh
- `cggmp21/secp256k1` keygen
- `cggmp21/secp256k1` presign
- `cggmp21/secp256k1` online sign

## Files to add or modify

Recommended new files:

```text
frost/ed25519/session_snapshot_test.go
frost/ed25519/sign_state_invariant_test.go
frost/ed25519/keygen_state_invariant_test.go
frost/ed25519/reshare_state_invariant_test.go

cggmp21/secp256k1/session_snapshot_test.go
cggmp21/secp256k1/keygen_state_invariant_test.go
cggmp21/secp256k1/presign_state_invariant_test.go
cggmp21/secp256k1/sign_state_invariant_test.go
```

Existing tests may also be extended if there are already nearby state-machine tests.

## Snapshot design

Snapshots must not expose secret values. They should only capture:

- terminal flags
- phase-like flags
- per-party accepted-message presence
- per-party verified-message presence
- whether local temporary secret-bearing state exists
- whether completion artifacts exist
- whether outbound flags were set

### FROST signing snapshot

Suggested shape:

```go
type frostSignSnapshot struct {
    Completed bool
    Aborted   bool

    CommitmentSenders []tss.PartyID
    PartialSenders    []tss.PartyID

    PartialSent bool
    HasDNonce   bool
    HasENonce   bool
    HasMessage  bool
    HasSignature bool
}
```

### FROST keygen snapshot

```go
type frostKeygenSnapshot struct {
    Completed bool
    Aborted   bool
    HasPending bool
    HasKeyShare bool

    CommitmentSenders []tss.PartyID
    ShareSenders      []tss.PartyID
    ConfirmationSenders []tss.PartyID

    OwnPolyLen int
    OwnMessagesLen int
}
```

### FROST reshare / refresh snapshot

```go
type frostReshareSnapshot struct {
    Completed bool
    Aborted   bool
    HasNewShare bool

    CommitSenders []tss.PartyID
    ShareSenders  []tss.PartyID
}
```

### CGGMP presign snapshot

```go
type cggmpPresignSnapshot struct {
    Completed bool
    Aborted   bool

    Round1PayloadSenders []tss.PartyID
    Round1ProofSenders   []tss.PartyID
    Round1VerifiedSenders []tss.PartyID

    Round2Senders []tss.PartyID
    Round3Senders []tss.PartyID

    Round2Sent bool
    Round3Sent bool

    HasKShare bool
    HasGamma  bool
    HasXBar   bool
}
```

### CGGMP online sign snapshot

```go
type cggmpSignSnapshot struct {
    Completed bool
    Aborted   bool
    HasSignature bool

    PartialSenders []tss.PartyID
    HasAttempt bool
    HasStore bool
}
```

## Required invariant tests

### Reject path must not mutate state

For each message class, add tests with this shape:

```go
before := snapshotSession(s)
out, err := s.HandleXMessage(badEnv)
after := snapshotSession(s)

require.Error(t, err)
require.Empty(t, out)
require.Equal(t, before, after)
```

Cover at least:

- malformed wire
- wrong round
- wrong payload type
- wrong plan hash
- unknown sender
- wrong recipient
- wrong broadcast/confidentiality policy
- duplicate conflicting message
- cryptographic verification failure

### Duplicate idempotence

For duplicate identical messages, assert current intended behavior explicitly:

```go
before := snapshotSession(s)
out, err := s.HandleXMessage(sameEnv)
after := snapshotSession(s)

require.NoError(t, err) // or existing duplicate policy
require.Empty(t, out)
require.Equal(t, before, after)
```

If current behavior is not idempotent, record it in `STATUS.md` before changing behavior.

### Emit atomicity baseline

Where injection is practical, force envelope construction or marshal failure and assert:

- no sent flag changes
- no local partial is written
- no beta/alpha/delta secret is committed
- no completed artifact is installed
- no nonce is cleared before emission is committed

If injection requires small production seam changes, defer those seams to the relevant phase and record the gap in `STATUS.md`.

## Acceptance criteria

- Snapshot helpers exist for all targeted session types.
- At least one no-mutation test exists for each protocol family:
  - FROST sign
  - FROST keygen
  - FROST reshare/refresh
  - CGGMP keygen
  - CGGMP presign
  - CGGMP online sign
- Current duplicate behavior is documented by tests or by explicit notes in `STATUS.md`.
- No production protocol logic is refactored in this phase.

## Suggested test commands

```sh
go test ./frost/ed25519 -run 'Test.*Invariant|Test.*Reject|Test.*Duplicate'
go test ./cggmp21/secp256k1 -run 'Test.*Invariant|Test.*Reject|Test.*Duplicate'
```

If the local Go toolchain cannot run the tests, record the exact failure in `STATUS.md`.
