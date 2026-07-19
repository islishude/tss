# `tssrun` Integration API

`github.com/islishude/tss/tssrun` defines transport- and database-neutral
contracts for public run admission, active-session routing, and durable key
lifecycle state. Protocol packages still own plans, cryptographic state
machines, payloads, and wire formats.

The package does not implement a coordinator, network, production database,
KMS, or secret manager. Memory implementations and `FileLifecycleStore` are
reference helpers.

## Run Admission

`RunIntent` is the public control-plane record accepted by each local party:

```go
type RunIntent struct {
    RunID     string
    Protocol  tss.ProtocolID
    Kind      RunKind
    SessionID tss.SessionID

    Parties   tss.PartySet
    Signers   tss.PartySet
    Threshold int

    Binding     GenerationBinding
    ParentKeyID string
    PresignID   string

    TargetKeyID         string
    TargetKeyGeneration KeyGeneration

    PlanDigest    []byte
    ContextDigest []byte
}
```

The current validator requires `Binding` for every run kind. For `RunKeygen`,
it is the declared exact output binding. For presign, sign, refresh, reshare,
and child derivation, it is the exact source/parent binding. Refresh and
reshare declare another generation of the same key ID; child derivation
declares a distinct key ID and target generation. The target epoch is absent
because the protocol derives it during the run.

`Parties` and `Signers` must already be sorted, unique, and non-zero.
Presign is CGGMP21-only. Presign, sign, and child derivation require a 32-byte
context digest; CGGMP21 sign requires a presign ID, while FROST sign rejects
one.

`RunIntent.AcceptanceDigest()` wraps the protocol `PlanDigest` with every
immutable intent field, including the complete source binding and target
descriptor. Persist and compare this digest, not the raw plan digest:

```go
digest := run.AcceptanceDigest()
if err := tssrun.AcceptPlanDigest(ctx, runStore, run, self, digest); err != nil {
    return err
}
```

`RunStore` provides `CreateRun`, local plan acceptance, lookup by
protocol/session, started state, local completion, and local abort. Its key
invariants are:

- `RunID` and `(Protocol, SessionID)` are unique and remain non-reusable;
- a party may accept only the canonical acceptance digest, with exact repeats
  idempotent and conflicts returning `ErrPlanDigestConflict`;
- only run participants may mutate local state (`Signers` are the participants
  for sign and presign; `Parties` for other kinds);
- one party's terminal result does not retire another active local party; and
- `LocalRunResult` requires a 32-byte output digest and the binding/presign
  identity required by the run kind. Refresh, reshare, and child results must
  use the declared target and a new epoch.

`MemoryRunStore` is process-local and non-durable.

## Session Registration and Dispatch

Every interactive protocol session implements:

```go
type ProtocolSession interface {
    Handle(tss.InboundEnvelope) ([]tss.Envelope, error)
    Completed() bool
    Destroy()
}
```

`SessionRegistry` indexes active local sessions by
`Protocol + SessionID + Party`. `RegisterStartedSession` first places a gated
session in the registry and then calls `RunStore.MarkStarted`. Concurrent
dispatch waits for that durable decision: success activates the session;
failure returns the storage error and retires the registry entry. Callers may
release initial outbound envelopes only after registration succeeds.

`Dispatcher.Dispatch` accepts an already opened `InboundEnvelope`, looks up
the local session, calls `Handle`, and forwards any returned envelopes through
the configured `tssrun.Transport`:

```text
raw bytes + transport facts
  -> tss.OpenEnvelope or tssrun.DispatchInbound
  -> Dispatcher.Dispatch
  -> ProtocolSession.Handle
  -> Transport.SendAll
```

`DispatchInbound` combines the first two steps through a caller-provided
`Receiver` (or the default `EnvelopeReceiver`). It does not create trusted
`ReceiveInfo`; the transport adapter must provide those facts.

Unknown sessions fail with `RejectUnknownSession` by default. A
`DurableBufferUnknownSession` stores an already opened envelope through
`UnknownEnvelopeStore`; the application must later wait for run acceptance and
session registration, then look up and re-dispatch the envelope so the
protocol guard revalidates it. Memory registries and buffers are reference
implementations.

`Dispatcher` does not automatically retire completed sessions or destroy
them. The application must remove terminal entries and release session-owned
state.

## Generation Binding

```text
GenerationBinding = KeyID + KeyGeneration + EpochID
```

`KeyGeneration` is a store/application compare-and-swap token. `EpochID` is a
non-zero 32-byte cryptographic authorization epoch. Matching only a key ID,
public key, or generation string is insufficient.

`GenerationRecord.Blob` and `PresignCandidate.Blob` may contain secrets.
Production stores must encrypt them and authenticate their public metadata.
All returned records are snapshots; implementations must not expose aliases to
stored byte slices.

## `LifecycleStore`

`LifecycleStore` is the transactional authority for generations, leases,
presigns, attempts, and cutover. The interface groups operations as follows:

| Boundary                   | Operations and required effect                                                                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initial generation         | `InstallInitialGeneration` installs one exact first generation if no lineage exists; `LoadCurrentGeneration` is authoritative.                                                  |
| Leases                     | `AcquireRunLease` binds work to one exact current generation and session; `FinishRunLease` records its terminal outcome.                                                        |
| New-only reshare receiver  | `AcquireReshareReceiverLease` anchors the authenticated public source without creating a local current source generation.                                                       |
| Refresh failure            | `MarkProtocolRefreshFailed` completes the exact lease and durably disables later refresh for the key ID; other work remains policy-dependent.                                   |
| Available presign          | `CommitAvailablePresignFromLease` stores the candidate and completes its lease atomically; `PreparePresignCandidate` returns a read-only snapshot; `BurnPresign` tombstones it. |
| Online attempt             | `CommitSignAttempt` validates the current binding, claims the presign, removes secret availability, and stores one immutable intent plus exact outbox atomically.               |
| Attempt progress           | `QueryAttemptOutcome`, `MarkAttemptDelivered`, `CompleteAttempt`, and `AbortAttempt` update or recover that same immutable attempt.                                             |
| Same-key cutover           | `BeginCutoverFromLease` fences new source work; `CommitCutover` installs target, retires/clears source, and burns source-epoch available presigns atomically.                   |
| Reshare dealer retirement  | `CommitRetirementFromLease` completes an old-only dealer without installing a local target.                                                                                     |
| Child/new receiver install | `CommitInitialGenerationFromLease` and `CommitInitialGenerationFromReshareLease` create an exact first generation in the target lineage.                                        |
| Cutover recovery           | `BeginCutover`, `AbortCutover`, and idempotent exact retries expose the lower-level fence/reconciliation boundary.                                                              |

Keygen, refresh, reshare, and child leases are exclusive for a lineage. Sign
and presign leases may coexist, subject to the store's exact session and
generation checks.

An available presign remains available across encoding and reads. Availability
ends only through atomic sign claim, explicit burn, or source cutover. A
committed `SignAttemptRecord` contains public recovery metadata and the exact
outbox, but never the candidate's secret blob or normalized tuple.

If `CommitSignAttempt` has unknown durable outcome, the error carries an exact
`AttemptQuery`. Reconcile only that query through `QueryAttemptOutcome` or the
protocol's `ResumeSign`; do not create a new intent for the presign. Delivery
and signature completion are separate durable facts, and a successful attempt
is terminal only when both are recorded.

## Reference Implementations and Conformance

`MemoryLifecycleStore` is a mutex-protected semantic reference, not durable
state.

`FileLifecycleStore` is an encrypted reference implementation with one
manifest across all key lineages. It takes sorted per-lineage OS advisory locks
followed by a manifest lock, writes and fsyncs immutable encrypted blobs before
the manifest swap, and reconciles unreferenced crash artifacts on reopen.
`Close` clears its in-memory passphrase copy but does not delete durable state.
It is not a substitute for a transactional production database and KMS/HSM
policy.

External implementations should run:

```go
import "github.com/islishude/tss/tssrun/conformance"

conformance.RunConformance(t, conformance.Harness{
    NewRunStore:        newRunStore,
    NewLifecycleStore:  newLifecycleStore,
    NewSessionRegistry: newRegistry,
    NewUnknownStore:    newUnknownStore,
})
```

Supply only the constructors implemented by the backend. Add backend-specific
transaction, crash, locking, encryption, corruption, and unknown-outcome tests;
the generic suite cannot prove those properties.
