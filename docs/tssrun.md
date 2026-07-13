# tssrun Integration API

The `tssrun` package is the minimal public production-integration layer for
protocol run lifecycle, data-plane routing, and durable boundary semantics. It
does not implement a coordinator, database, network transport, KMS, or secret
manager.

## Session Surface

Every interactive protocol session exposes the same inbound handler surface:

```go
type ProtocolSession interface {
    Handle(tss.InboundEnvelope) ([]tss.Envelope, error)
    Completed() bool
    Destroy()
}
```

`Handle` is the protocol state-machine entrypoint for already opened inbound
envelopes. It does not decode transport bytes and it does not bypass
`EnvelopeGuard`: callers must first create a `tss.InboundEnvelope` with
`tss.OpenEnvelope`, using transport-authenticated `tss.ReceiveInfo`, then route
that inbound envelope to the locally registered session.

`Completed` is a terminal-state hint for dispatchers and registries. Completed
or retired sessions should be removed from the active registry so stale
envelopes fail closed through the unknown-session policy. `Destroy` releases
session-owned secret material. CGGMP21 Figure 8 completion exposes only a
public persisted descriptor; its normalized secret tuple is store-owned.

## Run Store

`RunIntent` records the public run metadata: protocol, kind, session ID, party
set, signer set, exact source generation binding, lifecycle target descriptor,
presign ID, protocol plan digest, and context digest.

`RunStore` enforces these control-plane invariants:

- `RunID` is unique.
- `protocol + session_id` is unique.
- Each party accepts one canonical `RunIntent.AcceptanceDigest()` per run.
- `AcceptanceDigest` uses a repository transcript to wrap the protocol
  `PlanDigest` with every immutable run-intent field, including the complete
  source binding and target key ID and generation. Reusing one protocol digest
  with substituted lifecycle metadata therefore fails closed.
- `RunIntent.PlanDigest`, `AcceptanceDigest`, and local output digests are
  32-byte SHA-256 values.
- Every run names an exact source `GenerationBinding` containing key ID,
  generation, and authorization epoch.
- Refresh and reshare name the same key ID and a distinct target generation.
  The protocol creates the new target epoch during the run, so it is not part
  of the pre-run target descriptor.
- Child derivation names a distinct target key ID and target generation. It
  likewise records the protocol-created child epoch only in the local result.
- Presign runs are CGGMP21-only and bind a signer set, key generation, presign
  ID, and 32-byte signing-context digest.
- Signing runs bind a signer set, key generation, and 32-byte signing-context
  digest. CGGMP21 signing also binds a presign ID; FROST signing rejects one.
- Lifecycle mutations must name a party in the run's participant set; signing
  and presigning use the signer set.
- Re-accepting the same acceptance digest is idempotent.
- Accepting a different digest fails with `ErrPlanDigestConflict`.
- One local party completing or aborting does not retire another accepted local
  party for the same run.
- Runs with no accepted local party still active are not returned by
  `LookupBySession`, and new parties cannot accept that terminal run later.
- Local completion requires a SHA-256 output digest and an exact generation
  binding consistent with the run intent. Refresh and reshare must return the
  declared target key ID and generation with a new epoch. Child derivation must
  return the declared distinct child key ID and generation with a new epoch.
  Presign and sign remain bound to the complete source binding. Repeating the
  same completion is idempotent; replacing it is rejected as terminal.

`MemoryRunStore` is a reference implementation for tests and examples only. A
production store must be durable and recoverable.

## Registry And Dispatcher

`SessionRegistry` stores active local sessions by:

```text
protocol + session_id + local_party
```

`Dispatcher.Dispatch` accepts an already opened `tss.InboundEnvelope`, looks up
the active session, calls `ProtocolSession.Handle`, and sends returned outbox
envelopes through a caller-provided `Transport`.

The receive path is:

```text
raw bytes + transport facts
  -> tss.OpenEnvelope
  -> tssrun.Dispatcher.Dispatch
  -> ProtocolSession.Handle
  -> Transport.SendAll
```

The default unknown-session behavior is fail-closed rejection. If a deployment
buffers unknown sessions, buffered messages must be replayed only after a run is
accepted, a session is registered, and the session lookup succeeds again.

## Durable Boundaries

`LifecycleStore` is the single transactional boundary for key generations, run
leases, presigns, online-sign attempts, and generation cutover:

```text
GenerationBinding = key ID + local generation token + cryptographic EpochID

current generation
  -> leased protocol work
  -> available presign
  -> claimed exact sign attempt
  -> durable delivery and completion

current generation
  -> exclusive refresh/reshare lease
  -> generation fence
  -> atomic target cutover and source retirement

current parent
  -> exclusive child lease
  -> fresh child epoch
  -> first generation of a distinct key lineage
```

- `LoadCurrentGeneration` is authoritative. Protocol starts must compare the
  entire returned binding, canonically decode and re-encode the secret blob,
  and perform algorithm-specific material validation before use.
- `AcquireRunLease` binds work to one exact generation, run kind, and session.
  Refresh, reshare, and child derivation are exclusive with other generation
  work; presign and sign follow the store's compatible-lease rules.

- `CommitAvailablePresignFromLease` atomically stores one available presign and
  completes the exact presign lease. The same public presign artifact cannot be
  persisted under another lifecycle slot.
- `CommitSignAttempt` atomically claims an available presign and persists the
  immutable public intent and exact recovery outbox. An unknown commit outcome
  is resolved only through `QueryAttemptOutcome` with the exact query.
- `MarkAttemptDelivered`, `CompleteAttempt`, and `AbortAttempt` update the same
  immutable attempt. Delivery and completion are independent durable facts.
- `MarkProtocolRefreshFailed` atomically aborts the exact refresh lease and
  durably disables future refresh runs for that key ID. Signing and presigning
  remain allowed.
- `BeginCutoverFromLease` atomically completes the exact refresh or reshare
  lease and creates a generation fence. `CommitCutover` installs the target,
  retires and clears the source record's blob and metadata, and burns available
  presigns from the source epoch. It refuses other active leases and
  non-terminal signing attempts.
- `CommitInitialGenerationFromLease` atomically completes an exact child
  derivation lease and creates the first generation of a distinct child key
  lineage. Child derivation never uses the same-key cutover path.
- `CommitInitialGenerationFromReshareLease` gives a new-only receiver the same
  atomic first-generation installation without pretending it owned the source
  secret blob.

An available presign is a secret `PresignCandidate` plus public metadata under
one canonical public slot. Its encoding does not change availability.
Availability ends only through the store's atomic sign claim, explicit burn, or
source-epoch cutover. A committed attempt never retains the candidate's secret
blob or normalized tuple.

Outcome-unknown errors are not ordinary retry permission. The caller must keep
the exact `AttemptQuery`, reconcile that same mutation, and never construct a
new intent for the affected presign.

`MemoryLifecycleStore` is a non-durable reference implementation for tests and
examples. `FileLifecycleStore` is an encrypted reference implementation whose
single manifest covers all key lineages, allowing parent-to-child creation to
linearize at one atomic rename. Operations acquire sorted per-lineage OS locks
before the manifest lock; immutable encrypted blobs are fsynced before the
manifest references them, and reopen reconciliation removes orphan blobs and
temporary manifests left by a pre-swap crash. It is not a substitute for a
production database transaction and KMS or HSM protection.

Third-party store implementations should run `tssrun/conformance.RunConformance`
with constructors for their `RunStore`, `LifecycleStore`, `SessionRegistry`,
and `UnknownEnvelopeStore` implementations before use.
