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
session-owned secret material; caller-owned key shares and presigns retain their
own lifecycle rules.

## Run Store

`RunIntent` records the public run metadata: protocol, kind, session ID, party
set, signer set, key identifiers, generation, presign ID, plan digest, and
context digest.

`RunStore` enforces these control-plane invariants:

- `RunID` is unique.
- `protocol + session_id` is unique.
- Each party accepts one plan digest per run.
- Re-accepting the same digest is idempotent.
- Accepting a different digest fails with `ErrPlanDigestConflict`.
- Completed and aborted sessions are not returned by `LookupBySession`.

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

`KeyShareStore`, `PresignInventory`, and `CutoverStore` describe durable
lifecycle semantics without requiring a particular storage backend.

`KeyShareStore` models current-generation key-share install, refresh/reshare
compare-and-swap, and retirement. Storage implementations are responsible for
secret-material encryption.

`PresignInventory` models scheduling visibility only. It does not replace
CGGMP21 `SignAttemptStore`; online signing is still linearized by the
protocol-specific durable sign-attempt commit.

`CutoverStore` serializes refresh and reshare output installation so only one
cutover for a key generation is active and commit uses CAS-equivalent semantics.

The memory implementations are non-durable reference stores. They are useful for
conformance tests, local examples, and integration scaffolding, not production
state.

Third-party store implementations should run `tssrun/conformance.RunConformance`
with constructors for their `RunStore`, `SessionRegistry`, and
`UnknownEnvelopeStore` implementations before use.
