# tssrun Integration API

The `tssrun` package is the minimal public production-integration layer for
protocol run lifecycle, data-plane routing, and durable boundary semantics. It
does not implement a coordinator, database, network transport, KMS, or secret
manager.

## Session Surface

Protocol sessions implement:

```go
type ProtocolSession interface {
    Handle(tss.InboundEnvelope) ([]tss.Envelope, error)
    Completed() bool
    Destroy()
}
```

The existing protocol-specific methods such as `HandleKeygenMessage`,
`HandlePresignMessage`, and `HandleSignMessage` remain available. `Handle` is a
uniform alias for dispatchers.

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

`Dispatcher.Dispatch` routes opened inbound envelopes to the registered
`ProtocolSession` and sends returned outbox envelopes through a caller-provided
`Transport`.

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
