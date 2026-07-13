# Production Integration Model

This document describes the production integration contract implemented by the
`tssrun` package for running the interactive protocols in this repository across
processes or machines.

All interactive protocols in this library are party-local state machines. The
library does not create, distribute, authorize, schedule, or recover protocol
runs across machines. Production applications must provide a control plane that
creates one shared public run intent, distributes it to every participant,
records acceptance, assigns one session ID, routes envelopes by
protocol/session/party, and commits the resulting local state atomically.

## Scope and Responsibility Boundary

The library is responsible for:

- Plan validation.
- Local party startup validation.
- Canonical envelope construction.
- Envelope guard validation.
- Replay, equivocation, and wrong-session rejection.
- Protocol state-machine transitions.
- Proof and transcript verification.
- Key share and presign record serialization.
- Sign-attempt durable interface semantics.

The application is responsible for:

- Deciding that a protocol run is authorized.
- Generating or accepting one shared session ID.
- Distributing public run metadata.
- Authenticating party-to-transport identity mapping.
- Recording each party's acceptance of the same run.
- Storing the active session registry.
- Routing envelopes.
- Durably buffering or rejecting unknown-session messages.
- Encrypting and persisting key shares and presigns.
- Atomically installing refresh and reshare outputs.
- Retiring old key generations.
- Operating monitoring, retries, backoff, and recovery.

## Control Plane vs Data Plane

The control plane creates and authorizes `tssrun.RunIntent` metadata, distributes it
to participants, records acceptance and completion, and owns lifecycle
decisions.

The data plane sends and receives `tss.Envelope` messages. It provides
authenticated and, where required, confidential transport, supplies
`tss.ReceiveInfo` to `tss.OpenEnvelope`, and supplies broadcast acknowledgments
and certificates.

The coordinator is not a cryptographic participant unless it is also a party. It
does not need access to private shares, nonces, Paillier secrets, or presign
secrets. A faulty coordinator can cause liveness failures or propose invalid
runs, but each party must independently validate policy and plan metadata before
starting.

## RunIntent Metadata

Production systems should persist application run metadata equivalent to
`tssrun.RunIntent`:

```go
type RunIntent struct {
    RunID     string
    Protocol  tss.ProtocolID
    Kind      tssrun.RunKind
    SessionID tss.SessionID

    Parties   tss.PartySet
    Signers   tss.PartySet
    Threshold int

    KeyID         string
    KeyGeneration tssrun.KeyGeneration
    ParentKeyID   string
    PresignID     string

    PlanDigest    []byte
    ContextDigest []byte
}
```

`RunID` is an application identifier. `SessionID` is the protocol-level nonce
bound into envelopes, plans, transcripts, proofs, and replay protection.
`PlanDigest` is derived from the library plan and can be exchanged or recorded by
the control plane before data-plane messages are released.

Run admission requires a non-empty key ID for every kind. Refresh and reshare
bind the current key generation. Presign and sign bind the signer set, key
generation, and a 32-byte normalized signing-context digest; CGGMP21 presign
and sign also bind the one-use presign ID.

The actual fields should match the deployment's storage and policy model. The
important invariant is that all public intent needed to reconstruct the same
protocol plan is authenticated and accepted before the first envelope is
processed.

## Session ID Ownership

Each protocol run has exactly one session ID.

For keygen, refresh, reshare, presign, and sign, the session ID belongs to the
run or job, not to an individual party. Every participant in the same run must
use the same session ID.

A party must reject a run if the session ID was previously used locally for the
same protocol namespace. A party must reject envelopes with unknown, stale,
retired, completed, or mismatched session IDs unless the application explicitly
implements durable unknown-session buffering and revalidation.

The session ID is public, but it must be fresh and unpredictable.

## Plan Construction and Plan Digest Acceptance

"Shared plan" means equivalent public metadata, not a shared Go object. Each
party reconstructs its own plan from the same authenticated run metadata. The
resulting plan digest must be identical across parties.

```go
job := loadAcceptedKeygenJob()

plan, err := secp256k1.NewKeygenPlan(secp256k1.KeygenPlanOption{
    SessionID: job.SessionID,
    Parties:   job.Parties,
    Threshold: job.Threshold,
})
if err != nil {
    return err
}

planHash, err := plan.Digest()
if err != nil {
    return err
}

if err := tssrun.AcceptPlanDigest(ctx, runStore, run, self, planHash); err != nil {
    return err
}
```

A typical control-plane flow is:

1. A proposer creates `tssrun.RunIntent` metadata.
2. Each party validates metadata against local policy.
3. Each party reconstructs the plan.
4. Each party records `planHash` acceptance.
5. After enough or all required parties accept the same `planHash`, data-plane
   delivery begins.

## Local Session Startup

`StartXxx` functions are local startup functions. They are called once by each
participating party for its own local role. They do not contact remote parties.
They return initial outbound envelopes that the application must route.

```go
guard, err := buildGuard(job, self)
if err != nil {
    return err
}

session, out, err := secp256k1.StartKeygen(
    plan,
    tss.LocalConfig{Self: self, Context: ctx},
    guard,
)
if err != nil {
    return err
}

if err := tssrun.RegisterStartedSession(ctx, runStore, registry, run, self, session); err != nil {
    return err
}
return transport.SendAll(out)
```

Registration makes the session routable before the durable `MarkStarted`
operation completes. Inbound dispatches that enter during this window wait for
the durable decision: successful startup forwards them to the session, while a
failed startup returns the storage error and retires the registry entry.

## Envelope Routing and Session Registry

Route inbound envelopes by:

```text
protocol + session_id + recipient_party
```

`To == 0` is broadcast. `To != 0` is a direct message.

```go
func OnEnvelope(raw []byte, info tss.ReceiveInfo, cert *tss.BroadcastCertificate) error {
    in, err := tss.OpenEnvelope(raw, info, tss.WithBroadcastCertificate(cert))
    if err != nil {
        return err
    }

    return dispatcher.Dispatch(ctx, in)
}
```

The dispatcher looks up active sessions by
`protocol + session_id + local_party`. If no session is registered, the default
`tssrun.RejectUnknownSession` policy fails closed. A deployment that implements
durable buffering should use `tssrun.UnknownEnvelopeStore` semantics: buffered
envelopes are already opened with `tss.OpenEnvelope`, but they still must be
looked up and revalidated through the registered protocol session before use.

Direct messages carrying private shares or protocol secrets must be delivered
over channels that `OpenEnvelope` receives as `ChannelConfidential`. Broadcast
messages must be delivered consistently and accompanied by the configured
acknowledgment or certificate policy.

## Completion and Durable Commit Boundaries

Completion accessors return local output. The application decides when that
output becomes durable and externally visible.

| Flow            | Completion accessor         | Durable boundary                                                                                              |
| --------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| FROST Keygen    | `KeygenSession.KeyShare()`  | Encrypted local `KeyShare` write.                                                                             |
| FROST Sign      | `SignSession.Signature()`   | Signature result visibility or request completion.                                                            |
| FROST Refresh   | `ReshareSession.KeyShare()` | Compare-and-swap install over current key share.                                                              |
| FROST Reshare   | `ReshareSession.KeyShare()` | New recipient key share install; old generation retirement by control plane.                                  |
| CGGMP21 Keygen  | `KeygenSession.KeyShare()`  | Encrypted local `KeyShare` write.                                                                             |
| CGGMP21 Presign | `PresignSession.Presign()`  | Encrypted local `Presign` write before inventory visibility.                                                  |
| CGGMP21 Sign    | `SignSession.Signature()`   | `SignAttemptStore.CommitSignAttempt` before outbound release; completion persistence before final visibility. |
| CGGMP21 Refresh | `RefreshSession.KeyShare()` | Compare-and-swap install over current key share.                                                              |
| CGGMP21 Reshare | `ReshareSession.Result()`   | New recipient key share install; old generation retirement by control plane.                                  |

## Restart and Recovery

Applications should persist accepted runs, active session IDs, committed sign
attempts, delivery progress, and completed local outputs.

If a process restarts before local session state is recoverable, the
application should either restart the same protocol run from the beginning only
when the protocol permits it, or mark the run failed and create a new run with a
new session ID.

For CGGMP21 online signing, never create a new sign session with a different
session ID for a presign whose commit outcome is unknown. Use the same request
and `ResumeSign`.

## Per-Flow Recipes

### TrustedDealerImportRun

Public run metadata consists of the canonical `TrustedDealerImportPlan`, its
digest, and the normal keygen session ID. The plan binds the target public key,
chain code, party set, threshold, and per-party contribution commitments.
CGGMP21 plans additionally bind Paillier size and security parameters.

The dealer sends each secret `TrustedDealerContribution` out of band to only
its named party. Each participant accepts the plan digest in the run store and
calls `StartTrustedDealerImport`; the returned `KeygenSession` is registered and
routed exactly like ordinary keygen. There is no dealer envelope sender or
setup round. A contribution restored in another process does not bypass the
control plane's single-run/session acceptance rule.

Centralized provisioning may call `GenerateTrustedDealerKeyShares`, which runs
the same sessions in one process and returns both the public plan and the
completed share map. This mode is a total-trust boundary and is not a transport
simulation for production distributed operation.

### FROST Ed25519 Keygen

Public metadata includes a fresh keygen session ID, parties, threshold, and any
application key identifier. Each party reconstructs `ed25519.NewKeygenPlan`,
records the plan digest, builds a guard for `tss.ProtocolFROSTEd25519`, calls
`ed25519.StartKeygen`, dispatches inbound envelopes to the session's `Handle`
method, and routes any returned envelopes.

`KeygenSession.KeyShare()` becomes available only after the confirmation round.
Persist the encrypted local key share before marking the party complete.

### FROST Ed25519 Sign

Public metadata includes a fresh signing session ID, key ID or key generation
ID, signer set, message, and any signing context or derivation request. Each
signer reconstructs `ed25519.NewSignPlan`, calls `ed25519.StartSign`, routes
inbound envelopes through the session's `Handle` method, and verifies the final
signature before exposing the result.

HD derivation is local/public context resolution, not an interactive run. The
signing run must still bind the resolved derivation context.

### FROST Ed25519 Refresh

Public metadata includes a fresh refresh session ID and the current key
generation ID. Each party loads the current key share, reconstructs
`ed25519.NewRefreshPlan`, calls `ed25519.StartRefresh`, and routes
inbound envelopes through the session's `Handle` method.

Refresh preserves party set, threshold, group public key, and chain code. Treat
the refreshed key share as staged output and install it with compare-and-swap
against the expected current generation.

### FROST Ed25519 Reshare

Public metadata includes a fresh reshare session ID, old key generation ID, old
dealer set, new recipient set, and new threshold. Old parties call
`ed25519.StartReshare`; new-only recipients call
`ed25519.StartReshareRecipient`. All parties dispatch inbound envelopes to the
session's `Handle` method and route any returned envelopes.

The control plane owns the cutover. It must not retire the old generation until
the required new-generation commit condition is satisfied.

### CGGMP21 secp256k1 Keygen

Public metadata includes a fresh keygen session ID, parties, threshold, and any
explicit security parameters. Each party reconstructs
`secp256k1.NewKeygenPlan`, records the plan digest, builds a guard for
`tss.ProtocolCGGMP21Secp256k1`, calls `secp256k1.StartKeygen`, and routes
inbound envelopes through the session's `Handle` method.

`KeygenSession.KeyShare()` becomes available only after confirmation. Persist
the encrypted local key share before marking it usable.

### CGGMP21 secp256k1 Presign

Public metadata includes a fresh presign session ID, key ID or key generation
ID, signer set, and `secp256k1.PresignContext`. Each signer loads its local key
share, validates membership and threshold policy, reconstructs
`secp256k1.NewPresignPlan`, calls `secp256k1.StartPresign`, and routes
inbound envelopes through the session's `Handle` method.

A completed presign is a per-party local one-use record. Persist the encrypted
`Presign` before exposing it to inventory. There is no shared presign object
across machines.

### CGGMP21 secp256k1 Sign

Public metadata includes a fresh signing session ID, key ID, local inventory ID
for the encrypted presign record, signer set exactly matching the presign
binding, and `secp256k1.SignRequest` intent. The inventory ID must not be the
internal secret-derived presign content commitment. The sign session ID belongs
to the online signing attempt, not to the earlier presign run.

Each signer loads the local key share and local presign, verifies the presign is
not consumed locally, calls `VerifyCryptographicMaterialWithLimits` after
decoding, reconstructs `secp256k1.NewSignPlan`, calls `secp256k1.StartSign`, and
routes inbound envelopes through the session's `Handle` method. `StartSign` and
`ResumeSign` repeat the strong verification before durable attempt operations.

`StartSign` must commit through `SignAttemptStore` before releasing outbound
envelopes. An unknown commit outcome consumes the presign operationally. Recover
with the same request and `ResumeSign`; do not retry with a new session ID or a
different digest.

### CGGMP21 secp256k1 Refresh

Public metadata includes a fresh refresh session ID and current key generation
ID. Each party loads the current key share, reconstructs
`secp256k1.NewRefreshPlan`, calls `secp256k1.StartRefresh`, and routes
inbound envelopes through the session's `Handle` method.

The refreshed key share is staged output. Install it only with compare-and-swap
against the expected current key generation.

### CGGMP21 secp256k1 Reshare

Public metadata includes a fresh reshare session ID, old key generation ID,
dealer parties, new parties, new threshold, and old public key material from the
current generation. Old-only parties call `secp256k1.StartReshareDealer`;
new-only parties call `secp256k1.StartReshareReceiver`; overlap parties call
`secp256k1.StartReshareOverlap` when applicable.

New receiver parties persist the new key share. Old-only parties do not install
a new share. The control plane retires the old generation only after the
required new-generation commit condition is satisfied.

## Failure Handling Matrix

| Failure                                          | Required behavior                                                                                         |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| Party receives unknown-session envelope          | Reject or durably buffer and revalidate later.                                                            |
| Party receives wrong-protocol envelope           | Reject.                                                                                                   |
| Party receives wrong sender or recipient         | Reject.                                                                                                   |
| Plan hash mismatch before start                  | Do not start data-plane delivery.                                                                         |
| Plan hash mismatch during protocol               | Abort run and report invalid peer or run metadata.                                                        |
| `StartXxx` succeeds but outbound delivery fails  | Application-specific retry; for CGGMP21 sign use attempt-store recovery.                                  |
| Keygen completed but key-share persistence fails | Do not mark key usable.                                                                                   |
| Presign completed but persistence fails          | Do not add presign to inventory.                                                                          |
| Sign attempt commit outcome unknown              | Do not reuse presign; retry same intent or `ResumeSign`.                                                  |
| Refresh completed but CAS install fails          | Do not overwrite newer key share; mark run stale or conflicting.                                          |
| Reshare partially installed                      | Control plane must not retire old generation until required new-generation commit condition is satisfied. |

## Operational Checklist

- One authorized run record exists before envelopes are released.
- All participating parties accepted the same plan hash.
- The session ID is fresh for the protocol namespace.
- Inbound envelopes route to an active `(protocol, sessionID, recipient)` entry.
- Unknown-session handling is durable or fail-closed.
- Direct secret-bearing payloads are delivered over confidential channels.
- Broadcast certificates are persisted according to policy.
- Keygen and presign outputs are encrypted before they become visible.
- Refresh and reshare outputs are installed with compare-and-swap semantics.
- CGGMP21 sign attempts recover by exact attempt, not by presign reuse.
