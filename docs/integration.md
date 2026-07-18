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
- Key share, epoch, and private presign record validation and serialization.
- Unified generation, lease, available-presign, attempt, and cutover semantics.

The application is responsible for:

- Deciding that a protocol run is authorized.
- Generating or accepting one shared session ID.
- Distributing public run metadata.
- Authenticating party-to-transport identity mapping.
- Recording each party's acceptance of the same run.
- Storing the active session registry.
- Routing envelopes.
- Durably buffering or rejecting unknown-session messages.
- Encrypting and durably implementing `LifecycleStore` secret records.
- Reconciling unknown transaction outcomes.
- Authorizing retirement and cross-party cutover policy.
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

    Binding     tssrun.GenerationBinding
    ParentKeyID string
    PresignID   string

    TargetKeyID         string
    TargetKeyGeneration tssrun.KeyGeneration

    PlanDigest    []byte
    ContextDigest []byte
}
```

`RunID` is an application identifier. `SessionID` is the protocol-level nonce
bound into envelopes, plans, transcripts, proofs, and replay protection.
`PlanDigest` is derived from the library plan. Before data-plane messages are
released, parties exchange and accept `RunIntent.AcceptanceDigest()`. That
canonical repository transcript wraps `PlanDigest` with every immutable intent
field, including the complete source binding and target descriptor. The
protocol plan must also bind those fields, providing two independent checks
against control-plane substitution.

Run admission requires an exact source `GenerationBinding`. Refresh and reshare
name that same source key ID and a distinct target generation. Child derivation
names a distinct child key ID and target generation. These target descriptors
omit an epoch because the protocol produces the new authorization epoch during
the run; the local result must contain the exact target key ID and generation
plus a valid new epoch. Presign and sign bind the signer set, complete source
binding, and a 32-byte normalized signing-context digest; CGGMP21 presign and
sign also bind the one-use presign ID.

The actual fields should match the deployment's storage and policy model. The
important invariant is that all public intent needed to reconstruct the same
protocol plan is authenticated and accepted before the first envelope is
processed.

## Session ID Ownership

Each protocol run has exactly one session ID.

For keygen, refresh, reshare, child derivation, presign, and sign, the session
ID belongs to the run or job, not to an individual party. Every participant in
the same run must use the same session ID.

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
if !bytes.Equal(planHash, run.PlanDigest) {
    return tssrun.ErrPlanDigestConflict
}

if err := tssrun.AcceptPlanDigest(ctx, runStore, run, self, run.AcceptanceDigest()); err != nil {
    return err
}
```

A typical control-plane flow is:

1. A proposer creates `tssrun.RunIntent` metadata.
2. Each party validates metadata against local policy.
3. Each party reconstructs the plan.
4. Each party checks `planHash` against `RunIntent.PlanDigest` and records the
   canonical `RunIntent.AcceptanceDigest()`.
5. After enough or all required parties accept the same acceptance digest,
   data-plane delivery begins.

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

Completion accessors expose only output permitted by the protocol's durable
boundary. For CGGMP21 presign, sign, refresh, reshare, and child generation,
store commit is part of completion rather than a caller-performed follow-up.

| Flow                     | Completion accessor/result  | Durable boundary                                                                                  |
| ------------------------ | --------------------------- | ------------------------------------------------------------------------------------------------- |
| FROST Keygen             | `KeygenSession.KeyShare()`  | Encrypted local key-share write.                                                                  |
| FROST Sign               | `SignSession.Signature()`   | Signature result visibility or request completion.                                                |
| FROST Refresh            | `RefreshSession.KeyShare()` | Application compare-and-swap and retirement policy.                                               |
| FROST Reshare            | `ReshareSession.KeyShare()` | Application compare-and-swap and retirement policy.                                               |
| CGGMP21 Keygen           | confirmed `KeyShare`        | Install one exact initial `GenerationBinding` only after Figure 6 and Figure 7/F.1 complete.      |
| CGGMP21 Presign          | public `PersistedPresign`   | `CommitAvailablePresignFromLease` stores the normalized tuple and completes the lease atomically. |
| CGGMP21 Sign             | `SignSession.Signature()`   | `CommitSignAttempt` before outbound release; `CompleteAttempt` before signature visibility.       |
| CGGMP21 Refresh/Reshare  | confirmed target epoch      | Generation fence followed by atomic cutover, source retirement, and source-presign burn.          |
| CGGMP21 Child Derivation | installed child binding     | `CommitInitialGenerationFromLease` creates the distinct child lineage atomically.                 |

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
dealer set, new receiver set, and new threshold. Old-only parties call
`ed25519.StartReshareDealer`; new-only parties call
`ed25519.StartReshareReceiver`; overlap parties call
`ed25519.StartReshareOverlap`. All parties dispatch inbound envelopes to the
session's `Handle` method and route any returned envelopes.

The control plane owns the cutover. It must not retire the old generation until
the required new-generation commit condition is satisfied.

### CGGMP21 secp256k1 Keygen

Public metadata includes a fresh keygen session ID, parties, threshold, and any
explicit security parameters. Each party reconstructs
`secp256k1.NewKeygenPlan`, records the plan digest, builds a guard for
`tss.ProtocolCGGMP21Secp256k1`, calls `secp256k1.StartKeygen`, and routes
inbound envelopes through the session's `Handle` method.

The session runs paper Figure 6 and then a complete Figure 7/F.1
auxiliary-information protocol. The final share contains the common RID,
dynamic Shamir identifiers, independent Paillier and Ring-Pedersen material,
`EpochID`, and the target confirmation set. Install that canonical encrypted
share as one exact initial `GenerationBinding` before marking it usable.

### CGGMP21 secp256k1 Presign

Public metadata includes a fresh presign session ID, the exact source
`GenerationBinding`, signer set, non-zero 32-byte protocol `PresignID`, and a
signing context with an empty path. Each signer constructs the same public
`PresignPlan` and calls:

```go
session, out, err := secp256k1.StartPresign(plan, secp256k1.PresignRuntime{
    Local:          local,
    Guard:          guard,
    LifecycleStore: lifecycle,
    Binding:        binding,
})
```

The start reloads and revalidates the authoritative current generation and
acquires a durable presign lease before returning `out`. Figure 8 completion
atomically stores the local normalized tuple and completes the lease.
`session.Presign()` then returns only a repeatable public persisted descriptor;
there is no cross-machine or caller-owned secret presign object.

### CGGMP21 secp256k1 Sign

Public metadata includes a fresh signing session ID, exact generation binding,
canonical public presign slot, unique attempt ID, signer set exactly matching
the Figure 8 artifact, delivery policy, and `tss.SignIntent`. The session ID belongs
to this online attempt, not to the earlier presign run.

Each signer constructs `NewSignPlan` from its public persisted metadata and
calls:

```go
session, out, err := secp256k1.StartSign(plan, secp256k1.SignRuntime{
    Local:          local,
    Guard:          guard,
    LifecycleStore: lifecycle,
    Binding:        binding,
    PresignID:      persisted.SlotID(),
    AttemptID:      attemptID,
    DeliveryPolicy: deliveryPolicy,
})
```

`StartSign` reloads and revalidates the key and available candidate, constructs
the exact Figure 10 partial and canonical outbox, then calls
`CommitSignAttempt`. That transaction is the only online linearization point.
An unknown outcome makes every new intent forbidden. Reconcile with the exact
`AttemptQuery` and `ResumeSign`; do not choose a new session, attempt, or digest.

### CGGMP21 secp256k1 Refresh

Public metadata includes a fresh refresh session ID and current key generation
ID. Each party loads the current key share, reconstructs
`secp256k1.NewRefreshPlan`, calls `secp256k1.StartRefresh`, and routes
inbound envelopes through the session's `Handle` method.

Refresh runs a fresh Figure 7/F.1 epoch with independent moduli, new RID, and
new dynamic identifiers while preserving the group public key and chain code.
Fence the source through the lifecycle lease, then atomically install the
target generation, retire the source secret blob, and burn source-epoch
available presigns. A protocol-level failure durably disables later refresh for
the lineage; a local pre-start or storage failure does not.

### CGGMP21 secp256k1 Reshare

Public metadata includes a fresh reshare session ID, old key generation ID,
dealer parties, new parties, new threshold, and old public key material from the
current generation. Old-only parties call `secp256k1.StartReshareDealer`;
new-only parties call `secp256k1.StartReshareReceiver`; overlap parties call
`secp256k1.StartReshareOverlap` when applicable.

New receiver parties persist the new key share. Old-only parties do not install
a new share. The temporary Lagrange-weighted handoff is not sign-ready state.
Every target runs Figure 7/F.1 and receives a fresh RID, dynamic identifiers,
and independent auxiliary material before confirmation. Use lifecycle cutover
for overlap/source holders and the new-lineage reshare transaction for new-only
receivers. Retire the source authorization epoch in application policy after
the required target commit condition is satisfied.

### CGGMP21 secp256k1 Child Derivation

Public metadata includes the exact parent generation, a non-empty
non-hardened BIP32 path, a fresh child-derivation session, and a distinct target
key ID and generation. Construct `NewChildDerivationPlan` from the parent public
state, then call `StartChildDerivation` with the guard and `LifecycleStore`.

The session reloads the parent, acquires an exclusive lease, applies the public
tweak, runs a complete Figure 7/F.1 protocol under a child SID, and atomically
installs the first child generation. The parent remains current. Presign and
sign plans accept only an already installed generation and an empty path.

## Failure Handling Matrix

| Failure                                                 | Required behavior                                                                               |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Party receives unknown-session envelope                 | Reject or durably buffer and revalidate later.                                                  |
| Party receives wrong-protocol envelope                  | Reject.                                                                                         |
| Party receives wrong sender or recipient                | Reject.                                                                                         |
| Plan hash mismatch before start                         | Do not start data-plane delivery.                                                               |
| Plan hash mismatch during protocol                      | Abort run and report invalid peer or run metadata.                                              |
| `StartXxx` succeeds but outbound delivery fails         | Application-specific retry; for CGGMP21 sign replay only the exact durable attempt outbox.      |
| Keygen completed but key-share persistence fails        | Do not mark key usable.                                                                         |
| Figure 8 protocol succeeds but atomic persistence fails | No descriptor or available presign; abort/reconcile the exact lease.                            |
| Sign attempt commit outcome unknown                     | Do not reuse presign; retry same intent or `ResumeSign`.                                        |
| Cutover outcome unknown                                 | Keep the source fenced and reconcile the exact fence; do not admit new source work.             |
| Reshare partially installed                             | Do not retire source policy until the required target-generation commit condition is satisfied. |
| Child install fails                                     | Parent remains current; child lineage must remain absent or reconcile the exact transaction.    |

## Operational Checklist

- One authorized run record exists before envelopes are released.
- All participating parties accepted the same plan hash.
- The session ID is fresh for the protocol namespace.
- Inbound envelopes route to an active `(protocol, sessionID, recipient)` entry.
- Unknown-session handling is durable or fail-closed.
- Direct secret-bearing payloads are delivered over confidential channels.
- Broadcast certificates are persisted according to policy.
- CGGMP21 key generations and available presigns become visible only through
  their lifecycle transactions.
- Refresh and reshare use lease fencing and atomic cutover.
- Non-hardened children are distinct lineages with fresh auxiliary epochs.
- CGGMP21 sign attempts recover by exact attempt, not by presign reuse.
