# Integration Model

This document describes how an application runs the party-local state machines
across processes or machines. `tssrun` provides contracts for admission,
routing, and lifecycle state; it does not provide a distributed coordinator or
recoverable protocol-session engine.

## Responsibility Boundary

| Library                                                                   | Application                                                                                  |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Validate protocol plans and local startup.                                | Authorize a run and distribute its authenticated public metadata.                            |
| Construct canonical envelopes and validate immutable inbound envelopes.   | Authenticate peer identity, classify channel protection, and collect broadcast certificates. |
| Reject wrong protocol/session/round/party/plan, replay, and equivocation. | Persist session-ID claims, accepted run intent, inbox/outbox state, and local results.       |
| Verify protocol equations, transcripts, and proofs.                       | Provide transport, retry/backoff, monitoring, and incident response.                         |
| Validate and serialize key shares and presign records.                    | Encrypt records and implement production `RunStore` and `LifecycleStore` transactions.       |
| Enforce current CGGMP21 lease, attempt, and cutover transitions.          | Reconcile unknown transaction outcomes and coordinate cross-party authorization/cutover.     |

The coordinator is not a cryptographic participant unless it is also a party.
It must not receive shares, nonces, Paillier factors, MtA witnesses, presign
secrets, trusted-dealer contributions, or reconstructed secrets.

## End-to-End Run

Every interactive run follows the same outer sequence:

1. Create one `tssrun.RunIntent` with a fresh shared `SessionID`.
2. Each local party authenticates the metadata, reconstructs the protocol
   plan, verifies `Plan.Digest()` against `RunIntent.PlanDigest`, and persists
   `RunIntent.AcceptanceDigest()`.
3. Construct the protocol `EnvelopeGuard` and local session.
4. Register the session with `tssrun.RegisterStartedSession`; only then release
   the initial outbound envelopes.
5. Open every received wire record with transport-derived `ReceiveInfo` and
   dispatch the returned `InboundEnvelope`.
6. Commit the protocol result at the flow-specific durable boundary, record the
   local `LocalRunResult`, retire the registry entry, and destroy caller-owned
   secret state.

Each participant reconstructs an equivalent plan; parties never share a Go
plan object. A typical admission check is:

```go
plan, err := secp256k1.NewKeygenPlan(secp256k1.KeygenPlanOption{
    SessionID: run.SessionID,
    Parties:   run.Parties,
    Threshold: run.Threshold,
})
if err != nil {
    return err
}

planDigest, err := plan.Digest()
if err != nil {
    return err
}
if !bytes.Equal(planDigest, run.PlanDigest) {
    return tssrun.ErrPlanDigestConflict
}
if err := tssrun.AcceptPlanDigest(
    ctx, runStore, run, self, run.AcceptanceDigest(),
); err != nil {
    return err
}
```

`RunIntent.Parties` and `Signers` must be canonical sorted sets. The complete
run-intent field rules, including source/target binding semantics, are in
[`tssrun.md`](tssrun.md#run-admission).

## Guard Construction

The application builds one guard for the local session:

```go
guard, err := (tss.GuardConfig{
    Self:             self,
    Parties:          parties,
    Protocol:         protocol,
    SessionID:        sessionID,
    Policies:         policies,
    Cache:            replayCache,
    AckVerifier:      ackVerifier,
    EnvelopeVerifier: envelopeVerifier,
}).BuildGuard()
```

`BuildGuard` always requires a replay cache and ack verifier. It requires an
envelope verifier when any policy requires portable sender signatures.
CGGMP21 starts that emit signed direct envelopes also require
`LocalConfig.EnvelopeSigner`.

The guard's party set is the construction-time universe. Protocol sessions
apply narrower per-round sender sets for role-dependent flows such as reshare.
Do not weaken the guard to accommodate changing roles.

## Startup and Routing

`Start*` functions create only the caller's local role. They neither contact
peers nor send the returned envelopes:

```go
session, out, err := secp256k1.StartKeygen(
    plan,
    tss.LocalConfig{Self: self, Context: ctx, EnvelopeSigner: signer},
    guard,
)
if err != nil {
    return err
}
if err := tssrun.RegisterStartedSession(
    ctx, runStore, registry, run, self, session,
); err != nil {
    session.Destroy()
    return err
}
return transport.SendAll(ctx, out)
```

`RegisterStartedSession` gates inbound handling on the durable `MarkStarted`
decision. This avoids both a routing gap and processing before durable startup.

The receive path is:

```go
func OnEnvelope(raw []byte, info tss.ReceiveInfo, cert *tss.BroadcastCertificate) error {
    in, err := tss.OpenEnvelope(raw, info, tss.WithBroadcastCertificate(cert))
    if err != nil {
        return err
    }
    return dispatcher.Dispatch(ctx, in)
}
```

The dispatcher indexes the local session by
`Protocol + SessionID + local Party`. `Envelope.To == 0` still means broadcast;
it does not change the registry key. Unknown sessions fail closed unless the
application configures a durable buffer. Buffered envelopes must be
re-dispatched after acceptance and registration so the session guard performs
full validation.

Secret-bearing direct messages must arrive with
`ReceiveInfo.Protection == ChannelConfidential`. Broadcast messages require
the certificate selected by the protocol policy. Neither fact may be copied
from untrusted message fields.

## Durable Boundaries

`RunStore` and `LifecycleStore` serve different purposes:

- `RunStore` records authenticated public intent and each local party's status.
- `LifecycleStore` is the transactional authority for exact generations,
  leases, available CGGMP21 presigns, online attempts, and cutover.

The protocol-specific boundary is:

| Flow                           | Result visible from session                      | Required durable action                                                                                     |
| ------------------------------ | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| FROST keygen                   | `KeygenSession.KeyShare()`                       | Encrypt and install the caller-owned share before marking it usable.                                        |
| FROST sign                     | `SignSession.Signature()`                        | Persist/expose the verified signature according to application policy.                                      |
| FROST refresh                  | `RefreshSession.KeyShare()`                      | Compare-and-swap the staged share against the expected current generation.                                  |
| FROST reshare receiver/overlap | `ReshareSession.KeyShare()`                      | Install the target share; coordinate old-generation retirement externally.                                  |
| FROST old-only reshare dealer  | terminal session, no share                       | Keep the session active through target confirmations, then record local completion.                         |
| CGGMP21 keygen                 | confirmed `KeyShare`                             | Canonically encode and call `InstallInitialGeneration` with the exact produced epoch.                       |
| CGGMP21 presign                | public `PersistedPresign`                        | Already committed by `CommitAvailablePresignFromLease`; no caller-owned secret presign is returned.         |
| CGGMP21 sign                   | `secp256k1.Signature`                            | Attempt is claimed before outbox visibility; completion is durable before `Signature()` returns success.    |
| CGGMP21 refresh                | confirmed share and `ResultMetadata`             | Native session commits the fenced same-key cutover before terminal success.                                 |
| CGGMP21 reshare                | share only for target holders; none for old-only | Native session commits target install, overlap cutover, or old-only retirement according to the local role. |
| CGGMP21 child derivation       | `InstalledBinding()`                             | Native session creates the first generation of the distinct child lineage before success.                   |

Completion does not remove the `SessionRegistry` entry. The application must
retire it after the durable result/abort decision and call `Destroy`.

## FROST API Map

| Flow           | Plan construction                                      | Local start                                                                                |
| -------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Keygen         | `ed25519.NewKeygenPlan`                                | `ed25519.StartKeygen(plan, local, guard)`                                                  |
| Sign           | `ed25519.NewSignPlan`                                  | `ed25519.StartSign(key, plan, ed25519.SignRuntime{Local: local, Guard: guard})`            |
| Refresh        | `ed25519.NewRefreshPlan`                               | `ed25519.StartRefresh(oldKey, plan, local, guard)`                                         |
| Reshare holder | `ed25519.NewResharePlan`                               | `StartReshareDealer` or `StartReshareOverlap` with `(oldKey, plan, local, guard)`          |
| Reshare joiner | `ed25519.NewPublicResharePlan`                         | `ed25519.StartReshareReceiver(plan, local, guard)`                                         |
| HD derivation  | `KeyShare.Derive` or public metadata derivation helper | Local operation; it is not an interactive `StartChildDerivation` run in the FROST package. |

FROST refresh preserves committee, threshold, public key, and chain code.
Reshare preserves the group public key while changing committee and/or
threshold. The application owns generation tokens and compare-and-swap policy
for both.

## CGGMP21 API Map

| Flow             | Plan construction                  | Local start and lifecycle dependency                                                                    |
| ---------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Keygen           | `secp256k1.NewKeygenPlan`          | `StartKeygen(plan, local, guard)`; application installs confirmed initial generation.                   |
| Presign          | `secp256k1.NewPresignPlan`         | `StartPresign(plan, runtime)` with `PresignRuntime`.                                                    |
| Sign             | `secp256k1.NewSignPlan`            | `StartSign(plan, runtime)` with `SignRuntime`.                                                          |
| Refresh          | `secp256k1.NewRefreshPlan`         | `StartRefresh(plan, runtime)` with `RefreshRuntime`.                                                    |
| Reshare          | `secp256k1.NewResharePlan`         | Role-specific `StartReshare*` with one `ReshareRuntime`; new-only receivers use a public source anchor. |
| Child derivation | `secp256k1.NewChildDerivationPlan` | `StartChildDerivation(plan, run)` with `ChildDerivationRun`.                                            |

Each runtime supplies the local config, guard, lifecycle store, exact source
binding, and flow-specific identifiers or target descriptor required by its
exported fields. Construct it with named fields; the protocol validates the
complete runtime before acquiring a lease.

Presign and sign accept only an already installed generation and an empty
derivation path. A non-hardened child must first become a distinct installed
lineage through the child-derivation flow.

`StartPresign` reloads and validates the current generation before acquiring
its lease. Figure 8 completion commits the normalized tuple and exposes only
public metadata. `StartSign` reloads the generation and candidate, constructs
and verifies the Figure 10 partial, and atomically claims the presign with the
exact outbox before returning it.

Refresh and reshare construct their plan from authenticated source metadata,
but start from `LifecycleStore`, not a caller-supplied secret key. Transient
post-protocol persistence failures remain pending on the live session and are
retried with `RetryLifecycleCommit`. Child derivation similarly installs the
child before reporting completion.

## Trusted Import and Reconstruction

Both protocol packages expose the same ceremony shape:

1. `NewTrustedDealerImport` returns a public plan and one secret
   `TrustedDealerContribution` per party.
2. Deliver each contribution only to its named party over confidential,
   authenticated, encrypted storage/transport.
3. The party accepts the plan digest and calls `StartTrustedDealerImport`; the
   returned keygen session uses the normal keygen routing and confirmation
   path.

`GenerateTrustedDealerKeyShares` instead runs every party in one process and
centralizes all output shares; for CGGMP21 it also centralizes every Paillier
private key. It is a provisioning helper, not a distributed transport model.

`ReconstructSecretKey` requires enough unique shares from one exact lifecycle
generation and does not consume or revoke them. `SecretKey.MarshalBinary`
exports a caller-owned 32-byte secret. Treat import, centralized provisioning,
reconstruction, and export as separately authorized exfiltration ceremonies.

## Restart and Unknown Outcomes

Public protocol sessions do not expose a general durable mid-round snapshot
and resume API. If a process loses an in-progress session, reconcile any
durable lease or fence, mark the run failed, and start a newly authorized run
with a new session ID unless a protocol-specific recovery API says otherwise.

CGGMP21 online signing is the explicit exception. If
`CommitSignAttempt` may have committed, retain the exact `AttemptQuery` and use
`QueryAttemptOutcome` or `ResumeSign`. Never change the session, attempt,
intent digest, signer set, presign ID, generation, or epoch. `ResumeSign`
returns only the exact stored outbox while delivery remains incomplete.

Persist accepted runs, session-ID claims, transport inbox/outbox progress,
attempt delivery, and completion records as one recovery design. A transport
replay still enters through `OpenEnvelope` and the normal guard.

## Failure Matrix

| Failure                                            | Required behavior                                                                                         |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Unknown session                                    | Reject, or durably buffer and re-dispatch only after acceptance and registration.                         |
| Wrong protocol, party, recipient, plan, or session | Reject without state mutation or effects.                                                                 |
| `Start*` succeeds but initial send fails           | Apply transport retry policy; CGGMP21 sign may replay only the exact committed attempt outbox.            |
| FROST share persistence/CAS fails                  | Do not expose the target as current; reconcile an outcome-unknown CAS before selecting either generation. |
| CGGMP21 keygen install fails                       | Do not mark the share usable.                                                                             |
| Figure 8 persistence fails                         | No available descriptor; finish or reconcile the exact presign lease.                                     |
| Sign-attempt commit outcome is unknown             | Query/resume the same attempt; never reuse the presign.                                                   |
| Refresh/reshare lifecycle commit is transient      | Keep the live session pending and call `RetryLifecycleCommit`; do not release withheld effects early.     |
| Cutover or child-install outcome is unknown        | Reconcile the exact store mutation; do not admit competing source work or child lineage.                  |
| Partial reshare deployment                         | Keep source authorization until the configured target-holder commit condition is satisfied.               |

## Integration Checklist

- The run is authorized and every party accepts the same acceptance digest.
- `SessionID` is fresh and durably non-reusable for the protocol namespace.
- `ReceiveInfo` comes only from authenticated transport state.
- Secret direct payloads use confidential channels; broadcasts have full
  certificates.
- The active registry is populated before outbound visibility and retired
  after durable terminal disposition.
- Production stores pass `tssrun/conformance` plus backend crash and
  unknown-outcome tests.
- CGGMP21 operations name the complete generation and epoch.
- Presign availability changes only through atomic claim, explicit burn, or
  source cutover.
- Recovery uses exact durable descriptors, never reconstructed intent.
