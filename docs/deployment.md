# Deployment Guide

This guide describes the operational boundary expected by the repository. It
is not a production-readiness claim: the library has not completed an
independent production audit, and the CGGMP21 Paillier/ZK layer still requires
independent cryptographic review.

Read the [integration model](integration.md), [`tssrun` contracts](tssrun.md),
and [security notes](security.md) before deploying a protocol package. Protocol
`Start*` functions create party-local state machines; the application owns
authorization, coordination, transport, durability, recovery, and operations.

## Required Components

A deployment needs these explicit components:

| Component                | Required responsibility                                                                                   |
| ------------------------ | --------------------------------------------------------------------------------------------------------- |
| Control plane            | Authorize one canonical `RunIntent`, distribute public metadata, and record each local acceptance/result. |
| Authenticated data plane | Open wire envelopes with transport-derived facts, collect broadcast certificates, and deliver outboxes.   |
| Session registry         | Route active `(Protocol, SessionID, local Party)` entries and retire terminal sessions.                   |
| Replay/session store     | Atomically claim session IDs and message slots without evicting live security state.                      |
| Lifecycle database       | Implement generation, lease, presign, attempt, and cutover transactions.                                  |
| Key management           | Encrypt secret records, control decrypt authority, rotate keys, and audit access.                         |
| Recovery state           | Persist accepted runs, inbox/outbox progress, exact recovery descriptors, backups, and incident records.  |

The coordinator is not a cryptographic party unless explicitly deployed as
one. It must not receive private shares, nonces, Paillier factors, MtA
witnesses, presign secret tuples, trusted-dealer contributions, or
reconstructed secrets.

## Run Admission

Before releasing the first envelope:

1. Create one fresh, unpredictable `SessionID` for the run and claim it
   durably in the protocol namespace.
2. Authenticate every public `RunIntent` field and validate it against local
   authorization policy.
3. Reconstruct the protocol plan and compare its digest with
   `RunIntent.PlanDigest`.
4. Persist the canonical `RunIntent.AcceptanceDigest()` for the local party.
5. Build the production guard, start the local role, and call
   `RegisterStartedSession` before sending its initial outbox.

Use complete `GenerationBinding` values wherever the flow is lifecycle-bound:

```text
KeyID + KeyGeneration + EpochID
```

Matching only a key ID, public key, or local generation string is not an
authorization check. The exact signer/party set, context digest, target
descriptor, plan digest, and presign ID where applicable must also agree.
Failed and retired runs do not make a session ID reusable.

Unknown-session envelopes are rejected by default. If the deployment enables
durable buffering, quota the buffer and retain the authenticated receive facts
and certificate. Re-dispatch only after the run is accepted and the local
session is registered; normal guard validation must still run.

## Authenticated Transport

The receive adapter supplies facts that the envelope cannot self-assert:

```text
raw bytes + authenticated peer + channel protection + certificate
  -> tss.OpenEnvelope
  -> tssrun.Dispatcher.Dispatch
  -> ProtocolSession.Handle
  -> authenticated outbox delivery
```

- Derive `ReceiveInfo.Peer`, `PeerKeyID`, `ChannelID`, and `Protection` from the
  authenticated channel, never from payload fields.
- Use `ChannelConfidential` for direct messages that contain shares, nonces, or
  other protocol secrets.
- Collect a complete signed `BroadcastCertificate` for broadcast policies and
  persist it with the delivery decision when recovery depends on it.
- Preserve each exact canonical outbox for at-least-once retry. Never rebuild a
  CGGMP21 online-sign outbox from a new intent.
- Remove terminal registry entries so delayed traffic reaches the
  unknown-session policy.

Messages may arrive in any order within the current phase. Across phases, they
are rejected unless the state machine explicitly buffers and later revalidates
that payload. Do not add a transport-side exception for early, conflicting, or
cross-session traffic.

## Durable Stores

### Public run and routing state

Production implementations of `RunStore`, `SessionRegistry`, and
`UnknownEnvelopeStore` must preserve the semantics described in
[`tssrun.md`](tssrun.md). A registry may be process-local if the application's
routing and ownership model makes one process authoritative, but accepted run
and session-ID state must survive restart.

### Secret lifecycle state

`LifecycleStore` is the sole authority for CGGMP21 generation records,
available presigns, signing attempts, and native refresh/reshare/child
transitions. The critical atomic effects are:

| Transaction                                | Atomic effect                                                                                                       |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `InstallInitialGeneration`                 | Install one exact first generation only if the lineage is absent.                                                   |
| `AcquireRunLease`                          | Bind one session and run kind to the exact generation; enforce compatible/exclusive work.                           |
| `CommitAvailablePresignFromLease`          | Store one available presign and complete its lease together.                                                        |
| `CommitSignAttempt`                        | Revalidate the generation, claim/remove the available secret presign, and store immutable intent plus exact outbox. |
| `MarkAttemptDelivered` / `CompleteAttempt` | Advance the same immutable attempt; delivery and completion are independent facts.                                  |
| `BeginCutoverFromLease` / `CommitCutover`  | Fence source work, install target, retire/clear source, and burn source-epoch available presigns.                   |
| `CommitRetirementFromLease`                | Complete an old-only reshare dealer without installing a local target.                                              |
| Initial child/receiver commit              | Create the first exact generation in a distinct child or new-only receiver lineage.                                 |

`GenerationRecord.Blob` and `PresignCandidate.Blob` contain secret material.
Encrypt them with per-record authenticated encryption, randomized nonces, key
versioning, rotation, and access-controlled KMS/HSM-backed keys. Authenticate
public metadata with the ciphertext. Never put secret bytes in plaintext
indexes, paths, logs, metrics, traces, error strings, or crash reports.

`Memory*` implementations are test/example helpers. `FileLifecycleStore` is an
encrypted crash-semantics reference, not a production database. External
stores should run `conformance.RunConformance` and backend-specific tests for
transactions, concurrent claims, crash points, locking, corruption,
encryption, and unknown outcomes.

## Key Ceremonies

### Keygen and initial install

Do not expose a generated key until every required protocol confirmation has
completed and the local share is durably installed. FROST returns a
caller-owned share for application-managed encrypted persistence. CGGMP21
keygen returns a confirmed share whose canonical bytes and exact produced
epoch must be installed with `InstallInitialGeneration`.

Use default production-policy limits and CGGMP21 security parameters. Reduced
profiles are test controls and must not enter a production run or store.

### Trusted import and reconstruction

Trusted import and reconstruction are explicit exfiltration ceremonies, not
ordinary signing helpers.

- Authorize the public import plan separately from each secret contribution.
- Deliver a contribution only to its named party over confidential,
  authenticated transport and encrypted storage; destroy it after successful
  use.
- Treat `GenerateTrustedDealerKeyShares` as a total-trust boundary because it
  centralizes all shares and, for CGGMP21, all Paillier private keys.
- For reconstruction, load enough unique shares from one exact generation in
  an isolated process, export only to the approved destination, and clear the
  returned bytes.
- Reconstruction does not consume, revoke, or weaken the source shares. The
  authorization workflow must decide what happens to them.

### CGGMP21 presign and sign

Presign plans bind one exact generation, signer set, protocol presign ID,
security profile, and empty derivation path. Figure 8 success is not an
in-memory availability flag: only `CommitAvailablePresignFromLease` creates an
available slot, and `PresignSession.Presign()` returns public metadata.

`CommitSignAttempt` is the online linearization point. It destroys the
available secret state and retains the immutable attempt plus exact public
recovery outbox. Persist delivery acknowledgments/certificate separately from
final signature completion. Expose terminal success only after the completion
record is durable.

### Refresh, reshare, and child generation

- FROST refresh/reshare returns staged caller-owned shares. Install them with
  application compare-and-swap and coordinate source retirement externally.
- CGGMP21 refresh and reshare use native exclusive leases and lifecycle
  commit. A transient post-protocol store error leaves the live session pending
  for `RetryLifecycleCommit`.
- Old-only reshare dealers must remain active through the required target
  confirmations. New-only receivers install their first generation without
  pretending to own the source secret record.
- A CGGMP21 non-hardened child is a distinct lineage with fresh Figure 7/F.1
  auxiliary material. The parent remains current. Presign/sign select the
  installed child and use an empty derivation path.

## Unknown Outcomes and Recovery

A timeout, cancellation, crash, or I/O error from a durable mutation may leave
its outcome unknown. Do not infer rollback from an error return.

| Durable state or uncertainty                 | Recovery action                                                                                         |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Available presign                            | Select only through the authoritative store and claim atomically.                                       |
| `CommitSignAttempt` outcome unknown          | Retain its exact `AttemptQuery`; call `QueryAttemptOutcome` or `ResumeSign`.                            |
| Attempt committed, delivery incomplete       | Replay only the exact stored outbox and persist verified recipient acknowledgments/certificate.         |
| Attempt delivered, completion incomplete     | Restore inbound progress and finish the same attempt; do not create another intent.                     |
| FROST compare-and-swap outcome unknown       | Re-read the authoritative generation before choosing source or target.                                  |
| Refresh/reshare cutover fenced or uncertain  | Reconcile or abort the exact fence; admit no new source work meanwhile.                                 |
| Child installation uncertain                 | Query the declared child key ID/target binding; do not create a competing lineage.                      |
| Process lost a non-terminal protocol session | Reconcile leases/fences, fail the run, and authorize a new session unless a specific resume API exists. |

The public API does not provide general mid-round session snapshot recovery.
`ResumeSign` is the explicit CGGMP21 online-sign exception. A live CGGMP21
refresh or reshare session may retry its pending durable transition through
`RetryLifecycleCommit`; that is not a post-crash session reconstruction API.

Back up lifecycle state, encryption-key metadata, accepted run intent,
session-ID claims, and transport inbox/outbox state as one recovery design.
After restore, canonically decode, validate, and re-encode secret records and
compare the complete generation binding. Corrupt, missing, non-canonical, or
cross-epoch records fail closed.

## Monitoring and Secret Handling

Alert on:

- proof, confirmation, or partial-equation verification failure;
- Figure 7 accusations or Figure 9 red alerts;
- replay, equivocation, plan mismatch, or cross-epoch input;
- presign burns, unavailable slots, or conflicting attempts;
- unknown mutation outcomes and unresolved cutover fences; and
- session timeouts, unknown-session buffer pressure, and persistent delivery
  gaps.

Public party/session/plan/epoch/attempt identifiers may be logged only when
operational policy permits. Never log secret scalars, shares, chain-code
contributions, Paillier factors, ordinary DH exponents, MtA witnesses, presign
blobs, trusted contributions, reconstructed secrets, or raw lifecycle blobs.

Call `Destroy` on caller-owned sessions, shares, presigns, contributions,
reconstructed keys, and derivation results as soon as they are no longer
needed. Go cannot guarantee secure deletion; use isolated short-lived
processes, restrictive crash reporting, disabled core dumps, minimal
privileges, and encrypted storage. Do not describe best-effort clearing as a
zeroization guarantee.

## Readiness Checklist

Before enabling deployment traffic, verify:

1. Every party accepts the same canonical run intent and fresh session ID.
2. Peer identity and channel protection come from authenticated transport.
3. Secret direct messages are confidential and broadcasts have full signed
   certificates.
4. Initial outboxes are released only after durable startup registration.
5. Production stores pass conformance, concurrency, crash, corruption, and
   unknown-outcome tests.
6. Secret records and integrity-sensitive metadata are transactionally
   encrypted and authenticated.
7. Every CGGMP21 operation names the exact generation and epoch.
8. Presign availability changes only through atomic claim, burn, or source
   cutover.
9. Recovery retains exact descriptors and never invents replacement intent.
10. Monitoring, backup/restore drills, incident response, and secret-log
    scanning are active.

## Upgrades

Canonical TLV records carry schema-local frame versions; semantic
`tss.ProtocolVersion` is bound separately into protocol digests and
transcripts. Decoders reject unknown versions, retired layouts, extra fields,
and trailing bytes.

Coordinate protocol, wire, storage schema, proof domains, and lifecycle-store
changes across all parties. Regenerate and verify intentional vectors before
deployment. Do not add fallback decoders or compatibility shims for retired
pre-production records.
