# Production Deployment Guide

This guide describes the deployment boundary implemented by this repository.
It is not a production-readiness claim: the library has not completed an
independent production audit, and the CGGMP21 Paillier/ZK layer still requires
independent cryptographic review.

Read [`integration.md`](integration.md), [`tssrun.md`](tssrun.md), and
[`security.md`](security.md) before integrating a protocol package. The
`StartXxx` functions are party-local state-machine constructors; the
application remains responsible for authorization, coordination, transport,
durability, recovery, and operations.

## Deployment Model

A production deployment has three explicit boundaries:

1. The control plane authorizes one canonical `tssrun.RunIntent`, distributes
   its public fields, and records each party's acceptance digest.
2. The data plane opens authenticated envelopes, enforces confidentiality and
   broadcast policy, and routes them to a registered local session.
3. The durability plane implements `tssrun.LifecycleStore` as the single
   transactional authority for key generations, run leases, available
   presigns, signing attempts, and generation cutover.

The coordinator is not a cryptographic participant unless it is also one of
the parties. It must not receive private shares, nonce shares, Paillier private
keys, MtA witnesses, presign secret tuples, trusted-dealer contributions, or
reconstructed secrets.

## Run Admission

Every keygen, refresh, reshare, child-derivation, presign, and signing run has a
fresh shared session ID. Each party reconstructs the protocol plan from the
same authenticated public metadata and checks its digest against the accepted
`RunIntent` before releasing the first envelope.

For lifecycle-bound CGGMP21 runs, the intent names an exact
`GenerationBinding`:

```text
key ID + local generation token + cryptographic EpochID
```

Matching only the key ID or public key is insufficient. The complete binding,
plan digest, signer or party set, context digest, lifecycle target, and
presign ID where applicable must agree.

Use one durable session-ID claim per protocol namespace. A failed or retired
run does not make its session ID reusable. Unknown-session envelopes are
rejected by default; deployments that durably buffer them must reopen and
revalidate them through the newly registered session before use.

## Authenticated Transport

The receive path is:

```text
raw bytes + authenticated transport facts
  -> tss.OpenEnvelope
  -> tssrun.Dispatcher.Dispatch
  -> ProtocolSession.Handle
  -> authenticated outbox delivery
```

`ReceiveInfo.Peer`, `PeerKeyID`, `ChannelID`, and `Protection` must be derived
from the transport, not copied from untrusted message fields. Direct messages
that contain shares or protocol witnesses require
`tss.ChannelConfidential`. Broadcast delivery must satisfy the configured
acknowledgment and certificate policy.

Within a round, messages may arrive in any order. Across rounds, protocol state
machines reject early messages unless that specific phase explicitly buffers
them. Replayed, conflicting, cross-session, wrong-plan, and wrong-recipient
messages fail closed.

The application should register a successfully started session before making
its outbound envelopes visible. Remove completed, aborted, and retired
sessions from the registry so delayed traffic reaches the unknown-session
policy.

## Unified Lifecycle Store

`tssrun.LifecycleStore` is the only authoritative CGGMP21 persistence
boundary. A production implementation must provide atomic transactions and
encrypt secret-bearing blobs with a KMS or HSM-backed scheme.

| Operation                                  | Required atomic effect                                                                                                      |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `InstallInitialGeneration`                 | Install the first exact generation for a key ID only if none exists.                                                        |
| `AcquireRunLease`                          | Bind one run kind and session to the exact current generation.                                                              |
| `CommitAvailablePresignFromLease`          | Store one available presign and finish its presign lease together.                                                          |
| `CommitSignAttempt`                        | Revalidate the current generation, consume one available presign, and store the immutable intent and exact outbox together. |
| `MarkAttemptDelivered` / `CompleteAttempt` | Advance the same immutable signing attempt without creating a new claim.                                                    |
| `BeginCutoverFromLease`                    | Finish the refresh or reshare lease and fence new source-generation work.                                                   |
| `CommitCutover`                            | Install the target, retire and clear the source, and burn all source-epoch available presigns together.                     |
| `CommitInitialGenerationFromLease`         | Install a derived child as the first generation of a distinct key lineage.                                                  |
| `CommitInitialGenerationFromReshareLease`  | Install a new-only receiver's first generation without claiming it owned the source secret.                                 |

`MemoryLifecycleStore` is a test/reference helper and is not durable.
`FileLifecycleStore` is an encrypted reference implementation with one
manifest covering all lineages. It serializes cross-process mutations with
sorted per-lineage OS locks and a manifest lock, fsyncs immutable encrypted
blobs before the manifest swap, and reconciles orphan crash artifacts on the
next open operation. It demonstrates ordering and crash semantics, but it is
not a substitute for a transactional production database and a production
key-management design.

Third-party backends should run `tssrun/conformance.RunConformance` and add
backend-specific transaction, crash, encryption, locking, corruption, and
unknown-outcome tests.

### Secret Storage

`GenerationRecord.Blob` and `PresignCandidate.Blob` contain secret material.
They must never appear in logs, metrics, tracing attributes, paths, plaintext
indexes, error strings, or crash reports. Public metadata is still integrity
sensitive and must be authenticated with the encrypted record.

The passphrase-encryption helpers and file lifecycle store are references. A
production design should use per-record authenticated encryption, randomized
nonces, key versioning, rotation, and KMS/HSM policy. Encryption does not
replace lifecycle transactions.

## CGGMP21 Key Generation

CGGMP21 keygen executes the paper's Figure 6 followed by Figure 7/F.1 and a
repository confirmation round. Figure 6 establishes the additive public key
and shared `rho`; Figure 7 creates the secret sharing, Paillier and independent
Ring-Pedersen auxiliary setup, shared `RID`, dynamic party identifiers, and a
new `EpochID`.

`KeyShare()` remains unavailable until the confirmation set binds the complete
transcript, epoch, party set, public key, and chain code. Only then may the
application canonically encode the share and call
`InstallInitialGeneration`. Use the share's exact epoch when constructing the
initial `GenerationBinding`.

The production proof profile is `(Ell, EllPrime, Epsilon, ChallengeBits,
MinPaillierBits) = (256, 1280, 512, 256, 3072)`, targeting the repository's
128-bit classical security profile. Every party generates an independent
Paillier modulus `N` and independent Ring-Pedersen modulus `Nhat`; these are not
the same modulus and are validated separately. Reduced parameters are test
controls only.

### Trusted-Dealer Import and Reconstruction

Trusted-dealer import uses the same public Figure 6 and Figure 7/F.1 path after
each party receives its explicitly authorized secret contribution through a
confidential, authenticated, KMS-backed channel. The public import plan and
digest belong in the control plane; each contribution belongs only to its
named party and must be destroyed when no longer needed.

Secret reconstruction is a separate exfiltration ceremony. Require explicit
authorization, load one exact lifecycle generation, validate at least the
threshold number of shares in an isolated process, export only to the approved
destination, and clear the returned bytes. Reconstruction does not silently
consume, retire, or weaken the source generation.

## CGGMP21 Presign and Sign

### Figure 8 Presign

The offline run implements Figure 8. Its successful normalized local artifact
is:

```text
(Gamma, k_i/delta, chi_i/delta,
 {(Delta_j^(delta^-1), S_j^(delta^-1))}_j)
```

The presign plan binds one exact generation and epoch, signer set, 32-byte
protocol presign ID, security profile, and signing context. The context uses an
empty derivation path: online or presign-time path derivation is rejected.

Completion is the atomic
`CommitAvailablePresignFromLease` transaction. `PresignSession.Presign()`
returns a public-only `PersistedPresign` descriptor containing the lifecycle
slot and public metadata; it does not return the normalized secret tuple.
Availability is store state, not a wire bit. Canonical encoding or decoding
does not consume an available artifact and does not prove that a slot is
available.

If Figure 8's aggregate checks fail, the session enters the paper's Figure 9
red-alert path using `Pi_dec` and setup-less `Pi_aff-g*` evidence. A Figure 9
failure never produces an available presign.

### Figure 10 Online Signing

The online plan is constructed from the current key generation and public
presign metadata. `StartSign` then loads the exact generation and available
presign candidate from `LifecycleStore`, prepares and self-verifies the local
partial, and calls `CommitSignAttempt` before exposing its broadcast envelope.

That commit is the linearization point. It atomically removes availability and
stores the immutable attempt identity, public Figure 10 verification context,
and exact canonical outbox. A committed attempt never retains the available
presign's secret blob or normalized secret tuple.

Every received partial is checked directly with Figure 10's equation:

```text
Gamma^sigma_j = DeltaTilde_j^m * STilde_j^r
```

An invalid partial is attributed to its sender in that round; Figure 10 defines
no later proof phase.

Delivery and signature completion are separate durable facts. Persist
recipient acknowledgments and the required verifier-backed broadcast
certificate with `MarkAttemptDelivered`; persist the final signature with
`CompleteAttempt` before exposing terminal success.

### Unknown Outcomes and Recovery

A timeout, cancellation, process crash, or I/O error from a lifecycle mutation
may leave its durable outcome unknown. This is not permission to reuse a
presign or create another intent.

For `CommitSignAttempt`, retain the exact public `AttemptQuery` from
`AttemptOutcomeUnknownError` and reconcile only through
`QueryAttemptOutcome`/`ResumeSign`. `ResumeSign` validates the immutable
binding and returns the exact stored outbox only while delivery remains
incomplete. Remote inbound partials still require a durable application inbox
or at-least-once transport replay.

Never change the digest, context, session ID, signer set, presign ID, attempt
ID, generation, or epoch during recovery.

## Refresh, Reshare, and Child Generations

### Refresh

CGGMP21 refresh reruns Figure 7/F.1. It preserves the group public key, party
set, threshold, and chain code while replacing the secret sharing, Paillier and
Ring-Pedersen auxiliary keys, `RID`, dynamic identifiers, and `EpochID`.

`StartRefresh` loads the exact source generation from `LifecycleStore` and
acquires an exclusive refresh lease. A successful confirmation set produces a
target generation. The session begins a generation fence and commits an atomic
same-key cutover; source material is retired and source-epoch available
presigns are burned. A protocol-level refresh failure durably disables further
refresh for that key ID until operator remediation, while signing and
presigning may remain allowed by policy.

### Reshare

The canonical `ResharePlan` binds the entire source generation and declares
the target parties, threshold, and generation token. Old-only dealers,
new-only receivers, and overlap parties start their explicit roles from the
same accepted intent.

Existing holders use source-generation leases and same-key cutover. New-only
receivers use a public `ReshareReceiverAnchor` and
`CommitInitialGenerationFromReshareLease`; they do not pretend to own the
source secret record. Do not retire the source generation until the configured
target-holder confirmation and lifecycle commit conditions are satisfied.

### Explicit Child Derivation

Non-hardened BIP32 derivation creates a distinct child key lineage through
`ChildDerivationPlan` and `StartChildDerivation`. The plan binds the parent
generation, resolved path, child key ID, target generation, session, and
security profile. The child run establishes fresh Figure 7 auxiliary material,
`RID`, dynamic identifiers, and `EpochID` before
`CommitInitialGenerationFromLease` installs it.

The parent remains current and usable. A child is never an in-memory view of
the parent and never shares the parent's auxiliary epoch. Presign and sign
plans reject non-empty derivation paths; callers must select the already
installed child generation instead.

## Restart and Disaster Recovery

Back up the encrypted lifecycle database, encryption-key metadata, accepted
run intents, and transport inbox/outbox state as one recovery design. Do not
back up secret records without their authoritative lifecycle state.

| Durable state                            | Recovery action                                                                                       |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Available presign                        | May be selected only through `PreparePresignCandidate` and atomically claimed by `CommitSignAttempt`. |
| Committed attempt, delivery incomplete   | Call `ResumeSign` with the exact query and replay only the stored outbox.                             |
| Attempt delivered, completion incomplete | Restore inbound delivery and finish the same attempt; do not replay as a new intent.                  |
| Source generation fenced                 | Reconcile or abort the exact cutover fence; do not admit new source work.                             |
| Target cutover committed                 | Load only the target as current; source blobs and available presigns must be retired.                 |
| Child installation outcome unknown       | Query the child key ID and exact target binding; do not create a competing lineage.                   |

After restore, canonically decode, validate, and re-encode every generation and
presign candidate before use. Compare the full binding and known public key,
not just storage keys. Corrupt, missing, cross-epoch, or non-canonical records
fail closed.

## Monitoring

Alert on:

- any proof or partial-equation verification failure;
- Figure 7 decryption-error accusations or Figure 9 red alerts;
- replay, equivocation, plan mismatch, or cross-epoch messages;
- presign unavailable, burned, or conflicting-attempt results;
- unknown lifecycle mutation outcomes;
- cutover fences that remain unresolved;
- session timeouts and persistent delivery gaps.

Logs may contain public party IDs, session IDs, plan hashes, epoch IDs, and
public attempt descriptors when operationally necessary. They must never
contain secret scalars, private shares, chain-code contributions, Paillier
factors, DH exponents except the protocol-defined public accusation, MtA
witnesses, presign blobs, reconstructed secrets, or raw lifecycle blobs.

## Destruction

Call `Destroy()` on caller-owned sessions, key-share copies, and secret objects
as soon as they are no longer needed. A shallow Go copy of an opaque secret
handle may share lifecycle state; use documented clone-returning accessors when
independent ownership is required.

Go cannot guarantee secure deletion. Use short-lived isolated processes,
locked-down crash reporting, disabled core dumps, minimal privileges, and
KMS/HSM-backed storage controls. Do not describe best-effort clearing as a
zeroization guarantee.

## Startup Checklist

Before enabling production traffic, verify:

1. Every party accepts the same canonical run intent and fresh session ID.
2. Envelope sender identity comes from authenticated transport.
3. Secret direct messages use a transport-verified confidential channel.
4. The production `LifecycleStore` passes conformance and crash tests.
5. Key generations, presigns, and lifecycle metadata are transactionally
   encrypted and authenticated.
6. Every CGGMP21 run names the exact generation and epoch.
7. Presign availability ends only through atomic claim, explicit burn, or
   source cutover.
8. Unknown outcomes retain their exact reconciliation descriptor.
9. Refresh and reshare use fenced atomic cutover; child derivation creates a
   distinct key lineage.
10. Monitoring, backup, incident response, and secret-log scanning are active.

## Version Upgrades

Every TLV record has one schema-local version in its frame header, while
`tss.ProtocolVersion` is bound separately into protocol transcripts. Decoders
reject unknown versions, retired layouts, extra fields, and trailing bytes.

Coordinate protocol, wire, storage-schema, proof-domain, and lifecycle-store
upgrades across every party. Regenerate and verify intentional vectors before
deployment. Do not add fallback decoders or compatibility shims for retired
pre-production records.
