# Architecture

This module contains party-local threshold-signature state machines. It is
transport- and database-neutral: applications own run authorization, peer
authentication, delivery, durable storage, and recovery.

## Package Ownership

- `github.com/islishude/tss` owns shared identifiers, immutable inbound
  envelopes, delivery policy, guards, replay and broadcast validation, public
  evidence, signing context, HD types, and the externally committed refresh
  scheduler.
- `github.com/islishude/tss/tssrun` owns run-intent acceptance, active-session
  routing, unknown-session policy, exact generation bindings, and lifecycle
  store interfaces.
- `github.com/islishude/tss/frost/ed25519` owns FROST-style Ed25519 DKG,
  signing, refresh, resharing, trusted import, reconstruction, and derivation.
- `github.com/islishude/tss/cggmp21/secp256k1` owns CGGMP21 Figures 6-10,
  Figure 7/F.1 epoch creation, trusted import, reconstruction, refresh,
  resharing, and explicit child lineages.
- `internal/wire` owns strict canonical TLV encoding; `internal/transcript`
  owns repository-defined labeled SHA-256 transcripts; `internal/secret` owns
  fixed-width secret wrappers.
- `internal/curve`, `internal/shamir`, `internal/bip32util`,
  `internal/paillier`, `internal/paillier/paillierct`, `internal/mta`, and
  `internal/zk/*` own narrow cryptographic primitives.
- `internal/testharness`, `internal/testutil`, and `internal/testvectors` own
  shared runners, mutation and restart tools, limits-aware fixtures, and
  canonical vectors.

Internal packages are implementation details, not stable APIs.

## Receive and Dispatch Path

Protocol starts and handlers emit `tss.Envelope` values. The library does not
open sockets, authenticate peers, encrypt messages, collect acknowledgments,
or retry delivery.

```text
raw bytes + transport-verified ReceiveInfo + optional certificate
  -> tss.OpenEnvelope
  -> tssrun.Dispatcher.Dispatch
  -> ProtocolSession.Handle
  -> caller-owned DispatchResult
  -> durable outbox write
  -> application transport delivery
```

`OpenEnvelope` performs canonical envelope decoding and binds the decoded
sender to transport facts. `EnvelopeGuard` then checks the expected protocol
and session, allowed sender set, recipient, registered delivery policy,
portable sender signature when required, channel confidentiality, broadcast
certificate, and replay slot. The semantic `tss.ProtocolVersion` is bound into
digests and transcripts; it is not a mutable envelope field or a separate
guard check.

Secret-bearing direct payloads require authenticated confidential transport.
Broadcast-mode protocol policies require a complete verifier-backed
`BroadcastCertificate`.

`EnvelopeGuard` is immutable after construction. Protocol starts compare its
canonical policy digest with the exact protocol policy set, so production code
cannot replace the replay authority, verifier, or delivery policy after
startup. `BroadcastConsistency` commits one exact envelope before accepting
acknowledgments and re-verifies the complete set before reporting completion or
producing a certificate.

## State-Machine Transaction Boundary

The receive boundary first opens the canonical envelope and applies the guard,
including its atomic replay-slot decision. The protocol handler then follows
this ownership sequence for the payload:

```text
decode -> semantic validate -> cryptographic verify
       -> prepare transition and outbound envelopes
       -> commit protocol state, durable effects, and secret ownership
       -> release effects
```

Rejected input must not mutate accepted protocol state or emit envelopes.
Prepared secret values stay under cleanup ownership until commit transfers
them to the session or durable store. Outbound envelopes are constructed
before the state that makes them visible is committed.

Every public session operation serializes on the same session lock. `Handle`
checks both its delivery context and the session context at decode,
proof/party-loop, preparation, and pre-commit boundaries. One indivisible
large-integer operation is not interruptible mid-call. Once a durable mutation
starts, its result is authoritative or explicitly unknown and must be
reconciled rather than inferred from cancellation.

The public lifecycle states are `Starting`, `Active`, `CommitPending`,
`Succeeded`, `Aborted`, `ClosePending`, and `Closed`. Pending durable success
retains the exact candidate/outbox for `RetryLifecycleCommit` or `ResumeSign`;
pending durable abort retains its lease, fence, or query for an identical
`Abort`/`Close` retry.

Identical duplicates follow the phase's explicit idempotence rule. Conflicting
duplicates are rejected as replay, equivocation, or verification failures and
never replace accepted state. Readiness is derived from accepted party slots,
not from an independent message counter.

## Identity and Generation Model

These identifiers have different roles:

| Identifier                 | Scope                                                                         |
| -------------------------- | ----------------------------------------------------------------------------- |
| `tss.SessionID`            | One protocol run; bound into envelopes, plans, transcripts, and proofs.       |
| `tssrun.KeyGeneration`     | Application/store compare-and-swap token for one key lineage.                 |
| `tssrun.EpochID`           | Cryptographic authorization epoch.                                            |
| `tssrun.GenerationBinding` | Exact tuple of key ID, generation token, and epoch ID.                        |
| CGGMP21 `SID` / `RID`      | Stable key-lineage identity and current auxiliary-protocol common randomness. |

FROST shares bind the participant set, threshold, commitments, public key,
chain code, lifecycle plan, and confirmation set.

Every sign-ready CGGMP21 generation also contains an `EpochContext` with its
SID, RID, dynamic Shamir identifiers, public shares, separately generated Paillier and
Ring-Pedersen material, auxiliary digest, and source epoch. Figure 6 output is
not exposed as a sign-ready key between Figure 6 and Figure 7/F.1.

Opaque share accessors return defensive public copies. Secret records use
canonical binary encoding and require caller-managed encryption at the
production storage boundary.

## Durable Lifecycle

`tssrun.RunStore` records public run acceptance and local status.
`tssrun.LifecycleStore` is a separate transactional authority for generation
records and secret-bearing lifecycle state.

Current CGGMP21 presign, sign, refresh, reshare, and child-derivation starts
load the authoritative generation and acquire their lifecycle lease before
returning protocol envelopes. Both keygen packages expose a confirmed share
and an `InstallKeyShare` helper that validates and canonically encodes it,
derives its non-zero protocol epoch, and installs the predeclared key ID and
generation. FROST refresh and reshare expose caller-owned shares; their
compare-and-swap remains an application responsibility. The generic root refresh scheduler is
only for externally committed refresh protocols such as FROST, not for
CGGMP21's native cutover flow.

### Presign and online sign

```text
current CGGMP21 generation
  -> RunPresign lease
  -> atomically committed available presign
  -> RunSign lease
  -> atomically claimed immutable attempt + exact outbox
  -> durable delivery and durable completion
```

`CommitSignAttempt` is the one-use claim point. An outcome-unknown error may
only be reconciled with the exact `AttemptQuery`; it never authorizes another
intent or presign reuse.

### Refresh, reshare, and child lineage

Refresh and overlap/source-holder reshare use an exclusive lease followed by a
generation fence and atomic cutover. Cutover installs the target, retires and
clears the source record, and burns source-epoch available presigns. Old-only
reshare dealers use the retirement transaction; new-only receivers use an
authenticated `ReshareReceiverAnchor` and initial-generation transaction.

A CGGMP21 child is a distinct key lineage. Its plan binds the parent and target
descriptor, the protocol derives fresh auxiliary material, and
`CommitInitialGenerationFromLease` installs the first child generation without
mutating the parent.

## Reference Stores

`MemoryRunStore`, `MemorySessionRegistry`, `MemoryUnknownEnvelopeStore`, and
`MemoryLifecycleStore` are in-memory test/example helpers.

`FileLifecycleStore` is an encrypted reference `LifecycleStore`. `store.meta`
runs Argon2id once per open to unwrap a random data-encryption key; later root,
lineage, and index operations use only that key with fresh nonces. The encrypted
root names immutable per-lineage snapshots, 16-bit partitioned global indexes,
and one monotonic transaction ID. A multi-lineage operation fsyncs every new
snapshot and bucket before one root rename publishes all references atomically.
Open/recovery removes unreferenced artifacts; ordinary reads never write.
`CompactLifecycle` replaces old terminal history with fixed tombstones while
preserving non-reuse. The retired `manifest.enc` shape is rejected without
migration or fallback. This design still does not replace a production
database transaction or KMS/HSM.

## Protocol Outputs

FROST signing has two online rounds and produces a standard 64-byte Ed25519
signature. CGGMP21 separates a three-round Figure 8 presign from one-round
Figure 10 signing; every partial is verified directly before valid partials
are combined into a low-S ECDSA signature.

Protocol equations, proof domains, and phase-specific failure behavior belong
in the protocol documents, while deployment policy belongs in
[`deployment.md`](deployment.md).
