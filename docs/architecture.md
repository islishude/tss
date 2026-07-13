# Architecture

This module is a transport- and database-neutral threshold-signature library.

## Package Ownership

- `github.com/islishude/tss` owns shared identifiers, envelopes, authenticated
  inbound opening, guards, replay protection, broadcast certificates, evidence,
  signing context, and scheduling helpers.
- `github.com/islishude/tss/tssrun` owns accepted run intent, session registry,
  dispatch, unknown-session policy, exact generation bindings, and the unified
  durable lifecycle contract.
- `github.com/islishude/tss/frost/ed25519` owns FROST-style Ed25519 DKG,
  signing, refresh, resharing, import, reconstruction, and derivation.
- `github.com/islishude/tss/cggmp21/secp256k1` owns the Figure 6-10 CGGMP21
  state machines, Figure 7/F.1 epoch creation, trusted import, reconstruction,
  refresh, resharing, and explicit non-hardened child generation.
- `internal/wire` owns strict canonical TLV encoding.
- `internal/transcript` owns repository-defined labeled SHA-256 transcripts.
- `internal/secret` owns fixed-width secret scalar and signed-integer wrappers.
- `internal/curve`, `internal/shamir`, `internal/bip32util`,
  `internal/paillier`, `internal/paillier/paillierct`, `internal/mta`, and
  `internal/zk` own narrow cryptographic primitives. CGGMP21 Figure 8 uses
  `Πenc-elg`, `Πelog`, and `Πaff-g`; Figure 9 uses setup-less `Πaff-g*` and
  `Πdec`.
- `internal/testharness`, `internal/testutil`, and `internal/testvectors` own
  shared runners, mutation tools, and canonical fixtures.

## Transport Model

Protocol starts and inbound handlers return `tss.Envelope` values. The library
does not open sockets, authenticate peers, encrypt messages, or retry delivery.

The receive path is:

```text
raw bytes + authenticated transport facts
  -> tss.OpenEnvelope
  -> tssrun.Dispatcher.Dispatch
  -> ProtocolSession.Handle
  -> caller transport
```

`OpenEnvelope` validates the envelope wire record and binds
`ReceiveInfo.Peer`. `EnvelopeGuard` then checks protocol, semantic version,
session, sender, recipient, delivery mode, confidentiality, sender signature,
broadcast certificate, and replay slot before protocol payload decoding.

Secret-bearing direct payloads require authenticated confidential transport.
Broadcast payloads require the policy's complete consistency certificate.

## Protocol Handler Transactions

All state-machine handlers follow:

```text
decode -> policy validate -> cryptographic verify
       -> prepare transition and outbound envelopes
       -> commit replay, state, store, and secret ownership
       -> release effects
```

Rejected input cannot mutate accepted state or emit envelopes. Prepared secret
objects remain owned by a cleanup stack until commit transfers ownership.
Outbound envelopes are constructed before the state that authorizes them is
committed.

Identical duplicates follow the phase's explicit idempotence rule. Conflicting
duplicates are replay, equivocation, or verification failures and never
overwrite accepted state. Readiness is derived from authoritative accepted
party slots rather than a separate message counter.

## Key and Epoch Model

`GenerationBinding` identifies one durable key ID, local generation token, and
cryptographic authorization `EpochID`.

FROST generations bind their participant set, commitments, public key, chain
code, and confirmation set.

Every sign-ready CGGMP21 generation additionally contains a canonical
`EpochContext` with stable SID, common RID, dynamic Shamir identifiers, public
shares, independent Paillier and Ring-Pedersen material, auxiliary digest, and
source epoch. Figure 6 output becomes usable only after Figure 7/F.1 and the
target confirmation set complete.

Opaque key-share accessors return defensive public copies. Secret records use
canonical binary encoding and must be encrypted by the production store.

## Unified Durable Lifecycle

`tssrun.LifecycleStore` is the transaction boundary for:

- loading and validating the exact current generation;
- acquiring generation-bound run leases;
- committing available CGGMP21 presigns;
- atomically claiming a presign with an immutable signing intent and exact
  outbox;
- persisting delivery, completion, abort, and burn state;
- fencing refresh or reshare cutover; and
- installing the first generation of a distinct child lineage.

`MemoryLifecycleStore` is for tests and examples. `FileLifecycleStore` is an
encrypted reference implementation. It takes sorted per-lineage OS locks plus
the global manifest lock, writes immutable encrypted blobs before one fsynced
manifest swap, and removes unreferenced crash artifacts when reopening state.
Neither store replaces a production database transaction and KMS/HSM policy.

### CGGMP21 presign and sign

`StartPresign` loads the exact current generation from `LifecycleStore` and
acquires a lease before releasing Figure 8 envelopes. Successful completion
atomically stores the normalized tuple and finishes the lease. The public
session accessor returns only a persisted descriptor.

`StartSign` constructs and verifies the Figure 10 partial before
`CommitSignAttempt` atomically validates the generation, claims the available
presign, removes its secret availability, and stores the exact recovery outbox.
Unknown outcomes may only recover the same attempt. Delivery and final
signature visibility are separate durable updates.

### Refresh, reshare, and child generation

Refresh and reshare use an exclusive lease and generation fence. The final
cutover transaction installs the target, retires the source, clears its secret
blob, and burns source-epoch available presigns.

A non-hardened BIP32 child is not installed by mutating its parent. The child
plan binds a distinct key ID and generation, applies the public tweak, runs a
fresh Figure 7/F.1 auxiliary protocol, and atomically creates the first child
generation. The parent remains current.

## Signing Lifecycles

FROST Ed25519 signs in two online rounds: nonce commitments and partial
signatures. Aggregation verifies each partial and produces a standard 64-byte
Ed25519 signature.

CGGMP21 separates Figure 8 offline presigning from Figure 10 signing. The
available presign contains local one-use normalized secret shares and public
per-signer commitments. Figure 10 checks each partial directly, sums only valid
partials, and applies low-S normalization to the final ECDSA signature.

## Public vs Internal

Public packages expose plans, party-local sessions, public metadata snapshots,
and durability interfaces. Internal packages are deliberately narrow and are
not stable APIs. Their documentation exists so protocol reviewers can trace
equations, transcript domains, resource limits, ownership, and failure
behavior.
