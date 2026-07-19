# Root Package

`github.com/islishude/tss` contains the transport-neutral types shared by the
FROST and CGGMP21 packages. This document focuses on integration boundaries;
the generated Go documentation is the exhaustive exported-symbol reference.

## Parties, Sessions, and Local Dependencies

`PartyID` is a `uint32`. Zero is reserved for unset values and broadcast
recipients. Protocol parties may use any unique non-zero identifiers; they are
not required to be contiguous. Plan constructors validate and canonicalize the
party sets used in transcripts.

`SessionID` is a 32-byte public nonce for one protocol run. One coordinator or
job creates it and distributes it as authenticated run metadata; parties in the
same run do not generate independent IDs.

```go
id, err := tss.NewSessionID(nil)       // crypto/rand
id, err = tss.NewSessionID(myReader)  // caller-provided randomness
id, err = tss.SessionIDFromBytes(raw) // exact 32-byte parse
```

`MarshalText` and `String` use hexadecimal encoding, and `Bytes` returns a
copy. Persist accepted and terminal IDs per protocol namespace. Retirement of
replay data is safe only after durable policy makes the ID unavailable for
reuse.

`LocalConfig` contains only party-local execution dependencies:

```go
type LocalConfig struct {
    Self           PartyID
    Rand           io.Reader
    Context        context.Context
    RoundTimeout   time.Duration
    Log            Logger
    EnvelopeSigner EnvelopeSigner
}
```

Nil `Rand`, `Context`, and `Log` values resolve to `crypto/rand`,
`context.Background`, and a no-op logger. Shared session ID, committee,
threshold, signer set, signing intent, derivation context, limits profile, and
security parameters belong in protocol-specific immutable plans.
`ThresholdConfig` is the validated state-machine representation assembled from
a plan plus local dependencies; new lifecycle integrations should use the
plan-first `Start*` APIs.

## Envelopes and Receive Facts

`Envelope` is the canonical protocol wire record:

```go
type Envelope struct {
    Protocol        ProtocolID
    SessionID       SessionID
    Round           uint8
    From            PartyID
    To              PartyID // zero means broadcast
    PayloadType     PayloadType
    Payload         []byte
    SenderSignature []byte
}
```

Use `NewEnvelope(EnvelopeInput{...})`; it validates basic fields and copies
payload and signature bytes. `MarshalBinary` and `UnmarshalBinary` use strict
canonical TLV framing and reject unknown type/version, malformed fields,
limits violations, and trailing data.

An `Envelope` does not carry trusted transport state. The receive adapter must
derive `ReceiveInfo` from its authenticated channel and call `OpenEnvelope`:

```go
in, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{
    Peer:       peerID,
    Protection: tss.ChannelConfidential,
    ChannelID:  channelID,
    PeerKeyID:  peerKeyID,
})
```

`OpenEnvelope` decodes the wire record, requires an authenticated non-zero
peer and a defined channel-protection value, and checks
`ReceiveInfo.Peer == Envelope.From`. It returns an immutable
`InboundEnvelope`; its accessors return values or defensive copies. Protocol
policy is applied later by `EnvelopeGuard`.

### Digest and Signature Domains

`Envelope.Digest` binds protocol, semantic `ProtocolVersion`, session, round,
sender, recipient, payload type, payload, and `SenderSignature` when present.
It is used for complete-envelope identity and broadcast acknowledgments.

`EnvelopeSigningDigest` and `Envelope.SigningDigest` bind the same message slot
and payload but deliberately exclude `SenderSignature`. `SignEnvelope` signs
that digest, and `VerifyEnvelopeSignature` verifies it. The TLV frame version
is separate from the semantic protocol version.

## Delivery Policy and Guard

Each protocol exports a `PolicySet` keyed by protocol, round, and payload type:

```go
type DeliveryPolicy struct {
    Protocol               ProtocolID
    Round                  uint8
    PayloadType            PayloadType
    Mode                   DeliveryMode
    Confidentiality        ConfidentialityPolicy
    BroadcastConsistency   BroadcastConsistencyPolicy
    RequireSenderSignature bool
}
```

Unregistered payload types fail closed. `MustNewPolicySet` also rejects any
broadcast-mode entry that does not require broadcast consistency.

Production code builds a guard with `GuardConfig.BuildGuard`. It requires a
non-nil replay cache and broadcast-ack verifier; if any policy requires sender
signatures, it also requires an `EnvelopeSignatureVerifier`. CGGMP21 starts
that emit signed direct messages additionally need
`LocalConfig.EnvelopeSigner`.

For each inbound envelope, the guard verifies:

- expected protocol and session;
- allowed non-local sender and transport identity binding;
- channel-protection classification and direct recipient;
- registered delivery mode and confidentiality policy;
- portable sender signature when required;
- a complete verifier-backed broadcast certificate when required; and
- replay or equivocation for the canonical message slot.

Reshare and other role-dependent sessions call `ValidateForRound` through
`ValidateInbound` with the sender set allowed for that message. The guard's
`Parties` value remains the construction-time universe. A narrowly defined
early-message path may call `ValidateInboundWithoutReplay`, but the message
must pass full validation before later use.

`NewTestEnvelopeGuard` supplies in-memory/no-op verification dependencies and
panics outside `go test`; it is not a production constructor.

## Broadcast Certificates

`BroadcastCertificate` binds the protocol, session, round, sender, payload
type, payload hash, complete envelope digest, recipient set, and one signed
`BroadcastAck` per recipient.

`VerifyStructure` checks canonical shape and message binding only.
`VerifyFull` additionally verifies every acknowledgment signature and is the
production validation path used by `EnvelopeGuard`. The certificate and ack
binary decoders reject duplicate, out-of-order, missing, and mismatched
records.

The root package also provides `BroadcastConsistency` to collect verified
acknowledgments for one broadcast and detect conflicting digests. Persisting
the resulting certificate and delivery decision remains an application
responsibility.

## Replay Cache

```go
type ReplayCache interface {
    CheckAndStore(slot MessageSlotKey, payloadHash [32]byte) error
    RetireSession(protocol ProtocolID, sessionID SessionID) error
}
```

`MessageSlotKey` contains protocol, session, round, sender, recipient, and
payload type. The payload hash is deliberately separate:

- a new slot is stored and returns `nil`;
- the same hash in the same slot returns `ErrDuplicateMessage`;
- a different hash in the same slot returns `ErrEquivocation`; and
- a full bounded cache returns `ErrReplayCacheFull` without evicting accepted
  security state.

`InMemoryReplayCache` is bounded and process-local. Production deployments
that route across processes need a durable/shared implementation with atomic
`CheckAndStore`. Call `RetireSession` only after the session is terminal and its
ID is durably non-reusable. `RefreshScheduler` performs that retirement for
the refresh session IDs it claims.

## Protocol Errors and Evidence

Protocol state machines return `*ProtocolError` with a machine-readable code,
round, optional attributed party, optional `Blame`, and wrapped error.
`errors.Is` and `errors.As` work through `Unwrap`.

| Code constants                                                                                                             | Meaning                                                |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `ErrCodeInvalidConfig`, `ErrCodeInvalidMessage`, `ErrCodeRound`                                                            | Invalid startup or message routing/state.              |
| `ErrCodeDuplicate`, `ErrCodeVerification`, `ErrCodeAggregateSignInvalid`                                                   | Duplicate or failed cryptographic/transcript checks.   |
| `ErrCodeNotReady`, `ErrCodeConsumed`, `ErrCodeCompleted`, `ErrCodeAborted`                                                 | Lifecycle disposition.                                 |
| `ErrCodeLimitExceeded`, `ErrCodeTooManyParties`, `ErrCodeTooManySigners`, `ErrCodePayloadTooLarge`, `ErrCodeProofTooLarge` | Explicit resource-limit failure.                       |
| `ErrCodeInvariant`                                                                                                         | Local bug or corrupted state; never participant blame. |
| `ErrCodeNotImplemented`                                                                                                    | Explicitly unsupported operation.                      |

`ErrCodeAggregateSignInvalid` remains an exported generic code; the current
CGGMP21 Figure 10 path verifies and attributes individual invalid partials
instead.

`BlameEvidence` is a canonical public record containing the message identity,
payload and envelope digests, failure kind, reason, and named public inputs.
`IdentificationRecord` carries the verifiable public artifact for signed
equivocation, certified broadcast failures, or proof-backed accusations.
Algorithm-specific verifiers must rebind evidence to trusted session context.

Neither record is a license to copy secrets into evidence. Protocol code must
exclude private shares, nonces, Paillier factors, MtA witnesses, trusted-dealer
contributions, and reconstructed secrets. Treat evidence as integrity-sensitive
public operational data and validate it before storage or sharing.

## Signing and HD Types

`SignIntent` binds a session ID, `SigningContext`, message, and signer set.
`SigningContext` binds the key ID, chain ID, derivation request, policy domain,
and message domain. Both protocol packages construct their immutable sign plan
from this public intent.

The root package does not define a protocol-neutral signature container:
FROST returns a 64-byte Ed25519 signature, while CGGMP21 returns its own
low-S `secp256k1.Signature` with `R`, `S`, and `RecoveryID`.

`KeyShare` is the common opaque interface:

```go
type KeyShare interface {
    Algorithm() Algorithm
    PartyID() PartyID
    Derive(path DerivationPath, opts ...DeriveOption) (*DerivationResult, error)
    MarshalBinary() ([]byte, error)
    Destroy()
}
```

`DerivationPath` accepts `m` or non-hardened paths such as `m/0/1`, with at
most 255 levels. FROST can use the local additive derivation result during
signing. A CGGMP21 child becomes signable only after the protocol-specific
`ChildDerivationPlan` installs a distinct lifecycle generation; presign and
sign plans require an empty derivation path.

## Refresh Scheduler

`RefreshScheduler` drives protocols whose refreshed share is committed by an
external `CommitKeyShare(previous, refreshed)` compare-and-swap callback. Its
callbacks must also load the current share and durably claim the shared
session ID. A normal commit error transfers no ownership; an error wrapping
`ErrRefreshCommitOutcomeUnknown` leaves ownership with the callback for exact
reconciliation.

Protocols that own a lifecycle lease and cutover transaction must use their
native API. In particular, CGGMP21 refresh is not driven through this generic
scheduler.

## Reference Encryption and Logging

The passphrase helpers encrypt key-share, presign, and sign-attempt bytes with
Argon2id-derived ChaCha20-Poly1305 keys. Record type, KDF parameters, and key ID
are authenticated; decryptors that accept an expected key ID reject a valid
record for another ID.

These helpers are reference/demo primitives, not a database or production key
management system. See [`deployment.md`](deployment.md) for storage
requirements.

`Logger` provides context-aware `Debug`, `Info`, `Warn`, and `Error` methods.
`NopLogger` is the default, and `NewSLogger` adapts `log/slog.Logger`. Callers
must ensure fields never contain secret material.
