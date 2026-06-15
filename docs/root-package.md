# Root Package

The `github.com/islishude/tss` root package provides shared types used by both `frost/ed25519` and `cggmp21/secp256k1`.

## LocalConfig

`LocalConfig` carries only party-local runtime dependencies. Lifecycle-wide intent such as the session ID, threshold, participant set, signer set, HD mode, and message context belongs in the protocol-specific immutable plan.

```go
type LocalConfig struct {
    Self         PartyID
    Rand         io.Reader       // optional; defaults to crypto/rand
    Context      context.Context // optional; defaults to context.Background()
    RoundTimeout time.Duration
    Log          Logger          // optional; defaults to no-op
}
```

Protocol lifecycle APIs use the plan-first shape:

```go
plan, err := secp256k1.NewKeygenPlan(secp256k1.KeygenPlanOption{
    SessionID: sessionID, Parties: parties, Threshold: threshold, EnableHD: enableHD,
})
session, out, err := secp256k1.StartKeygen(plan, tss.LocalConfig{Self: self}, guard)
```

Plan constructors canonicalize and validate global intent. Start functions validate `LocalConfig.Self` against that plan and return `ErrCodeInvalidConfig` for invalid local startup configuration.

`ThresholdConfig` remains the protocol state-machine representation assembled from a validated plan plus `LocalConfig`; lifecycle callers should not use it to express global intent.

## PartyID

`PartyID` is a `uint32` identifying one protocol participant. Zero is reserved (unset). Both protocol packages expect parties to be numbered `1..n`.

## SessionID

`SessionID` is a 32-byte nonce separating independent protocol executions.

```go
id, _ := tss.NewSessionID(nil)          // crypto/rand
id, _ := tss.NewSessionID(myReader)     // custom reader
id, _ := tss.SessionIDFromBytes(raw)    // parse from bytes
```

It supports `MarshalText`/`UnmarshalText` (hex), `Bytes()` (copy), and `String()` (hex). Every protocol run must use a fresh, unpredictable session ID. Reusing a session ID across runs allows cross-session replay.

## Envelope

Protocol state machines emit `tss.Envelope` values. `Envelope` is only the
canonical wire/protocol message; it does not carry receive-side transport facts.
Inbound handlers accept `tss.InboundEnvelope`, which is created by opening raw
wire bytes with transport-verified `ReceiveInfo`.

```go
type Envelope struct {
    Protocol       ProtocolID       // e.g. ProtocolCGGMP21Secp256k1
    Version        uint16           // wire version (currently 1)
    SessionID      SessionID        // scopes this message to a run
    Round          uint8            // protocol round number
    From           PartyID          // sender
    To             PartyID          // recipient; 0 means broadcast
    PayloadType    PayloadType      // identifies the payload schema
    Payload        []byte           // TLV-encoded protocol payload
    TranscriptHash [32]byte         // SHA-256 of public envelope metadata
}
```

### Construction

Production code must use `NewEnvelope(EnvelopeInput{...})` which validates fields and computes the transcript hash. Direct struct literals are not safe — they bypass transcript hash computation.

```go
env, err := tss.NewEnvelope(tss.EnvelopeInput{
    Protocol:    tss.ProtocolCGGMP21Secp256k1,
    SessionID:   sessionID,
    Round:       1,
    From:        1,
    PayloadType: "cggmp21.secp256k1.keygen.share",
    Payload:     payload,
})
```

`OpenEnvelope(raw, receiveInfo, opts...)` decodes wire bytes, recomputes the
transcript hash, and returns an `InboundEnvelope`. It rejects missing peer
identity, missing channel protection, and peer/envelope sender mismatch before
the guard runs.

### Encoding

`MarshalBinary()` produces canonical TLV bytes. `UnmarshalBinary()` decodes and rejects:

- Wrong wire type identifier (JSON fallback, legacy GG20 identifiers).
- Mismatched version.
- Missing or malformed fields.
- Trailing bytes.

See [docs/wire.md](wire.md) for the full canonical encoding specification.

### Transcript Binding

`DomainSeparatedHash()` uses the canonical labeled SHA-256 transcript encoding
from [`wire.md`](wire.md). Its domain label is followed by named entries for
`protocol`, `version`, `session_id`, `round`, `from`, `to`, `payload_type`, and
`payload`. The hash is set automatically by `NewEnvelope()` and verified by
`EnvelopeGuard.Validate()`.

### Transport Semantics

Transport security is not self-declared by the envelope. The receive adapter must
authenticate the peer, classify the actual channel protection, and call
`OpenEnvelope`:

```go
type ReceiveInfo struct {
    Peer       PartyID
    Protection ChannelProtection // Unknown, Plaintext, or Confidential
    ChannelID  string
    PeerKeyID  string
    ReceivedAt time.Time
}

in, err := tss.OpenEnvelope(raw, tss.ReceiveInfo{
    Peer:       peerID,
    Protection: tss.ChannelConfidential,
})
```

Delivery requirements (confidentiality, broadcast consistency) are defined per
payload type by protocol `PolicySet` and enforced by `EnvelopeGuard`.
`PolicySet` describes what the protocol requires; `ReceiveInfo` describes what
the transport actually observed.

### DeliveryPolicy & PolicySet

Each protocol defines a `PolicySet` that maps `(protocol, round, payloadType)` to delivery requirements:

```go
type DeliveryPolicy struct {
    Protocol             ProtocolID
    Round                uint8
    PayloadType          PayloadType
    Mode                 DeliveryMode              // Direct or Broadcast
    Confidentiality      ConfidentialityPolicy     // Required, Optional, or Forbidden
    BroadcastConsistency BroadcastConsistencyPolicy // None or Required
}
```

Unregistered payload types are **rejected by default** (fail-closed). See `cggmp21/secp256k1/policy.go` and `frost/ed25519/policy.go` for the complete matrices.

### EnvelopeGuard

`EnvelopeGuard` performs centralized security validation before any protocol handler processes an inbound envelope. It enforces these checks in order:

1. Protocol match
2. Session ID match
3. Version check
4. Transcript hash integrity
5. Sender membership in party set
6. Authenticated transport peer is present
7. `ReceiveInfo.Peer == Envelope.From`
8. Channel protection is set
9. Recipient correctness
10. Policy lookup (fail-closed for unknown payloads)
11. Delivery mode enforcement (direct vs broadcast)
12. Confidentiality enforcement against policy
13. Broadcast consistency certificate verification with `VerifyFull` (when required)
14. Replay and equivocation detection via `ReplayCache.CheckAndStore`

Each protocol session must be constructed with an `EnvelopeGuard` passed to its
`Start*` entry point, and handlers call `Validate(inbound)` as their first step.
A nil guard returns `ErrMissingEnvelopeGuard`. Production deployments use
`GuardConfig.BuildGuard`; tests use `NewTestEnvelopeGuard`, which panics when
not running under `go test` to prevent accidental production use. Sessions expose
`Guard()` as a read-only accessor for transport adapters.

### BroadcastCertificate

When a policy requires `BroadcastConsistencyRequired`, the transport must supply
a `BroadcastCertificate` to `OpenEnvelope` via `WithBroadcastCertificate`,
proving all parties received the same payload. Use
`BroadcastCertificate.VerifyFull` for production validation — it requires a
`BroadcastAckVerifier` to verify individual ack signatures. `VerifyStructure`
performs structural checks only and is intended for test code and low-level
parsing.

```go
type BroadcastCertificate struct {
    Protocol       ProtocolID
    SessionID      SessionID
    Round          uint8
    From           PartyID
    PayloadType    PayloadType
    PayloadHash    [32]byte
    TranscriptHash [32]byte
    Recipients     PartySet
    Acks           []BroadcastAck
}
```

CGGMP21 keygen round 1 (commitments, Paillier keys, proofs) and refresh/reshare round 1 commitments require broadcast consistency certificates. All broadcast-mode policies in FROST and CGGMP21 policy sets now require `BroadcastConsistencyRequired`. In-memory test helpers relax this with `inProcessPolicies()` / `simulationCGGMP21Policies()`.

### ReplayCache

```go
type ReplayCache interface {
    CheckAndStore(slot MessageSlotKey, transcriptHash [32]byte) error
}
```

`CheckAndStore` atomically checks whether a message slot has been seen and returns:

- `nil` when the slot is new (first use).
- `ErrDuplicateMessage` when the slot exists with the same transcript hash (harmless duplicate, silently dropped by the guard).
- `ErrEquivocation` when the slot exists with a different transcript hash (malicious or faulty sender).

`MessageSlotKey` identifies a unique protocol message slot by `(protocol, sessionID, round, from, to, payloadType)`. Unlike the old `ReplayKey`, it does not include the transcript hash — two different payloads in the same slot with different transcript hashes constitute equivocation.

`SlotKeyFromEnvelope` and `PayloadHashFromEnvelope` construct the arguments for `CheckAndStore` from an envelope.

Production sessions must use a non-nil `ReplayCache`. An `InMemoryReplayCache` is provided for single-process use.

## ProtocolError

`ProtocolError` is the stable error shape returned by all protocol state machines.

```go
type ProtocolError struct {
    Code  string   // machine-readable code (see constants below)
    Round uint8    // round where the failure occurred
    Party PartyID  // party attributed with the failure (0 if none)
    Blame *Blame   // public blame evidence, nil when not attributable
    Err   error    // wrapped underlying error
}
```

Error code constants:

| Constant                 | Meaning                                                                        |
| ------------------------ | ------------------------------------------------------------------------------ |
| `invalid_config`         | Invalid local configuration.                                                   |
| `invalid_message`        | Malformed or cross-session message.                                            |
| `duplicate_message`      | Repeated or replayed message within a round.                                   |
| `wrong_round`            | Message delivered to the wrong protocol round.                                 |
| `verification_failed`    | Cryptographic or transcript check failed.                                      |
| `aggregate_sign_invalid` | Aggregate ECDSA signature failed verification (suspect set, not attributable). |
| `not_ready`              | Not enough messages collected yet.                                             |
| `consumed`               | One-use material already consumed (presign).                                   |
| `completed`              | Session already completed.                                                     |
| `aborted`                | Session previously aborted with attributed blame.                              |
| `not_implemented`        | Intentionally unsupported feature.                                             |

`ProtocolError` implements `Unwrap()` for `errors.Is`/`errors.As` support. `NewProtocolError(code, round, party, err)` constructs an error without blame.

## Blame & BlameEvidence

When a verification failure can be attributed to a specific party, state machines return a `ProtocolError` with `Blame`:

```go
type Blame struct {
    Reason   string    // human-readable failure description
    Parties  []PartyID // attributed parties
    Evidence []byte    // deterministic BlameEvidence binary encoding, nil if not attributable
}
```

`BlameEvidence` is a canonical TLV binary record binding:

- Protocol, version, session ID.
- Round, sender, payload type.
- Payload hash, transcript hash.
- Evidence kind (see `EvidenceKind` constants) and reason.
- Selected public input hashes (commitments, Paillier keys, transcript hashes).

It **never** contains private shares, nonces, or Paillier secret-key material. Evidence is safe to log and share across operators.

`NewBlameEvidence` constructs a validated record from an envelope. `UnmarshalBlameEvidence` decodes and re-validates. CGGMP21-specific evidence is validated against trusted session context by `secp256k1.VerifyBlameEvidence`.

`EvidenceKind` constants cover keygen, presign, sign, refresh, reshare, and FROST failure classes.

## Logger

```go
type Logger interface {
    Debug(ctx context.Context, msg string, fields ...any)
    Info(ctx context.Context, msg string, fields ...any)
    Warn(ctx context.Context, msg string, fields ...any)
    Error(ctx context.Context, msg string, fields ...any)
}
```

`NopLogger()` returns a no-op implementation. `SLogger` adapts `log/slog.Logger` via `tss.NewSLogger(slog.Default())`.

Set `LocalConfig.Log` to capture structured logs. Protocol completion and failure events include `party_id` and `session_id` for cross-party correlation.

## Algorithm & Signature

```go
const (
    AlgorithmCGGMP21Secp256k1 Algorithm = "cggmp21-secp256k1"
    AlgorithmFROSTEd25519     Algorithm = "frost-ed25519"
)

type Signature struct {
    Algorithm Algorithm `json:"algorithm"`
    PublicKey []byte    `json:"public_key"`
    Data      []byte    `json:"data"`
    R         []byte    `json:"r,omitempty"`
    S         []byte    `json:"s,omitempty"`
}
```

`Signature` is a protocol-agnostic container. Algorithm-specific packages return `*Signature` from their `Signature()` accessors.

## KeyShare Interface

```go
type KeyShare interface {
    Algorithm() Algorithm
    PartyID() PartyID
    PublicKeyBytes() []byte
    MarshalBinary() ([]byte, error)
    Destroy()
}
```

Both `frost/ed25519.KeyShare` and `cggmp21/secp256k1.KeyShare` implement this
interface. They are opaque handles with copy-returning metadata getters.
`Destroy()` clears local secret material shared by all shallow copies of the
same handle. `MarshalBinary()` produces deterministic TLV bytes for
persistence. Algorithm session completion accessors return independently owned
shares that require separate destruction.

## Persistence Helpers

`EncryptKeyShareWithPassphrase` / `DecryptKeyShareWithPassphrase` and `EncryptPresignWithPassphrase` / `DecryptPresignWithPassphrase` provide ChaCha20-Poly1305 encryption with Argon2id key derivation from a passphrase. KDF parameters, version, algorithm, record type, and key ID are stored as authenticated metadata in the envelope:

```go
raw, _ := share.MarshalBinary()
encrypted, _ := tss.EncryptKeyShareWithPassphrase(raw, passphrase, "key-1", nil)
// store encrypted...

raw, _ := tss.DecryptKeyShareWithPassphrase(encrypted, passphrase)
share, _ := secp256k1.UnmarshalKeyShare(raw)
```

These are **reference/demo implementations**. Production deployments should use a KMS or HSM. See [docs/deployment.md](deployment.md) for the full persistence guide.

## Party Utilities

- `ContainsParty(parties, id)` — reports whether `id` appears in `parties`.
- `SortParties(parties)` — returns a sorted copy used by plan constructors and protocol handlers that need canonical participant ordering.
