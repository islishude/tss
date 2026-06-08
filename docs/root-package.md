# Root Package

The `github.com/islishude/tss` root package provides shared types used by both `frost/ed25519` and `cggmp21/secp256k1`.

## ThresholdConfig

`ThresholdConfig` carries local participant configuration for a protocol run. It is validated by `Validate()` and passed to `StartKeygen`, `StartPresign`, and `StartSign` constructors.

```go
type ThresholdConfig struct {
    Threshold    int
    Parties      []PartyID
    Self         PartyID
    SessionID    SessionID
    Rand         io.Reader       // optional; defaults to crypto/rand
    Context      context.Context // optional; defaults to context.Background()
    RoundTimeout time.Duration   // reserved for future use
    Log          Logger          // optional; defaults to no-op
}
```

`Validate()` checks:

- `Threshold > 0`, `len(Parties) > 0`, `Threshold <= len(Parties)`.
- No duplicate or zero-value party IDs.
- `Self` is in the party set.

`SortedParties()` returns the canonical ascending-order copy used by transcript binding and interpolation.

`Reader()` returns `c.Rand` when set, falling back to `crypto/rand.Reader`.

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

All protocol state machines communicate through `tss.Envelope`. It is the **only** message type exchanged between parties.

```go
type Envelope struct {
    Protocol             string    // protocol name (e.g. "frost-ed25519-v1")
    Version              uint16    // wire version (currently 1)
    SessionID            SessionID // scopes this message to a run
    Round                uint8     // protocol round number
    From                 PartyID   // sender
    To                   PartyID   // recipient; 0 means broadcast
    PayloadType          string    // identifies the payload schema
    Payload              []byte    // TLV-encoded protocol payload
    TranscriptHash       []byte    // SHA-256 of public envelope metadata
    ConfidentialRequired bool      // transport must encrypt this message
}
```

### Encoding

`MarshalBinary()` produces canonical TLV bytes. `UnmarshalBinary()` decodes and rejects:

- Wrong wire type identifier (JSON fallback, legacy GG20 identifiers).
- Mismatched version.
- Missing or malformed fields.
- Trailing bytes.

See [docs/wire.md](wire.md) for the full canonical encoding specification.

### Transcript Binding

`DomainSeparatedHash()` hashes `(label, protocol, version, round, session, from, to, confidential, payload_type, payload)`. `WithTranscriptHash()` returns a copy of the envelope with its transcript hash set.

`ValidateBasic(protocol, session, parties)` checks protocol name, version, session ID, transcript integrity, and sender membership. This is the **first fail-closed boundary** every protocol handler calls before decoding the payload.

### Transport Semantics

| `To`     | `ConfidentialRequired` | Meaning                                       |
| -------- | ---------------------- | --------------------------------------------- |
| `0`      | `false`                | Broadcast to all parties.                     |
| non-zero | `true`                 | Point-to-point, must be encrypted in transit. |
| non-zero | `false`                | Point-to-point, non-confidential.             |

Keygen shares, presign pairwise MtA messages, and reshare/refresh shares all set `ConfidentialRequired = true`. Broadcast commitments and online signing partials are non-confidential.

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

| Constant              | Meaning                                           |
| --------------------- | ------------------------------------------------- |
| `invalid_config`      | Invalid local configuration.                      |
| `invalid_message`     | Malformed or cross-session message.               |
| `duplicate_message`   | Repeated or replayed message within a round.      |
| `wrong_round`         | Message delivered to the wrong protocol round.    |
| `verification_failed` | Cryptographic or transcript check failed.         |
| `not_ready`           | Not enough messages collected yet.                |
| `consumed`            | One-use material already consumed (presign).      |
| `completed`           | Session already completed.                        |
| `aborted`             | Session previously aborted with attributed blame. |
| `not_implemented`     | Intentionally unsupported feature.                |

`ProtocolError` implements `Unwrap()` for `errors.Is`/`errors.As` support. `NewProtocolError(code, round, party, err)` constructs an error without blame.

## Blame & BlameEvidence

When a verification failure can be attributed to a specific party, state machines return a `ProtocolError` with `Blame`:

```go
type Blame struct {
    Reason   string    // human-readable failure description
    Parties  []PartyID // attributed parties
    Evidence []byte    // deterministic BlameEvidence JSON, nil if not attributable
}
```

`BlameEvidence` is a deterministic JSON record binding:

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

Set `ThresholdConfig.Log` to capture structured logs. Protocol completion and failure events include `party_id` and `session_id` for cross-party correlation.

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

Both `frost/ed25519.KeyShare` and `cggmp21/secp256k1.KeyShare` implement this interface. `Destroy()` clears local secret material. `MarshalBinary()` produces deterministic TLV bytes for persistence.

## Persistence Helpers

`EncryptKeyShareWithPassphrase` / `DecryptKeyShareWithPassphrase` and `EncryptPresignWithPassphrase` / `DecryptPresignWithPassphrase` provide AES-256-GCM encryption with Argon2id key derivation from a passphrase. KDF parameters, version, algorithm, record type, and key ID are stored as authenticated metadata in the envelope:

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
- `SortParties(parties)` — returns a sorted copy. Used by `ThresholdConfig.SortedParties()` and by protocol handlers that need canonical signer ordering.
