# Production Deployment Guide

This guide covers the end-to-end lifecycle of a TSS deployment using this library, from initial key generation through online signing and key rotation.

## Key Lifecycle

### 1. Key Generation

Each participant generates its share independently through the DKG protocol. See the package docs for `frost/ed25519` and `cggmp21/secp256k1` for per-protocol details.

```go
import (
    "github.com/islishude/tss"
    "github.com/islishude/tss/cggmp21/secp256k1"
)

config := tss.ThresholdConfig{
    Threshold: 2,
    Parties:   []tss.PartyID{1, 2, 3},
    Self:      1,
    SessionID: sessionID,
}
session, envelopes, err := secp256k1.StartKeygen(config)
// Route envelopes to other parties via authenticated transport. Keep routing
// any envelopes returned by HandleKeygenMessage; keygen emits a confirmation
// round before KeyShare() becomes available.
```

After all parties exchange messages, each obtains a `KeyShare`:

```go
share, ok := session.KeyShare()
if !ok {
    // DKG not yet complete — wait for more messages.
}
```

### 2. Persistence

Serialise the key share to TLV bytes and encrypt before storage:

```go
raw, _ := share.MarshalBinary()
encrypted, _ := tss.EncryptKeyShareWithPassphrase(raw, passphrase, "key-1", nil)
// Store `encrypted` in durable storage (database, file, secrets manager).
```

For CGGMP21, presign records must also be persisted:

```go
raw, _ := presign.MarshalBinary()
encrypted, _ := tss.EncryptPresignWithPassphrase(raw, passphrase, "presign-1", nil)
```

The `tss.EncryptKeyShareWithPassphrase` and `tss.EncryptPresignWithPassphrase` helpers use ChaCha20-Poly1305 with Argon2id key derivation from a passphrase. These are **reference/demo implementations**. Production deployments should prefer a KMS or HSM.

### 3. Loading

On process restart, load and decrypt the key share:

```go
raw, _ := tss.DecryptKeyShareWithPassphrase(encrypted, passphrase)
share, err := secp256k1.UnmarshalKeyShare(raw)
```

For CGGMP21 presign records, check the consumed flag before use:

```go
raw, _ := tss.DecryptPresignWithPassphrase(encrypted, passphrase)
presign, _ := secp256k1.UnmarshalPresign(raw)
if secp256k1.IsPresignConsumed(presign) {
    // Discard; do not reuse.
}
```

### 4. Signing

**FROST Ed25519:**

```go
signSession, out, err := ed25519.StartSign(share, sessionID, signers, message)
// Route out (round 1 commitments) to other signers.
// Handle round 1 responses; obtain round 2 partials.
sig, ok := signSession.Signature()
// Signature is a standard 64-byte Ed25519 value; verify with crypto/ed25519.
```

**CGGMP21 secp256k1:**

```go
// Offline presign (can be done in advance):
ctx := secp256k1.PresignContext{KeyID: "key-1", ChainID: "chain-1", PolicyDomain: "policy", MessageDomain: "app"}
presignSession, out, err := secp256k1.StartPresignWithContext(keyShare, sessionID, signers, ctx)
// Route messages. Obtain Presign record.
presign, _ := presignSession.Presign()
// Persist presign immediately.
encrypted, _ := tss.EncryptPresignWithPassphrase(presign.MarshalBinary(), passphrase, "presign-1", nil)

// Online signing (fast, one round):
message := []byte("payload")
request := secp256k1.SignRequest{Context: ctx, Message: message, LowS: true}
signSession, out, _ := secp256k1.StartSign(keyShare, presign, sessionID, request)
// Route the single partial-signature round.
sig, ok := signSession.Signature()
secp256k1.VerifySignature(publicKey, request, sig) // true
```

After signing, mark the presign consumed:

```go
consumed, _ := secp256k1.MarkPresignConsumed(presign)
encrypted, _ := tss.EncryptPresignWithPassphrase(consumed.MarshalBinary(), passphrase, "presign-1", nil)
// Persist updated record so restart won't reuse.
```

### 5. Destruction

Call `Destroy()` on sessions and key shares when they are no longer needed. Go zeroisation is best-effort; use short-lived processes for stronger guarantees.

```go
share.Destroy()
presign.Destroy()
session.Destroy()
signSession.Destroy()
```

## Transport Integration

### Envelope Serialisation

Envelopes are the only message type exchanged between parties. They have a deterministic binary encoding:

```go
env, err := tss.NewEnvelope(tss.EnvelopeInput{...})
raw, err := env.MarshalBinary()
// Transmit `raw` bytes.

// On the receiving side:
var received tss.Envelope
err := received.UnmarshalBinary(data)
// Transport adapter must set received.Security from authenticated channel:
received.Security.Authenticated = true
received.Security.AuthenticatedParty = peerID
received.Security.Confidential = isEncrypted
```

### Recommended Transport Patterns

**Message delivery guarantees:**

- Broadcast messages (`To == 0`) must reach all participants.
- Secret-bearing point-to-point messages must have `To` set to the receiver;
  the transport must set `Security.Confidential = true` and the `EnvelopeGuard`
  enforces confidentiality per the protocol `PolicySet`.
- `Security.Confidential` is a transport-verified fact set by the receive path;
  it is not encryption. Sending those payloads through a plaintext broker,
  relay, log, or WebSocket is unsafe even when the flag is set.
- Within a round, messages can be delivered in any order.
- Across rounds, messages must be processed sequentially — round N must complete before round N+1.

**Transport options:**

| Transport                 | Notes                                                 |
| ------------------------- | ----------------------------------------------------- |
| gRPC bidirectional stream | Strong typing, TLS, built-in auth interceptors        |
| WebSocket + JSON framing  | Encode envelope bytes as base64 or hex                |
| NATS                      | Subject-based routing maps naturally to broadcast/p2p |

### Message Routing Pattern

```go
func routeMessages(session Session, transport Transport) error {
    for {
        env := transport.Recv()
        out, err := session.HandleMessage(env)
        if err != nil {
            var pe *tss.ProtocolError
            if errors.As(err, &pe) && pe.Blame != nil {
                logBlame(pe.Blame)
            }
            // Abort session or continue based on error code.
        }
        for _, e := range out {
            transport.Send(e)
        }
        if session.IsCompleted() {
            return nil
        }
    }
}
```

## Persistence Encryption

### Recommended Pattern (ChaCha20-Poly1305)

```go
func encrypt(plaintext, key []byte) ([]byte, error) {
    aead, _ := chacha20poly1305.New(key)
    nonce := make([]byte, aead.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    return aead.Seal(nonce, nonce, plaintext, nil), nil
}
```

### Key Management

- **Key derivation:** Derive encryption keys from a passphrase using Argon2id with per-record salt. This is a reference/demo implementation; prefer a KMS or HSM in production.
- **Nonce management:** Use random 12-byte nonces. Never reuse a nonce with the same key.
- **Key rotation:** Rotate encryption keys when rotating TSS key shares (proactive refresh).

The `tss.EncryptKeyShareWithPassphrase` and `tss.EncryptPresignWithPassphrase` helpers implement this pattern as a reference.

## Backup and Disaster Recovery

### Backup Strategy

- Back up each encrypted key share to geographically separated durable storage.
- Consider a **Shamir backup** of the encryption passphrase with a higher threshold than the signing threshold (e.g., 5-of-7 backup recovery for a 3-of-5 signing scheme).
- Back up CGGMP21 presign records alongside key shares.

### Recovery Flow

1. Restore encrypted key share from backup.
2. Decrypt with the recovery passphrase.
3. Load into a new session.
4. Verify against known group public key.
5. If presigns exist, check consumed flags — discard consumed presigns.

## Monitoring and Alerting

### Key Metrics

| Metric                                | Alert Threshold                               | Severity |
| ------------------------------------- | --------------------------------------------- | -------- |
| Paillier proof verification failures  | > 0 in any session                            | Warning  |
| Blame evidence events                 | Any occurrence                                | Warning  |
| Signature failures (aggregate verify) | > 0 in any session                            | Error    |
| Session timeouts                      | Session unfinished after 2x expected duration | Warning  |
| Presign reuse attempts                | Any occurrence                                | Critical |

### Log-Based Monitoring

Enable the `Logger` interface on `ThresholdConfig` to capture structured logs. Protocol completion/failure events include `party_id` and `session_id` for cross-party correlation.

```go
config := tss.ThresholdConfig{
    // ...
    Log: tss.NewSLogger(slog.Default()),
}
```

## Security Startup Checklist

Before first production deployment, verify:

1. **Transport authentication:** Every `Envelope.From` matches the authenticated transport identity.
2. **Session ID freshness:** New session IDs are generated for every protocol run using `tss.NewSessionID`.
3. **Storage encryption:** Key shares and presign records are encrypted at rest using ChaCha20-Poly1305 or a KMS.
4. **Secret material logging:** Verify no log output contains `secret.Scalar`, Paillier private keys, nonce values, or share values.
5. **Presign lifecycle:** Presign consumed flags are persisted and checked on restart.
6. **Blame evidence handling:** Protocol errors with `Blame != nil` are surfaced to operators.
7. **Process isolation:** Key-share processes run with minimal privileges, no core dumps, locked-down crash reporting.
8. **Network segmentation:** Signing processes are isolated from public-facing services.

## Version Upgrades

- Wire format version is encoded in every `Envelope.Version` and key-share record.
- Decoders reject unknown versions. Multi-version deployments must coordinate upgrades.
- Binary TLV encoding uses canonical tags. The decoder rejects unknown tags and trailing bytes.
- Before upgrading, verify that all participants are running the same library version.
