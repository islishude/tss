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

parties := tss.NewPartySet(1, 2, 3)
plan, err := secp256k1.NewKeygenPlan(secp256k1.KeygenPlanOption{
    SessionID: sessionID,
    Parties: parties,
    Threshold: 2,
})
local := tss.LocalConfig{Self: 1}
guard, err := (tss.GuardConfig{
    Self:        local.Self,
    Parties:     tss.PartySet(parties),
    Protocol:    tss.ProtocolCGGMP21Secp256k1,
    SessionID:   sessionID,
    Policies:    secp256k1.CGGMP21Policies(),
    Cache:       replayCache,
    AckVerifier: ackVerifier,
}).BuildGuard()
session, envelopes, err := secp256k1.StartKeygen(plan, local, guard)
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

For CGGMP21 presign records, the serialized consumed flag is only a local
snapshot. It is useful for discarding records that were already persisted as
consumed, but it is not the durable one-use boundary:

```go
raw, _ := tss.DecryptPresignWithPassphrase(encrypted, passphrase)
presign, _ := secp256k1.UnmarshalPresign(raw)
if secp256k1.IsPresignConsumed(presign) {
    // Discard; do not reuse.
}
```

Restored CGGMP21 presigns require a durable sign-attempt record. Provide
`SignRequest.AttemptStore`. `CommitSignAttempt` is the only StartSign
linearization point; `LoadSignAttempt` is for `ResumeSign` and diagnostics.
The store must atomically bind a presign ID to one intent and one attempt. A
repeated identical attempt returns `SignAttemptExistingSame`; the same intent
with a different attempt returns `secp256k1.ErrSignAttemptNonDeterminism`; a
different intent returns `secp256k1.ErrSignAttemptConflict`; a durable tombstone
returns `secp256k1.ErrSignAttemptBurned`. These are consumed outcomes. Any
other commit error has an unknown outcome and must be recovered with the same
request or `ResumeSign`.

### 4. Signing

**FROST Ed25519:**

```go
signGuard, err := (tss.GuardConfig{
    Self:        share.PartyID(),
    Parties:     tss.PartySet(signers),
    Protocol:    tss.ProtocolFROSTEd25519,
    SessionID:   sessionID,
    Policies:    ed25519.FROSTPolicies(),
    Cache:       replayCache,
    AckVerifier: ackVerifier,
}).BuildGuard()
signPlan, err := ed25519.NewSignPlan(ed25519.SignPlanOption{
    Key: share, SessionID: sessionID, Signers: signers, Message: message,
})
signSession, out, err := ed25519.StartSign(share, signPlan, tss.LocalConfig{Self: share.PartyID()}, signGuard)
// Route out (round 1 commitments) to other signers.
// Handle round 1 responses; obtain round 2 partials.
sig, ok := signSession.Signature()
// Signature is a standard 64-byte Ed25519 value; verify with crypto/ed25519.
```

**CGGMP21 secp256k1:**

```go
// Offline presign (can be done in advance):
ctx := secp256k1.PresignContext{
    KeyID: "key-1", ChainID: "chain-1",
    Derivation: tss.DerivationRequest{
        Scheme: tss.DerivationSchemeBIP32Secp256k1,
        Path: tss.MustParseDerivationPath("m/0/1"),
    },
    PolicyDomain: "policy", MessageDomain: "app",
}
presignGuard, err := (tss.GuardConfig{
    Self:        keyShare.PartyID(),
    Parties:     tss.PartySet(signers),
    Protocol:    tss.ProtocolCGGMP21Secp256k1,
    SessionID:   sessionID,
    Policies:    secp256k1.CGGMP21Policies(),
    Cache:       replayCache,
    AckVerifier: ackVerifier,
}).BuildGuard()
presignPlan, err := secp256k1.NewPresignPlan(secp256k1.PresignPlanOption{
    Key: keyShare, SessionID: sessionID, Signers: signers, Context: ctx,
})
presignSession, out, err := secp256k1.StartPresign(keyShare, presignPlan, tss.LocalConfig{Self: keyShare.PartyID()}, presignGuard)
// Route messages. Obtain Presign record.
presign, _ := presignSession.Presign()
// Persist presign immediately.
rawPresign, _ := presign.MarshalBinary()
encrypted, _ := tss.EncryptPresignWithPassphrase(rawPresign, passphrase, "presign-1", nil)

// Online signing (fast, one round):
message := []byte("payload")
request := secp256k1.SignRequest{
    Context:      ctx,
    Message:      message,
    AttemptStore: store, // required durable intent and encrypted outbox
}
signGuard, err := (tss.GuardConfig{
    Self:        keyShare.PartyID(),
    Parties:     tss.PartySet(signers),
    Protocol:    tss.ProtocolCGGMP21Secp256k1,
    SessionID:   sessionID,
    Policies:    secp256k1.CGGMP21Policies(),
    Cache:       replayCache,
    AckVerifier: ackVerifier,
}).BuildGuard()
signPlan, _ := secp256k1.NewSignPlan(secp256k1.SignPlanOption{
    Key: keyShare, Presign: presign, SessionID: sessionID, Request: request,
})
signSession, out, _ := secp256k1.StartSign(keyShare, presign, signPlan, tss.LocalConfig{Self: keyShare.PartyID(), Context: context.Background()}, signGuard)
// Route the single partial-signature round.
sig, ok := signSession.Signature()
secp256k1.VerifySignature(publicKey, request, sig) // true
```

After signing, you may persist a consumed snapshot for operational clarity, but
this is not a replacement for the durable attempt record:

```go
_ = secp256k1.MarkPresignConsumed(presign)
rawConsumed, _ := presign.MarshalBinary()
encrypted, _ := tss.EncryptPresignWithPassphrase(rawConsumed, passphrase, "presign-1", nil)
// Persist updated record so operators can see the consumed snapshot.
```

`StartSign` constructs and self-verifies the candidate partial before mutation,
checks `ctx.Err()`, then atomically commits the presign binding and exact
encrypted outbox through `SignAttemptStore`. An identical retry replays the same
attempt. A conflicting intent, burn tombstone, or same-intent/different-attempt
non-determinism fails with `ErrCodeConsumed`. Storage timeout, cancellation, or
I/O error during commit returns `ErrSignAttemptOutcomeUnknown`; never release
that presign. Retry the same intent or call `ResumeSign`.

`ResumeSign` returns the exact committed envelope only until delivery is
durably complete. An at-least-once dispatcher should keep replaying it until
`UpdateSignAttemptDelivery` has persisted acknowledgments from every recipient
and the required broadcast certificate. After the delivery certificate is
durable, `ResumeSign` rebuilds the session without returning outbound replay.
Signature completion alone is not a delivery acknowledgment.

`NewFileSignAttemptStore` is an encrypted append-only reference implementation.
It fsyncs immutable encrypted objects, creates the presign claim or burn
tombstone with an atomic hard link, records delivery ACKs/certificates and
completion as append-only objects, and fsyncs directories. It stores plaintext
hash metadata separately from randomized ciphertext and authenticates object
kind/binding data through the passphrase-encryption AAD. Production systems
should normally implement the interface with a transactional database and
KMS/HSM encryption.

### 5. Destruction

Call `Destroy()` on sessions and key shares when they are no longer needed. Go zeroisation is best-effort; use short-lived processes for stronger guarantees.

`KeyShare` and CGGMP21 `Presign` are opaque shared-lifecycle handles. Assigning
one value to another variable does not clone secret material: destroying or
consuming either shallow copy affects every handle to that state. Session
completion accessors return independent records; destroy each one separately.
Algorithm-specific metadata snapshots and party-scoped public records return
caller-owned copies.

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
protection := tss.ChannelPlaintext
if isEncrypted {
    protection = tss.ChannelConfidential
}
received, err := tss.OpenEnvelope(data, tss.ReceiveInfo{
    Peer:       peerID,
    Protection: protection,
    ChannelID:  channelID,
    PeerKeyID:  peerKeyID,
})
```

### Recommended Transport Patterns

**Message delivery guarantees:**

- Broadcast messages (`To == 0`) must reach all participants.
- Secret-bearing point-to-point messages must have `To` set to the receiver;
  the transport must report `ChannelConfidential` in `ReceiveInfo` and the
  `EnvelopeGuard` enforces confidentiality per the protocol `PolicySet`.
- `ReceiveInfo.Protection` is a transport-verified fact set by the receive path;
  it is not encryption. Sending those payloads through a plaintext broker,
  relay, log, or WebSocket is unsafe even if the adapter misreports protection.
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

## Proactive Refresh Scheduling

The root `tss.RefreshScheduler` drives the transport loop for both protocol
packages. Select the algorithm-specific runner and provide a durable replay
cache, broadcast ACK verifier, externally coordinated session-ID source, and an
atomic key-share commit:

```go
runner := frost.NewRefreshRunner(frost.RefreshRunnerOptions{})
scheduler, err := tss.NewRefreshScheduler(tss.RefreshSchedulerOptions[*frost.KeyShare]{
    Interval:    24 * time.Hour,
    Transport:   transport,
    Runner:      runner,
    ReplayCache: replayCache,
    AckVerifier: ackVerifier,
    LoadKeyShare: func(ctx context.Context) (*frost.KeyShare, error) {
        return store.LoadCurrent(ctx)
    },
    SessionIDSource: func(ctx context.Context, current *frost.KeyShare) (tss.SessionID, error) {
        return coordinator.NextRefreshSession(ctx, current.PublicKeyBytes())
    },
    CommitKeyShare: func(ctx context.Context, previous, refreshed *frost.KeyShare) error {
        return store.CompareAndSwap(ctx, previous, refreshed)
    },
})
if err != nil {
    return err
}
return scheduler.Run(ctx)
```

Use `secp256k1.NewRefreshRunner` for CGGMP21 and configure its Paillier limits
and security profile when required. All participants in one refresh must receive
the same session ID, and every later run must use a new ID.

`CommitKeyShare` is the linearization point. It must atomically persist and
install `refreshed` only while `previous` remains current. Normal commit errors
cause the scheduler to destroy the candidate share. If storage cannot determine
whether the commit succeeded, wrap `tss.ErrRefreshCommitOutcomeUnknown` and
retain the candidate for reconciliation.

`Run` waits one interval before the first refresh; `RunOnce` starts immediately.
Only one call may be active per scheduler. The scheduler exits on the first
protocol, transport, or commit failure and does not retry or coordinate restart
across participants.

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
5. If presigns exist, let durable attempts or burn tombstones decide
   availability: consumed snapshot plus matching attempt resumes; consumed
   snapshot with no attempt/tombstone is burned; unconsumed snapshot plus an
   existing attempt resumes that attempt.
6. Configure a durable `SignAttemptStore` before any CGGMP21 online signing call.

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

Set the `Logger` interface on `LocalConfig` to capture structured logs. Protocol completion/failure events include `party_id` and `session_id` for cross-party correlation.

```go
local := tss.LocalConfig{
    Self: 1,
    Log: tss.NewSLogger(slog.Default()),
}
```

## Security Startup Checklist

Before first production deployment, verify:

1. **Transport authentication:** Every `Envelope.From` matches the authenticated transport identity.
2. **Session ID freshness:** New session IDs are generated for every protocol run using `tss.NewSessionID`.
3. **Storage encryption:** Key shares, presigns, and sign-attempt outboxes are encrypted at rest using ChaCha20-Poly1305 or a KMS.
4. **Secret material logging:** Verify no log output contains `secret.Scalar`, Paillier private keys, nonce values, or share values.
5. **Presign lifecycle:** Durable attempts or burn tombstones are authoritative on restart; committed, outcome-unknown, or possibly sent presigns only resume their bound attempt.
6. **Blame evidence handling:** Protocol errors with `Blame != nil` are surfaced to operators.
7. **Process isolation:** Key-share processes run with minimal privileges, no core dumps, locked-down crash reporting.
8. **Network segmentation:** Signing processes are isolated from public-facing services.

## Version Upgrades

- Each TLV record carries its schema-local wire version in the frame header.
- Envelope and blame records do not duplicate that version in their field body.
- `tss.ProtocolVersion` is a separate semantic version bound into protocol
  transcripts and durable signing intent.
- Decoders reject unknown wire versions. Multi-version deployments must coordinate upgrades.
- Binary TLV encoding uses canonical tags. The decoder rejects unknown tags and trailing bytes.
- Before upgrading, verify that all participants use matching protocol and wire
  schema versions.
