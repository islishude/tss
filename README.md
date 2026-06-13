# tss

Go threshold-signature building blocks.

| Package             | Description                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------- |
| `frost/ed25519`     | FROST-style threshold Ed25519 ([RFC 9591 (FROST)](https://www.rfc-editor.org/rfc/rfc9591)). |
| `cggmp21/secp256k1` | [CGGMP21-style](https://eprint.iacr.org/2021/060) threshold ECDSA with Paillier MtA.        |

## Status

`frost/ed25519` implements a usable FROST flow: dealerless DKG, two-round signing, partial verification, Ed25519-compatible aggregation, resharing, and BIP32-Ed25519 HD derivation.

`cggmp21/secp256k1` implements dealerless DKG, offline presigning, single-round online signing, proactive refresh, resharing, BIP32 HD derivation, and blame attribution. Paillier proof layer uses CGGMP24 Πmod and Ring-Pedersen Πprm semantics.

## Quick Start

### Ed25519 (FROST)

```go
import (
    stded "crypto/ed25519"
    "github.com/islishude/tss"
    ed25519 "github.com/islishude/tss/frost/ed25519"
)

// DKG with guard — every protocol Start* call requires an EnvelopeGuard
// that enforces transport authentication, confidentiality, and replay protection.
sessionID, _ := tss.NewSessionID(nil)
parties := []tss.PartyID{1, 2, 3}
ps := tss.PartySet(parties)

sessions := make(map[tss.PartyID]*ed25519.KeygenSession)
var messages []tss.Envelope
for _, id := range parties {
    guard := tss.NewTestEnvelopeGuard(id, ps, tss.ProtocolFROSTEd25519, sessionID, ed25519.FROSTPolicies())
    kg, out, _ := ed25519.StartKeygen(tss.ThresholdConfig{
        Threshold: 2, Parties: parties, Self: id, SessionID: sessionID,
    }, guard)
    sessions[id] = kg
    messages = append(messages, out...)
}
for _, env := range messages { /* deliver authenticated+confidential to recipients */ }
share, _ := sessions[1].KeyShare()

// Sign
sig, _ := stded.Sign(message, map[tss.PartyID]*ed25519.KeyShare{1: share, 2: share2})
stded.Verify(share.PublicKey, message, sig) // true
```

Full examples in [`frost/ed25519/examples_test.go`](frost/ed25519/examples_test.go).

### secp256k1 (CGGMP21)

```go
// DKG → Presign (offline) → Sign (online, one round)
sessionID, _ := tss.NewSessionID(nil)
parties := tss.PartySet{1, 2, 3}
kgGuard := tss.NewTestEnvelopeGuard(1, parties, tss.ProtocolCGGMP21Secp256k1, sessionID, secp256k1.CGGMP21Policies())

kg, kgOut, _ := secp256k1.StartKeygen(tss.ThresholdConfig{...}, kgGuard)
// ... exchange kgOut and handler-returned keygen messages through confirmation round ...
share, _ := kg.KeyShare()

signers := []tss.PartyID{1, 2}
ctx := secp256k1.PresignContext{KeyID: "key-1", ChainID: "chain-1", PolicyDomain: "policy", MessageDomain: "app"}
presignID, _ := tss.NewSessionID(nil)
presignGuard := tss.NewTestEnvelopeGuard(1, tss.PartySet(signers), tss.ProtocolCGGMP21Secp256k1, presignID, secp256k1.CGGMP21Policies())
presign, presignOut, _ := secp256k1.StartPresignWithContext(share, presignID, signers, ctx, presignGuard)
// ... exchange presignOut messages over authenticated+confidential transport ...
pre, _ := presign.Presign()

message := []byte("payload")
request := secp256k1.SignRequest{Context: ctx, Message: message, LowS: true}
signID, _ := tss.NewSessionID(nil)
signGuard := tss.NewTestEnvelopeGuard(1, tss.PartySet(signers), tss.ProtocolCGGMP21Secp256k1, signID, secp256k1.CGGMP21Policies())
signSess, signOut, _ := secp256k1.StartSign(share, pre, signID, request, signGuard)
// ... exchange signOut messages ...
sig, _ := signSess.Signature()
secp256k1.VerifySignature(share.PublicKey, request, sig) // true
```

Full examples in [`cggmp21/secp256k1/integration_example_test.go`](cggmp21/secp256k1/integration_example_test.go) and [`cggmp21/secp256k1/examples_test.go`](cggmp21/secp256k1/examples_test.go).

## Documentation

| Document                                                                 | Content                                                                                       |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| [docs/root-package.md](docs/root-package.md)                             | Root package types, envelopes, errors, blame evidence.                                        |
| [docs/frost-ed25519.md](docs/frost-ed25519.md)                           | Full FROST Ed25519 protocol: DKG, signing, resharing, BIP32.                                  |
| [docs/cggmp21-secp256k1.md](docs/cggmp21-secp256k1.md)                   | Full CGGMP21 secp256k1 protocol: keygen, presign, signing, refresh, resharing, HD derivation. |
| [docs/architecture.md](docs/architecture.md)                             | Package boundaries, transport model, state-machine lifecycle.                                 |
| [docs/security.md](docs/security.md)                                     | Threat model, caller responsibilities, constant-time Paillier, secret lifecycle.              |
| [docs/wire.md](docs/wire.md)                                             | Canonical TLV encoding rules and decoder policy.                                              |
| [docs/paillier-zk-proofs.md](docs/paillier-zk-proofs.md)                 | Paillier ZK proof inventory, usage by phase, review blockers.                                 |
| [docs/audit-guide.md](docs/audit-guide.md)                               | Complete proof-to-paper mapping for cryptographic review.                                     |
| [docs/deployment.md](docs/deployment.md)                                 | Production guide: key lifecycle, transport, backups, monitoring.                              |
| [docs/cggmp21-protocol-checklist.md](docs/cggmp21-protocol-checklist.md) | Implementation tracking against the CGGMP21 specification.                                    |
| [docs/testing-rules.md](docs/testing-rules.md)                           | Test tiers, required invariants, fuzzing, golden vectors, crash/restart expectations.         |

## Security

See [docs/security.md](docs/security.md) for the threat model, caller responsibilities, secret-material lifecycle, constant-time Paillier constraints, and production checklist.
