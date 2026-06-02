# tss

Go threshold-signature building blocks.

| Package             | Description                                                        |
| ------------------- | ------------------------------------------------------------------ |
| `frost/ed25519`     | FROST-style threshold Ed25519 (RFC 9591).                          |
| `cggmp21/secp256k1` | **Experimental.** CGGMP21-style threshold ECDSA with Paillier MtA. |

References: [RFC 9591 (FROST)](https://www.rfc-editor.org/rfc/rfc9591), [CGGMP21 (ePrint 2021/060)](https://eprint.iacr.org/2021/060).

## Status

`frost/ed25519` implements a usable FROST flow: dealerless DKG, two-round signing, partial verification, Ed25519-compatible aggregation, resharing, and BIP32-Ed25519 HD derivation.

`cggmp21/secp256k1` signs without exposing private key shares or nonce shares. The ZK proof layer is prepared for independent review but **not yet audited**. The experimental warning stays until Paillier/ZK review is complete. See [docs/audit-guide.md](docs/audit-guide.md).

## Quick Start

### Ed25519 (FROST)

```go
// DKG
sessionID, _ := tss.NewSessionID(nil)
parties := []tss.PartyID{1, 2, 3}
sessions := make(map[tss.PartyID]*ed25519.KeygenSession)
var messages []tss.Envelope
for _, id := range parties {
    kg, out, _ := ed25519.StartKeygen(tss.ThresholdConfig{
        Threshold: 2, Parties: parties, Self: id, SessionID: sessionID,
    })
    sessions[id] = kg
    messages = append(messages, out...)
}
for _, env := range messages { /* deliver to recipients via HandleKeygenMessage */ }
share, _ := sessions[1].KeyShare()

// Sign
sig, _ := ed25519.Sign(message, map[tss.PartyID]*ed25519.KeyShare{1: share, 2: share2})
crypto.ed25519.Verify(share.PublicKey, message, sig) // true
```

### secp256k1 (CGGMP21)

```go
// DKG → Presign (offline) → Sign (online, one round)
sessionID, _ := tss.NewSessionID(nil)
kg, kgOut, _ := secp256k1.StartKeygen(tss.ThresholdConfig{...})
// ... exchange kgOut messages, obtain KeyShare ...

signers := []tss.PartyID{1, 2}
ctx := secp256k1.PresignContext{KeyID: "key-1", ChainID: "chain-1", PolicyDomain: "policy", MessageDomain: "app"}
presign, presignOut, _ := secp256k1.StartPresignWithContext(share, sessionID, signers, ctx)
// ... exchange presignOut messages ...
pre, _ := presign.Presign()

message := []byte("payload")
request := secp256k1.SignRequest{Context: ctx, Message: message, LowS: true}
signSess, signOut, _ := secp256k1.StartSign(share, pre, signID, request)
// ... exchange signOut messages ...
sig, _ := signSess.Signature()
secp256k1.VerifySignature(share.PublicKey, request, sig) // true
```

Full examples in [`examples_test.go`](frost/ed25519/examples_test.go) and [`examples_test.go`](cggmp21/secp256k1/examples_test.go).

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

## Internal Packages

| Package                        | Purpose                                                           |
| ------------------------------ | ----------------------------------------------------------------- |
| `internal/shamir`              | Shamir sharing and interpolation over prime-order fields.         |
| `internal/secret`              | Fixed-length `Scalar`; no `String()`, `BigInt()`, or JSON.        |
| `internal/curve/*`             | Curve helpers backed by fiat-crypto field arithmetic.             |
| `internal/fiat`                | fiat-crypto generated arithmetic for Ed25519/secp256k1 fields.    |
| `internal/mta`                 | Paillier MtA product-share protocol (Start/Respond/Finish).       |
| `internal/paillier`            | Paillier primitives; constant-time `c^λ mod n²` via `paillierct`. |
| `internal/paillier/paillierct` | Constant-time `c^λ mod n²` via `filippo.io/bigmod`.               |
| `internal/wire`                | Strict TLV encoding for all binary records.                       |
| `internal/zk/paillier`         | Seven ZK proof types for Paillier operations.                     |
| `internal/zk/schnorr`          | secp256k1 Schnorr proof-of-knowledge.                             |

## Development

```sh
make all          # build, test, vet, lint
make test         # tests with race detector
make test-count   # CI stress tests (10 iterations, 1h)
make check        # CI-ready: build + vet + lint + fmt-md + tidy
make lint-fix     # linter with auto-fix
make help         # list all targets
```

## Security

- Never log secret scalar, nonce, Paillier private-key, or key-share bytes.
- Call `Destroy()` on shares, presigns, and sessions when done.
- `ConfidentialRequired` envelopes carry secret material — deliver them encrypted.
- `Blame.Evidence` contains public hashes only; safe to log and share.
- CGGMP21 presigns are one-use; reuse breaks ECDSA security.
- Go zeroization is best-effort. Use short-lived processes, encrypted persistence, and process isolation for stronger guarantees.

See [docs/security.md](docs/security.md) for the full threat model and caller responsibilities.
