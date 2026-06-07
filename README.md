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
import "crypto/ed25519";

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
ed25519.Verify(share.PublicKey, message, sig) // true
```

Full examples in [`frost/ed25519/examples_test.go`](frost/ed25519/examples_test.go).

### secp256k1 (CGGMP21)

```go
// DKG → Presign (offline) → Sign (online, one round)
sessionID, _ := tss.NewSessionID(nil)
kg, kgOut, _ := secp256k1.StartKeygen(tss.ThresholdConfig{...})
// ... exchange kgOut and handler-returned keygen messages through confirmation round ...
share, _ := kg.Complete()

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

## Internal Packages

| Package                        | Purpose                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `internal/shamir`              | Shamir sharing and interpolation over prime-order fields.                      |
| `internal/secret`              | Fixed-length `Scalar`; no `String()`, `BigInt()`, or JSON.                     |
| `internal/curve/*`             | Curve helpers backed by fiat-crypto field arithmetic.                          |
| `internal/fiat`                | fiat-crypto generated arithmetic for Ed25519/secp256k1 fields.                 |
| `internal/mta`                 | Paillier MtA product-share protocol (Start/Respond/Finish) with Πaff-g proofs. |
| `internal/paillier`            | Paillier primitives; constant-time `c^λ mod n²` via `paillierct`.              |
| `internal/paillier/paillierct` | Constant-time `c^λ mod n²` via `filippo.io/bigmod`.                            |
| `internal/wire`                | Strict TLV encoding for all binary records.                                    |
| `internal/zk/paillier`         | ZK proofs: Πmod, Πprm, Πenc, Πaff-g, Πlog\*.                                   |
| `internal/zk/schnorr`          | secp256k1 Schnorr proof-of-knowledge.                                          |

## Development

```sh
make all          # build, test, vet, lint
make test         # tests with race detector
make test-count   # CI stress tests (10 iterations, 1h)
make check        # CI-ready: build + vet + lint + format + tidy
make lint-fix     # linter with auto-fix
make help         # list all targets
```

## Security

See [docs/security.md](docs/security.md) for the threat model, caller responsibilities, secret-material lifecycle, constant-time Paillier constraints, and production checklist.
