# tss

Go threshold-signature building blocks for:

- `frost/ed25519`: dealerless FROST-style threshold Ed25519.
- `gg20/secp256k1`: GG20-shaped secp256k1 threshold ECDSA API.

## Status

This repository is an early library implementation, not a production audited TSS stack.

The Ed25519 package implements a usable FROST-style flow: dealerless DKG, two-round signing, partial signature verification, and aggregation into signatures accepted by `crypto/ed25519.Verify`.

The secp256k1 package currently exposes the planned GG20 API shape, but its signing path is explicitly experimental. It reconstructs signing secret and nonce shares from a threshold subset, and does not yet implement the full GG20 Paillier MtA and zero-knowledge proof machinery. Do not use `gg20/secp256k1` as production GG20 threshold ECDSA until that MPC path is completed and independently audited.

## Packages

| Package                                   | Purpose                                                                                 |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `github.com/islishude/tss`                | Shared types: parties, sessions, envelopes, errors, key-share and signature interfaces. |
| `github.com/islishude/tss/frost/ed25519`  | FROST-style Ed25519 DKG and signing.                                                    |
| `github.com/islishude/tss/gg20/secp256k1` | Experimental secp256k1 threshold ECDSA API with GG20 package shape.                     |
| `internal/shamir`                         | Shamir sharing and interpolation helpers.                                               |
| `internal/curve/*`                        | Minimal curve helpers used by the protocol packages.                                    |
| `internal/paillier`                       | Paillier primitives for the future GG20 signing path.                                   |
| `internal/zk/schnorr`                     | secp256k1 Schnorr proof-of-knowledge primitive.                                         |

## Transport Model

Protocol sessions return `tss.Envelope` values. The library is transport-neutral:

- Broadcast messages have `To == 0`.
- Private messages set `To` and `ConfidentialRequired`.
- Callers must provide authenticated, confidential, replay-resistant delivery.
- The library validates protocol name, version, session id, round, sender membership, payload type, and transcript hash.

## Basic Ed25519 Flow

The tests include a compact in-memory simulator for DKG and signing. The real integration pattern is:

1. Create the same `tss.SessionID` for all parties in a session.
2. Call `ed25519.StartKeygen` for each local party.
3. Deliver returned envelopes to other parties with `HandleKeygenMessage`.
4. Persist each completed `KeyShare` using `MarshalBinary`.
5. For signing, call `ed25519.StartSign` on each signer and deliver round 1/round 2 envelopes.
6. Read the final 64-byte signature from `Signature()` and verify it with `crypto/ed25519.Verify`.

For convenience in tests and demos, `ed25519.Sign(message, shares)` runs an in-memory signing exchange over the supplied key shares.

## Basic secp256k1 Flow

The secp256k1 package follows the same session-state pattern:

1. Run `secp256k1.StartKeygen`.
2. Run `secp256k1.StartPresign` for the signer subset.
3. Run `secp256k1.StartSignDigest` with a 32-byte digest and a one-use presign record.
4. Verify the `(r, s)` result with `secp256k1.VerifyDigest`.

`Presign.Used` is consumed at signing start to catch nonce reuse. This is still an experimental implementation and leaks threshold material to participating signers during signing.

## Development

Run:

```sh
go test ./...
go test -race ./...
```

The test suite covers:

- Shamir interpolation and duplicate-party rejection.
- secp256k1 point encoding and ECDSA verification.
- Ed25519 scalar/point consistency and VSS verification.
- Paillier encryption/decryption and homomorphic operations.
- Schnorr proof verification.
- `1-of-1`, `2-of-3`, and `3-of-5` protocol simulations.
- duplicate messages, bad partial signatures, key-share round trips, and presign reuse rejection.

## Security Notes

- Do not log secret scalar, nonce, Paillier private-key, or key-share bytes.
- Always destroy no-longer-needed key shares with `Destroy()` when practical.
- Treat `ConfidentialRequired` envelopes as secret-bearing messages.
- Keep signer sets sorted before interpolation; helper APIs do this where needed.
- Full GG20 security still requires Paillier MtA, range/proof systems, identifiable abort, and audit work.
