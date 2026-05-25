# tss

Go threshold-signature building blocks for:

- `frost/ed25519`: dealerless FROST-style threshold Ed25519.
- `cggmp21/secp256k1`: CGGMP21-shaped secp256k1 threshold ECDSA API.

## Status

This repository is an early library implementation, not a production audited TSS stack.

The Ed25519 package implements a usable FROST-style flow: dealerless DKG, two-round signing, partial signature verification, and aggregation into signatures accepted by `crypto/ed25519.Verify`.

The secp256k1 package exposes a CGGMP21-style API and now signs without transmitting or reconstructing private key shares or nonce shares. Its signing path uses Paillier MtA/MtAwc-style product sharing, round-1 echo checks, optional additive-shift signing, and an unaudited proof implementation, so it remains explicitly experimental until independent cryptographic review is complete.

## Packages

| Package                                      | Purpose                                                                                 |
| -------------------------------------------- | --------------------------------------------------------------------------------------- |
| `github.com/islishude/tss`                   | Shared types: parties, sessions, envelopes, errors, key-share and signature interfaces. |
| `github.com/islishude/tss/frost/ed25519`     | FROST-style Ed25519 DKG and signing.                                                    |
| `github.com/islishude/tss/cggmp21/secp256k1` | Experimental secp256k1 threshold ECDSA API with CGGMP21 package shape.                  |
| `internal/shamir`                            | Shamir sharing and interpolation helpers.                                               |
| `internal/curve/*`                           | Curve helpers with fiat-crypto backed scalar/field wrappers.                            |
| `internal/mta`                               | Paillier MtA product-share protocol helpers.                                            |
| `internal/paillier`                          | Paillier primitives used by the CGGMP21-style signing path.                             |
| `internal/wire`                              | Strict TLV encoding used by binary envelopes and key-share records.                     |
| `internal/zk/paillier`                       | Paillier encryption, range, modulus, and MtA response proofs.                           |
| `internal/zk/schnorr`                        | secp256k1 Schnorr proof-of-knowledge primitive.                                         |

## Transport Model

Protocol sessions return `tss.Envelope` values. The library is transport-neutral:

- Broadcast messages have `To == 0`.
- Private messages set `To` and `ConfidentialRequired`.
- Callers must provide authenticated, confidential, replay-resistant delivery.
- The library validates protocol name, version, session id, round, sender membership, payload type, and transcript hash.

## Identifiable Abort Evidence

Verification failures can attach `tss.Blame.Evidence` with a deterministic `tss.BlameEvidence` record. Evidence binds the public protocol context, sender, round, payload type, payload hash, transcript hash, reason, and selected public input hashes. Confidential payloads are represented by hashes rather than plaintext.

The secp256k1 package exposes `secp256k1.VerifyBlameEvidence` for validating CGGMP21 evidence against public session context such as parties, signer set, group public key, Paillier public keys, and transcript hashes. This improves blame attribution for malformed proofs and failed aggregate signatures, but it is not a substitute for a full CGGMP21 identifiable-abort security review.

## Canonical Encoding

`tss.Envelope`, CGGMP21/FROST key shares, CGGMP21 presign records, protocol payloads, MtA messages, Paillier keys, and proof records use strict TLV binary formats. The default decoders reject JSON fallback, trailing bytes, duplicate or unsorted wire tags, malformed curve/scalar encodings, and non-canonical nested Paillier keys.

CGGMP21 key-share decoders require complete Paillier/ZK keygen material, including the local Paillier keypair, modulus proof, full public Paillier-key set, share proof, and keygen transcript hash. Shares missing that material are rejected during decode or validation. Unexpected wire type identifiers are not accepted.

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

`Presign.Consumed` is set before any online signing envelope is emitted to catch nonce reuse. The online signing message contains only a partial `s_i`, not the local private-key share or local nonce share.

For additive-shift signing, pass `secp256k1.SignOptions{LowS: true, AdditiveShift: shift}` to `StartSignDigestWithOptions` and verify against `secp256k1.DerivePublicKey(publicKey, shift)`.

## Development

Run:

```sh
golangci-lint run --fix
go test -race ./...
```

The test suite covers:

- Shamir interpolation and duplicate-party rejection.
- secp256k1 point encoding and ECDSA verification.
- fiat-crypto backed secp256k1 and Ed25519 scalar/field arithmetic wrappers.
- Ed25519 scalar/point consistency and VSS verification.
- Paillier encryption/decryption and homomorphic operations.
- Schnorr proof verification.
- deterministic blame evidence encoding and tamper rejection.
- canonical TLV encoding for envelopes, key shares, and CGGMP21 presigns.
- `1-of-1`, `2-of-3`, and `3-of-5` protocol simulations.
- duplicate messages, bad partial signatures, echo mismatches, additive-shift signatures, key-share round trips, and presign reuse rejection.

## Documentation

The design notes are kept under `docs/` and should be updated with protocol or wire-format changes:

- `docs/architecture.md`: package boundaries and state-machine responsibilities.
- `docs/security.md`: caller responsibilities, threat model limits, and audit status.
- `docs/wire.md`: canonical TLV encoding rules and decoder policy.
- `docs/cggmp21-secp256k1.md`: CGGMP21-style secp256k1 equations and message flow.
- `docs/frost-ed25519.md`: FROST Ed25519 DKG/signing equations and message flow.

New exported Go identifiers require doc comments. Protocol equations, transcript/domain separation, and sensitive scalar or nonce handling also need explanatory comments. Examples in `examples_test.go` files exercise the public API and should be kept current with API changes.

## Security Notes

- Do not log secret scalar, nonce, Paillier private-key, or key-share bytes.
- Always destroy no-longer-needed key shares, presigns, and sessions with
  `Destroy()` when practical. Go memory zeroization is best-effort; see
  `docs/security.md` for limits.
- Treat `ConfidentialRequired` envelopes as secret-bearing messages.
- Treat `Blame.Evidence` as public diagnostic material: it should contain hashes and public inputs only.
- Keep signer sets sorted before interpolation; helper APIs do this where needed.
- Full CGGMP21 security still requires independent audit work.
