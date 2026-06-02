# Security Notes

This repository is not a production-audited TSS stack.

## Threat Model

The library assumes each local caller controls one honest party state machine and receives envelopes from an external authenticated transport. State machines reject malformed messages, wrong sessions, wrong rounds, duplicate messages, non-participants, invalid curve/scalar encodings, and failed proof checks.

The library does not protect against a transport that lies about sender identity, drops all messages, strips confidentiality, replays old traffic before the caller checks session ids, or leaks persisted key-share files.

## Caller Responsibilities

Callers must provide:

- authenticated peer identity for every envelope;
- encryption for envelopes with `ConfidentialRequired`;
- replay protection and session-id freshness;
- durable storage encryption for key shares and presigns;
- secure deletion or `Destroy` calls for no-longer-needed local shares;
- operational monitoring for protocol errors and blame evidence.

Never log secret scalar, nonce, Paillier private-key, key-share, or presign bytes. Blame evidence is designed to contain public hashes and public context only.

## Production Integration Checklist

Before passing an inbound envelope to any state machine, the caller must verify
that the authenticated transport identity for the peer exactly matches
`Envelope.From`. The library checks that `Envelope.From` is a participant or
signer where applicable, but it cannot know whether the transport authenticated
the same party id.

Every inbound envelope must include the transcript hash produced by
`Envelope.WithTranscriptHash`. `ValidateBasic` rejects missing or mismatched
transcript hashes before payload decoding, so callers should recompute the hash
after any relay, storage, or framing layer changes an envelope.

Session ids must be fresh, unpredictable, and scoped to one protocol run. A
completed or attributable-aborted session rejects later messages without
mutating local state; callers should stop routing messages to such sessions and
surface the original protocol error and blame evidence.

The repository intentionally leaves these integration pieces to callers:
network transport, peer authentication, storage encryption, secure deletion of
persisted records, retries, consensus over session creation, KMS/HSM policy,
and operational alerting.

See [docs/deployment.md](deployment.md) for a complete deployment guide covering
key lifecycle, transport integration, persistence encryption, backup, and
monitoring.

## Secret-Material Lifecycle

Secret-bearing records reject default JSON marshaling. Persist `KeyShare` and
CGGMP21 `Presign` values only through their explicit binary encoders, then store
the resulting bytes under caller-managed encryption.

Algorithm-specific `KeyShare` structs keep secret scalar and Paillier private-key
bytes in unexported fields. Their string and Go-string formatting is redacted.
Session `KeyShare()` accessors return caller-owned copies, so mutating a returned
share does not mutate session-retained state. Callers must still destroy returned
shares when they are no longer needed.

Call `Destroy` on key shares, presigns, keygen sessions, presign sessions, and
signing sessions once they are no longer needed. These methods clear local
secret byte slices and scalar state such as Shamir shares, nonces, online
partials, Paillier private factors, and CGGMP21 presign shares while leaving
public metadata, such as party ids, public keys, signer sets, transcript hashes,
and public signatures, available for diagnostics where practical.

Zeroization in Go is best-effort. The library clears owned byte slices and
overwrites currently referenced `big.Int` words, but Go's garbage collector,
compiler optimizations, stack copies, immutable prior encodings, and caller-made
copies can leave historical secret material elsewhere in process memory. Use
short process lifetimes, encrypted persistence, locked-down crash reporting, and
process isolation when stronger memory-erasure guarantees are required.

## Constant-Time Paillier Private-Key Operations

Paillier private-key modular exponentiation (`c^λ mod n²`) is implemented via
`filippo.io/bigmod` in `internal/paillier/paillierct`. This replaces the
variable-time `math/big.Int.Exp` for secret-exponent paths.

`math/big` remains acceptable for:

- public-key encryption (`g^m mod n²`, `r^n mod n²`);
- public-exponent proof verification;
- parameter parsing and test vectors;
- key generation (one-time, offline).

`math/big.Int.Exp` must not be used when the exponent is a secret:
λ, μ, or an MtA responder scalar `b`.

The constant-time path enforces:

- fixed-length big-endian encodings for modulus, base, and exponent;
- Montgomery-ladder exponentiation via `bigmod.Nat.Exp`;
- ciphertext blinding (`c' = c * r^n mod n²`) during decryption;
- no secret-dependent branches, array indices, or early returns.

Secret scalars (`λ`, `μ`) are stored as `secret.Scalar` (fixed-length bytes)
and do not expose `String()`, variable-length `Bytes()`, `BigInt()`, or JSON
encoding.

## CGGMP21 Status

`cggmp21/secp256k1` implements CGGMP21-style threshold ECDSA with Paillier MtA/ZK proofs. It avoids transmitting or reconstructing private shares and nonce shares during signing, checks that presign participants share the same round-1 broadcast view, supports caller-provided additive public-key shifts and BIP32 HD derivation, and encodes all payloads as canonical binary TLV records.

The Paillier/ZK proof layer has been prepared for independent cryptographic audit. See `docs/audit-guide.md` for the complete proof-to-paper mapping.

Caller responsibilities (not provided by this library):

- network transport with peer authentication and encryption;
- storage encryption for key shares and presign records;
- proactive refresh scheduling (`RefreshScheduler` provides periodic key rotation with configurable interval and transport interface);
- SLIP10 path derivation (BIP32 HD derivation is implemented for secp256k1).

## One-Time Presigns

CGGMP21 presigns include nonce-derived local material. Reusing a presign can break ECDSA security. `StartSign` sets `Presign.Consumed` before constructing any outbound online signing envelope so reuse fails before a second partial signature leaves the process. Presigns are also bound to `PresignContext` fields: key id, chain id, derivation path, policy domain, and message domain.

## Blame Evidence

When a failure can be attributed, `ProtocolError.Blame` may include `Evidence`. Evidence binds protocol, session, round, sender, payload type, payload hash, transcript hash, reason, and selected public input hashes. Use `secp256k1.VerifyBlameEvidence` to validate CGGMP21 evidence against known public context.
