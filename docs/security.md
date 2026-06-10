# Security Notes

**Hard precondition**: The transport layer must set `SecurityContext` (authenticated identity, confidentiality) on every received envelope. `EnvelopeGuard` enforces confidentiality requirements per payload type via the protocol `PolicySet`. This library does **not** seal or open transport ciphertexts — it validates `Security.Confidential` at the guard boundary. Unencrypted transport of secret-bearing envelopes will expose keygen shares, nonce material, and MtA responses to any observer on the message path.

This repository is not a production-audited TSS stack.

## Threat Model

The library assumes each local caller controls one honest party state machine and receives envelopes from an external authenticated transport. State machines reject malformed messages, wrong sessions, wrong rounds, duplicate messages, non-participants, invalid curve/scalar encodings, and failed proof checks.

The library does not protect against a transport that lies about sender identity, drops all messages, strips confidentiality, replays old traffic before the caller checks session ids, or leaks persisted key-share files.

## Caller Responsibilities

Callers must provide:

- authenticated peer identity for every envelope, set via `Envelope.Security.AuthenticatedParty` and `Authenticated`;
- encryption for secret-bearing envelopes, signalled by `Envelope.Security.Confidential`. Confidentiality requirements are defined per payload type by protocol `PolicySet` and enforced by `EnvelopeGuard`;
- **equivocation-resistant broadcast** for all broadcast-mode protocol messages:
  every participant must receive identical payloads, verified by
  `BroadcastCertificate` with `VerifyFull`. The guard detects equivocation via
  `ReplayCache.CheckAndStore` when the same message slot carries different
  transcript hashes. After keygen completes, compare `KeygenTranscriptHash`
  across parties as an additional defense-in-depth check;
- replay protection via `ReplayCache` and session-id freshness;
- durable storage encryption for key shares and presigns (`tss.EncryptKeyShareWithPassphrase` and `tss.EncryptPresignWithPassphrase` are Argon2id-based reference/demo implementations — production should use a KMS or HSM);
- secure deletion or `Destroy` calls for no-longer-needed local shares;
- operational monitoring for protocol errors and blame evidence.

Never log secret scalar, nonce, Paillier private-key, key-share, or presign bytes. Blame evidence is designed to contain public hashes and public context only.
FROST Ed25519 `ChainCode` values are not signing secrets, but HD key
consistency depends on them; back them up and distribute them only with the
same authorization checks used for key-share metadata.

## Production Integration Checklist

`EnvelopeGuard` is the mandatory first fail-closed boundary for every inbound
envelope. Construct a guard via `tss.GuardConfig.BuildGuard` (production) or
`tss.NewTestEnvelopeGuard` (tests only — panics outside `go test`) and attach
it to every session with `SetGuard` **before** processing any inbound messages. Sessions return
`ErrMissingEnvelopeGuard` when an envelope arrives without a configured guard.
Production `GuardConfig.BuildGuard` requires a non-nil `AckVerifier`
(`BroadcastAckVerifier`) for broadcast ack signature verification.

Before passing an inbound envelope to any state machine, the caller must verify
that the authenticated transport identity for the peer exactly matches
`Envelope.From`. The guard checks that `Envelope.From` is a participant and that
`Security.AuthenticatedParty == Envelope.From`, rejecting identity mismatches.

Every inbound envelope must include the transcript hash produced by
`NewEnvelope`. `EnvelopeGuard.Validate` rejects missing or mismatched
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
bytes in unexported fields. Key shares and CGGMP21 presign records store local
scalar shares as fixed-length `secret.Scalar` values rather than exported byte
slices. Their string and Go-string formatting is redacted. Session `KeyShare()`
accessors return caller-owned copies, so mutating a returned share does not
mutate session-retained state. Callers must still destroy returned shares when
they are no longer needed.

Call `Destroy` on key shares, presigns, keygen sessions, presign sessions, and
signing sessions once they are no longer needed. These methods clear local
secret byte slices and scalar state such as Shamir shares, nonces, online
partials, Paillier private factors, and CGGMP21 presign shares while leaving
public metadata, such as party ids, public keys, signer sets, transcript hashes,
and public signatures, available for diagnostics where practical.

FROST Ed25519 signing nonces are derived from 32 bytes of fresh randomness and
the local secret-share scalar encoding. A `SignSession` stores nonce bytes only
until its round-2 partial payload is constructed; successful partial generation
and attributable signing failures clear those bytes immediately. `Destroy`
should still be called after completion or abort to clear message copies,
partials, shifted verification keys, and any remaining session-owned material.

FROST resharing share envelopes carry confidential scalar shares.
Transports must authenticate the sender and encrypt these point-to-point
messages, setting `Security.Confidential` so the guard enforces the policy. New HD reshare recipients must be provisioned
with the old 32-byte chain code through an authorized metadata channel; the
chain code is not a signing secret, but losing or substituting it changes child
key derivation.

CGGMP21/secp256k1 resharing also sends confidential old-dealer shares to the
new receiver set. New-only receivers must be provisioned with authenticated old
key metadata, including the old group public key, chain code, keygen transcript
hash, and old party set. Substituting any of that metadata can produce a share
for the wrong key context even when the final public-key preservation check
passes.

Zeroization in Go is best-effort. The library clears owned byte slices and
overwrites currently referenced `big.Int` words, but Go's garbage collector,
compiler optimizations, stack copies, immutable prior encodings, and caller-made
copies can leave historical secret material elsewhere in process memory. Use
short process lifetimes, encrypted persistence, locked-down crash reporting, and
process isolation when stronger memory-erasure guarantees are required.

## Destroy and Abort Lifecycle

Every session type (`KeygenSession`, `PresignSession`, `SignSession`,
`RefreshSession`, `ReshareSession`) implements a `Destroy()` method that
clears all secret-bearing fields: nonce scalars, Shamir shares, Paillier
private keys, MtA witnesses, polynomial coefficients, ciphertext maps, and
assembled key shares. `Destroy()` is idempotent and safe to call on a nil
receiver.

Protocol abort paths call an internal `abort()` method that marks the session
aborted and immediately clears accumulated secret state. A verification failure
or blame-attributed protocol error triggers `abort()` automatically through the
handler's deferred recovery. This prevents secret material from persisting in
memory after a failed run when the caller may not explicitly call `Destroy()`.

Callers must still call `Destroy()` on sessions, `KeyShare`, and `Presign`
values once they are no longer needed. The library does not hook into
finalizers or runtime cleanup — only explicit `Destroy()` calls guarantee
that owned byte slices and `big.Int` backing arrays are overwritten.

Key shares and presign records held by a session as **references** (e.g.,
`SignSession.key` and `SignSession.presign`) are NOT destroyed by the
session's `Destroy()` — they are caller-owned and must be destroyed
separately.

### Deployment Recommendations

For high-assurance deployments where process-memory zeroization matters:

- **Disable core dumps** (`ulimit -c 0`, or set `kernel.core_pattern` to
  `|/bin/false` on Linux).
- **Restrict crash reporting** — do not upload full process dumps to crash
  analytics services.
- **Use short-lived signer processes** — spawn a process per signing
  operation or batch, so the OS reclaims memory on exit.
- **Encrypt persisted key material** with a KMS or HSM rather than relying
  on in-process passphrase encryption.
- **Disable Go's heap profiling and memory profiling** in production builds
  to prevent secret material from appearing in pprof output.

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

The Paillier/ZK proof layer has been rewritten to use CGGMP-compatible constructions:

- **Πenc**: Paillier encryption in range with Ring-Pedersen commitments, large integer masks sampled from ±2^(Ell+Epsilon), and strict ciphertext membership and response range checks. Presign Round 1 uses verifier-specific Πenc proofs because the statement binds the verifier's Ring-Pedersen auxiliary parameters.
- **Πaff-g**: Paillier affine operation with group commitment in range, replacing the legacy MTAResponseProof. Uses Ring-Pedersen commitments and binds the prover's Paillier key, the verifier's auxiliary parameters, and all statement fields into the Fiat-Shamir challenge.
- **Πlog\***: Group element vs Paillier encryption in range, replacing the legacy LogProof. Uses Ring-Pedersen commitment to hide the integer witness and binds the Paillier ciphertext, curve points, and base point into the challenge.

All three proofs use the canonical typed transcript API; the Fiat-Shamir challenge is never reduced modulo the secp256k1 order for Paillier-integer proofs.

Presign and signing entry points are enabled. The Paillier MtA/ZK proof layer has
not yet received independent cryptographic review. See
`docs/paillier-zk-proofs.md` for the current status and production blockers, and
`docs/audit-guide.md` for the proof-to-paper mapping designed to facilitate such
a review.

## Keygen Broadcast Consistency

The keygen protocols assume authenticated transport and converge through an
explicit confirmation round. After local DKG material verifies, FROST Ed25519
and CGGMP21 secp256k1 `KeygenSession` instances automatically broadcast a
`KeygenConfirmation` message binding the session ID, sender, threshold, party
set, public key, keygen transcript hash, and commitments hash. A `KeyShare` is
not exposed by `KeygenSession.KeyShare()` until the full confirmation set is
received and verified.

Applications must keep delivering keygen envelopes until the protocol-specific
completion accessor returns a share:

```go
out, err := kg.HandleKeygenMessage(env)
share, ok := kg.KeyShare() // FROST; CGGMP21 also exposes Complete()
```

CGGMP21/secp256k1 key shares are not valid for signing until the full
confirmation evidence set is embedded in the share and `Validate()` succeeds.
FROST keygen shares produced by `KeygenSession` also embed and verify keygen
confirmations; FROST reshare/refresh shares continue to rely on their own
reshare transcript and group-key preservation checks.

Transport responsibilities:

- bind every envelope to an authenticated sender identity, set `Envelope.Security.AuthenticatedParty` and `Authenticated`;
- never let a payload field override the transport-authenticated sender;
- fan out broadcast envelopes to every party;
- protect confidential share envelopes with point-to-point encryption or equivalent controls, set `Envelope.Security.Confidential`;
- supply `BroadcastCertificate` when the protocol policy requires `BroadcastConsistencyRequired` (all broadcast-mode messages in CGGMP21 and FROST policy sets);
- treat `SecurityContext` as transport-verified facts, not self-declared metadata; this library enforces confidentiality and broadcast consistency through `EnvelopeGuard`;
- treat two different confirmations from one sender in one session as equivocation;
- never persist or use keygen material before the completion accessor returns a confirmed `KeyShare`.

## Paillier Ciphertext Membership

All Paillier public operations (`Decrypt`, `AddCiphertexts`, `AddPlaintext`, `MulPlaintext`) validate ciphertext membership in `Z*_{n²}` before acting on inputs. Unchecked variants (`AddCiphertextsUnchecked`, `AddPlaintextUnchecked`, `MulPlaintextUnchecked`) skip the expensive gcd check but still enforce basic range and nil guards. Callers must ensure ciphertexts passed to unchecked helpers have been validated through upstream proof checks.

Caller responsibilities (not provided by this library):

- network transport with peer authentication and encryption;
- storage encryption for key shares and presign records (the built-in `EncryptKeyShareWithPassphrase`/`EncryptPresignWithPassphrase` helpers are Argon2id-based reference/demo implementations — production deployments should integrate a KMS or HSM);
- proactive refresh scheduling (`RefreshScheduler` provides periodic key rotation with configurable interval and transport interface);
- SLIP10 path derivation (BIP32 HD derivation is implemented for secp256k1);
- authenticated keygen message delivery through the confirmation round before any presign/sign operation.

## One-Time Presigns

CGGMP21 presigns include nonce-derived local material. Reusing a presign can break ECDSA security. `StartSign` verifies the presign's key binding fields against the supplied `KeyShare` before constructing any outbound partial, then sets `Presign.Consumed` before constructing the online signing envelope so reuse fails before a second partial signature leaves the process. Presigns are bound to both the key share `(group public key, keygen transcript hash, participant-set hash)` and `PresignContext` fields: key id, chain id, derivation path, policy domain, and message domain.

## Blame Evidence

When a failure can be attributed, `ProtocolError.Blame` may include `Evidence`. Evidence binds protocol, session, round, sender, payload type, payload hash, transcript hash, reason, and selected public input hashes. Use `secp256k1.VerifyBlameEvidence` to validate CGGMP21 evidence against known public context.
