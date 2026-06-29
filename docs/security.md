# Security Notes

**Hard precondition**: The transport layer must authenticate the sender, classify
the actual channel protection, and call `OpenEnvelope(raw, ReceiveInfo, ...)` for
every received envelope. `EnvelopeGuard` enforces confidentiality requirements
per payload type via the protocol `PolicySet`. This library does **not** seal or
open transport ciphertexts — it compares `ReceiveInfo.Protection` with the
policy at the guard boundary. Unencrypted transport of secret-bearing envelopes
will expose keygen shares, nonce material, and MtA responses to any observer on
the message path.

This repository is not a production-audited TSS stack.

## Threat Model

The library assumes each local caller controls one honest party state machine and receives envelopes from an external authenticated transport. State machines reject malformed messages, wrong sessions, wrong rounds, duplicate messages, non-participants, invalid curve/scalar encodings, and failed proof checks.

The library does not protect against a transport that lies about sender identity, drops all messages, strips confidentiality, replays old traffic before the caller checks session ids, or leaks persisted key-share files.

## Caller Responsibilities

Callers must provide:

- authenticated peer identity for every inbound envelope, recorded as `ReceiveInfo.Peer`;
- encryption for secret-bearing envelopes, reported as `ReceiveInfo.Protection = ChannelConfidential`. Confidentiality requirements are defined per payload type by protocol `PolicySet` and enforced by `EnvelopeGuard`;
- **equivocation-resistant broadcast** for all broadcast-mode protocol messages:
  every participant must receive identical payloads, verified by
  `BroadcastCertificate` with `VerifyFull`. The guard detects equivocation via
  `ReplayCache.CheckAndStore` when the same message slot carries different
  payload hashes. After keygen completes, compare `KeygenTranscriptHash`
  across parties as an additional defense-in-depth check;
- replay protection via `ReplayCache` and session-id freshness;
- durable storage encryption for key shares and presigns (`tss.EncryptKeyShareWithPassphrase` and `tss.EncryptPresignWithPassphrase` are Argon2id-based reference/demo implementations — production should use a KMS or HSM);
- an atomic durable `SignAttemptStore` for CGGMP21 presigns. `StartSign`
  refuses to sign unless `SignRuntime.AttemptStore` is provided. The store is
  the only StartSign linearization point and must bind one presign content ID to
  one immutable attempt. The content ID commits to nonce secrets and is
  secret-tainted: implementations must derive an opaque store-local key and
  must not expose the content ID in paths, logs, metrics, or plaintext metadata.
  Conflicts, burn tombstones, and same-intent/different-attempt
  non-determinism are consumed outcomes; ordinary I/O, timeout, or cancellation
  errors during commit have unknown outcome and must be recovered by retrying or
  resuming the same attempt. `LoadSignAttempt` is not a StartSign concurrency
  check;
- durable delivery state for CGGMP21 online signing. The exact committed
  envelope may be replayed at least once until ACKs from all recipients and the
  final broadcast certificate are durable. After delivery completion, resume
  must not return outbound replay. Signature completion is a separate durable
  visibility decision;
- secure deletion or `Destroy` calls for no-longer-needed local shares;
- operational monitoring for protocol errors and blame evidence.

Never log secret scalar, nonce, Paillier private-key, key-share, or presign bytes. Blame evidence is designed to contain public hashes and public context only.
FROST Ed25519 `ChainCode` values are not signing secrets, but HD key
consistency depends on them; back them up and distribute them only with the
same authorization checks used for key-share metadata.

## Production Integration Checklist

`EnvelopeGuard` is the mandatory first fail-closed boundary for every inbound
envelope. Construct a guard via `tss.GuardConfig.BuildGuard` (production) or
`tss.NewTestEnvelopeGuard` (tests only — panics outside `go test`) and pass it
to the protocol `Start*` call that creates the session. Startup returns
`ErrMissingEnvelopeGuard` when no guard is supplied, and handlers keep the same
nil-guard fail-closed check for defense in depth.
Production `GuardConfig.BuildGuard` requires a non-nil `AckVerifier`
(`BroadcastAckVerifier`) for broadcast ack signature verification.

Before passing an inbound envelope to any state machine, the caller must open raw
wire bytes with `OpenEnvelope`. The receive path must authenticate the peer and
set `ReceiveInfo.Peer`; `OpenEnvelope` and the guard both check that this peer
matches `Envelope.From`.

Callers using `tssrun.Dispatcher` can standardize this sequence with
`tssrun.DispatchInbound`, which opens raw bytes through a `tssrun.Receiver`
before routing to the registered protocol session.

The envelope digest is computed from the protocol, semantic
`tss.ProtocolVersion`, session, round, sender, recipient, payload type, and
payload. The protocol version is a constant rather than mutable envelope state;
the TLV frame schema version is validated separately during decoding. Callers
use `Envelope.Digest()` or `InboundEnvelope.Digest()`, both of which return the
distinct `EnvelopeDigest` type.

All repository-defined SHA-256 transcripts use labeled entries through
`internal/transcript`. The domain is the first entry, and every field binds both
its stable name and canonical value encoding. This prevents ambiguity between
adjacent byte strings and makes field omission, substitution, and reordering
change the digest. RFC 9591 SHA-512 functions and direct content hashes remain
defined by their respective standards or call sites.

Session ids must be fresh, unpredictable, and scoped to one protocol run. A
completed or attributable-aborted session rejects later messages without
mutating local state; callers should stop routing messages to such sessions and
surface the original protocol error and blame evidence.

The repository intentionally leaves these integration pieces to callers:
network transport, peer authentication, storage encryption, secure deletion of
persisted records, retries, consensus over session creation, KMS/HSM policy,
and operational alerting.

Use the `tssrun` package to make run acceptance, session registry lookup,
unknown-session policy, and durable cutover boundaries explicit. Its memory
stores are reference implementations only; production deployments need durable,
recoverable stores with their own encryption and access control.

See [docs/deployment.md](deployment.md) for a complete deployment guide covering
key lifecycle, transport integration, persistence encryption, backup, and
monitoring.

## Secret-Material Lifecycle

Secret-bearing records reject default JSON marshaling. Persist `KeyShare` and
CGGMP21 `Presign` values only through their explicit binary encoders, then store
the resulting bytes under caller-managed encryption.

Algorithm-specific `KeyShare` types, CGGMP21 `Presign`, and CGGMP21
`ResharePlan` are opaque handles with no exported state fields. Key shares,
presign records, and CGGMP21 keygen/refresh/reshare DKG share state store local
scalar shares as fixed-length `secret.Scalar` values. CGGMP21 DKG share payloads
also encode shares as fixed 32-byte scalar fields, and secp256k1 Shamir
arithmetic uses fixed-width scalar operations rather than retaining `big.Int`
shares. Byte, slice, map, context, and nested-record getters return caller-owned
copies. Their string and Go-string formatting is redacted.

A shallow Go copy of a key share or presign is another handle to the same
lifecycle state. It does not duplicate secret material and cannot bypass
`Destroy()` or presign consumption. Key-share completion accessors return
independently owned key shares, so mutating or destroying a returned share does
not affect session-retained state. `PresignSession.Presign()` instead transfers
its one completed record to the caller and will not return it again. Callers
must destroy every caller-owned record when it is no longer needed.

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
partials, additive-shift scalars, and any remaining session-owned material.

FROST resharing share envelopes carry confidential scalar shares.
Transports must authenticate the sender and encrypt these point-to-point
messages, reporting `ChannelConfidential` in `ReceiveInfo` so the guard enforces the policy. New HD reshare recipients must be provisioned
with the old 32-byte chain code through an authorized metadata channel; the
chain code is not a signing secret, but losing or substituting it changes child
key derivation.

CGGMP21/secp256k1 resharing also sends confidential old-dealer shares to the
new receiver set. New-only receivers must be provisioned with authenticated old
key metadata, including the old group public key, chain code, keygen transcript
hash, and old party set. Substituting any of that metadata can produce a share
for the wrong key context even when the final public-key preservation check
passes.

CGGMP21 refresh and reshare preserve the existing chain code. Their final
confirmation evidence must repeat the preserved chain code exactly; callers
should treat the chain code as authenticated key metadata, not as an optional
display field.

CGGMP21 reshare plans must be exchanged or persisted through
`ResharePlan.MarshalBinary()` and `UnmarshalResharePlan()`. The strict canonical
decoder applies total-size and field limits, requires verification shares in
old-party order, and performs full semantic validation before exposing a plan.

CGGMP21 reshare does not cryptographically revoke old shares. Once a new
authorization epoch is accepted, deployments must retire the old epoch in policy,
wallet, coordinator, and transport layers; otherwise a threshold of old shares
can still sign under the same group public key. Old and new shares must not be
mixed in one protocol session.

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

Non-negative secrets (`λ`, `μ`, Paillier factors, randomness, CGGMP key shares,
presign shares, MtA openings, and DKG shares) use fixed-width `secret.Scalar`.
Signed Paillier proof masks use `secret.SignedInt`. Schnorr proof generation and
verification use secp256k1 scalar arithmetic without `math/big`. Owned
`big.Int` temporaries exist only at Paillier validation, encoding, and public
proof-response arithmetic boundaries and are cleared after use.

This does not claim that the full Paillier implementation is constant-time.
Only secret-exponent modular exponentiation is required to use
`internal/paillier/paillierct`; public-modulus, public-challenge, and public-proof
operations may remain variable-time.

## CGGMP21 Status

`cggmp21/secp256k1` implements CGGMP21-style threshold ECDSA with Paillier MtA/ZK proofs. It avoids transmitting or reconstructing private shares and nonce shares during signing, checks that presign participants share the same round-1 broadcast view, supports path-first BIP32 HD derivation through `tss.SigningContext`, and encodes all payloads as canonical binary TLV records.

The Paillier/ZK proof layer has been rewritten to use CGGMP-compatible constructions:

- **Πenc**: Paillier encryption in range with Ring-Pedersen commitments, large integer masks sampled from ±2^(Ell+Epsilon), and strict ciphertext membership and response range checks. Presign Round 1 uses verifier-specific Πenc proofs because the statement binds the verifier's Ring-Pedersen auxiliary parameters.
- **Πaff-g**: Paillier affine operation with group commitment in range. Uses Ring-Pedersen commitments and binds the prover's Paillier key, the verifier's auxiliary parameters, and all statement fields into the Fiat-Shamir challenge.
- **Πlog\***: Group element vs Paillier encryption in range. Uses Ring-Pedersen commitment to hide the integer witness and binds the Paillier ciphertext, curve points, and base point into the challenge.

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

- bind every inbound envelope to an authenticated sender identity via `ReceiveInfo.Peer`;
- never let a payload field override the transport-authenticated sender;
- fan out broadcast envelopes to every party;
- protect confidential share envelopes with point-to-point encryption or equivalent controls, and report `ChannelConfidential`;
- supply `BroadcastCertificate` through `WithBroadcastCertificate` when the protocol policy requires `BroadcastConsistencyRequired` (all broadcast-mode messages in CGGMP21 and FROST policy sets);
- treat `ReceiveInfo` as transport-verified facts, not self-declared metadata; this library enforces confidentiality and broadcast consistency through `EnvelopeGuard`;
- treat two different confirmations from one sender in one session as equivocation;
- never persist or use keygen material before the completion accessor returns a confirmed `KeyShare`.

## Paillier Ciphertext Membership

All Paillier public operations (`Decrypt`, `AddCiphertexts`, `AddPlaintext`, `MulPlaintext`) validate ciphertext membership in `Z*_{n²}` before acting on inputs. Unchecked variants (`AddCiphertextsUnchecked`, `AddPlaintextUnchecked`, `MulPlaintextUnchecked`) skip the expensive gcd check but still enforce basic range and nil guards. Callers must ensure ciphertexts passed to unchecked helpers have been validated through upstream proof checks.

Caller integration responsibilities:

- network transport with peer authentication and encryption;
- storage encryption for key shares and presign records (the built-in `EncryptKeyShareWithPassphrase`/`EncryptPresignWithPassphrase` helpers are Argon2id-based reference/demo implementations — production deployments should integrate a KMS or HSM);
- distributed refresh coordination: every participant must use the same externally coordinated, unique session ID for one run;
- atomic key-share replacement: `RefreshScheduler` drives FROST or CGGMP21 refresh, but `CommitKeyShare` must persist and install the new share only if the loaded previous share is still current;
- hardened/private-key path derivation (online signing supports non-hardened BIP32-style public derivation);
- authenticated keygen message delivery through the confirmation round before any presign/sign operation.

`RefreshScheduler` requires an explicit replay cache and broadcast ACK verifier,
serializes local refresh runs, and exits on the first protocol, transport, or
commit error. It does not provide cross-node transactions, automatic retries,
or session-ID agreement. A commit error wrapping
`ErrRefreshCommitOutcomeUnknown` transfers recovery responsibility for the new
share to the caller because durable replacement may already have succeeded.

## One-Time Presigns

CGGMP21 presigns include nonce-derived local material. Reusing a presign can
break ECDSA security. Serialized presigns persist enough public context to replay
every signprep proof and recompute the round-1 echo and presign transcript.
`UnmarshalBinary` is structural only; importers should explicitly call
`VerifyCryptographicMaterialWithLimits`. `StartSign` and `ResumeSign` enforce
the same full self-verification before durable attempt work. `StartSign` then
constructs and self-verifies a candidate partial and canonical-encodes its
envelope before consuming the presign. It atomically commits the immutable
intent and exact envelope through `SignRuntime.AttemptStore`. Only a committed
envelope may be returned or transmitted. A commit error has an unknown outcome:
the presign remains bound and callers may only retry or `ResumeSign` the same
attempt. `MarshalBinary` persists a consumed snapshot, while the durable attempt
record is the restart and outbox boundary. Presigns remain bound to the key
share, security parameters, and all `tss.SigningContext` fields, including
requested and resolved derivation paths.

## Blame Evidence

When a failure can be attributed, `ProtocolError.Blame` may include `Evidence`.
Evidence binds protocol, session, round, sender, payload type, payload hash,
envelope digest, reason, and selected public input hashes. Use
`secp256k1.VerifyBlameEvidence` to validate CGGMP21 evidence against known public
context.
