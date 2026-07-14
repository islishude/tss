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
- durable storage encryption for key generations and available presigns. The
  built-in passphrase and file helpers are reference implementations;
  production should use a transactional database plus KMS or HSM protection;
- one atomic durable `tssrun.LifecycleStore` for CGGMP21. `StartPresign` and
  `StartSign` refuse to operate without the exact current
  `GenerationBinding`. Figure 8 completion atomically stores one available
  presign and finishes its lease. `CommitSignAttempt` is the only online
  linearization point: it validates the complete generation, claims the public
  presign slot, removes its secret availability, and persists one immutable
  attempt and exact outbox. Conflicts and burns are terminal. Ordinary I/O,
  timeout, or cancellation errors during commit have unknown outcome and must
  be reconciled with the exact `AttemptQuery`; a new intent is forbidden;
- durable delivery state for CGGMP21 online signing. The exact committed
  envelope may be replayed at least once until ACKs from all recipients and the
  final broadcast certificate are durable. After delivery completion, resume
  must not return outbound replay. `ResumeSign` reauthenticates every persisted
  ACK and the final certificate with the resumed guard's ACK verifier; a store
  record that is only structurally valid is rejected. Signature completion is
  a separate durable visibility decision;
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
CGGMP21 policies also require canonical sender signatures on every direct
envelope. Production guards therefore require `EnvelopeVerifier`, and CGGMP21
keygen, refresh, reshare, and presign starts require `LocalConfig.EnvelopeSigner`.
The signature binds protocol, semantic version, session, round, sender,
recipient, payload type, and payload hash. Two different valid signatures for
the same message slot are portable equivocation evidence; an invalid signature
is a transport-authentication failure and is never converted into blame.

Before passing an inbound envelope to any state machine, the caller must open raw
wire bytes with `OpenEnvelope`. The receive path must authenticate the peer and
set `ReceiveInfo.Peer`; `OpenEnvelope` and the guard both check that this peer
matches `Envelope.From`.

Callers using `tssrun.Dispatcher` still open raw transport bytes with
`tss.OpenEnvelope` first, then pass the resulting `tss.InboundEnvelope` to
`Dispatcher.Dispatch` for registry lookup and `ProtocolSession.Handle` routing.

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

### Trusted import and explicit export

Trusted-dealer import and secret reconstruction deliberately cross the normal
threshold boundary. Applications must authorize them as separate key
ceremonies; possession of the Go API is not an authorization policy.

`TrustedDealerContribution` records contain a secret scalar contribution and
must be encrypted in transit and at rest, never logged, and destroyed after a
successful party start. They are bound to one session, party, and plan. The
application run store must still reject duplicate starts across restored copies
or processes. The public plan commits to every contribution's public point and
chain-code commitment, so a substituted local contribution or round-1 constant
term fails closed.

`SecretKey.MarshalBinary` is an explicit exfiltration boundary. It returns a
caller-owned fixed 32-byte secret that the caller must clear. Reconstruction
does not destroy or revoke the original shares. Once the scalar is exported,
threshold confidentiality no longer applies until every exported copy is
destroyed. FROST exports the canonical group scalar, not the original Ed25519
seed.

Centralized `GenerateTrustedDealerKeyShares` places every generated share in
one process. For CGGMP21 this includes every Paillier private key. Use the
interactive contribution flow when the dealer should not retain or generate
participant auxiliary private material.

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

A shallow Go copy of an opaque secret handle refers to the same lifecycle state;
it does not duplicate secret material or bypass `Destroy()`. Key-share
completion accessors return independently owned key shares. CGGMP21 Figure 8
completion is different: `PresignSession.Presign()` returns a repeatable,
public-only `PersistedPresign` descriptor only after the normalized secret tuple
has been committed to `LifecycleStore`. The store owns and clears that tuple.

Call `Destroy` on key shares, presigns, keygen sessions, presign sessions, and
signing sessions once they are no longer needed. These methods clear local
secret byte slices and scalar state such as Shamir shares, nonces, online
partials, Paillier private factors, and CGGMP21 presign shares while leaving
public metadata, such as party ids, public keys, signer sets, transcript hashes,
and public signatures, available for diagnostics where practical.

FROST Ed25519 signing nonces are derived from 32 bytes of fresh randomness,
the local secret-share scalar encoding, and a labeled hash that binds the
session, message, signing context, sign plan, and hiding/binding nonce role.
A `SignSession` stores nonce bytes only
until its round-2 partial payload is constructed; successful partial generation
and attributable signing failures clear those bytes immediately. `Destroy`
should still be called after completion or abort to clear message copies,
partials, additive-shift scalars, public nonce commitments, and any remaining
session-owned material.
Round-1 nonce commitment points must use canonical, non-identity prime-order
encodings. Failure to decode an authenticated signer's commitment is an
attributable terminal error, not a recoverable malformed-message rejection.
Failure to decode an authenticated signer's round-2 partial payload, including
a non-canonical scalar, is likewise an attributable terminal error under RFC
9591 Sections 5.3 and 7.4. The abort clears any remaining nonces, partials,
message copy, and derivation state.

FROST `KeyShare.Derive` validates the complete lifecycle confirmation and
secret/public consistency before using derivation metadata. Destroyed shares and
shares whose public metadata no longer matches their lifecycle state cannot
derive child keys; public-only derivation requires a separately validated
metadata snapshot.

FROST verification shares are canonical, non-identity prime-order elements.
An identity verification share publicly fixes the corresponding Shamir share
to zero and can reduce the effective secrecy threshold. Standalone shares,
persisted `KeyShare` records, and aggregate DKG/refresh/reshare evaluation all
reject it. An aggregate identity at one participant index terminally aborts the
lifecycle without blaming one dealer and clears staged secret material.

CGGMP21 signing accepts only an already established generation with an empty
signing path. A non-hardened BIP32 result becomes signable only through
`ChildDerivationPlan` and `StartChildDerivation`, which load the exact parent,
run a fresh Figure 7/F.1 auxiliary protocol, and atomically create the first
generation of a distinct child lineage. The child receives a new SID, RID,
epoch, dynamic identifiers, Paillier keys, and independent auxiliary setup.

FROST resharing share envelopes carry confidential scalar shares.
Transports must authenticate the sender and encrypt these point-to-point
messages, reporting `ChannelConfidential` in `ReceiveInfo` so the guard enforces the policy. New HD reshare recipients must be provisioned
through an authorized metadata channel with the old public key, 32-byte chain
code, party set, group commitments, lifecycle session ID, transcript hash, and
plan hash. The reshare plan binds all of these source-generation anchors. The
chain code is not a signing secret, but losing or substituting it changes child
key derivation.

CGGMP21/secp256k1 resharing also sends confidential old-dealer shares to the
new receiver set. New-only receivers must be provisioned with authenticated old
key metadata, including the old group public key, chain code, lifecycle session
ID, keygen transcript hash, lifecycle plan hash, commitments, and old party set.
The canonical `ResharePlan` binds those exact source-generation anchors and a
dealer rejects a plan whose anchors do not match its local old share.
Substituting any of that metadata can produce a share for the wrong key context
even when the final public-key preservation check passes.

The CGGMP21 reshare plan additionally carries the complete canonical source
`EpochContext` and its explicit `EpochID`. Dealer interpolation uses the
source epoch's dynamic Shamir identifiers, never transport `PartyID` values.
The target handoff uses separate plan-bound provisional identifiers; those
identifiers and all temporary Paillier keys, encrypted contributions, and
proofs are destroyed after the handoff and are not sign-ready auxiliary
material. Every target must complete a fresh Figure 7/F.1 run before a new
`KeyShare` exists. The resulting epoch preserves the stable source SID, records
the exact source EpochID, uses the reshare SessionID as its proof run, and
derives fresh final identifiers from the new RID.

CGGMP21 refresh binds the source generation's lifecycle session, keygen
transcript hash, lifecycle plan hash, and group commitments hash into its plan.
Equal group public keys and chain codes are not sufficient to admit shares into
one refresh run. CGGMP21 refresh and reshare preserve the existing chain code.
Their final confirmation evidence must repeat the preserved chain code exactly;
callers should treat the chain code as authenticated key metadata, not as an
optional display field.

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

Lifecycle-backed CGGMP21 sessions own the exact key and presign material they
load from `LifecycleStore` and destroy it on terminal success or failure.
Caller-owned key shares used to construct public plans remain separately owned
and must still be destroyed by the caller.

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

`cggmp21/secp256k1` follows Figures 6-10 of the bundled 2024 paper, with the
Appendix F.1 threshold adaptation and repository lifecycle bindings:

- Figure 6 commits and proves additive key contributions, then immediately
  hands the public key into Figure 7/F.1.
- Figure 7/F.1 creates the sign-ready authorization epoch. Each party generates
  independent Paillier `N` and Ring-Pedersen `Nhat`, commits before reveal,
  derives a common RID and dynamic Shamir identifiers, proves `Πprm`, `Πmod`,
  and receiver-specific `Πfac`, and sends DH-masked polynomial evaluations.
- Figure 8 uses verifier-specific `Πenc-elg`, then `Πelog` and pairwise
  `Πaff-g`, then a final `Πelog`. It verifies both aggregate equations and
  stores only normalized `(Gamma,kTilde_i,chiTilde_i,DeltaTilde,STilde)`.
- Figure 9 is entered only after an aggregate nonce or chi equation fails. It
  verifies the paper's setup-less `Πaff-g*` and `Πdec` records. An invalid proof
  attributes its authenticated sender; an all-valid unresolved alert is an
  unblamed invariant failure.
- Figure 10 checks every partial directly against the normalized commitments.
  There is no additional accountability exchange during signing.

The production profile is `(Ell,EllPrime,Epsilon,ChallengeBits) =
(256,1280,512,256)` with independent Paillier and auxiliary moduli of at least
3072 bits. This is the paper's 128-bit secp256k1 profile. Reduced profiles are
test-only explicit inputs and remain bound into plans and proofs.

`EpochContext` binds the stable SID, XOR-derived RID, non-zero collision-free
dynamic identifiers, public shares, auxiliary material, source epoch, and
`EpochID`. `KeyGeneration` is only a local durable token and never replaces the
cryptographic epoch binding.

All secret-exponent Paillier operations must use
`internal/paillier/paillierct`. Affine masks are wide fixed-length signed
integers. Decryption interprets them through the centered representative before
curve-order reduction.

The Paillier/ZK layer has not received independent cryptographic review. The
paper-to-code map is in [`cggmp21-paper-mapping.md`](cggmp21-paper-mapping.md),
and active proof relations and limitations are in
[`paillier-zk-proofs.md`](paillier-zk-proofs.md).

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
out, err := kg.Handle(env)
share, ok := kg.KeyShare() // FROST; CGGMP21 also exposes Complete()
```

CGGMP21/secp256k1 key shares are not valid for signing until the full
confirmation evidence set is embedded in the share and `Validate()` succeeds.
FROST keygen shares produced by `KeygenSession` embed and verify keygen
confirmations. FROST reshare/refresh also has a mandatory target-holder
confirmation round; its resulting shares are unavailable until the complete
set agrees on the reshare transcript, new commitments, preserved group public
key, and preserved chain code. Removed old dealers compute that same binding
from public commitments and do not enter their terminal state until they have
verified the full target confirmation set.

Transport responsibilities:

- bind every inbound envelope to an authenticated sender identity via `ReceiveInfo.Peer`;
- never let a payload field override the transport-authenticated sender;
- fan out broadcast envelopes to every party;
- fan out FROST reshare confirmations across the old/new party union while
  constructing their broadcast certificate against the target `newParties` set;
- protect confidential share envelopes with point-to-point encryption or equivalent controls, and report `ChannelConfidential`;
- supply `BroadcastCertificate` through `WithBroadcastCertificate` when the protocol policy requires `BroadcastConsistencyRequired` (all broadcast-mode messages in CGGMP21 and FROST policy sets);
- treat `ReceiveInfo` as transport-verified facts, not self-declared metadata; this library enforces confidentiality and broadcast consistency through `EnvelopeGuard`;
- treat two different confirmations from one sender in one session as equivocation;
- never persist or use keygen material before the completion accessor returns a confirmed `KeyShare`.

## Paillier Ciphertext Membership

All Paillier public operations (`Decrypt`, `AddCiphertexts`, `AddPlaintext`, `MulPlaintext`) validate ciphertext membership in `Z*_{n²}` before acting on inputs. Unchecked variants (`AddCiphertextsUnchecked`, `AddPlaintextUnchecked`, `MulPlaintextUnchecked`) skip the expensive gcd check but still enforce basic range and nil guards. Callers must ensure ciphertexts passed to unchecked helpers have been validated through upstream proof checks.

Caller integration responsibilities:

- network transport with peer authentication and encryption;
- transactional storage encryption for key generations, available presigns,
  attempts, delivery, and completion; reference helpers do not replace a KMS
  or HSM;
- distributed refresh coordination: every participant must use the same externally coordinated, unique session ID for one run;
- atomic CGGMP21 cutover through `LifecycleStore`, including fencing new work,
  installing the target epoch, retiring the source blob, and burning its
  available presigns;
- explicit child-lineage creation for non-hardened BIP32 keys; hardened
  derivation is unsupported;
- authenticated keygen message delivery through the confirmation round before any presign/sign operation.

`RefreshScheduler` coordinates local protocol execution but does not provide
cross-node transactions, automatic retries, or session-ID agreement. CGGMP21
deployments must still use the lifecycle lease and cutover transaction as the
authoritative replacement boundary.

## One-Time Presigns

CGGMP21 presigns include nonce-derived local material. Reusing a presign can
break ECDSA security.

`StartPresign` loads the exact current generation, acquires a `RunPresign`
lease, and releases Figure 8 envelopes only after both checks succeed. Figure 8
completion calls `CommitAvailablePresignFromLease` before reporting success.
The transaction persists the normalized secret tuple, public recovery metadata,
and lease completion atomically. The public session accessor returns only a
`PersistedPresign` descriptor.

The private presign record contains `Gamma`, local `kTilde_i` and `chiTilde_i`,
and signer-ordered `DeltaTilde_j` and `STilde_j`, together with exact epoch,
plan, signer, context, and transcript bindings. Its binary encoding does not
change lifecycle availability. Canonical decode is structural; use
`VerifyCryptographicMaterialWithLimits` before importing a candidate outside
the authoritative start path.

`StartSign` loads the key generation and available candidate from
`LifecycleStore`, canonically re-encodes them, performs full material checks,
constructs and self-verifies the Figure 10 partial, and encodes the exact
outbound envelope before mutation. `CommitSignAttempt` then atomically validates
the generation, claims the presign, removes the secret candidate, and persists
the immutable intent, public verification context, and exact outbox. Only a
successful exact-attempt commit may release the envelope.

After a successful, conflicting, burned, or outcome-unknown commit, no other
intent may use that presign. An unknown outcome is reconciled only with the
exact `AttemptQuery`; `ResumeSign` may replay the committed outbox until the
authenticated delivery certificate is durable. Completion is a separate
durable update. Recovery never reloads the normalized secret tuple.

Presign and sign bind an already established lifecycle epoch and require an
empty signing path. Use a distinct child generation before presigning for a
non-hardened BIP32 child.

## Blame Evidence

When a failure can be attributed, `ProtocolError.Blame` may include `Evidence`.
Evidence binds protocol, session, round, sender, payload type, payload hash,
envelope digest, reason, and selected public input hashes. Use
`secp256k1.VerifyBlameEvidence` to validate CGGMP21 evidence against known public
context. Broadcast certificates embedded in presign/sign evidence are verified
against the exact signer set, while lifecycle evidence remains scoped to its
full participant set.
