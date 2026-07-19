# Security Notes

This repository is not a production-audited TSS stack. In particular, the
CGGMP21 Paillier/ZK layer still requires independent cryptographic review.
Implemented checks, cleanup calls, and test coverage are not claims of
production readiness, complete side-channel resistance, crash safety, or
secure deletion.

The hard integration precondition is an authenticated receive path. The
transport must derive the peer identity and channel protection from trusted
transport state, call `tss.OpenEnvelope`, and deliver only the resulting
`tss.InboundEnvelope` to a session constructed with an `EnvelopeGuard`. The
library does not encrypt transport traffic or authenticate a socket by itself.

## Threat Model

Each local process is assumed to protect one party's state and to execute the
library code honestly. Other protocol parties may send malformed, conflicting,
replayed, out-of-order, or cryptographically invalid messages. With the required
guard and an honest local runtime, handlers validate protocol/session identity,
sender and recipient, delivery policy, canonical encoding, plan bindings,
proofs, commitments, and signature shares before committing a transition.

The library does not protect against:

- a compromised local process, RNG, dependency, identity key, or persistence
  key;
- a receive adapter that lies about `ReceiveInfo.Peer` or
  `ReceiveInfo.Protection`;
- loss of availability caused by dropped, delayed, or selectively delivered
  traffic;
- plaintext persistence, logs, crash dumps, caller-made secret copies, or
  unauthorized backups;
- reuse of a session ID after replay state has been retired;
- continued authorization of a superseded generation or source committee after
  refresh or reshare; or
- side channels outside the narrow constant-time boundaries documented below.

## Mandatory Inbound Boundary

The intended receive path is:

```text
authenticated transport facts + raw bytes
  -> tss.OpenEnvelope
  -> tssrun.Dispatcher.Dispatch
  -> protocol session Handle
```

`OpenEnvelope` performs canonical envelope decoding, requires a non-zero peer
and known channel-protection classification, and checks that
`ReceiveInfo.Peer == Envelope.From`. It does not independently establish those
transport facts.

Before protocol decoding, `EnvelopeGuard` enforces the expected protocol and
session, sender membership, self-sender rejection, recipient, registered
delivery policy, required sender signature, direct/broadcast mode,
confidentiality, broadcast certificate, and replay slot. Unknown payload
policies fail closed.

Production code constructs guards with `tss.GuardConfig.BuildGuard`. It requires
a non-nil `BroadcastAckVerifier`; when any configured policy requires portable
sender signatures it also requires an `EnvelopeSignatureVerifier`.
`tss.NewTestEnvelopeGuard` uses no-op verifiers and panics outside `go test`; it
is not a production fallback.

### Confidentiality

`ReceiveInfo.Protection` reports what the transport actually provided.
`PolicySet` says what the payload requires. The guard compares the two; it does
not seal or open ciphertexts.

Both protocol policy sets require confidential direct delivery for
secret-bearing shares and witnesses, including FROST keygen/reshare shares and
CGGMP21 auxiliary, presign, and reshare material. A transport that sends those
payloads in plaintext exposes them before the library can repair the breach;
the guard can only reject the delivery based on truthful transport metadata.

### Broadcast consistency

Every broadcast-mode policy in the FROST and CGGMP21 policy sets requires a
`BroadcastCertificate`. The certificate must bind the exact envelope and carry
one acknowledgment from every party in the phase-specific recipient set.
Production validation uses `BroadcastCertificate.VerifyFull`, including the
configured acknowledgment-signature verifier.

The transport must fan out one identical broadcast view, collect and persist
the acknowledgments, and attach the certificate through
`tss.WithBroadcastCertificate` when opening the inbound envelope. FROST reshare
confirmations are routed across the old/new union, but their certificate is
verified against the target `newParties` set.

`ReplayCache.CheckAndStore` reserves a slot identified by protocol, session,
round, sender, recipient, and payload type. The same payload hash returns
`ErrDuplicateMessage`; a different payload hash in that slot returns
`ErrEquivocation`. A bounded cache fails closed when full. Do not retire replay
state until durable run admission prevents that protocol/session pair from
ever being reused.

### Portable CGGMP21 sender signatures

CGGMP21 policies require canonical sender signatures on direct auxiliary,
proof, and share messages, and on the signed decryption-error broadcasts.
With the standard CGGMP21 policy set, protocol start paths therefore require
`LocalConfig.EnvelopeSigner`, while the guard requires the matching verifier.
FROST currently relies on authenticated transport and signed broadcast
acknowledgments; its payload policies do not require `SenderSignature`.

`EnvelopeSigningDigest` binds protocol, semantic protocol version, session,
round, sender, recipient, payload type, and payload while excluding the
signature field itself. `Envelope.Digest()` is a distinct digest used for
envelope equality and broadcast acknowledgments; it includes
`SenderSignature` when present. Do not substitute one digest for the other.

An invalid sender signature is a transport-authentication failure and is not
converted into protocol blame. Two different valid signed payloads for the
same slot can be retained as portable equivocation evidence.

## Caller Responsibilities

The application must provide all of the following:

- **Run admission:** authorize one canonical public run intent, distribute a
  fresh unpredictable session ID, and have every party accept the same plan and
  run-intent digest before releasing effects.
- **Authenticated transport:** derive peer identity, key identity, channel
  identity, and channel protection from the transport rather than payload
  fields.
- **Replay and broadcast durability:** use a replay cache and persist the
  acknowledgment/certificate state needed by the selected delivery policy.
- **Safe registration:** register the session before making its initial
  outbound envelopes visible. Remove terminal sessions only after delayed
  traffic will be handled by the intended unknown-session policy.
- **Unknown-session handling:** reject by default. If envelopes are durably
  buffered, reopen or otherwise preserve their authenticated receive facts and
  run the complete guard and protocol validation after the session is
  registered; buffering is not acceptance.
- **Encrypted persistence:** protect key generations, available presigns,
  trusted-dealer contributions, attempts, delivery records, and backups with
  authenticated encryption and an appropriate KMS/HSM policy.
- **Transactional lifecycle:** implement the atomic operations required by
  `tssrun.LifecycleStore` for CGGMP21, and compare-and-swap generation cutover
  for FROST refresh/reshare.
- **Authorization and revocation:** separately authorize trusted import,
  reconstruction, child generation, refresh, reshare, signing, and old-committee
  retirement.
- **Operations:** keep secrets out of logs, metrics, traces, paths, panic
  output, profiles, fixtures, and crash reports; monitor protocol errors, store
  failures, unknown outcomes, and blame evidence.
- **Cleanup:** call `Destroy` on no-longer-needed secret-bearing values and
  sessions, clear caller-owned encodings, and arrange retention/key-destruction
  controls for persisted copies, subject to the Go memory-erasure limitations
  below.

The in-memory stores, passphrase helpers, and `FileLifecycleStore` are reference
implementations, not substitutes for a production transactional database and
key-management design. See [`deployment.md`](deployment.md) for the complete
deployment and recovery contract and [`tssrun.md`](tssrun.md) for the public run
and store interfaces.

## Secret-Material Lifecycle

### Opaque values and ownership

Algorithm-specific `KeyShare` types, CGGMP21 `Presign`, and long-lived plan
types with validated internal state are opaque handles. Secret-bearing key
shares, presigns, contributions, and reconstructed keys reject default JSON
marshaling; use their explicit canonical binary encoders and encrypt the
resulting bytes before persistence.

A shallow Go copy of an opaque handle that contains shared lifecycle state is
not an independent secret copy and does not bypass `Destroy`. An explicit
`Clone` or a session completion accessor may return independently owned secret
material; the API documentation identifies those cases, and every returned
owner must be destroyed separately. Exported snapshot and byte accessors return
caller-owned copies, which the package cannot later clear.

Call `Destroy` on all no-longer-needed secret-bearing objects, including key
shares, `SecretKey` and trusted-dealer contributions, CGGMP21 private presign
values, and keygen, presign, sign, refresh, reshare, or child-derivation
sessions as applicable. Terminal protocol paths also clear the package-owned
secret state they no longer need. Public metadata and final public results may
remain available where the type's documented lifecycle permits it.

Do not infer that an object is safe to reuse merely because a start or commit
returned an error. One-use contribution and presign APIs distinguish definite
non-commit, terminal consumption/burn, and unknown durable outcome.

### Trusted import and explicit reconstruction

Trusted-dealer import and secret reconstruction deliberately cross the normal
threshold-confidentiality boundary. Possession of the Go API is not an
authorization policy; applications must isolate and approve these operations
as separate key ceremonies.

`TrustedDealerContribution` records contain a secret scalar contribution and,
for FROST, a chain-code contribution. Each belongs to one party, session, and
plan and must be encrypted in transit and at rest, never logged, and destroyed
after use. The in-process one-use guard does not replace durable duplicate-start
protection across processes or restored copies.

`SecretKey.MarshalBinary` is an explicit exfiltration boundary. It returns a
caller-owned fixed-width secret encoding. Reconstruction validates an exact
lifecycle generation and does not consume, revoke, or weaken the source shares.
Once the scalar is exported, threshold confidentiality no longer protects any
copy of it.

Centralized `GenerateTrustedDealerKeyShares` puts every generated participant
share in one process. For CGGMP21, that includes participant Paillier private
material. Use the interactive contribution path when that centralized trust
boundary is unacceptable.

FROST import, reconstruction, and scalar/seed distinctions are specified in
[`frost-ed25519.md`](frost-ed25519.md#trusted-dealer-import-and-reconstruction).
The corresponding CGGMP21 boundary is described in
[`cggmp21-secp256k1.md`](cggmp21-secp256k1.md#public-entry-points).

## Go Memory Erasure Boundary

Go zeroization is best-effort. `Destroy` methods and terminal cleanup overwrite
the package's currently referenced mutable byte slices, fixed-width secret
wrappers, curve scalars, and selected `big.Int` words, then release references
where practical. They cannot prove that historical copies are absent from the
heap, stack, registers, immutable strings, prior encodings, compiler-generated
temporaries, garbage-collector state, caller-owned copies, or crash artifacts.

Explicit `Destroy` calls are still required because they trigger the cleanup the
package can perform; they do not guarantee secure erasure. A successful abort or
destroy test proves only that the inspected current references were cleared.

Where process-memory exposure matters:

- disable or tightly restrict core dumps, crash uploads, heap profiles, and
  memory profiles;
- isolate signer processes and keep their lifetime and privilege set narrow;
- avoid converting secrets to strings or variable-length encodings;
- encrypt persistence and authenticate public metadata alongside secret blobs;
  and
- use an HSM, isolated signer, or other architecture with a stronger erasure
  boundary when the Go process model is insufficient.

## FROST-Specific Boundaries

The complete protocol is specified in
[`frost-ed25519.md`](frost-ed25519.md). The security-critical integration points
are:

- dealerless and trusted-import keygen require a constant-term Schnorr proof
  from every dealer before any round-2 share envelope is released;
- keygen and reshare share envelopes are confidential direct messages;
- malformed authenticated commitments, proofs, shares, nonce commitments, and
  partials follow the phase-specific terminal/blame rules, while guard rejection
  and plan-hash mismatch remain separate nonterminal cases;
- confidential-share blame is synthetic and contains neither the share, its
  original payload, nor a hash of either;
- verification shares must be canonical, non-identity prime-order points;
- production signing nonces bind fresh randomness and the local share to the
  session, message, signing context, plan, and nonce role;
- `KeyShare.Derive` validates the complete share before using its HD metadata,
  while public-only derivation requires caller-authenticated metadata; and
- refresh/reshare preserve the public key and chain code but do not revoke the
  old committee. New-only receivers must receive the exact authenticated source
  lifecycle metadata, and the application owns durable cutover and retirement.

The chain code is not itself a signing secret, but it is integrity-sensitive:
loss or substitution changes HD child derivation. Back it up and distribute it
with the same authorization checks used for the rest of key metadata.

## CGGMP21 Lifecycle and One-Time Presigns

CGGMP21 signing is tied to an exact `tssrun.GenerationBinding`, not merely a key
ID or equal public key. Presign and online-sign plans require an empty derivation
path. A non-hardened child becomes signable only after
`StartChildDerivation` creates a distinct durable child lineage with fresh
auxiliary material and epoch binding.

One atomic durable `tssrun.LifecycleStore` is the authority for CGGMP21 key
generations, leases, available presigns, signing attempts, delivery, completion,
and cutover:

1. `StartPresign` loads the exact current generation and acquires a durable
   `RunPresign` lease before releasing Figure 8 effects.
2. Figure 8 completion calls `CommitAvailablePresignFromLease`, atomically
   storing the normalized secret candidate and finishing the lease. The public
   accessor returns only a `PersistedPresign` descriptor.
3. `StartSign` loads and fully validates the exact generation and available
   candidate, constructs and self-verifies the Figure 10 partial, and encodes
   the exact outbox before mutation.
4. `CommitSignAttempt` atomically revalidates the generation, claims the
   presign slot, removes secret availability, and persists one immutable intent
   and exact outbox. Only a successful exact-attempt commit may release that
   envelope.
5. Delivery and signature visibility are separate durable transitions.
   `MarkAttemptDelivered` persists authenticated acknowledgments and the final
   broadcast certificate; `CompleteAttempt` persists completion.

A presign must never become available to another intent after a successful,
conflicting, burned, or outcome-unknown commit attempt. Treat a timeout,
cancellation, I/O error, or `AttemptOutcomeUnknownError` according to the store
contract as an unknown outcome, not permission to retry with a new intent.
Reconcile only with the exact `AttemptQuery` through
`QueryAttemptOutcome`/`ResumeSign`. `ResumeSign` validates durable attempt,
delivery, acknowledgment, and certificate bindings and replays only the exact
committed outbox while delivery remains incomplete; it never reloads the
consumed normalized secret tuple.

CGGMP21 reshare does not cryptographically revoke the old shares. After
accepting the new authorization epoch, retire the old epoch in policy,
coordinator, wallet, storage, and transport layers and prevent old/new shares
from entering one protocol session. Detailed Figure 6-10 and cutover behavior
belongs to [`cggmp21-secp256k1.md`](cggmp21-secp256k1.md) and
[`deployment.md`](deployment.md).

## Paillier and Secret-Exponent Boundary

Any modular exponentiation whose exponent is secret must use the fixed-width
path in `internal/paillier/paillierct`; `math/big.Int.Exp` is forbidden for such
inputs. This includes Paillier private exponents, secret plaintext exponents,
MtA responder scalars, secret proof nonces/masks, and private-key-derived
recovery exponents.

The fixed-width path uses `filippo.io/bigmod.Nat.Exp` with fixed-length
big-endian modulus, base, and exponent encodings. Paillier decryption additionally
blinds the ciphertext as `c' = c*r^n mod n^2` before exponentiation. This is a
narrow implementation boundary, not a claim that all Paillier, proof, curve,
or surrounding Go operations are constant-time.

`math/big.Int.Exp` may be used only when the exponent is public, such as the
public Paillier modulus in `r^n mod n^2`, fixed public powers, or public proof
verification responses. The fact that an operation happens during key
generation or proof generation is not an exemption.

Checked Paillier operations validate ciphertext membership in `Z*_(n^2)` before
decryption or homomorphic arithmetic. The `*Unchecked` arithmetic helpers omit
the GCD membership test but retain nil and range checks; callers may use them
only after an upstream proof or explicit validation established membership.

The production CGGMP21 profile requires Paillier and Ring-Pedersen moduli of at
least 3072 bits and
`(Ell, EllPrime, Epsilon, ChallengeBits) = (256, 1280, 512, 256)`. Reduced
profiles are explicit test controls and are bound into plans and proofs. Local
setup generates the two moduli separately and validation rejects equality, but
it does not explicitly check their GCD or prove independent factor generation
to peers. The Paillier/ZK layer has not received independent cryptographic
review; see
[`cggmp21-paper-mapping.md`](cggmp21-paper-mapping.md) and
[`paillier-zk-proofs.md`](paillier-zk-proofs.md).

## Blame Evidence

`BlameEvidence` is intentionally public-only. It may contain protocol and
session identifiers, message-slot metadata, public hashes, public proof data,
and a public envelope digest. It must never contain a private share, nonce,
Paillier factor, MtA secret, presign secret tuple, trusted contribution,
reconstructed secret, or a hash of a confidential share payload.

Evidence is meaningful only with the authenticated public context for the run.
Use `secp256k1.VerifyBlameEvidence` for CGGMP21 evidence. FROST public-message
evidence may bind the actual public envelope; FROST confidential-share evidence
uses the synthetic form described above.

An invalid transport signature is not cryptographic blame. CGGMP21 Figure 7
decryption failure may disclose its dedicated ephemeral DH witness only in the
authenticated protocol accusation payload; that witness must not be copied
into generic blame, logs, errors, snapshots, or metrics.

Operational handling should preserve evidence bytes and the public run context,
surface unattributed invariant failures distinctly, and avoid treating the mere
presence of `ProtocolError.Blame` as independent proof without validation.
