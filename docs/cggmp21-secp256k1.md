# CGGMP21 secp256k1

`cggmp21/secp256k1` implements threshold ECDSA over secp256k1 using the
protocol schedule in the bundled 2024 revision of
[`cggmp21.pdf`](cggmp21.pdf). Figure numbers in this document refer only to
that bundled paper. The repository adds authenticated envelopes, canonical TLV
records, labeled transcripts, resource limits, and a durable lifecycle around
the paper protocol.

This implementation is not independently audited or production ready. In
particular, the Paillier and zero-knowledge layer still requires an independent
cryptographic review.

The paper writes group operations multiplicatively. The Go curve package uses
additive notation. Thus paper expressions such as `g^x`, `A^x`, and products of
points appear in code as `[x]G`, `[x]A`, and point addition.

The implementation contract and source locations are summarized in
[`cggmp21-paper-mapping.md`](cggmp21-paper-mapping.md).

## Protocol Surface

The sign-ready lifecycle is:

```text
Figure 6 key generation
  -> Figure 7 / Appendix F.1 auxiliary-information run
  -> confirmed key generation and authorization epoch
  -> Figure 8 available presign
  -> Figure 10 one-round signing
```

The package also supports:

- trusted-dealer import followed by the same auxiliary-information boundary;
- explicit threshold reconstruction as a separately authorized exfiltration
  ceremony;
- same-party proactive refresh through Figure 7/F.1;
- party-set or threshold resharing with a temporary handoff followed by a
  complete Figure 7/F.1 run for the target committee; and
- non-hardened BIP32 child creation as a distinct key lineage with a fresh
  auxiliary epoch.

## Authorization Epoch

Every sign-ready `KeyShare` contains one canonical `EpochContext`:

```text
SID               stable key-lineage identity
RID               XOR of the committed per-party RID contributions
EpochID           digest of SID, RID, committee, threshold, public shares,
                  Paillier keys, auxiliary moduli, and Pedersen bases
Identifier[j]     H(SID, RID, party[j]) reduced to a non-zero field element
PublicShare[j]    public Shamir share at Identifier[j]
AuxiliaryDigest   digest of the complete public auxiliary setup
SourceEpochID     parent epoch for refresh, reshare, or child lineage
```

`KeyGeneration` is a local durable compare-and-swap identifier. It is not a
cryptographic substitute for `EpochID`. Plans, payloads, proof domains, and
durable records bind the exact generation and epoch required by their phase.

Dynamic Shamir identifiers are derived only after every committed RID opening
has been accepted. Zero or colliding identifiers abort the run. Protocol code
never substitutes transport `PartyID` values for these field elements.

## State-Machine Transaction Boundary

Every inbound handler follows:

```text
decode -> policy validate -> cryptographic verify
       -> prepare transition and outbound envelopes
       -> commit replay, state, and secret ownership
       -> release effects
```

Malformed, replayed, conflicting, out-of-order, cross-session, wrong-plan, and
wrong-epoch input is rejected without advancing accepted state or releasing an
envelope. Prepared secret state is registered for cleanup until commit transfers
ownership to the session or durable store.

All protocol starts require an `EnvelopeGuard`. CGGMP21 direct messages also
require canonical sender signatures. Broadcast-mode messages require the
configured full broadcast certificate. Secret-bearing direct messages require
authenticated confidential transport.

## Figure 6: ECDSA Key Generation

Figure 6 creates the ECDSA public key but does not by itself create a sign-ready
repository `KeyShare`.

### Round 1: commitment

Party `i` samples its additive key contribution `x_i`, sets `X_i=[x_i]G`,
prepares the first Schnorr message `A_i`, and broadcasts only:

```text
V_i = H(SID, i, rho_i, X_i, A_i, u_i)
```

### Round 2: opening

After all commitments arrive, each party broadcasts `(rho_i,X_i,A_i,u_i)`.
Every receiver verifies the exact round-1 commitment before accepting the
opening.

### Round 3: proof

After all openings verify, parties derive the common coin
`rho = XOR(rho_i)`. Each party finalizes the Schnorr proof for `X_i` using the
same committed first message `A_i` and the common coin. The group public key is
the sum of all `X_i` in additive notation.

The implementation then immediately enters Figure 7/F.1. No `KeyShare` is
exposed between these phases.

## Figure 7 and Appendix F.1: Auxiliary Information

Figure 7 creates fresh Paillier and Ring-Pedersen material while Appendix F.1
adapts share refresh to a threshold Shamir committee. The repository threshold
`t` means exactly `t` shares reconstruct, so refresh polynomials have degree
`t-1` and contain `t` coefficients.

### Independent moduli

Each party generates two independent RSA-style moduli:

- `N_i`, the Paillier modulus with retained factors `(p_i,q_i)`; and
- `Nhat_i`, the auxiliary Ring-Pedersen modulus with retained trapdoor
  `lambda_i`.

They must be generated independently and must differ. Equal bit lengths do not
permit reusing one factorization for both roles. Public Ring-Pedersen parameters
are `(Nhat_i,s_i,t_i)` with a `Πprm` proof. Paillier correctness is established
with `Πmod` and receiver-specific `Πfac` proofs.

### Round 1: commit

Party `i` prepares:

- independent Paillier and auxiliary key material;
- a degree-`t-1` zero-sharing or contribution polynomial;
- one ephemeral DH public key for every peer;
- commit-ahead Schnorr first messages for the polynomial coefficients;
- `rid_i` and decommitment randomness.

Only the canonical commitment `V_i` is broadcast.

### Round 2: reveal

Each party opens the commitment with the polynomial commitments, DH keys,
Schnorr first messages, `N_i`, `(Nhat_i,s_i,t_i)`, `Πprm`, `rid_i`, and the
decommitment. Receivers verify:

- the round-1 opening;
- canonical committee and coefficient counts;
- the required zero constant term for refresh, or the declared contribution
  constant for keygen/child creation;
- both modulus floors and `N_i != Nhat_i`; and
- the Ring-Pedersen proof.

After every opening is accepted, the parties compute the common RID, derive
the dynamic identifiers, and compute the target `EpochID`.

### Round 3: proofs and confidential shares

Each party broadcasts the finalized coefficient Schnorr proofs. For every
recipient it sends a confidential direct record containing:

- `Πmod` for its Paillier modulus;
- receiver-specific `Πfac` relative to the recipient's auxiliary setup; and
- the polynomial evaluation masked with a key derived from the authenticated
  pairwise DH point.

The mask transcript binds SID, RID, target epoch, sender, recipient, and plan.
The direct payload contains no Paillier encryption of the refresh share.

The only path allowed to reveal an ephemeral DH exponent is the dedicated,
authenticated Figure 7 decryption-error accusation record. That witness must
not enter logs, ordinary errors, snapshots, metrics, or generic blame fields.

### Output and confirmation

Every target verifies the direct shares against the committed polynomial,
updates its Shamir share, reconstructs all public shares at the dynamic
identifiers, and verifies the expected group public key. Parties then confirm
the same transcript, epoch, commitments, public key, and chain code.

The final transcript contains the Figure 7 proofs, so those Fiat-Shamir proofs
cannot also include that transcript hash without a cycle. Proofs created after
RID derivation bind the final `EpochID`, run session, committee, parties, and
plan. The earlier `Πprm` binds its exact parameters, run, committee, prover, and
plan; its committed opening and those parameters are then covered by the final
transcript and epoch auxiliary digest. After the transcript is fixed, every
target uses its retained local Paillier factors to create a fresh local `Πmod`
under the sign-ready key-share domain. This post-protocol proof additionally
binds the complete epoch, group public key, final transcript, lifecycle kind,
and plan. Keygen, trusted import, refresh, reshare, and child creation all use
this same finalization step.

The new generation remains unavailable until the confirmation set is complete
and the lifecycle transaction commits it. Refresh preserves the public key and
chain code. The source generation remains the only current generation until
cutover succeeds.

## Figure 8: Threshold Presigning

A presign plan binds one exact current generation and epoch, one non-zero public
`PresignID`, a canonical signer set, security parameters, and an empty signing
path. Signing under a non-hardened child requires creating that child as its own
key lineage first.

### Round 1: encrypted nonce material

Signer `i` samples `k_i`, `gamma_i`, Paillier randomness, an ephemeral point
`Y_i`, and scalars `a_i,b_i`. It publishes:

```text
K_i = Enc_i(k_i)
G_i = Enc_i(gamma_i)
A_i = ([a_i]G, [a_i]Y_i + [k_i]G)
B_i = ([b_i]G, [b_i]Y_i + [gamma_i]G)
```

Each recipient receives verifier-specific `Πenc-elg` proofs for both `K_i/A_i`
and `G_i/B_i`. The proof domain binds the exact epoch, presign, plan, prover,
recipient, ciphertext, curve points, ranges, and the recipient's independent
auxiliary setup. A common hash of all accepted public round-1 payloads is echoed
in the following round.

### Round 2: pairwise affine operations

After all round-1 proofs verify, signer `i` publishes or directly sends:

```text
Gamma_i = [gamma_i]G
Πelog for (Gamma_i, B_i, Y_i)
D/F       affine response for gamma_i * k_j
Dhat/Fhat affine response for x_i * k_j
Πaff-g    for each affine response
```

The two Paillier affine paths produce additive shares used later for `delta_i`
and `chi_i`. Each `Πaff-g` binds both Paillier moduli, the verifier's auxiliary
setup, start and response ciphertexts, curve commitment, ranges, prover,
recipient, and epoch. Secret-exponent Paillier operations use
`internal/paillier/paillierct`.

### Round 3: delta and chi commitments

Signer `i` decrypts the accepted responses and computes field elements
`delta_i` and `chi_i`. It publishes:

```text
Gamma   = sum(Gamma_j)
Delta_i = [k_i]Gamma
S_i     = [chi_i]Gamma
delta_i
Πelog for (Delta_i, Gamma, A_i, Y_i)
```

After every proof verifies, each signer independently checks:

```text
[delta]G == sum(Delta_j)
[delta]X == sum(S_j)
where delta = sum(delta_j)
```

If either aggregate equation fails, the state machine enters Figure 9. If
`delta` is zero, or `Gamma` cannot produce a valid ECDSA nonce, the presign is
destroyed as an unattributed failure and the next run must use a new
`PresignID`.

### Normalized output

Success produces exactly the paper's normalized local tuple:

```text
Gamma
kTilde_i     = k_i / delta
chiTilde_i   = chi_i / delta
DeltaTilde_j = [delta^-1]Delta_j
STilde_j     = [delta^-1]S_j
```

The raw nonce shares, local aggregate shares, MtA masks, Paillier openings, and
proof randomness are destroyed when ownership transfers to the normalized
record. The tuple is secret, local to one signer, and usable once.

## Figure 9: Failed Nonce or Chi

Figure 9 is entered only when one of the two Figure 8 aggregate equations
fails. For the selected relation, every signer publishes:

- the canonical alert kind and alert digest;
- the public inbound and outbound MtA response pair for each peer;
- one setup-less `Πaff-g*` proof per peer; and
- the paper's aggregate ciphertext with a `Πdec` proof.

The first invalid proof attributes its authenticated sender. If every submitted
proof is valid while the original aggregate equation still fails, the session
destroys all retained witnesses and returns an unblamed invariant failure.
There is no second accountability phase during Figure 10.

## Figure 10: Online Signing

For the context-bound message digest `m` and
`r = x(Gamma) mod q`, signer `i` computes:

```text
sigma_i = kTilde_i * m + r * chiTilde_i
```

Every authenticated partial is checked directly against the normalized public
commitments:

```text
[sigma_i]Gamma == [m]DeltaTilde_i + [r]STilde_i
```

An invalid partial attributes the authenticated sender immediately. Valid
partials are summed. Low-S normalization and recovery-ID parity adjustment are
applied only to the final ECDSA signature.

## Unified Durable Lifecycle

`tssrun.LifecycleStore` is the single transactional boundary for CGGMP21 key
generations, run leases, available presigns, online attempts, and generation
cutover.

### Presign availability

`StartPresign(plan, runtime)` loads and canonically revalidates the exact current
generation named by `runtime.Binding`; it never accepts a caller-supplied secret
share. It acquires a `RunPresign` lease before any initial envelope becomes
visible.

On successful Figure 8 completion,
`CommitAvailablePresignFromLease` atomically:

1. verifies the lease and current generation;
2. persists the secret normalized tuple under the canonical public presign
   slot;
3. persists only public recovery metadata alongside it; and
4. completes the presign lease.

Only then does `PresignSession.Presign()` expose a repeatable,
public-only `PersistedPresign` descriptor. The session never returns the secret
tuple. A persistence failure destroys the candidate and aborts the lease.

An available presign encoding is side-effect free. Its availability is decided
by `LifecycleStore`, not by a mutable flag embedded in a caller-managed file.

### Atomic online attempt

`NewSignPlan` accepts public presign metadata. `StartSign(plan, runtime)` loads
the exact key generation and the available candidate from `LifecycleStore`,
revalidates both canonically and cryptographically, constructs the exact
outbound partial, and calls `CommitSignAttempt`.
`SignPlanOption.Intent` uses the root `tss.SignIntent`, and
`VerifySignature` accepts the corresponding root `tss.SignRequest`.

That one transaction must atomically:

- validate the complete current generation binding;
- claim the exact available `PresignID`;
- destroy or make unreachable its secret blob; and
- persist the immutable attempt intent, public verification context, and exact
  canonical recovery outbox.

No partial becomes externally visible before this commit. A conflict, explicit
burn, successful commit, or unknown commit outcome permanently prevents another
intent from using the presign. Unknown outcomes are reconciled only through
`QueryAttemptOutcome` and `ResumeSign` with the exact `AttemptQuery`.

Delivery and signature completion are separate durable updates on the same
attempt. Until the authenticated delivery certificate is durable,
`ResumeSign` may replay only the exact committed envelope. Signature visibility
waits for `CompleteAttempt`. Recovery never reloads the normalized secret tuple.

### Generation cutover

Refresh and reshare use an exclusive lease and a generation fence.
`BeginCutoverFromLease` prevents new work from entering the source generation.
`CommitCutover` atomically installs the target, retires and clears the source
secret blob, and burns every still-available presign from the source epoch.

A protocol-level refresh failure durably marks refresh disabled for that key
lineage while leaving signing and presigning on the current generation
available. A local pre-start or storage failure does not create that protocol
marker.

CGGMP21 refresh owns this cutover inside `RefreshSession`; it is not an
external-commit `tss.RefreshScheduler` runner. `StartRefresh` may return a
non-nil session together with a durable cutover error, and `Handle` may return
the same class of error after the session has staged its candidate. In either
case the caller retains that exact session, releases no withheld confirmation,
and calls `RetryLifecycleCommit` until the store gives an authoritative
terminal result. The caller must not install the candidate through a second
callback or destroy the session while reconciliation is pending. A later
refresh run reloads the current `GenerationBinding`, constructs a fresh plan
and runtime, and names a distinct target generation.

## Resharing

Resharing changes the party set or threshold without changing the group public
key.

An authorized subset of source holders first converts source-epoch Shamir
shares into additive dealer inputs using Lagrange coefficients calculated from
the source epoch's dynamic identifiers. The target handoff uses separate
plan-bound provisional identifiers. These are neither source identifiers nor
the final target identifiers.

The handoff's Paillier material, encrypted contributions, and proofs are
temporary transport state. After the target contributions verify, every target
runs all three Figure 7/F.1 rounds. Only the resulting fresh RID, final dynamic
identifiers, independent Paillier and auxiliary material, and confirmations
enter the new `KeyShare`.

Old-only dealers wait for mutually consistent target confirmations but never
receive a replacement share. Resharing does not cryptographically revoke old
shares; deployment policy must retire the source authorization epoch after
cutover.

## Non-Hardened Child Generations

`DeriveNonHardenedBIP32` remains a public preview calculation. A signable child
is created with `ChildDerivationPlan` and `StartChildDerivation`:

1. bind the exact parent `GenerationBinding`, non-empty non-hardened path,
   derived public key and chain code, distinct target key ID, and target
   generation;
2. load and validate the current parent through `LifecycleStore`;
3. acquire an exclusive child-derivation lease;
4. apply the public BIP32 tweak to the parent shares;
5. run a complete Figure 7/F.1 auxiliary-information protocol under a distinct
   child SID; and
6. atomically install the first generation of the child lineage with
   `CommitInitialGenerationFromLease`.

The parent remains current and usable. The child receives a new SID, RID,
`EpochID`, dynamic identifiers, Paillier keys, and independent auxiliary setup.
Presign and sign plans reject non-empty signing paths because those protocols
operate only on an already established lifecycle generation.

## Canonical Wire and Transcript Binding

Production protocol records use `internal/wire.Marshal` and `wire.Unmarshal`.
Decoders require the exact type identifier, schema version, contiguous expected
tags, canonical integers and points, bounded lists, and no trailing bytes.
Retired record shapes are rejected; there is no fallback decoder.

Every Figure 6-10 payload binds, as applicable:

- semantic protocol version, payload type, and round;
- session, stable SID, RID, `EpochID`, and `PresignID`;
- plan digest and security profile;
- authenticated sender and direct recipient;
- canonical committee or signer set; and
- every public field affecting the proof statement or result.

Repository-defined SHA-256 transcripts use `internal/transcript` labeled
entries. Proof-specific Fiat-Shamir construction is documented in
[`paillier-zk-proofs.md`](paillier-zk-proofs.md).

## Production Security Profile

The default secp256k1 profile follows Appendix C.1 and targets 128-bit classical
security:

```text
Ell             = 256
EllPrime        = 1280
Epsilon         = 512
ChallengeBits   = 256
MinPaillierBits = 3072
```

The Paillier modulus `N` and auxiliary modulus `Nhat` are each at least 3072
bits but are independently generated. `Πmod` and `Πprm` use 128 amplification
rounds. Reduced parameters are explicit test inputs, are bound into plans and
proof transcripts, and are never production defaults.

Fiat-Shamir field challenges use labeled SHA-256 expansion and rejection
sampling to obtain a canonical non-zero scalar. Modulus challenges use bounded
rejection sampling for a uniform unit. Both paths fail closed after their
bounded attempt count.

## Public Entry Points

The main construction and startup APIs are:

- `NewKeygenPlan` and `StartKeygen` for the combined Figure 6 then Figure 7/F.1
  flow;
- `NewPresignPlan` and `StartPresign(plan, PresignRuntime)` for Figure 8;
- `NewSignPlan`, `StartSign(plan, SignRuntime)`, and `ResumeSign` for Figure 10;
- `NewRefreshPlan` and `StartRefresh` for same-party refresh;
- `NewResharePlan` with role-specific dealer, receiver, and overlap starts;
- `NewChildDerivationPlan` and `StartChildDerivation`; and
- trusted import and reconstruction APIs described in
  [`security.md`](security.md).

Plans are shared public intent. Runtime values contain local dependencies such
as the party identity, guard, random source, context, and lifecycle store.

## Limitations

- The repository is not production audited.
- The Paillier/ZK implementation and its concrete transcript composition need
  independent cryptographic review.
- The security proof in the paper is for its stated model; repository transport,
  persistence, threshold extension, and lifecycle bindings are additional
  engineering boundaries that require review.
- File and memory lifecycle stores are reference implementations, not a
  production database or KMS/HSM.
- Go cleanup is best effort and is not a memory-forensic zeroization guarantee.
- Hardened BIP32 derivation is unsupported.
- Old and new authorization epochs remain cryptographically capable until
  deployment policy and storage complete retirement.
