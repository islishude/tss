# FROST Ed25519

The `frost/ed25519` package implements:

- proof-gated dealerless key generation based on the
  [original FROST paper](https://eprint.iacr.org/2020/852), followed by a
  repository-defined confirmation round;
- two-round FROST Ed25519 signing based on
  [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591), with an additional
  production nonce binding described below;
- same-committee refresh, party/threshold resharing, explicitly authorized
  trusted-dealer import and reconstruction, and non-hardened
  Khovratovich-Law Ed25519-BIP32 derivation.

RFC 9591 specifies signing, not dealerless key generation, lifecycle
confirmation, refresh, reshare, import, reconstruction, or HD derivation. Those
features are repository-defined extensions. The package produces standard
64-byte Ed25519 signatures accepted by `crypto/ed25519.Verify`.

This repository has not completed an independent production audit. Read
[`security.md`](security.md) and [`deployment.md`](deployment.md) before
integrating it.

## Protocol Surface

| Operation              | Rounds | Public entry points                                                                         |
| ---------------------- | ------ | ------------------------------------------------------------------------------------------- |
| Dealerless keygen      | 3      | `NewKeygenPlan`, `StartKeygen`                                                              |
| Trusted-dealer import  | 3      | `NewTrustedDealerImport`, `StartTrustedDealerImport`, `GenerateTrustedDealerKeyShares`      |
| Signing                | 2      | `NewSignPlan`, `StartSign`                                                                  |
| Same-committee refresh | 2      | `NewRefreshPlan`, `StartRefresh`                                                            |
| Reshare                | 2      | `NewResharePlan` or `NewPublicResharePlan`, then the role-specific `StartReshare*` function |
| Public HD derivation   | local  | `KeyShare.Derive`, `KeyShare.DeriveWithLimits`, `DeriveNonHardenedBIP32`                    |
| Secret reconstruction  | local  | `ReconstructSecretKey`, `ReconstructSecretKeyWithLimits`                                    |

Each participant reconstructs an equivalent immutable plan from authenticated
run metadata. Sharing a plan means agreeing on its public fields and digest; it
does not require sharing one Go object.

## Integration and State Transitions

Every run needs a fresh shared `tss.SessionID` and an `EnvelopeGuard` bound to
`tss.ProtocolFROSTEd25519`, the same session, and the local party. Raw inbound
bytes must first pass `tss.OpenEnvelope`; only the resulting
`tss.InboundEnvelope` may be delivered to `Handle`. See
[`root-package.md`](root-package.md) for guard, replay, confidentiality, and
broadcast-certificate requirements, and [`tssrun.md`](tssrun.md) for run
admission and dispatch.

Handlers use this transaction shape:

```text
decode -> policy validate -> cryptographic verify -> prepare transition -> commit -> effects
```

A rejected transition does not partially install the candidate input or emit
its prepared envelopes. Identical duplicates do not reapply state; conflicting
duplicates fail verification. Explicitly bufferable early messages occupy at
most one sender slot and are fully revalidated when their prerequisites arrive.
A terminal verification or invariant failure additionally moves the session to
its aborted state and clears package-owned retained secret state. Guard
rejections and plan-hash mismatches retain their separately defined nonterminal
behavior.

Construct and validate outbound envelopes before making the state that
authorizes them visible. Register a started session before releasing its first
outbound envelope, and keep routing until `Completed()` or the relevant output
accessor reports completion.

FROST refresh and reshare return staged key shares; the application owns the
durable compare-and-swap cutover. Do not select a generation from process-local
state after an unknown persistence outcome. The restart and ownership contract
is described in [`deployment.md`](deployment.md#refresh-reshare-and-child-generation).

## KeyShare Ownership and Limits

`KeyShare` is opaque. `PublicMetadata()` returns a caller-owned snapshot of the
party, threshold, canonical party set, group public key, chain code, group
commitments, lifecycle session ID, transcript hash, and plan hash.
`VerificationShare(party)` and `KeygenConfirmation(party)` return caller-owned
per-party public records.

The following ownership distinctions matter:

- A shallow Go copy of `KeyShare` is another handle to the same lifecycle
  state. Calling `Destroy` through either handle affects both.
- `KeyShare.Clone()` and session completion accessors return independently
  owned secret-bearing shares. Each result must be destroyed separately.
- Snapshot, byte, slice, and nested-record accessors return copies.
- Successful decode replaces the receiver only after the new value has fully
  decoded and validated, then clears the superseded receiver state. Failed
  decode leaves the receiver unchanged.

`Validate`, `ValidateConsistency`, `MarshalBinary`, `UnmarshalBinary`, and
`Derive` use `DefaultLimits()`. The defaults reject thresholds below two,
including 1-of-1, while allowing signer sets from the threshold through the
full committee. Tests or explicitly authorized non-production profiles that
allow 1-of-1 must use the matching `WithLimits` entry points consistently.
Limits are local resource and policy controls; they do not alter canonical wire
bytes or enter plan digests.

`Destroy` makes the share unusable and attempts to overwrite the package-owned
fixed-width secret scalar and chain-code buffer. This is best-effort
process-memory cleanup, not a secure-erasure guarantee; see
[`security.md`](security.md#go-memory-erasure-boundary).

## Distributed Key Generation

### Polynomial and Commitments

For threshold `t`, party `i` samples a degree-`t-1` polynomial over the
Ed25519 prime-order scalar field:

```text
f_i(x) = a_i,0 + a_i,1*x + ... + a_i,t-1*x^(t-1) mod q
C_i,k = a_i,k*B
```

`B` is the Ed25519 base point and
`q = 2^252 + 27742317777372353535851937790883648493`.

### Round 1: Commitments and Proof of Knowledge

Each party broadcasts:

- its `t` coefficient commitments;
- a commitment to its 32-byte chain-code contribution;
- the keygen plan hash; and
- a Schnorr proof of knowledge of `a_i,0` for `C_i,0`.

The proof is mandatory for dealerless and trusted-import runs at every allowed
threshold. The current version-1 payload requires the nested proof at tag 4;
the retired proof-less body is not accepted.

For proof nonce `r`, public commitment `R = r*B`, non-zero challenge `c`, and
response `mu`, verification is:

```text
mu = r + c*a_i,0 mod q
mu*B == R + c*C_i,0
```

`R` must be a canonical, non-identity prime-order point. `mu` is a canonical
scalar and may be zero if the equation holds. The challenge is derived with
rejection sampling from a labeled SHA-256 transcript. It binds the ciphersuite,
protocol and version, session, round, dealer, threshold, canonical committee,
plan hash, every coefficient commitment, the chain-code commitment,
`C_i,0`, and `R`. This is the proof-of-knowledge defense used against the
dealerless-DKG rogue-key attack described by the original paper.

The proof preparation owns a one-use nonce and consumes it on successful
finalization, failed finalization, cancellation, or destruction.

### Round 2: Confidential Shares

After every round-1 proof has verified, dealer `i` sends receiver `j`:

```text
s_i->j = f_i(j) mod q
```

This is a direct message (`To != 0`) whose transport must report
`ReceiveInfo.Protection == tss.ChannelConfidential`. No dealer releases its
round-2 envelopes before the complete proof set verifies.

A share that arrives before its dealer commitment may be retained in that
sender's bounded slot, but it does not advance the phase. At the round-1
cutover, and again before aggregation, it is checked against the accepted
commitments:

```text
s_i->j*B == sum(k=0..t-1, j^k*C_i,k)
```

### Round 3: Confirmation and Completion

After all commitments and shares verify, party `j` computes:

```text
x_j  = sum(i, s_i->j) mod q
GC_k = sum(i, C_i,k)
PK   = GC_0
V_p  = sum(k=0..t-1, p^k*GC_k)
```

Every `V_p` must be a canonical, non-identity prime-order point. An identity
verification share reveals that participant's Shamir share as zero, so the
session terminates with an unblamed verification failure and clears its staged
secret material.

The keygen transcript is a labeled SHA-256 transcript over the ciphersuite,
protocol/version, session, threshold, canonical party set, plan hash, aggregate
of the round-1 chain-code commitments, each dealer's commitments and canonical
proof bytes, group commitments, and verification shares. It deliberately binds
the commitment aggregate at this stage, not the unrevealed final chain code.

Each party then broadcasts `KeygenConfirmation`. Its `ChainCode` field contains
that sender's chain-code contribution, not the final aggregate. The remaining
fields bind the sender, session, threshold, party set, group public key,
transcript hash, group-commitments hash, and plan hash. Each reveal must match
its round-1 commitment; after the complete set is accepted, the final chain
code is the XOR of the contributions.

`KeygenSession.KeyShare()` remains unavailable until every party's canonical
confirmation has been received and verified. A confirmation that arrives before
its sender's round-1 commitment may be held in that sender's bounded slot and
is revalidated after the commitment is accepted.

### Keygen Failure and Evidence

An authenticated malformed or invalid round-1 commitment/proof or round-2 share
is a terminal verification failure and emits no protocol effects. Public
round-1 evidence may bind the actual public envelope. Confidential-share
evidence instead uses a synthetic empty-payload envelope plus public party-set
and commitment hashes; it never stores the share, the original payload, or a
hash of either.

Abort clears package-owned polynomial coefficients, accepted and pending secret
shares, pending key material, chain-code reveal buffers, and remaining proof
preparation state on a best-effort basis. Guard rejection and plan-hash mismatch
do not manufacture cryptographic blame.

## Signing

`NewSignPlan` validates the complete `KeyShare`, canonicalizes the signer set,
resolves the requested derivation path, and binds the session, key metadata,
signers, message, normalized `tss.SigningContext`, and derivation result into
the plan digest. By default, any signer-set size in
`threshold <= len(signers) <= len(parties)` is valid. Set
`Limits.Threshold.AllowOversizedSignerSet` to `false` for an exact-threshold
local policy; the actual signer set, but not that local policy flag, is in the
plan digest.

### Round 1: Nonce Commitments

Each signer creates hiding and binding nonces from separate 32-byte random
inputs, its fixed-width secret-share encoding, and a repository-defined binding
hash:

```text
binding = H_label(session, role, message, context_hash, sign_plan_hash)
d_i = H3(random32_d || SerializeScalar(x_i) || binding_d)
e_i = H3(random32_e || SerializeScalar(x_i) || binding_e)
D_i = d_i*B
E_i = e_i*B
```

`H3` here denotes the RFC 9591 ciphersuite nonce hash input, extended by the
final binding bytes. The extension separates nonce derivation across distinct
signing intents even if a reader repeats output; it does not make a predictable
or repeated reader acceptable. `SignRuntime.Local.Rand`, when supplied, must be
a CSPRNG in production. Exact RFC nonce-vector tests use a package-internal
RFC-only generator instead of changing production behavior.

`D_i` and `E_i` must be canonical, non-identity prime-order points. The nonce
scalars remain in the session only until the local round-2 payload has been
constructed.

### Binding Factors and Group Commitment

For the canonical signer order, the RFC functions compute:

```text
encoded_commitments = concat(SerializeScalar(i), D_i, E_i)
msg_hash             = H4(message)
commitment_hash      = H5(encoded_commitments)
rho_i                = H1(PK || msg_hash || commitment_hash || SerializeScalar(i))
R                    = sum(i, D_i + rho_i*E_i)
```

`PK` is the actual verification key: the group key for an empty path or the
derived child key for HD signing. `H1`, `H4`, and `H5` use the RFC 9591
`FROST-ED25519-SHA512-v1` ciphersuite and its `rho`, `msg`, and `com` labels.

If `R` is the identity, the session terminates with an unblamed verification
failure. It emits no partial, clears retained signing state, and does not retry
the same intent by rolling the round back.

### Round 2: Partials and Aggregation

Let:

```text
c        = H_Ed25519(R || PK || message) mod q
lambda_i = product(j in S, j != i, j/(j-i)) mod q
z_i      = d_i + rho_i*e_i + lambda_i*c*x_i mod q
```

For HD signing, `x_i` is replaced by `x_i + Delta`, where `Delta` is the
root-relative additive shift for the resolved path. Each partial is verified
before aggregation:

```text
z_i*B == D_i + rho_i*E_i + lambda_i*c*V_i
```

For HD signing, the verification share on the right is shifted by `Delta*B`.
A partial received before the complete commitment set is held in one bounded
sender slot and verified only after all commitments are available.

After every partial verifies:

```text
z   = sum(i, z_i) mod q
sig = R || z
```

The session verifies `sig` with `crypto/ed25519.Verify` before completing.
Because every partial already passed its equation, a final verification failure
is treated as an unblamed local invariant or dependency failure.

An authenticated malformed nonce commitment or partial payload, including a
non-canonical partial scalar, is an attributable terminal verification failure.
The session clears package-owned nonce, partial, message, commitment, and
derivation state on a best-effort basis. `Signature()` returns a copy of the
completed 64-byte signature; `Destroy()` also clears the retained signature.

## Refresh and Reshare

Refresh and reshare preserve the group public key and chain code. Refresh keeps
the same party set and threshold. True reshare may change either, but the
current protocol uses every old party as a dealer; all old parties therefore
must participate.

The reshare plan binds the source public key, chain code, old party set, group
commitments, lifecycle session ID, transcript hash, and lifecycle plan hash.
New-only receivers must obtain those public source-generation anchors through
an authenticated, authorized channel before calling `NewPublicResharePlan`.

The role-specific starts are:

- old only: `StartReshareDealer`;
- old and new: `StartReshareOverlap`;
- new only: `StartReshareReceiver`;
- same-committee refresh: `StartRefresh`.

For true reshare, old dealer `i` computes its Lagrange-weighted constant term
and samples a target-threshold polynomial:

```text
w_i    = lambda_i(old, 0)*x_i
g_i(0) = w_i
deg(g_i) = new_threshold - 1
```

It broadcasts the polynomial commitments and sends `g_i(j)` to each new party
over a confidential direct channel. A receiver verifies shares in canonical
old-party order and computes `x'_j = sum(i, g_i(j))`. This order makes blame for
the first invalid dealer deterministic when more than one share is invalid.

Refresh instead uses zero-constant polynomials, adds their evaluations to the
existing local share, and adds their commitments to the old group commitments.

After the complete old-dealer commitment set is available, every target holder
derives the same reshare transcript and broadcasts a round-2 confirmation over
the target party set. It binds the plan, target party set and threshold,
preserved public key and chain code, transcript, and new-commitments hash.
Receiver `KeyShare()` accessors remain unavailable until every target holder
has confirmed the same binding.

An old-only dealer receives no secret target share and never exposes a new
`KeyShare`. It remains active after round 1, derives the same public confirmation
binding, and completes only after verifying the full target confirmation set.
The transport must fan out these confirmations across the old/new union while
building each broadcast certificate against the target `newParties` set.

The protocol does not revoke the old shares. The control plane must make the
new generation durable and satisfy its cutover policy before retiring the old
generation; after cutover, it must prevent the old committee from authorizing
new work.

## Trusted-Dealer Import and Reconstruction

These APIs deliberately cross the ordinary threshold boundary and require a
separate authorization ceremony.

`NewTrustedDealerImport` splits an existing `SecretKey` and target chain code
into one non-zero, session/party/plan-bound `TrustedDealerContribution` per
party. The public `TrustedDealerImportPlan` binds the session, party set,
threshold, target public key and chain code, each constant-term commitment, and
each chain-code commitment. Its `Snapshot()` returns caller-owned public data;
`Commitments` and `ChainCodeCommitments` are separate maps.

Each contribution is a secret-bearing canonical record that belongs only to
its named party. Provision it through a confidential authenticated channel.
`StartTrustedDealerImport` validates and consumes the contribution only after
the local keygen session and its first outbound effect have been prepared. The
result then follows the same proof-gated three-round keygen state machine and
requires a constant-term proof from every participant.

`GenerateTrustedDealerKeyShares` drives those sessions through an authenticated
in-memory router and returns independently owned `KeyShare` values. It
centralizes every generated share in one process and is suitable only when that
explicit trust boundary is acceptable.

`ReconstructSecretKey` requires at least the threshold number of unique shares.
Every supplied share is fully validated and must match the same lifecycle
generation: threshold, parties, public key, chain code, commitments, lifecycle
session, transcript, plan, and confirmation mode. Reconstruction does not
consume, revoke, or modify the input shares.

`SecretKey.MarshalBinary` exports a caller-owned canonical 32-byte
little-endian group scalar. It is not an RFC 8032 seed. `NewSecretKeyFromSeed`
maps a seed to a scalar; reconstruction cannot recover the original seed. Clear
every exported copy and call `Destroy` on the `SecretKey`, while recognizing the
best-effort Go memory-erasure boundary.

## Non-Hardened HD Derivation

The package implements the public, non-hardened construction from the
[Khovratovich-Law paper](https://doi.org/10.1109/EuroSPW.2017.47).
For parent public point `A_(j-1)`, chain code `c_(j-1)`, and index `i_j`:

```text
Z_j     = HMAC-SHA512(c_(j-1), 0x02 || A_(j-1) || LE32(i_j))
delta_j = 8*LE_OS2IP(Z_j[0:28])
A_j     = A_(j-1) + delta_j*B
c_j     = HMAC-SHA512(c_(j-1), 0x03 || A_(j-1) || LE32(i_j))[32:64]
```

Each level uses the immediately preceding public point and chain code. The
cumulative `Delta = sum(delta_j)` is retained only for the final root-relative
relation `A_child = A_root + Delta*B`; it is not added again to an already
shifted parent.

A zero tweak is valid if the child point is not the identity. If the child is
the identity, `ErrorOnInvalidChild` returns `ErrInvalidChild`; `SkipInvalidChild`
increments the index and recomputes both the tweak and chain code. Only indices
below `2^31` are supported, and paths contain at most
`tss.MaxDerivationDepth == 255` indices.

`KeyShare.Derive` first validates the complete secret-bearing share.
`DeriveNonHardenedBIP32` operates on caller-supplied public key and chain code;
the caller is responsible for authenticating that metadata. Signing binds both
the requested and resolved path through `tss.SigningContext` and verifies the
final signature against the derived child key.

## Delivery Policy

`FROSTPolicies()` is the authoritative delivery-policy matrix. Every broadcast
requires a full broadcast certificate; broadcast confidentiality is optional.
The two share payloads require confidential direct channels.

| Payload type                         | Round | Mode      | Confidential channel required |
| ------------------------------------ | ----- | --------- | ----------------------------- |
| `frost.ed25519.keygen.commitments`   | 1     | broadcast | no                            |
| `frost.ed25519.keygen.share`         | 2     | direct    | yes                           |
| `frost.ed25519.keygen.confirmation`  | 3     | broadcast | no                            |
| `frost.ed25519.sign.commitment`      | 1     | broadcast | no                            |
| `frost.ed25519.sign.partial`         | 2     | broadcast | no                            |
| `frost.ed25519.reshare.commitments`  | 1     | broadcast | no                            |
| `frost.ed25519.reshare.share`        | 1     | direct    | yes                           |
| `frost.ed25519.reshare.confirmation` | 2     | broadcast | no                            |

“No” means confidentiality is not required by the policy, not that encrypted
transport is forbidden.

## Scope and Limitations

- The public signing API signs raw messages; it does not expose Ed25519ph or
  Ed25519ctx modes.
- The package does not provide transport, peer authentication, authorization,
  storage encryption, durable run admission, or distributed cutover.
- Hardened HD derivation is unsupported because it requires private-key
  material unavailable to one threshold participant.
- The protocol relies on the random-oracle model for its Fiat-Shamir and hash
  constructions and on callers supplying cryptographically secure randomness.
- The group public key and signatures are standard Ed25519 values; the package
  does not provide application- or chain-specific verification logic.

Executable API examples live in
[`frost/ed25519/examples_test.go`](../frost/ed25519/examples_test.go).
