# CGGMP21 2024 implementation map

This document is the implementation contract for
`cggmp21/secp256k1`. The only protocol source for this map is the bundled
2024 revision in [`cggmp21.pdf`](cggmp21.pdf). Repository authentication,
canonical TLV records, durable lifecycle state, and replay protection are
outer protocol bindings; they do not replace any proof relation or equation
below.

The repository threshold value `t` means that exactly `t` shares are enough
to reconstruct, so Shamir polynomials have degree `t-1` and contain `t`
coefficients. This resolves the inconsistent degree notation in Appendix F.1
by retaining the repository's externally tested threshold invariant.

## Common epoch contract

Every sign-ready key share carries one non-optional epoch context:

```text
SID              stable key/session identity
RID              XOR of the committed per-party rid contributions
EpochID          H(SID, RID, parties, threshold, public shares, lineage,
                   AuxDigest)
ShamirID[j]      first valid H(SID, RID, party[j], counter) in Fq
PublicShares[j]  public share for ShamirID[j]
AuxDigest        digest of every party's Paillier key and Ring-Pedersen setup
```

`KeyGeneration` is a local store CAS token and is never substituted for
`EpochID`. Payloads and proof domains bind every context field that exists at
construction time and affects the statement. Early Figure 6 records cannot
bind an RID or epoch that does not yet exist; Figure 7 `Pi_prm` is prepared
before RID derivation; broadcast statements have no direct recipient. Later
records bind the derived RID and `EpochID`, and recipient-specific proofs bind
the recipient. The accepted early records are subsequently covered by the
final transcript and epoch auxiliary digest.

Figure 6/7 keygen and interactive trusted import return an in-memory confirmed
`KeyShare`. A caller must serialize it and call
`tssrun.LifecycleStore.InstallInitialGeneration` before any store-backed
presign, sign, refresh, reshare, or child-derivation start. Later generations
are installed by their lifecycle transaction.

Deriving a public xpub remains a preview operation. CGGMP presign and sign
plans accept only an empty path. A signable non-hardened child is established
as a separate epoch after a public tweak and a complete auxiliary-information
run.

## Figure 6: key generation

| Round | Paper item             | Repository payload or action                                        | Required verification                                                      |
| ----- | ---------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 1     | commitment `V_i`       | `V_i`, chain-code commitment, plan digest                           | Canonical authenticated broadcast; retain both commitments                 |
| 2     | `rho_i, X_i, A_i, u_i` | Paper opening and plan digest; chain-code contribution stays hidden | `H(label,sid,i,rho_i,X_i,A_i,u_i,plan)=V_i` and exact plan                 |
| 3     | finalized `Pi_sch`     | Proof finalized from retained `x_i` and first-message randomness    | First message equals `A_i`; verify Schnorr under the common XOR coin `rho` |

The paper's product of all `X_i` is point addition in the Go implementation.
Figure 6 output is not a sign-ready `KeyShare`; it must immediately complete
Figure 7/F.1 and acquire an epoch context. The chain-code contribution is
opened and checked only in the final confirmation after that auxiliary run.

## Figure 7 and Appendix F.1: auxiliary information and refresh

| Round       | Payload                                                                                                                         | Statement and witness                                                                                                                                                   | Commit boundary                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 1           | commitment `V_i` plus plan digest                                                                                               | New Paillier factors; temporary separately generated auxiliary factors/trapdoor; DH exponents; degree `t-1` polynomial; commit-ahead proof state; `rid_i`; decommitment | No opened public material or new share becomes visible                      |
| 2           | polynomial commitments, DH keys, Schnorr first messages, Paillier `N_i`, auxiliary `Nhat_i,s_i,t_i`, `Pi_prm`, `rid_i`, opening | Opening of round-1 commitment                                                                                                                                           | Accept only after the commitment and zero-sum/public-polynomial checks pass |
| 3 broadcast | finalized `Pi_sch`, RID, EpochID, plan digest                                                                                   | Each polynomial coefficient/share exponent                                                                                                                              | Bind the XOR-derived RID and target EpochID                                 |
| 3 direct    | `Pi_mod`, verifier-specific `Pi_fac`, DH-masked share, RID, EpochID, plan digest                                                | Retained Paillier factors and the polynomial evaluation matching the committed polynomial; recipient setup is part of the receiver-specific factor-proof statement      | Decrypt/verify on staged state; transfer secret ownership only at commit    |

The auxiliary factorization and Ring-Pedersen trapdoor are destroyed after
`Pi_prm` preparation; the final key share retains only public
`(Nhat_i,s_i,t_i)` parameters and the party's separate Paillier private factors.

Dynamic identifiers are derived after every round-2 opening is accepted.
Candidates at or above the scalar order are retried with a domain-bound counter
up to 256 times. A zero candidate or collision terminates the protocol. DH masks
are derived from the authenticated pairwise DH point and bind SID, RID,
EpochID, sender, and recipient. A DH decryption-error witness is allowed only in
the dedicated authenticated accusation payload required by the paper and never
in logs, ordinary errors, or generic blame fields.

The common Figure 7 transcript commits to the accepted public proof records.
Proofs created after RID derivation bind the final epoch and lifecycle plan;
the earlier `Pi_prm` binds its exact parameters, run, committee, prover, and
plan, and its committed opening is covered by the final transcript and epoch
auxiliary digest. Because a proof cannot include a transcript that contains
itself, sign-ready completion adds one fresh local `Pi_mod` after the transcript
is fixed. Its key-share domain binds the final EpochContext, public key,
transcript, lifecycle kind, and plan. The same completion helper is used by
keygen, trusted import, refresh, reshare, and child creation.

Successful refresh preserves the ECDSA public key, installs the new epoch with
one lifecycle-store CAS, destroys store-owned old secret material, and burns
all old-epoch available presigns. A protocol failure releases the source epoch
for signing but permanently marks that SID lineage refresh-disabled. Local
pre-start or storage failures do not set that protocol state.

### Party-set and threshold resharing handoff

Resharing first converts an authorized subset of source-epoch Shamir shares
into additive inputs for the target committee. `ResharePlan` carries the full
canonical `SourceEpoch` and its explicit `SourceEpochID`; a dealer accepts the
plan only when that epoch, its dynamic identifiers and public shares, the
source commitments, security parameters, lifecycle session, transcript, and
plan digest exactly match its local source share.

For each old dealer `d`, the handoff polynomial constant is
`lambda_source[d] * x_d`, where `lambda_source` is calculated from the source
epoch identifiers for the selected dealer set. Target evaluation points are
temporary identifiers derived from the stable source SID, source EpochID,
reshare run SessionID, plan digest, and target party. They are non-zero and
collision-free and are never reused as final epoch identifiers. Each target
`j` receives and verifies `lambda_target[j] * f_d(id_j)`, so summing dealer
messages gives that target's additive Figure 7 input and summing all target
inputs reconstructs the unchanged group secret.

The handoff's Paillier keys, encrypted shares, proofs, and decrypted dealer
contributions are temporary transport state. Once the additive input is
verified, the target immediately executes all three Figure 7/F.1 rounds with
`StableSID = SourceEpoch.SID`, the reshare SessionID as the run session, and
`SourceEpochID` as lineage. Only Figure 7's new Paillier/Ring-Pedersen material,
fresh RID, dynamic identifiers, and confirmation set enter the final
`KeyShare`; all handoff secret state is destroyed. Dealer-only old parties wait
for a mutually consistent confirmation from every target but never receive a
new share.

## Figure 8: presigning

### Round 1

Each signer samples `k_i,gamma_i` and Paillier randomness, then publishes:

```text
K_i = Enc_i(k_i)
G_i = Enc_i(gamma_i)
Y_i
A_i = (g^a_i, Y_i^a_i g^k_i)
B_i = (g^b_i, Y_i^b_i g^gamma_i)
```

Each recipient receives verifier-specific `Pi_enc-elg` for `K_i/A_i` and
`G_i/B_i`. The proof statement contains the exact ciphertext, both ElGamal
commitment points, `Y_i`, range, prover, recipient, and epoch. A `Pi_logstar`
proof is not a substitute for this relation.

### Round 2

After all round-1 proofs verify, signer `i` broadcasts or directly sends:

```text
Gamma_i = g^gamma_i
Pi_elog(Gamma_i, g, B_i, Y_i)
D/F       affine response for gamma_i * k_j
Dhat/Fhat affine response for x_i * k_j
two verifier-specific Pi_aff-g proofs
```

The affine proof binds both Paillier moduli, the verifier auxiliary setup,
start and response ciphertexts, curve commitment, ranges, parties, and epoch.
Secret Paillier exponents use the repository constant-time exponentiation path.

### Round 3 and output

Signer `i` decrypts the accepted affine responses and computes field elements
`delta_i` and `chi_i`. Local values may be zero. It publishes:

```text
delta_i
Delta_i = Gamma^k_i
S_i     = Gamma^chi_i
Pi_elog(Delta_i, Gamma, A_i, Y_i)
```

After every proof verifies, each signer checks independently:

```text
g^delta = product(Delta_i)
X^delta = product(S_i)
```

If `delta=0`, or `Gamma` cannot yield a valid ECDSA nonce, the whole presign is
destroyed as an unattributed failure and a new PresignID is required. Otherwise
the only reusable output shape is:

```text
Gamma
kTilde_i   = k_i / delta
chiTilde_i = chi_i / delta
DeltaTilde_j = Delta_j^(delta^-1)
STilde_j     = S_j^(delta^-1)
```

Raw `k_i`, `gamma_i`, `delta_i`, `chi_i`, MtA masks, proof randomness, and
superseded artifacts are destroyed when ownership transfers to this normalized
record.

## Figure 9: failed nonce or chi

Figure 9 is entered only when one of the two aggregate equations above fails.
For the selected relation, every signer publishes the canonical alert and, for
each peer, both public MtA response views plus one setup-less `Pi_aff-g*`; the
same record contains the aggregate ciphertext relation with one `Pi_dec`.
Verification also rechecks the original accepted `Pi_aff-g` records against the
authenticated transcript view. Portable evidence contains only public proof
material and authenticated envelopes. If every proof verifies while the alert
remains unresolved, the run ends with an unblamed invariant. Figure 10 ends
with direct partial attribution; it defines no later proof phase.

## Figure 10: signing

For `r = x(Gamma) mod q`, signer `i` computes:

```text
sigma_i = kTilde_i * m + r * chiTilde_i
```

The lifecycle store atomically validates the current generation and EpochID,
claims the PresignID for the exact signing attempt, and commits the canonical
outbox before it becomes visible. The normalized signing tuple is destroyed
after a successful, conflicting, or outcome-unknown commit. Recovery replays
the exact durable outbox and does not reload one-use signing secrets.

Every authenticated partial is checked directly:

```text
Gamma^sigma_i = DeltaTilde_i^m * STilde_i^r
```

An invalid partial attributes the authenticated sender immediately. Valid
partials are summed, then canonical low-S normalization and recovery-ID
adjustment are applied only to the final output.

## Prepare, commit, effects

All inbound handlers and local starts obey:

```text
decode -> policy validate -> cryptographic verify
       -> prepare transition and every outbound envelope
       -> commit replay/state/store ownership
       -> release effects
```

Prepared secrets are registered in a cleanup stack. A marshal, signer,
envelope, store, completion, or replay-commit failure destroys all uncommitted
shares, Paillier material, proof randomness, and partial outbox data. Rejected
input cannot mutate an accepted slot, consume a presign, or emit an effect.

## Proof profile

The production profile implements Appendix C.1 with
`(Ell,Epsilon,EllPrime)=(256,512,1280)`, 256-bit challenges, independently
generated 3072-bit minimum Paillier and auxiliary moduli, and 128-round
`Pi_mod`/`Pi_prm` amplification. Exact relations, transcript construction,
challenge sampling, source files, and retained-but-inactive primitives live in
[`paillier-zk-proofs.md`](paillier-zk-proofs.md); that document is authoritative
for proof implementation details.
