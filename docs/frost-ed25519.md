# FROST Ed25519

The `frost/ed25519` package implements a dealerless FROST-style threshold Ed25519 protocol based on [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591).

## Protocol Overview

| Phase     | Rounds | Description                                               |
| --------- | ------ | --------------------------------------------------------- |
| DKG       | 2      | Dealerless distributed key generation plus confirmation.  |
| Signing   | 2      | Nonce commitment (round 1), partial signature (round 2).  |
| Resharing | 1      | Zero-coefficient polynomial refresh; group key preserved. |
| BIP32 HD  | local  | Khovratovich-Law non-hardened child key derivation.       |

The group public key is a standard Ed25519 verification key. Signatures are standard 64-byte `R || S` Ed25519 values verifiable with `crypto/ed25519.Verify`.

## Session Transition Contract

FROST keygen, signing, refresh, and reshare handlers follow:

```text
decode -> policy validate -> cryptographic verify -> prepare transition -> commit -> effects
```

Rejected messages do not mutate accepted commitments, shares, partials, or
completion state. Decoded secret scalars and prepared nonce/share outputs remain
owned by the transition until commit and are destroyed on rejection. Outbound
envelopes are fully constructed before the corresponding state is committed.
Identical duplicates never reapply state; conflicting duplicates are rejected
without overwriting accepted values. Completion readiness is derived from the
accepted per-party state.

## Production Run Recipes

The recipes below describe production integration metadata. They do not add a
new library API. A shared plan means equivalent authenticated run metadata, not
a shared Go object.

### FROST KeygenRun

Public run metadata includes a fresh keygen session ID, parties, threshold, and
any application key identifier. Each party validates the metadata, reconstructs
`NewKeygenPlan`, records the plan digest acceptance, builds an `EnvelopeGuard`
for `tss.ProtocolFROSTEd25519` and the same session ID, calls `StartKeygen`
locally, dispatches inbound envelopes to `KeygenSession.Handle`, and routes any
returned envelopes.

The keygen session ID is stored in `KeyShare` metadata after completion.
`KeygenSession.KeyShare()` becomes available only after the confirmation round.
Persist the encrypted local key share before marking the party complete or the
key usable.

### FROST SignRun

Public run metadata includes a fresh signing session ID, key ID or key
generation ID, signer set, message, and any signing context or derivation
request. Each signer reconstructs `NewSignPlan`, calls `StartSign`, routes
nonce commitments and partial signatures through `SignSession.Handle`, and
verifies the final signature before exposing the result.

HD derivation is local/public context resolution, not an interactive run. The
signing run must bind the resolved derivation context.

### FROST RefreshRun

Public run metadata includes a fresh refresh session ID, current key generation
ID, and the current public key metadata. Each party reconstructs
`NewRefreshPlan` from its current local `KeyShare`, calls `StartRefresh`, routes
`ReshareSession.Handle`, and obtains the staged output through
`ReshareSession.KeyShare()`.

Refresh preserves party set, threshold, group public key, and chain code.
Install the refreshed `KeyShare` with compare-and-swap semantics against the
expected current key generation.

### FROST ReshareRun

Public run metadata includes a fresh reshare session ID, old key generation ID,
old parties, new parties, and new threshold. Old parties act as dealers and call
`StartReshare`. New-only recipients call `StartReshareRecipient`. New-only
recipients need public reshare metadata out of band before starting the
recipient flow. All roles route `ReshareSession.Handle`.

The control plane owns old/new generation cutover and must not retire the old
generation until the required new-generation commit condition is satisfied.

## KeyShare API and Ownership

`KeyShare` is an opaque handle. Public metadata cannot be changed through struct
fields after validation. `PartyID()`, `Threshold()`, and `KeygenSessionID()`
return scalar values. `PublicMetadata()` returns a caller-owned snapshot of the
party set, group public key, chain code, group commitments, session binding,
transcript hash, and plan hash. Per-party public material is queried with
`VerificationShare(party)` and `KeygenConfirmation(party)`.

The persistent per-party material is keyed by `PartyID`. Its key set must match
the canonical participant set exactly. Ordered transcript and confirmation
material is always derived from the participant order, never Go map iteration.
The current map-based KeyShare wire layout intentionally does not decode the
retired record-list layout.

Keygen, refresh, reshare, and sign plans expose aggregate caller-owned values
through `Snapshot()` methods rather than independent slice and byte getters.

The local share is stored as `internal/secret.Scalar` fixed-length bytes.
`String()`, `GoString()`, and `Format()` redact it, while `MarshalJSON()` rejects
the record. `Destroy()` zeroes the package-owned secret and chain code in place.
A shallow Go copy is only another handle to that same lifecycle state.
`KeygenSession.KeyShare()` and reshare completion accessors return independently
owned shares that must each be destroyed separately.

## Distributed Key Generation

### Polynomial Sampling

Each party `i` samples a random polynomial over the Ed25519 prime-order scalar field:

```
f_i(x) = a_{i,0} + a_{i,1}·x + … + a_{i,t-1}·x^{t-1}  (mod q)
```

where `t` is the threshold and `q` is the Ed25519 scalar order (`2^252 + 27742317777372353535851937790883648493`).

### Commitments

Each party publishes Pedersen commitments to its polynomial coefficients:

```
C_{i,k} = a_{i,k} · B          for k ∈ [0, t-1]
```

where `B` is the Ed25519 base point. Commitments are broadcast as a `keygenCommitmentsPayload` TLV record.

### Share Distribution

Each party computes private shares for every other party and delivers them in confidential point-to-point envelopes:

```
s_{i→j} = f_i(j)   (mod q)
```

The share is encoded as a canonical 32-byte scalar and sent as a direct confidential message (`To != 0`, transport must report `ChannelConfidential` in `ReceiveInfo`).

### Share Verification

Each receiver `j` verifies share `s_{i→j}` against dealer `i`'s commitments:

```
s_{i→j} · B  ≟  Σ_{k=0}^{t-1} (j^k · C_{i,k})
```

A failed verification returns a `ProtocolError` with `Blame` evidence binding the dealer ID, commitment hash, and reason.

### Confirmation and Completion

When all `n` dealers' commitments and shares are collected and verified:

1. **Secret aggregation:** `x_j = Σ_{i=1}^{n} s_{i→j} mod q`
2. **Group commitments:** For each degree `k`, `GC_k = Σ_{i=1}^{n} C_{i,k}`
3. **Group public key:** `PK = GC_0` (the aggregated degree-zero commitment)
4. **Verification shares:** For each party `p`, `V_p = Σ_{k=0}^{t-1} (p^k · GC_k)`
5. **Chain code:** If HD is enabled, `chain = XOR_{i=1}^{n} chainCode_i`
6. **Transcript hash:** Labeled, domain-separated SHA-256 binding the ciphersuite context, protocol, version, session ID, threshold, sorted parties, aggregate chain code, every dealer commitment set, group commitments, and verification shares. This value is identical for every party in the completed DKG.

At this point the session has only local pending material. It then broadcasts a
round-2 `KeygenConfirmation` payload binding the session ID, sender, threshold,
party set, group public key, keygen transcript hash, and group commitments hash.
Because the transcript hash binds every dealer commitment set and the aggregate
chain code, any equivocated broadcast view produces a mismatching confirmation.

`KeygenSession.KeyShare()` returns `false` until confirmations from every party
are received, canonical, non-confidential broadcasts, and consistent with the
local pending material. The resulting `KeyShare` stores the local scalar share
`x_j`, group public key `PK`, group commitments, verification shares, chain
code, keygen session ID, keygen transcript hash, and keygen confirmation
evidence.

A canonical confirmation that arrives before its sender's round-1 commitment
is held in that sender's bounded pending slot. It is verified and promoted only
after the commitment arrives, so transport reordering does not abort DKG.

### Domain Separation

Keygen commitment hashing uses the label `frost-ed25519-keygen-commitments-v1`. The full domain binds `(session ID, threshold, sorted parties, dealer ID, commitment bytes)`.

Repository-defined FROST transcript fields use the canonical labeled-entry
encoding documented in [`wire.md`](wire.md). Party sets are sorted and encoded
as canonical uint32 lists; dealer and verification-share records repeat their
party ID before the associated public fields. The keygen transcript binds the
aggregate of the round-1 chain-code commitments, not the final aggregate chain
code. RFC 9591 `H1`/`H4`/`H5` retain their RFC-defined SHA-512 concatenation.

## Signing

Signing operates in two rounds. Only `threshold` or more signers from the original participant set may participate.

### Round 1: Nonce Commitments

Each signer `i` derives two hedged nonces from the RFC 9591 `H3` inputs plus a
repository-defined context binding:

```
d_i = H3(random32 || SerializeScalar(x_i) || nonce_context("hiding"))
e_i = H3(random32 || SerializeScalar(x_i) || nonce_context("binding"))
```

`nonce_context` binds the signing session ID, message, signing-context hash,
sign-plan hash, and nonce role. This prevents repeated `NonceReader` output from
reusing the same nonce across different signing intents. `random32` comes from
`SignOptions.NonceReader` or `crypto/rand.Reader`; custom readers must still be
CSPRNGs and must not intentionally repeat output.
The session stores the canonical nonce bytes only until the round-2 partial is
constructed. After that point the nonce bytes are cleared and set to `nil`.

The signer broadcasts the public commitments:

```
D_i = d_i · B
E_i = e_i · B
```

These are sent as a `nonceCommitment` payload in a round-1 broadcast envelope.

### Binding Factor

After collecting all signers' nonce commitments, each signer computes the binding factor `ρ_i` (per RFC 9591):

```
encoded = Σ SerializeScalar(i) || D_i || E_i   // sorted by participant id
msg_hash = H4(message)
commitment_hash = H5(encoded)
ρ_i = H1(PK || msg_hash || commitment_hash || SerializeScalar(i))
```

`PK` is the actual verification key for the signature: the original group key
for normal signing, or the shifted child key when HD additive signing is used.
`H1`, `H4`, and `H5` use the RFC 9591 Ed25519 ciphersuite context string
`"FROST-ED25519-SHA512-v1"` with the `"rho"`, `"msg"`, and `"com"` labels.

### Group Commitment

Each signer computes the group nonce commitment `R`:

```
R = Σ_{j} (D_j + ρ_j · E_j)
```

A signer whose `R` is the identity point aborts (probability negligible for honest nonces).

### Round 2: Partial Signatures

Each signer computes the Ed25519 challenge:

```
c = H_Ed25519(R || PK || message)   mod q
```

The Lagrange coefficient `λ_i` for signer `i` among the signing set:

```
λ_i = Π_{j∈S, j≠i}  j / (j - i)   mod q
```

The partial signature is:

```
z_i = d_i + ρ_i·e_i + λ_i·c·x_i   mod q
```

With an HD additive shift `δ`:

```
z_i = d_i + ρ_i·e_i + λ_i·c·(x_i + δ)   mod q
```

The signing session clears `d_i` and `e_i` immediately after the partial
payload is constructed. After successful aggregation it also clears its message
copy, partial scalars, and retained partial envelopes. Call
`SignSession.Destroy()` when the session is no longer needed to clear the
remaining session-owned material on a best-effort basis.

### Aggregation and Verification

Each signer verifies every received partial `z_j` before aggregation:

```
z_j · B  ≟  D_j + ρ_j·E_j + λ_j·c·V_j
```

where `V_j` is the signer's verification share from DKG.

After all partials are verified, the aggregate is:

```
z = Σ_{j∈S} z_j   mod q
```

The final signature is the standard 64-byte Ed25519 value:

```
sig = R || z
```

This is verified with `crypto/ed25519.Verify(PK, message, sig)`. A failed final verification returns `ProtocolError` with `EvidenceKindFrostAggregateSignature` blame.

### Signing Entry Point

Applications create a shared sign plan and run one `SignSession` per signer with
`StartSign`. The `tss.SigningContext` binds the key, chain, derivation path,
policy domain, and message domain without changing the message bytes:

```go
ctx := tss.SigningContext{
    KeyID: "key-1", ChainID: "chain-1",
    Derivation: tss.DerivationRequest{
        Scheme: tss.DerivationSchemeEd25519KhovratovichLaw,
        Path: tss.MustParseDerivationPath("m/0/1"),
    },
    PolicyDomain: "policy", MessageDomain: "app",
}
plan, err := ed25519.NewSignPlan(ed25519.SignPlanOption{
    Key: share, SessionID: sessionID, Signers: signers, Context: ctx, Message: message,
})
session, out, err := ed25519.StartSign(share, plan, ed25519.SignRuntime{
    Local: tss.LocalConfig{Self: self},
    Guard: guard,
})
```

## Resharing

Resharing updates the threshold or participant set while preserving the group
public key. True resharing requires all old parties to be online as dealers.
`StartRefresh` is the same-party proactive-refresh variant.

### Protocol

For true resharing, each party `i` from the original participant set:

1. Computes `w_i = λ_i(old, 0) · x_i`.
2. Samples `g_i(x)` where `g_i(0) = w_i` and `deg(g_i) = threshold_new - 1`.
3. Broadcasts commitments `C'_{i,k} = g_{i,k}·B`.
4. Sends private shares `g_i(j)` to each party `j` in the new participant set.

Each receiver `j` verifies each share against its dealer's commitments, then computes:

```
x'_j = Σ_i g_i(j)   mod q
```

Since `Σ_i g_i(0)` reconstructs the old group secret, the group public key is
preserved. `StartRefresh` instead uses zero-constant polynomials and adds the
refresh shares to the existing local share.

New group commitments are the sum of all reshare commitments, plus the old
commitments in refresh mode. The chain code is preserved from the original key
metadata. The reshare/refresh transcript hash is global across recipients and
binds old and new party sets, the old public key, chain code, refresh mode, all
dealer commitments, new commitments, and verification shares. `StartRefresh`
requires `config.Self` to match the supplied old key's party id. A new recipient
that does not hold an old `KeyShare` must receive the old 32-byte chain code out
of band and pass it to `StartReshareRecipient`.

## BIP32 HD Derivation

The package implements non-hardened BIP32-Ed25519 derivation following the [Khovratovich-Law / Cardano scheme](https://eprint.iacr.org/2018/483).

### Derivation

Use `KeyShare.Derive(path)` or `DeriveNonHardenedBIP32(pubKey, chainCode, path)`
to resolve a path into a `tss.DerivationResult` containing the child public key,
child chain code, resolved path, and internal additive shift.

For each path index `i`:

1. `Z = F(c_par, 0x02 || A_par || ser_32(i))` where `F(k, x) = HMAC-SHA512(k, HMAC-SHA512(k, x))`
2. `zL = 8 · LE_OS2IP(Z[0:28]) mod q` (cofactor clearing)
3. `cumulativeShift += zL mod q`
4. `childPub = A_par + cumShift · B`
5. `childChain = F(c_par, 0x03 || A_par || ser_32(i))[32:64]`

Only non-hardened indices (`i < 2^31`) are supported since hardened derivation requires the full private key, which no single party holds.

### Signing with HD

Bind the derivation path into the signing context before constructing the signing plan:

```go
ctx := tss.SigningContext{
    KeyID: "key-1", ChainID: "chain-1",
    Derivation: tss.DerivationRequest{
        Scheme: tss.DerivationSchemeEd25519KhovratovichLaw,
        Path: tss.MustParseDerivationPath("m/0/1/2"),
    },
    PolicyDomain: "policy", MessageDomain: "app",
}
plan, err := NewSignPlan(SignPlanOption{
    Key: share, SessionID: sessionID, Signers: signers,
    Context: ctx, Message: message,
})
runtime := SignRuntime{
    Local: tss.LocalConfig{Self: share.PartyID()},
    Guard: guard,
}
sess, out, err := StartSign(share, plan, runtime)
```

Each signer derives the same child key from the context path and adds the internal shift during partial generation. The resulting signature verifies against the child public key:

```go
crypto/ed25519.Verify(plan.VerificationKeyBytes(), message, sig) // true
```

## RFC 9591 Alignment

| Feature              | Implementation                                                         |
| -------------------- | ---------------------------------------------------------------------- |
| Context string       | `"FROST-ED25519-SHA512-v1"` per RFC 9591 §6.1                          |
| Ciphersuite          | Ed25519-SHA512 with the standard Ed25519 challenge                     |
| Nonce generation     | RFC 9591 `H3` over `random32` concatenated with `SerializeScalar(x_i)` |
| Binding factor       | RFC 9591 `H1` over `PK`, `H4(msg)`, `H5(encoded commitments)`, and `i` |
| Scalar encoding      | 32-byte little-endian canonical scalar encoding                        |
| Point encoding       | 32-byte compressed Edwards y-coordinate                                |
| Group commitment     | `R = Σ (D_j + ρ_j·E_j)` per RFC 9591                                   |
| Partial verification | Per-signer before aggregation with attributable blame                  |
| Signature format     | Standard 64-byte Ed25519 signature, `R` followed by `S`                |

### Differences from RFC 9591

- Key generation is dealerless DKG rather than the RFC Appendix C trusted dealer.
- Wire envelopes are this library's transport-neutral TLV messages, not an RFC wire format.
- `Signature()` returns a plain `[]byte` rather than a structured `(R, z)` tuple — the caller can split on the 32-byte boundary if needed.

## Payload Types

| Payload Type                        | Direction      | Confidential | Content                             |
| ----------------------------------- | -------------- | ------------ | ----------------------------------- |
| `frost.ed25519.keygen.commitments`  | broadcast      | no           | Polynomial commitments + chain code |
| `frost.ed25519.keygen.share`        | point-to-point | yes          | Scalar share for one recipient      |
| `frost.ed25519.sign.commitment`     | broadcast      | no           | `(D, E)` nonce commitments          |
| `frost.ed25519.sign.partial`        | broadcast      | no           | Partial signature scalar `z_i`      |
| `frost.ed25519.reshare.commitments` | broadcast      | no           | Reshare polynomial commitments      |
| `frost.ed25519.reshare.share`       | point-to-point | yes          | Reshare scalar for one recipient    |

## Sequence Diagrams

### Protocol Flow Summary

```
DKG ──→ Signing (Online, 2 Rounds)
              │
              │  no offline pre-computation
              │  message required at round 1
              │  produces standard 64-byte Ed25519 signature
              │
         Reshare / Refresh (maintenance, PK preserved)
              │
         BIP32 HD Derivation (local, no network rounds)
```

### DKG — Distributed Key Generation (2 Rounds)

Round 1: each party broadcasts polynomial commitments and delivers private Shamir shares. Round 2: keygen confirmations are broadcast and cross-verified against the local transcript.

```mermaid
sequenceDiagram
    participant P1 as Party 1
    participant P2 as Party 2
    participant PN as Party N

    Note over P1,PN: Local Setup
    P1->>P1: Sample f₁(x)=a₁₀+a₁₁x+… deg t-1
    P1->>P1: C_{1,k}=a_{1,k}·B for k∈[0,t-1]
    P2->>P2: Sample f₂(x)=a₂₀+a₂₁x+… deg t-1
    P2->>P2: C_{2,k}=a_{2,k}·B for k∈[0,t-1]

    Note over P1,PN: Round 1 — Broadcast Commitments
    P1-->>PN: C_{1,k}, chain-code-commit₁
    P2-->>PN: C_{2,k}, chain-code-commit₂

    Note over P1,PN: Round 1 — Private Share Distribution (confidential)
    P1->>P2: s_{1→2}=f₁(2) mod q
    P1->>PN: s_{1→N}=f₁(N) mod q
    P2->>P1: s_{2→1}=f₂(1) mod q
    P2->>PN: s_{2→N}=f₂(N) mod q

    Note over P1,PN: Local Verification & Aggregation
    P1->>P1: s_{j→1}·B ≟ Σ(j^k·C_{j,k})
    P1->>P1: x₁=Σ s_{j→1}, GC_k=Σ C_{j,k}
    P1->>P1: PK=GC₀, V₁, transcript hash
    P2->>P2: s_{j→2}·B ≟ Σ(j^k·C_{j,k})
    P2->>P2: x₂=Σ s_{j→2}, PK=GC₀, V₂

    Note over P1,PN: Round 2 — Keygen Confirmation Broadcast
    P1-->>PN: KeygenConfirmation (session, PK, transcript, chain code)
    P2-->>PN: KeygenConfirmation (session, PK, transcript, chain code)
    PN-->>P1: KeygenConfirmation (session, PK, transcript, chain code)

    Note over P1,PN: All confirmations verified → KeyShare ready
```

### Signing — Online (2 Rounds)

**Online phase**: FROST has no offline pre-computation phase. The 2-round online signing requires the actual message at round 1 and produces a standard 64-byte Ed25519 signature `R‖z`. Partial signatures are verified per-party before aggregation.

Round 1: nonce commitment broadcast. Round 2: partial signature exchange with per-party verification before aggregation.

```mermaid
sequenceDiagram
    participant S1 as Signer 1
    participant S2 as Signer 2
    participant S3 as Signer 3

    Note over S1,S3: 【Online】 Round 1 — Nonce Commitments
    S1->>S1: d₁=H₃(rand‖x₁), e₁=H₃(rand‖x₁)
    S1->>S1: D₁=d₁·B, E₁=e₁·B
    S2->>S2: d₂=H₃(rand‖x₂), e₂=H₃(rand‖x₂)
    S2->>S2: D₂=d₂·B, E₂=e₂·B

    S1-->>S3: (D₁, E₁)
    S2-->>S3: (D₂, E₂)
    S3-->>S1: (D₃, E₃)

    Note over S1,S3: 【Online】 Compute Binding Factors (local)
    S1->>S1: ρⱼ=H₁(PK‖H₄(msg)‖H₅(encoded)‖j)
    S1->>S1: R=Σ(Dⱼ+ρⱼ·Eⱼ), c=H_Ed25519(R‖PK‖msg)

    Note over S1,S3: 【Online】 Round 2 — Partial Signatures
    S1->>S1: z₁=d₁+ρ₁·e₁+λ₁·c·x₁ mod q
    S2->>S2: z₂=d₂+ρ₂·e₂+λ₂·c·x₂ mod q
    S3->>S3: z₃=d₃+ρ₃·e₃+λ₃·c·x₃ mod q

    S1-->>S3: z₁
    S2-->>S3: z₂
    S3-->>S1: z₃

    Note over S1: 【Online】 Verify: zⱼ·B ≟ Dⱼ+ρⱼ·Eⱼ+λⱼ·c·Vⱼ
    Note over S2: 【Online】 Verify: zⱼ·B ≟ Dⱼ+ρⱼ·Eⱼ+λⱼ·c·Vⱼ
    Note over S3: 【Online】 Verify: zⱼ·B ≟ Dⱼ+ρⱼ·Eⱼ+λⱼ·c·Vⱼ

    Note over S1,S3: Aggregate: z=Σzⱼ → sig=R‖z → Ed25519.Verify(PK, msg, sig)
```

### Resharing (1 Round)

Changes participant set and/or threshold while preserving the group public key. Dealers (old parties) sample weighted polynomials and distribute shares to new receivers.

```mermaid
sequenceDiagram
    participant D1 as Dealer 1 (old)
    participant D2 as Dealer 2 (old)
    participant R1 as Receiver 1 (new)
    participant R2 as Receiver 2 (new)

    Note over D1,D2: Dealers: Compute Weighted Shares
    D1->>D1: w₁=λ₁(old,0)·x₁
    D1->>D1: Sample g₁(x), g₁(0)=w₁, deg t_new-1
    D2->>D2: w₂=λ₂(old,0)·x₂
    D2->>D2: Sample g₂(x), g₂(0)=w₂, deg t_new-1

    Note over D1,R2: Broadcast Dealer Commitments
    D1-->>R2: C'_{1,k}=g_{1,k}·B
    D2-->>R2: C'_{2,k}=g_{2,k}·B

    Note over D1,R2: Private Reshare Shares (confidential)
    D1->>R1: g₁(1) mod q
    D1->>R2: g₁(2) mod q
    D2->>R1: g₂(1) mod q
    D2->>R2: g₂(2) mod q

    Note over R1,R2: Verify & Aggregate
    R1->>R1: Verify gⱼ(1) against C'_{j,k}
    R1->>R1: x₁'=Σ gⱼ(1), verify PK'=PK
    R2->>R2: Verify gⱼ(2) against C'_{j,k}
    R2->>R2: x₂'=Σ gⱼ(2), verify PK'=PK

    Note over R1,R2: Broadcast Confirmations
    R1-->>D1: KeygenConfirmation (preserved chain code)
    R2-->>D2: KeygenConfirmation (preserved chain code)

    Note over D1,R2: New KeyShare ready. Σ gᵢ(0) reconstructs old group secret → PK preserved
```

### Same-Party Refresh

Proactive refresh preserving the participant set and threshold. Each party samples a zero-constant polynomial and adds shares to the existing key.

```mermaid
sequenceDiagram
    participant P1 as Party 1
    participant P2 as Party 2
    participant PN as Party N

    Note over P1,PN: Local Setup
    P1->>P1: Sample g₁(x) with g₁(0)=0, deg t-1
    P2->>P2: Sample g₂(x) with g₂(0)=0, deg t-1

    Note over P1,PN: Broadcast Commitments
    P1-->>PN: C'_{1,k}=g_{1,k}·B
    P2-->>PN: C'_{2,k}=g_{2,k}·B

    Note over P1,PN: Private Refresh Shares (confidential)
    P1->>P2: g₁(2) mod q
    P1->>PN: g₁(N) mod q
    P2->>P1: g₂(1) mod q
    P2->>PN: g₂(N) mod q

    Note over P1,PN: Verify & Aggregate
    P1->>P1: x₁'=x₁+Σ gⱼ(1), verify PK'=PK
    P2->>P2: x₂'=x₂+Σ gⱼ(2), verify PK'=PK

    Note over P1,PN: Broadcast Confirmations
    P1-->>PN: KeygenConfirmation (preserved chain code)
    P2-->>PN: KeygenConfirmation (preserved chain code)

    Note over P1,PN: Old commitments summed with refresh commitments → new KeyShare
```

### BIP32 HD Derivation (Local)

Non-hardened Khovratovich-Law child key derivation. Performed locally without network rounds; each signer resolves the same `tss.SigningContext` path and applies the resulting internal shift during partial signature generation.

```mermaid
sequenceDiagram
    participant Caller
    participant HD as HD Derivation (local)

    Note over Caller,HD: For each path index i

    Caller->>HD: KeyShare.Derive(m/0/1/2)

    loop For each index i in path
        HD->>HD: Z=F(c_par, 0x02‖A_par‖ser₃₂(i))
        HD->>HD: zL=8·LE_OS2IP(Z[0:28]) mod q
        HD->>HD: cumShift+=zL
        HD->>HD: childPub=A_par+cumShift·B
        HD->>HD: childChain=F(c_par, 0x03‖A_par‖ser₃₂(i))[32:64]
    end

    HD-->>Caller: DerivationResult(childPub, resolvedPath, childChain)

    Note over Caller: Signing context binds requested and resolved path
    Note over Caller: Verify against childPub with Ed25519.Verify
```

## API Reference

### Keygen

```go
option := KeygenPlanOption{
    SessionID: sessionID, Parties: parties, Threshold: threshold,
}
plan, err := NewKeygenPlan(option)
kg, out, err := StartKeygen(plan, tss.LocalConfig{Self: self, Rand: rng}, guard)
out, err := kg.Handle(env)
share, ok := kg.KeyShare()
metadata, ok := share.PublicMetadata()
publicKey := metadata.PublicKey.Bytes()
parties := metadata.Parties
```

### Signing

```go
plan, err := NewSignPlan(SignPlanOption{
    Key: share, SessionID: sessionID, Signers: signers,
    Context: ctx, Message: message,
})
runtime := SignRuntime{
    Local: tss.LocalConfig{Self: share.PartyID(), Rand: nonceReader},
    Guard: guard,
}
sess, out, err := StartSign(share, plan, runtime)
out, err := sess.Handle(env)
sig, ok := sess.Signature()
```

### Resharing

```go
plan, err := NewResharePlan(ResharePlanOption{
    OldKey: oldShare, SessionID: sessionID,
    NewParties: newParties, NewThreshold: newThreshold,
})
sess, out, err := StartReshare(oldShare, plan, tss.LocalConfig{Self: oldShare.PartyID(), Rand: rng}, guard)
recipientPlan, err := NewPublicResharePlan(PublicResharePlanOption{
    OldPublicKey: oldPublicKey, OldChainCode: oldChainCode, OldParties: oldParties,
    SessionID: sessionID, NewParties: newParties, NewThreshold: newThreshold,
})
recipient, err := StartReshareRecipient(recipientPlan, tss.LocalConfig{Self: self}, guard)
refreshPlan, err := NewRefreshPlan(RefreshPlanOption{OldKey: oldShare, SessionID: sessionID})
refresh, out, err := StartRefresh(oldShare, refreshPlan, tss.LocalConfig{Self: oldShare.PartyID(), Rand: rng}, guard)
out, err := sess.Handle(env)
newShare, ok := sess.KeyShare()
```

Old committee members call `StartReshare` and act as dealers. A participant
that is only in the new committee calls `StartReshareRecipient` with the old
group public key and old chain code so the completed share can verify
`oldPK == newPK` and preserve HD derivation metadata. Same-party proactive
refresh uses `StartRefresh`, which preserves the participant set and threshold.

### BIP32 HD

```go
path := tss.MustParseDerivationPath("m/0/1/2")
result, err := share.Derive(path)
childPub := result.ChildPublicKey
childChain := result.ChildChainCode
```

### Convenience

```go
share, err := UnmarshalKeyShare(raw)
```

## Scope and Limitations

- Signs raw messages only. Ed25519ph and Ed25519ctx are not exposed.
- No network transport, storage encryption, or peer authentication.
- Group public key is a standard Ed25519 key; no on-chain contract verification is provided.
- The protocol depends on Fiat-Shamir challenges via SHA-256/SHA-512; the random oracle assumption applies.
