# FROST Ed25519

The `frost/ed25519` package implements a dealerless FROST-style threshold Ed25519 protocol based on [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591).

## Protocol Overview

| Phase     | Rounds | Description                                               |
| --------- | ------ | --------------------------------------------------------- |
| DKG       | 1      | Dealerless distributed key generation.                    |
| Signing   | 2      | Nonce commitment (round 1), partial signature (round 2).  |
| Resharing | 1      | Zero-coefficient polynomial refresh; group key preserved. |
| BIP32 HD  | local  | Khovratovich-Law non-hardened child key derivation.       |

The group public key is a standard Ed25519 verification key. Signatures are standard 64-byte `R || S` Ed25519 values verifiable with `crypto/ed25519.Verify`.

## KeyShare Structure

```go
type KeyShare struct {
    Version              uint16
    Party                tss.PartyID
    Threshold            int
    Parties              []tss.PartyID
    PublicKey            []byte        // group Ed25519 public key (32 bytes)
    ChainCode            []byte        // optional 32-byte BIP32 chain code
    secret               *secret.Scalar // unexported: local scalar share x_i (fixed 32 bytes)
    GroupCommitments     [][]byte      // degree 0..threshold-1 public polynomial commitments
    VerificationShares   []VerificationShare
    KeygenTranscriptHash []byte
}
```

The `secret` field is unexported and stored as `internal/secret.Scalar` fixed-length bytes. `String()`, `GoString()`, `Format()`, and `MarshalJSON()` all redact it. `Destroy()` zeroes `secret` and `ChainCode` in place.

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

The share is encoded as a canonical 32-byte scalar and sent with `ConfidentialRequired = true`.

### Share Verification

Each receiver `j` verifies share `s_{i→j}` against dealer `i`'s commitments:

```
s_{i→j} · B  ≟  Σ_{k=0}^{t-1} (j^k · C_{i,k})
```

A failed verification returns a `ProtocolError` with `Blame` evidence binding the dealer ID, commitment hash, and reason.

### Completion

When all `n` dealers' commitments and shares are collected and verified:

1. **Secret aggregation:** `x_j = Σ_{i=1}^{n} s_{i→j} mod q`
2. **Group commitments:** For each degree `k`, `GC_k = Σ_{i=1}^{n} C_{i,k}`
3. **Group public key:** `PK = GC_0` (the aggregated degree-zero commitment)
4. **Verification shares:** For each party `p`, `V_p = Σ_{k=0}^{t-1} (p^k · GC_k)`
5. **Chain code:** If HD is enabled, `chain = XOR_{i=1}^{n} chainCode_i`
6. **Transcript hash:** Domain-separated SHA-256 binding the session ID, threshold, sorted parties, aggregate chain code, every dealer commitment set, group commitments, and verification shares. This value is identical for every party in the completed DKG.

The resulting `KeyShare` stores the local scalar share `x_j`, group public key `PK`, group commitments, verification shares, chain code, and keygen transcript hash.

### Domain Separation

Keygen commitment hashing uses the label `frost-ed25519-keygen-commitments-v1`. The full domain binds `(session ID, threshold, sorted parties, dealer ID, commitment bytes)`.

## Signing

Signing operates in two rounds. Only `threshold` or more signers from the original participant set may participate.

### Round 1: Nonce Commitments

Each signer `i` derives two hedged nonces with RFC 9591 `H3`:

```
d_i = H3(random32 || SerializeScalar(x_i))
e_i = H3(random32 || SerializeScalar(x_i))
```

`random32` comes from `SignOptions.NonceReader` or `crypto/rand.Reader`.
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
payload is constructed. Call `SignSession.Destroy()` when the session is no
longer needed to clear message copies, partials, shifted verification keys, and
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

### In-Memory Sign Helper

For tests and simple integrations, `Sign(message, shares)` runs the full two-round exchange in-process:

```go
pub, sig, err := ed25519.Sign(message, []*KeyShare{share1, share2})
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
of band and pass it to `StartReshareRecipient`; use `nil` for non-HD keys.

## BIP32 HD Derivation

The package implements non-hardened BIP32-Ed25519 derivation following the [Khovratovich-Law / Cardano scheme](https://eprint.iacr.org/2018/483).

### Derivation

```go
childPub, additiveShift, childChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1, 2})
```

For each path index `i`:

1. `Z = F(c_par, 0x02 || A_par || ser_32(i))` where `F(k, x) = HMAC-SHA512(k, HMAC-SHA512(k, x))`
2. `zL = 8 · LE_OS2IP(Z[0:28]) mod q` (cofactor clearing)
3. `cumulativeShift += zL mod q`
4. `childPub = A_par + cumShift · B`
5. `childChain = F(c_par, 0x03 || A_par || ser_32(i))[32:64]`

Only non-hardened indices (`i < 2^31`) are supported since hardened derivation requires the full private key, which no single party holds.

### Signing with HD

Pass the cumulative additive shift to `StartSignWithOptions`:

```go
childPub, sig, err := ed25519.SignWithOptions(message, shares, SignOptions{AdditiveShift: additiveShift})
```

Each signer adds `λ_i·c·δ` to their partial. The resulting signature verifies against the child public key:

```go
crypto/ed25519.Verify(childPub, message, sig) // true
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

## API Reference

### Keygen

```go
kg, out, err := StartKeygen(config)                  // standard
kg, out, err := StartKeygenWithOptions(config, opts) // with HD chain code
out, err := kg.HandleKeygenMessage(env)
share, ok := kg.KeyShare()
```

### Signing

```go
sess, out, err := StartSign(share, sessionID, signers, message)
sess, out, err := StartSignWithOptions(share, sessionID, signers, message, opts)
out, err := sess.HandleSignMessage(env)
sig, ok := sess.Signature()
```

### Resharing

```go
sess, out, err := StartReshare(oldShare, newParties, newThreshold, config)
recipient, err := StartReshareRecipient(oldPublicKey, oldChainCode, oldParties, newParties, newThreshold, config)
refresh, out, err := StartRefresh(oldShare, config)
out, err := sess.HandleReshareMessage(env)
newShare, ok := sess.KeyShare()
```

Old committee members call `StartReshare` and act as dealers. A participant
that is only in the new committee calls `StartReshareRecipient` with the old
group public key and old chain code so the completed share can verify
`oldPK == newPK` and preserve HD derivation metadata. Same-party proactive
refresh uses `StartRefresh`, which preserves the participant set and threshold.

### BIP32 HD

```go
childPub, shift, childChain, err := DeriveBIP32(pubKey, chainCode, path)
shiftedPub, err := DerivePublicKey(pubKey, additiveShift)
```

### Convenience

```go
pub, sig, err := Sign(message, shares)
pub, sig, err := SignWithOptions(message, shares, opts)
share, err := UnmarshalKeyShare(raw)
```

## Scope and Limitations

- Signs raw messages only. Ed25519ph and Ed25519ctx are not exposed.
- No network transport, storage encryption, or peer authentication.
- Group public key is a standard Ed25519 key; no on-chain contract verification is provided.
- The protocol depends on Fiat-Shamir challenges via SHA-256/SHA-512; the random oracle assumption applies.
