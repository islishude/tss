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
    secret               []byte        // unexported: local scalar share x_i (32 bytes)
    GroupCommitments     [][]byte      // degree 0..threshold-1 public polynomial commitments
    VerificationShares   []VerificationShare
    KeygenTranscriptHash []byte
}
```

The `secret` field is unexported. `String()`, `GoString()`, `Format()`, and `MarshalJSON()` all redact it. `Destroy()` zeroes `secret` and `ChainCode` in place.

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
6. **Transcript hash:** Domain-separated SHA-256 binding `(sessionID, threshold, parties, self, PK)`

The resulting `KeyShare` stores the local scalar share `x_j`, group public key `PK`, group commitments, verification shares, chain code, and keygen transcript hash.

### Domain Separation

Keygen commitment hashing uses the label `frost-ed25519-keygen-commitments-v1`. The full domain binds `(session ID, threshold, sorted parties, dealer ID, commitment bytes)`.

## Signing

Signing operates in two rounds. Only `threshold` or more signers from the original participant set may participate.

### Round 1: Nonce Commitments

Each signer `i` samples two random nonces:

```
(d_i, e_i) ← Z_q
```

and broadcasts their public commitments:

```
D_i = d_i · B
E_i = e_i · B
```

These are sent as a `nonceCommitment` payload in a round-1 broadcast envelope.

### Binding Factor

After collecting all signers' nonce commitments, each signer computes the binding factor `ρ_i` (per RFC 9591):

```
ρ_i = H1("FROST-ED25519-SHA512-v1rho" || domain || PK || message || ordered_commitments || i)
```

where `domain` binds `(session ID, threshold, all parties, signers, group public key)`, and `ordered_commitments` lists `(signer_id, D, E)` for each signer in ascending ID order.

`H1` is implemented via `HashToScalar` which uses SHA-512 and truncates to the scalar field.

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
sig, err := ed25519.Sign(message, []*KeyShare{share1, share2})
```

## Resharing

Resharing updates the threshold or participant set while preserving the group public key. It uses a **zero-coefficient polynomial refresh**: each existing party samples a fresh polynomial with constant term zero.

### Protocol

Each party `i` from the original participant set:

1. Samples `g_i(x)` where `g_i(0) = 0` and `deg(g_i) = threshold_new - 1`.
2. Broadcasts commitments `C'_{i,k} = g_{i,k}·B`.
3. Sends private shares `g_i(j)` to each party `j` in the new participant set.

Each receiver `j` verifies each share against its dealer's commitments, then computes:

```
x'_j = x_j + Σ_{i} g_i(j)   mod q
```

Since `Σ_i g_i(0) = 0`, the group secret (and thus the group public key) is preserved.

New group commitments are the sum of old group commitments plus all reshare commitments. The chain code is preserved from the original key share.

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
sig, err := ed25519.SignWithOptions(message, shares, SignOptions{AdditiveShift: additiveShift})
```

Each signer adds `λ_i·c·δ` to their partial. The resulting signature verifies against the child public key:

```go
crypto.ed25519.Verify(childPub, message, sig) // true
```

## RFC 9591 Alignment

| Feature              | Implementation                                              |
| -------------------- | ----------------------------------------------------------- | --- | --- |
| Context string       | `"FROST-ED25519-SHA512-v1"` per RFC 9591 §5.4.1             |
| Ciphersuite          | Ed25519-SHA512 (standard Ed25519 challenge)                 |
| Binding factor `H1`  | Prepends `"FROST-ED25519-SHA512-v1rho"` label, full domain  |
| `HashToScalar`       | Direct concatenation (no length-delimited encoding)         |
| Domain separation    | SHA-256 transcripts binding session, threshold, parties, PK |
| Scalar encoding      | 32-byte little-endian, canonical (reduced mod q)            |
| Point encoding       | 32-byte compressed Edwards y-coordinate                     |
| Group commitment     | `R = Σ (D_j + ρ_j·E_j)` per RFC 9591                        |
| Partial verification | Per-signer before aggregation with attributable blame       |
| Signature format     | Standard 64-byte `R                                         |     | S`  |

### Differences from RFC 9591

- Domain separation is more granular: session ID, threshold, full participant set, and group public key are bound into every transcript, providing stronger session isolation than the minimal RFC 9591 definition.
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
sess, out, err := StartReshare(oldShare, config, newParties)
out, err := sess.HandleReshareMessage(env)
newShare, ok := sess.KeyShare()
```

### BIP32 HD

```go
childPub, shift, childChain, err := DeriveBIP32(pubKey, chainCode, path)
shiftedPub, err := DerivePublicKey(pubKey, additiveShift)
```

### Convenience

```go
sig, err := Sign(message, shares)
sig, err := SignWithOptions(message, shares, opts)
share, err := UnmarshalKeyShare(raw)
```

## Scope and Limitations

- Signs raw messages only. Ed25519ph and Ed25519ctx are not exposed.
- No network transport, storage encryption, or peer authentication.
- Group public key is a standard Ed25519 key; no on-chain contract verification is provided.
- The protocol depends on Fiat-Shamir challenges via SHA-256/SHA-512; the random oracle assumption applies.
