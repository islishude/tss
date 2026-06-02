# CGGMP21 secp256k1

The `cggmp21/secp256k1` package implements a CGGMP21-style ([ePrint 2021/060](https://eprint.iacr.org/2021/060)) threshold ECDSA protocol over the secp256k1 curve. The ZK proof layer is prepared for independent review but **not yet audited** — the experimental warning stays until review is complete.

## Protocol Overview

| Phase   | Rounds | Description                                                      |
| ------- | ------ | ---------------------------------------------------------------- |
| Keygen  | 1      | DKG with Paillier key setup and ZK proofs.                       |
| Presign | 3      | Offline phase: nonce sharing via MtA, produces `Presign` record. |
| Sign    | 1      | Online phase: fast single-round partial signature exchange.      |
| Refresh | 1      | Key-share refresh with Paillier key rotation; fixed party set.   |
| Reshare | 1      | Key-share refresh with optional party-set changes.               |

The signing path never transmits or reconstructs private key shares or nonce shares. Each presign record is strictly one-use; reuse is caught before any partial signature leaves the process.

## KeyShare Structure

```go
type KeyShare struct {
    Version                 uint16
    Party                   tss.PartyID
    Threshold               int
    Parties                 []tss.PartyID
    PublicKey               []byte        // group secp256k1 public key (33 bytes compressed)
    ChainCode               []byte        // optional BIP32 chain code (32 bytes, XOR-aggregated)
    secret                  []byte        // unexported: local scalar share x_i (32 bytes)
    GroupCommitments        [][]byte
    VerificationShares      []VerificationShare
    PaillierPublicKey       []byte        // local Paillier public key (TLV-encoded)
    paillierPrivateKey      []byte        // unexported: local Paillier private key (λ, μ)
    PaillierProof           []byte        // Π^fac modulus proof
    PaillierPrimalityProof  []byte        // Π^prm primality proof
    PaillierPrimalityProofs [][]byte      // all parties' primality proofs
    PaillierPublicKeys      []PaillierPublicShare
    PaillierProofSessionID  tss.SessionID
    PaillierProofDomain     string
    ShareProof              []byte        // Schnorr proof of discrete-log knowledge
    KeygenTranscriptHash    []byte
}
```

The `secret` and `paillierPrivateKey` fields are unexported. `String()`, `GoString()`, `Format()`, and `MarshalJSON()` all redact them. `Destroy()` zeroes secret material in place. `KeyShare()` accessors return caller-owned copies.

### MPC Material Requirement

CGGMP21 key shares require full Paillier/ZK material for the signing path. `requireMPCMaterial()` rejects shares from old keygen flows that lack Paillier keys, modulus proofs, primality proofs, share proofs, or the keygen transcript hash.

## Keygen

### Phase 1: Per-Party Setup

Each party `i`:

1. **Paillier key generation**: Generates a Paillier keypair `(N_i, λ_i, μ_i)` with safe primes `p ≡ q ≡ 3 mod 4`. Default modulus size is 2048 bits (minimum 768 bits for MtA correctness).

2. **ZK proofs**: Produces two proofs bound to the keygen session domain:
   - **Π^fac** — knowledge of `N_i = p·q` factorization (modulus proof).
   - **Π^prm** — approximate equal bit-length of `p` and `q` (primality proof).

3. **Shamir polynomial**: Samples a random degree `t-1` polynomial:

   ```
   f_i(x) = a_{i,0} + a_{i,1}·x + … + a_{i,t-1}·x^{t-1}  mod q
   ```

   where `t` is the threshold and `q` is the secp256k1 order.

4. **HD chain code** (optional): Generates a random 32-byte chain-code share.

### Phase 2: Broadcast Commitments

Each party broadcasts:

- Polynomial commitments `C_{i,k} = a_{i,k}·G` for `k ∈ [0, t-1]`.
- Paillier public key (TLV-encoded).
- Π^fac proof.
- Π^prm proof.
- Optional chain-code share.

All bundled in a single `keygenCommitmentsPayload`.

### Phase 3: Private Share Distribution

Each party sends private Shamir shares to every other party:

```
s_{i→j} = f_i(j)  mod q
```

Sent with `ConfidentialRequired = true`.

### Phase 4: Completion

When all `n` parties' commitments and shares are received and verified:

1. **Share verification**: Each `s_{i→j}` checked against `C_{i,k}` via the standard Shamir commitment check.

2. **Secret aggregation**: `x_j = Σ_i s_{i→j} mod q`.

3. **Group public key**: `PK = Σ_i C_{i,0}` (aggregated degree-zero commitments).

4. **Verification shares**: `V_p = Σ_{k=0}^{t-1} (p^k · GC_k)` where `GC_k = Σ_i C_{i,k}`.

5. **Schnorr share proof**: Each party proves knowledge of `x_j` such that `V_j = x_j·G`, bound to the keygen transcript hash.

6. **Chain code** (HD): `chain = XOR_i chainCode_i`.

7. **Paillier proof domain**: The persisted local Π^fac is re-proved against `(PK, keygen_transcript_hash)` for out-of-context detection.

### Domain Separation

```
keygenCommitmentsHashLabel = "cggmp21-secp256k1-keygen-commitments-v1"
keygenTranscriptHashLabel  = "cggmp21-secp256k1-keygen-transcript-v1"
```

Paillier proof domains bind `(protocol, version, session, threshold, parties, self, proof_kind, paillier_pubkey)`. The key-share Paillier proof additionally binds `(group_public_key, keygen_transcript_hash)`.

## Presign (Offline Phase)

Presign produces a one-use `Presign` record containing local nonce shares. It must be run in advance of signing and the result persisted securely.

### Round 1: Nonce Commitments

Each signer `i` samples two local nonces:

```
k_i, γ_i ← Z_q
```

and broadcasts:

- `Γ_i = γ_i · G` (gamma commitment)
- `Enc_i(k_i)` — Paillier encryption of `k_i` under party `i`'s public key
- Π^Enc proof — unified encryption proof that the ciphertext and `Γ_i` commitment are consistent

Internally, each signer computes the Lagrange-adjusted secret:

```
x̄_i = λ_i · x_i   mod q
```

where `λ_i` is the Lagrange coefficient for signer `i` within the signer set.

### Round 1 Echo

Before entering round 2, each signer hashes all round-1 broadcasts into an echo hash. The echo is included in round 2 MtA messages. A mismatch between any two signers' echo hashes triggers an attributable abort, preventing a signer who received a different round-1 view from proceeding to pairwise MtA.

### Round 2: Pairwise MtA

For every ordered pair of distinct signers `(i, j)`, two MtA exchanges run in parallel:

**Delta MtA** (produces additive shares of `k·γ`):

- Initiator `i` sends `Enc_i(k_i)` to responder `j`.
- Responder `j` computes response `Enc_i(γ_j·k_i + β_{i→j})` with Π^mta proof.
- Result: `α_{i→j}` (initiator's share) and `β_{i→j}` (responder's share) such that `α_{i→j} + β_{i→j} = k_i·γ_j mod q`.

**Sigma MtA** (produces additive shares of `k·x`):

- Initiator `i` sends `Enc_i(k_i)` to responder `j`.
- Responder `j` computes response `Enc_i(x̄_j·k_i + β̂_{i→j})` with Π^mta proof.
- Result: `α̂_{i→j}` and `β̂_{i→j}` such that `α̂_{i→j} + β̂_{i→j} = k_i·x̄_j mod q`.

The MtA domain binds `(protocol, version, session, threshold, all_parties, signers, initiator, responder, mta_kind, group_pk, keygen_transcript, initiator_paillier_pk)`.

Each signer accumulates:

```
δ_i  = k_i·γ_i + Σ_{j≠i} α_{i→j} + Σ_{j≠i} β_{j→i}   mod q
χ_i  = k_i·x̄_i + Σ_{j≠i} α̂_{i→j} + Σ_{j≠i} β̂_{j→i}   mod q
```

### Round 3: Delta Broadcast

Each signer broadcasts `δ_i`. After collecting all deltas:

```
δ = Σ_i δ_i  mod q
Γ = Σ_i Γ_i
R = δ^{-1} · Γ
r = x(R) mod q
```

The `Presign` record stores `(k_i, χ_i, R, r, δ, transcript_hash)`. It is local-only and must not be shared with other parties.

### Presign Transcript

The transcript hash binds all signers' round-1 material (Gamma, EncK, EncKProof), all delta shares, R, r, and δ, preventing replay of presign material across sessions or signer sets.

## Online Signing

Online signing is a single round. For a 32-byte message digest `m`:

```
s_i = m·k_i + r·χ_i   mod q
```

The only outbound message is the scalar `s_i` together with the presign transcript hash. No private key share, nonce share, or Paillier secret material leaves the process.

### Aggregation

```
s = Σ_i s_i  mod q
```

Low-S normalization is applied by default (`s = min(s, q-s)`). The final ECDSA signature `(r, s)` is verified against the group public key before being returned. A failed verification returns `ProtocolError` with `EvidenceKindAggregateSign` blame.

### HD Additive Shift

Pass `SignOptions{AdditiveShift: shift}` to `StartSignDigestWithOptions`. Each signer adds `k_i·δ` to their local `χ_i`, and the resulting signature verifies against `DerivePublicKey(PK, shift)`.

## Presign Lifecycle

Presign records are strictly one-use:

```go
// Check before use:
if IsPresignConsumed(presign) { /* discard */ }

// StartSignDigest marks Consumed before emitting any outbound message:
sess, out, err := StartSignDigest(share, presign, sessionID, digest)

// After signing, persist the consumed record:
consumed, _ := MarkPresignConsumed(presign)
encrypted, _ := tss.EncryptPresign(consumed.MarshalBinary(), passphrase)
```

`StartSignDigest` sets `Consumed = true` **before** constructing the outbound signature envelope, so reuse fails before any partial signature leaves the process.

## Refresh

Refresh rotates key shares and Paillier keys while preserving the group public key and chain code. The participant set is **fixed** to the original key's parties.

Each party:

1. Generates a new Paillier keypair.
2. Produces Π^fac and Π^prm for the new key.
3. Samples a polynomial `g_i(x)` with `g_i(0) = 0`.
4. Broadcasts commitments + new Paillier public key + proofs.
5. Sends private refresh shares `g_i(j)` to each party.

Receivers verify shares, then:

```
x'_j = x_j + Σ_i g_i(j)   mod q
```

New Paillier material replaces the old. The keygen transcript hash is updated to the refresh session.

## Reshare

Reshare is similar to Refresh but allows changing the participant set and threshold. Existing parties act as dealers, and the new participant set may differ in size and identity.

Each existing party:

1. Generates a new Paillier keypair with Π^fac + Π^prm proofs.
2. Samples `g_i(x)` with `g_i(0) = 0` and degree = `threshold_new - 1`.
3. Broadcasts commitments + new Paillier public key + proofs.
4. Sends private shares to each party in the **new** participant set.

New participants only need to receive and verify — they don't need the old key share to participate.

The Π^log proof (discrete-log equality) is implemented but not yet wired into the reshare flow. See [docs/paillier-zk-proofs.md](paillier-zk-proofs.md) for review blockers.

## BIP32 HD Derivation

HD derivation is implemented via `DeriveBIP32` and `DerivePublicKey` (same API shape as the frost/ed25519 package). The additive shift is passed to `StartSignDigestWithOptions` and each signer applies `k_i·δ` locally.

## Blame Evidence

CGGMP21 evidence covers every attributable failure point:

| Phase           | Evidence Kind         | When                                          |
| --------------- | --------------------- | --------------------------------------------- |
| Keygen          | `keygen_commitment`   | Invalid Paillier key or proof.                |
| Keygen          | `keygen_share`        | DKG share fails commitment verification.      |
| Presign round 1 | `presign_round1`      | Invalid nonce commitment or encryption proof. |
| Presign round 2 | `presign_round2`      | Invalid MtA response or proof.                |
| Presign round 3 | `presign_round3`      | Invalid delta broadcast.                      |
| Online sign     | `sign_partial`        | Invalid online partial signature.             |
| Aggregation     | `aggregate_signature` | Final ECDSA signature fails verification.     |
| Refresh         | `refresh_share`       | Refresh share fails commitment verification.  |
| Reshare         | `reshare_share`       | Reshare share fails commitment verification.  |

Evidence records are deterministic JSON binding protocol context, payload hash, transcript hash, and public input hashes. They **never** contain private shares, nonces, or Paillier secret keys. `VerifyBlameEvidence` validates evidence against trusted session context (parties, signer set, public key, Paillier public keys, transcript hashes).

## Payload Types

| Payload Type                            | Direction      | Confidential | Content                                        |
| --------------------------------------- | -------------- | ------------ | ---------------------------------------------- |
| `cggmp21.secp256k1.keygen.commitments`  | broadcast      | no           | Polynomial commitments + Paillier key + proofs |
| `cggmp21.secp256k1.keygen.share`        | point-to-point | yes          | Scalar share for one recipient                 |
| `cggmp21.secp256k1.presign.round1`      | broadcast      | no           | `(Γ_i, Enc_i(k_i), Π^Enc, PaillierPK)`         |
| `cggmp21.secp256k1.presign.round2`      | point-to-point | yes          | MtA response ciphertexts + Π^mta proofs        |
| `cggmp21.secp256k1.presign.round3`      | broadcast      | no           | `δ_i` scalar share                             |
| `cggmp21.secp256k1.sign.partial`        | broadcast      | no           | `s_i` partial + presign transcript hash        |
| `cggmp21.secp256k1.refresh.commitments` | broadcast      | no           | Refresh polynomial commitments + new Paillier  |
| `cggmp21.secp256k1.refresh.share`       | point-to-point | yes          | Refresh scalar share                           |
| `cggmp21.secp256k1.reshare.commitments` | broadcast      | no           | Reshare commitments + new Paillier             |
| `cggmp21.secp256k1.reshare.share`       | point-to-point | yes          | Reshare scalar share                           |

## API Reference

### Keygen

```go
kg, out, err := StartKeygen(config)
kg, out, err := StartKeygenWithOptions(config, KeygenOptions{PaillierBits: 2048, EnableHD: true})
out, err := kg.HandleKeygenMessage(env)
share, ok := kg.KeyShare()
```

### Presign

```go
ps, out, err := StartPresign(share, sessionID, signers)
out, err := ps.HandlePresignMessage(env)
presign, ok := ps.Presign()
```

### Online Signing

```go
ss, out, err := StartSignDigest(share, presign, sessionID, digest)
// or with options:
ss, out, err := StartSignDigestWithOptions(share, presign, sessionID, digest, SignOptions{LowS: true, AdditiveShift: shift})
out, err := ss.HandleSignMessage(env)
sig, ok := ss.Signature()
ok := VerifyDigest(publicKey, digest, sig)
```

### Refresh

```go
rs, out, err := StartRefresh(oldShare, config)
out, err := rs.HandleRefreshMessage(env)
newShare, ok := rs.KeyShare()
```

### Reshare

```go
rs, out, err := StartReshare(oldShare, config, newParties)
out, err := rs.HandleReshareMessage(env)
newShare, ok := rs.KeyShare()
```

### Presign Lifecycle

```go
consumed, err := MarkPresignConsumed(presign)
ok := IsPresignConsumed(presign)
```

### Convenience

```go
share, err := UnmarshalKeyShare(raw)
presign, err := UnmarshalPresign(raw)
pubKey, sig, err := SignDigest(digest, shares) // in-memory exchange
```

## Constant-Time Guarantees

| Operation              | Implementation                                                      |
| ---------------------- | ------------------------------------------------------------------- |
| `c^λ mod n²` (decrypt) | `paillierct.ExpSecretBlinded` with blinding                         |
| `c^b mod n²` (MtA)     | `paillierct.ExpCT` (no blinding — ZK proof verifies exact relation) |
| `Enc(m, r)`            | `math/big.Int.Exp` (public exponent — acceptable)                   |

All Paillier secret exponents (`λ`, `μ`, MtA responder scalar `b`) are stored as `secret.Scalar` fixed-length bytes. They never expose `String()`, variable-length `Bytes()`, `BigInt()`, or JSON.

See [docs/security.md](security.md) for the full constant-time policy.

## Unsupported

- Network transport, storage encryption, peer authentication (caller responsibilities).
- Π^log proof not yet wired into reshare (implemented, pending integration).
- Full CGGMP21 identifiable-abort security review (experimental warning active).
- Production-audited ZK proofs (see [docs/audit-guide.md](audit-guide.md)).
