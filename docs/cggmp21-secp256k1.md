# CGGMP21 secp256k1

The `cggmp21/secp256k1` package implements a CGGMP21-style ([ePrint 2021/060](https://eprint.iacr.org/2021/060)) threshold ECDSA protocol over the secp256k1 curve. The ZK proof layer is prepared for independent review but **not yet audited** — the experimental warning stays until review is complete.

## Protocol Overview

| Phase   | Rounds | Description                                                                  |
| ------- | ------ | ---------------------------------------------------------------------------- |
| Keygen  | 2      | DKG with Paillier key setup, ZK proofs, and mandatory confirmation evidence. |
| Presign | 3      | Offline phase: nonce sharing via MtA, produces `Presign` record.             |
| Sign    | 1      | Online phase: fast single-round partial signature exchange.                  |
| Refresh | 1      | Key-share refresh with Paillier key rotation; fixed party set and threshold. |
| Reshare | 1      | Party-set/threshold resharing with old dealers and new receivers.            |

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
    PaillierProof           []byte        // Πmod modulus proof
    PaillierPublicKeys      []PaillierPublicShare
    RingPedersenParams      []byte        // local (N,s,t)
    RingPedersenProof       []byte        // Πprm Ring-Pedersen proof
    RingPedersenPublic      []RingPedersenPublicShare
    PaillierProofSessionID  tss.SessionID
    PaillierProofDomain     string
    ShareProof              []byte        // Schnorr proof of discrete-log knowledge
    KeygenTranscriptHash    []byte
    LogCiphertext           []byte        // Πlog* ciphertext (LogStarProof): Enc(x_i, ρ) under own Paillier key
    LogProof                []byte        // Πlog* proof (LogStarProof) of discrete-log equality with Ring-Pedersen commitment
    KeygenConfirmations     [][]byte      // canonical KeygenConfirmation evidence, sorted by Parties
    // logRandomness          []byte      // unexported: Paillier randomness for log ciphertext
}
```

The `secret` and `paillierPrivateKey` fields are unexported. `String()`, `GoString()`, `Format()`, and `MarshalJSON()` all redact them. `Destroy()` zeroes secret material in place. `KeyShare()` accessors return caller-owned copies.

### MPC Material Requirement

CGGMP21 key shares require full Paillier/ZK material and a complete keygen confirmation evidence set for the signing path. `requireMPCMaterial()` calls `Validate()`, which verifies every embedded `KeygenConfirmation` against the local keygen transcript, then checks that every party's Paillier public key is deserializable. Unconfirmed shares are rejected.

## Keygen

### Phase 1: Per-Party Setup

Each party `i`:

1. **Paillier key generation**: Generates a Paillier keypair `(N_i, λ_i, μ_i)` with safe primes `p ≡ q ≡ 3 mod 4`. Default modulus size is 2048 bits (minimum 768 bits for MtA correctness).

2. **ZK proofs**: Produces proofs bound to the keygen session domain:
   - **Πmod** — CGGMP24 Paillier-Blum modulus proof.
   - **Πprm** — CGGMP24 Ring-Pedersen parameter proof for `(N_i,s_i,t_i)`.

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

8. **Πlog\* proof**: Each party encrypts its aggregated secret share `x_j` under its own Paillier key and produces a Πlog\* proof (LogStarProof) binding the ciphertext to the party's verification share `V_j`, using the party's own Ring-Pedersen parameters for the commitment. This allows re-verification on load to detect out-of-context or tampered share material.

At this point the session has only local pending material. It is not a usable `KeyShare` and cannot be serialized, presigned with, signed with, or reshared.

### Phase 5: Keygen Confirmation

Each party broadcasts `cggmp21.secp256k1.keygen.confirmation` in keygen round 2. The payload is a canonical binary `KeygenConfirmation` binding the session ID, sender, threshold, ordered party set, group public key, keygen transcript hash, and commitments hash.

The keygen session stores one canonical confirmation from each party, sorted by `Parties`. Only after the full set verifies does `Complete()`/`KeyShare()` return a `KeyShare`. The serialized key share contains the full confirmation evidence set; old records without this evidence are invalid.

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
- party `i`'s Paillier public key

For each verifier `j != i`, signer `i` also sends a confidential Round 1 proof payload containing:

- a hash of the canonical public Round 1 payload
- `Πenc` (`EncProof`) proving `Enc_i(k_i)` encrypts a value in range under party `i`'s Paillier key

The `Πenc` proof is verifier-specific because its statement includes verifier `j`'s Ring-Pedersen auxiliary parameters. A proof generated for one verifier is rejected by another verifier. Round 2 is not emitted until both the peer's public Round 1 payload and the peer-to-local `Πenc` proof verify.

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
- Responder `j` computes response `Enc_i(γ_j·k_i + β_{i→j})` with Πaff-g proof (AffGProof).
- Result: `α_{i→j}` (initiator's share) and `β_{i→j}` (responder's share) such that `α_{i→j} + β_{i→j} = k_i·γ_j mod q`.

**Sigma MtA** (produces additive shares of `k·x`):

- Initiator `i` sends `Enc_i(k_i)` to responder `j`.
- Responder `j` computes response `Enc_i(x̄_j·k_i + β̂_{i→j})` with Πaff-g proof (AffGProof).
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

The transcript hash binds all signers' public round-1 material (Gamma, EncK, Paillier public key), all delta shares, R, r, and δ, preventing replay of presign material across sessions or signer sets. Per-verifier `Πenc` proof bytes are not persisted in the `Presign` record; they gate Round 2 emission during the live protocol.

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

### HD Derivation

Set `PresignContext.DerivationPath` before calling `StartPresignWithContext`. The BIP32 additive shift is derived and bound into the presign; online signing rejects a different key id, chain id, path, policy domain, or message domain.

## Presign Lifecycle

Presign records are strictly one-use:

```go
// Check before use:
if IsPresignConsumed(presign) { /* discard */ }

// StartSign marks Consumed before emitting any outbound message:
sess, out, err := StartSign(share, presign, sessionID, request)

// After signing, persist the consumed record:
consumed, _ := MarkPresignConsumed(presign)
encrypted, _ := tss.EncryptPresign(consumed.MarshalBinary(), passphrase)
```

`StartSign` sets `Consumed = true` **before** constructing the outbound signature envelope, so reuse fails before any partial signature leaves the process.

## Refresh

Refresh rotates key shares and Paillier keys while preserving the group public key and chain code. The participant set and threshold are **fixed** to the original key's parties and threshold.

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

Each party then encrypts its new share under its new Paillier key and produces a Πlog\* proof (LogStarProof) binding the ciphertext to the party's verification share. New Paillier material replaces the old. The keygen transcript hash is updated to the refresh session.

## Reshare

Reshare allows changing the participant set and threshold while preserving the group public key and chain code. A `ResharePlan` fixes the old party set, dealer subset, new receiver set, thresholds, old commitments, old verification shares, and session id before any message is accepted. Dealers are an agreed subset of old parties with size at least the old threshold. Parties in the new set act as receivers and generate fresh Paillier/Ring-Pedersen material for the new key share.

Each new receiver first:

1. Generates a new Paillier keypair with Πmod and Ring-Pedersen Πprm proofs.
2. Broadcasts the new Paillier public key, Ring-Pedersen parameters, and proofs.

Each dealer waits until all receiver auxiliary material has been collected, then:

1. Computes `λ_i` for interpolation at zero over the dealer set.
2. Samples `g_i(x)` with `g_i(0) = λ_i · x_i` and degree = `threshold_new - 1`.
3. Broadcasts dealer commitments for `g_i`, with `C_i0 = λ_i · V_i`.
4. Sends private shares `g_i(j)` to each party in the **new** participant set. The direct share payload binds the dealer, receiver, scalar share, and hash of the accepted dealer commitments.

Each new receiver:

1. Verifies each dealer commitment constant against the old verification share.
2. Verifies every dealer share against dealer commitments.
3. Aggregates `x'_j = Σ_i g_i(j) mod q`.
4. Aggregates dealer commitments and checks the degree-zero commitment equals the old group public key.

New-only participants call `StartReshareReceiver(plan, localParty, rng)`. Old-only dealers call `StartReshareDealer(oldShare, plan, rng)` and complete without a new `KeyShare`. Overlap parties call `StartReshareOverlap(oldShare, plan, rng)` and keep old and new secret material separate. `StartReshare` remains a convenience wrapper for old participants when a plan can be derived from the old key share.

The Πlog\* proof (LogStarProof, discrete-log equality with Ring-Pedersen commitment) is integrated into keygen, reshare, and refresh. Each `KeyShare` stores a ciphertext of its secret scalar under its own Paillier key together with a Πlog\* proof binding that ciphertext to the party's verification share. Re-verification on load catches out-of-context share material.

## BIP32 HD Derivation

HD derivation is implemented via `DeriveBIP32` and `DerivePublicKey` (same API shape as the frost/ed25519 package). Set `PresignContext.DerivationPath` before presign generation; the derived additive shift is stored in the presign and cannot be changed during online signing.

## Blame Evidence

CGGMP21 evidence covers every attributable failure point:

| Phase           | Evidence Kind         | When                                          |
| --------------- | --------------------- | --------------------------------------------- |
| Keygen          | `keygen_commitment`   | Invalid keygen public commitment.             |
| Keygen          | `keygen_paillier`     | Invalid Paillier key or modulus proof.        |
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

| Payload Type                                   | Direction      | Confidential | Content                                              |
| ---------------------------------------------- | -------------- | ------------ | ---------------------------------------------------- |
| `cggmp21.secp256k1.keygen.commitments`         | broadcast      | no           | Polynomial commitments + Paillier key + proofs       |
| `cggmp21.secp256k1.keygen.share`               | point-to-point | yes          | Scalar share for one recipient                       |
| `cggmp21.secp256k1.presign.round1`             | broadcast      | no           | `(Γ_i, Enc_i(k_i), PaillierPK)`                      |
| `cggmp21.secp256k1.presign.round1-proof`       | point-to-point | yes          | Public Round1 hash + verifier-specific Πenc proof    |
| `cggmp21.secp256k1.presign.round2`             | point-to-point | yes          | MtA response ciphertexts + Πaff-g proofs (AffGProof) |
| `cggmp21.secp256k1.presign.round3`             | broadcast      | no           | `δ_i` scalar share                                   |
| `cggmp21.secp256k1.sign.partial`               | broadcast      | no           | `s_i` partial + presign transcript hash              |
| `cggmp21.secp256k1.refresh.commitments`        | broadcast      | no           | Refresh polynomial commitments + new Paillier        |
| `cggmp21.secp256k1.refresh.share`              | point-to-point | yes          | Refresh scalar share                                 |
| `cggmp21.secp256k1.reshare.dealer_commitments` | broadcast      | no           | Old dealer weighted polynomial commitments           |
| `cggmp21.secp256k1.reshare.share`              | point-to-point | yes          | Old dealer scalar share for one new receiver         |
| `cggmp21.secp256k1.reshare.receiver_material`  | broadcast      | no           | New receiver Paillier/Ring-Pedersen material         |

## API Reference

### Keygen

```go
kg, out, err := StartKeygen(config)
kg, out, err := StartKeygenWithOptions(config, KeygenOptions{PaillierBits: 2048, EnableHD: true})
out, err := kg.HandleKeygenMessage(env)
share, ok := kg.Complete()
```

### Presign

```go
ctx := PresignContext{KeyID: "key-1", ChainID: "chain-1", PolicyDomain: "policy", MessageDomain: "app"}
ps, out, err := StartPresignWithContext(share, sessionID, signers, ctx)
out, err := ps.HandlePresignMessage(env)
presign, ok := ps.Presign()
```

### Online Signing

```go
request := SignRequest{Context: ctx, Message: message, LowS: true}
ss, out, err := StartSign(share, presign, sessionID, request)
out, err := ss.HandleSignMessage(env)
sig, ok := ss.Signature()
ok := VerifySignature(publicKey, request, sig)
```

### Refresh

```go
rs, out, err := StartRefresh(oldShare, config)
out, err := rs.HandleRefreshMessage(env)
newShare, ok := rs.KeyShare()
```

### Reshare

```go
plan, err := NewResharePlan(oldShare, sessionID, dealerParties, newParties, newThreshold, SecurityParameters{})
dealer, out, err := StartReshareDealer(oldShare, plan, rng)
receiver, out, err := StartReshareReceiver(plan, localParty, rng)
overlap, out, err := StartReshareOverlap(oldShare, plan, rng)
out, err := overlap.HandleMessage(env)
newShare, err := receiver.Result()
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
pubKey, sig, err := Sign(message, shares, ctx) // in-memory exchange
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
- Full CGGMP21 identifiable-abort security review (experimental warning active).
- Production-audited ZK proofs (see [docs/audit-guide.md](audit-guide.md)).
