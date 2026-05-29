# Cryptographic Audit Guide

This document maps every ZK proof to its CGGMP21 paper (ePrint 2021/060) specification for independent cryptographic review.

## Proof Inventory

| Proof                    | Paper § | Wire Type                                   | Code Location                                                                                                  |
| ------------------------ | ------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Π^fac (ModulusProof)     | 3.1     | <code>zk.paillier.modulus-proof</code>      | <code>internal/zk/paillier/proofs.go</code> <code>ProveModulus</code> / <code>VerifyModulus</code>             |
| Π^prm (PrimalityProof)   | 3.1     | <code>zk.paillier.primality-proof</code>    | <code>internal/zk/paillier/proofs.go</code> <code>ProvePrimality</code> / <code>VerifyPrimality</code>         |
| Π^Eq (EncScalarProof)    | 4.1     | <code>zk.paillier.enc-scalar-proof</code>   | <code>internal/zk/paillier/proofs.go</code> <code>ProveEncScalarAndRange</code> / <code>VerifyEncScalar</code> |
| EncRangeProof            | 4.1     | <code>zk.paillier.enc-range-proof</code>    | <code>internal/zk/paillier/proofs.go</code> <code>ProveEncScalarAndRange</code> / <code>VerifyEncRange</code>  |
| Π^Enc (EncryptionProof)  | 4.1     | <code>zk.paillier.encryption-proof</code>   | <code>internal/zk/paillier/proofs.go</code> <code>ProveEncryption</code> / <code>VerifyEncryption</code>       |
| Π^mta (MTAResponseProof) | 4.2     | <code>zk.paillier.mta-response-proof</code> | <code>internal/zk/paillier/proofs.go</code> <code>ProveMTAResponse</code> / <code>VerifyMTAResponse</code>     |
| Π^log (LogProof)         | 6.2     | <code>zk.paillier.log-proof</code>          | <code>internal/zk/paillier/proofs.go</code> <code>ProveLog</code> / <code>VerifyLog</code>                     |
| SchnorrProof             | 3.1     | <code>zk.schnorr.proof</code>               | <code>internal/zk/schnorr/schnorr.go</code>                                                                    |

---

## 1. Π^fac — Modulus Proof (Paillier-Blum Factorization)

**Statement:** Prover knows `p`, `q` such that `N = p·q` and `p ≡ q ≡ 3 (mod 4)`.

**Witness:** Paillier prime factors `p`, `q`.

**Protocol (Σ-protocol):**

1. Prover computes non-trivial sqrt of 1: `s = CRT(1 mod p, -1 mod q)`, then `s² ≡ 1 (mod N)`.
2. Prover samples random `r ← Z*_N`, commits `A = r² mod N`.
3. Challenge `e = challengeBits(SHA-256(modulusChallengeLabel || domain || party || PK_bytes || A), 128)`.
4. Response `z = r · s^e mod N`.
5. Verifier checks `z² ≡ A (mod N)`.

**Transcript inputs:** `modulusTranscriptLabel`, domain, party (4 bytes big-endian), public key bytes.

**Challenge inputs:** `modulusChallengeLabel`, domain, party, public key bytes, commitment A.

**Fiat-Shamir hash ordering:** `hashParts` with 4-byte length prefix per part.

**Verifier checks:**

- N is odd composite, `N ≢ 0 mod 3`, `N ≡ 1 mod 4`
- Small factor digest matches (primes 3–47)
- Transcript hash matches
- Challenge recomputed correctly
- `gcd(A, N) = 1`, `gcd(z, N) = 1`
- `z² ≡ A (mod N)`

---

## 2. Π^prm — Primality Proof

**Statement:** N = p·q where p and q have approximately equal bit-length (no trivial small factor).

**Witness:** Paillier prime factors `p`, `q`.

**Protocol (extends Π^fac):**

1. Prover computes non-trivial sqrt of 1 via CRT (same as Π^fac).
2. Prover commits A = r² mod N for random r.
3. Factor bit-length bound: max(BitLen(p), BitLen(q)) is bound into transcript.
4. Challenge e = challengeBits(SHA-256(primalityChallengeLabel || domain || party || PK_bytes || FactorBitLen || A), 128).
5. Response z = r · s^e mod N.
6. Verifier checks FactorBitLen ∈ [N.BitLen()/2 - 1, N.BitLen()/2 + 1] and z² ≡ A mod N.

**Transcript inputs:** `primalityTranscriptLabel`, domain, party, public key bytes, FactorBitLen (uint32), commitment A.

**Challenge inputs:** `primalityChallengeLabel`, domain, party, public key bytes, FactorBitLen (uint32), commitment A.

---

## 3. Π^Eq — Encrypted Scalar Proof

**Statement:** Ciphertext c = Enc(m, r) and public point V = m·G share the same scalar m.

**Witness:** Scalar m, randomness r.

**Protocol:**

1. Prover samples random α, ρ. Commits A_c = Enc(α, ρ), B = α·G, and publishes V = m·G.
2. Challenge e = SHA-256(encScalarChallengeLabel || transcript) mod q.
3. Response z = e·m + α, u = r^e · ρ mod N.
4. Verifier checks Enc(z, u) = A_c · c^e (mod N²) and z·G = B + e·V.

**Transcript:** `encScalarTranscriptLabel`, domain, pk_bytes, ciphertext, scalar_commitment V, cipher_commitment A_c, point_commitment B.

---

## 4. EncRangeProof

**Statement:** The scalar m encrypted in c satisfies m < q (secp256k1 order), using independent Fiat-Shamir challenge.

**Witness:** Scalar m, randomness r.

**Protocol:**

1. Prover samples α, ρ. Commits A_c = Enc(α, ρ), B = α·G.
2. Challenge e = SHA-256(encRangeChallengeLabel || transcript) mod q.
3. Response z = e·m + α, u = r^e · ρ mod N.
4. Verifier checks: z < q² + q, Enc(z, u) = A_c · c^e (mod N²), z·G = B + e·V.

**Transcript:** `encRangeTranscriptLabel`, domain, pk_bytes, ciphertext, scalar_commitment V, bound q, cipher_commitment A_c, point_commitment B.

**Digest:** SHA-256(encRangeDigestLabel || bound || challenge || response || transcript_hash).

---

## 5. Π^Enc — Unified Encryption Proof

**Statement:** Unifies Π^Eq and range constraint into a single Fiat-Shamir challenge. c = Enc(m, r), V = m·G, m < q.

**Witness:** Scalar m, randomness r.

**Protocol:** Same commitments as Π^Eq, but challenge and verification combine the range check into the same transcript. No separate range challenge needed.

**Transcript:** `encryptionTranscriptLabel`, domain, pk_bytes, ciphertext, scalar_commitment V, bound q, cipher_commitment A_c, point_commitment B.

**Challenge:** SHA-256(encryptionChallengeLabel || transcript) mod q.

**Verifier checks:**

- Enc(z, u) = A_c · c^e (mod N²)
- z·G = B + e·V
- z < q² + q (range bound)

---

## 6. Π^mta — MtA Response Proof

**Statement:** Response ciphertext c_resp = Enc(beta + a·b) given Enc(a), where b is the responder's secret scalar.

**Witness:** Scalar b, beta share, beta randomness β.

**Protocol:**

1. Prover commits: beta_comm = beta·G, b_nonce = μ·G, beta_nonce = ν·G, cipher_comm = Enc(a)^μ · Enc(ν, ρ).
2. Challenge e = SHA-256(mtaChallengeLabel || transcript) mod q.
3. Responses: z_b = e·b + μ, z_beta = e·beta + ν, u = β^e · ρ mod N.
4. Verifier checks Paillier relation and two curve relations.

**Transcript:** `mtaTranscriptLabel`, domain, pk_bytes, encA, response, b_commitment, beta_commitment, cipher_commitment, b_nonce, beta_nonce.

---

## 7. Π^log — Discrete Log Equality Proof

**Statement:** Ciphertext c = Enc(a, r) and curve point A = a·G share the same discrete log a. Used in CGGMP21 resharing (§6.2).

**Witness:** Scalar a, randomness r.

**Protocol:** Same structure as Π^Eq but binds the curve point A directly (not a separate scalar commitment). Challenge, response, and verification follow the same Σ-protocol pattern.

**Transcript:** `logTranscriptLabel`, domain, pk_bytes, ciphertext, point A, cipher_commitment, point_commitment.

---

## 8. Schnorr Proof

**Statement:** Knowledge of discrete log x of public key V = x·G. Used for share verification in CGGMP21 keygen (§3.1).

**Protocol:** Standard Schnorr Σ-protocol with Fiat-Shamir transformation. Commitment R = k·G, challenge = H(domain || V || R), response s = k + e·x.

---

## Domain Separation

All domain separation labels follow the format `<protocol>-<phase>-v1` and are included as the first hash block in every transcript:

| Protocol phase          | Domain label                                              |
| ----------------------- | --------------------------------------------------------- |
| Keygen commitments      | <code>cggmp21-secp256k1-keygen-commitments-v1</code>      |
| Keygen transcript       | <code>cggmp21-secp256k1-keygen-transcript-v1</code>       |
| Presign transcript      | <code>cggmp21-secp256k1-presign-transcript-v1</code>      |
| Presign round-1 echo    | <code>cggmp21-secp256k1-presign-round1-echo-v1</code>     |
| MtA response evidence   | <code>cggmp21-secp256k1-mta-response-evidence-v1</code>   |
| Aggregate sign evidence | <code>cggmp21-secp256k1-aggregate-sign-evidence-v1</code> |
| Reshare transcript      | <code>cggmp21-secp256k1-reshare-transcript-v1</code>      |
| Refresh transcript      | <code>cggmp21-secp256k1-refresh-transcript-v1</code>      |
| Outer proof domain      | <code>cggmp21-secp256k1-proof-domain-v1</code>            |

---

## Security Assumptions

1. **DDH over Paillier:** The Paillier encryption scheme is semantically secure under the Decisional Composite Residuosity (DCR) assumption.
2. **Discrete Log over secp256k1:** The EC-DL problem over secp256k1 is hard.
3. **Random Oracle Model:** All Fiat-Shamir transformations assume SHA-256 behaves as a random oracle.
4. **Safe Primes:** Paillier key generation produces Sophie Germain primes (p = 2p' + 1, q = 2q' + 1) for moduli ≥ 1024 bits, satisfying the Blum condition p ≡ q ≡ 3 (mod 4) automatically.
5. **Constant-time secret exponentiation:** All Paillier private-key operations (decrypt, MtA respond) use `filippo.io/bigmod` constant-time exponentiation. Ciphertext blinding is applied during decryption but NOT during MtA respond (the ZK proof verifies the exact ciphertext relationship).

---

## Known Limitations

- **Π^prm** does not provide a full GMR primality certificate. It proves equal factor size + Blum structure + safe-prime generation in keygen. A full primality proof (e.g., Pocklington or GMR) would require additional elliptic curve machinery.
- **EncRangeProof** range bound check (z < q² + q) is a statistical bound, not a strict zero-knowledge range proof. Combined with Π^Eq or Π^Enc, it provides heuristic soundness.
- **No side-channel hardening beyond constant-time exponentiation:** Memory access patterns, branch conditions, and cache timing of `math/big` in public-exponent paths are not hardened. Callers should use process isolation.
