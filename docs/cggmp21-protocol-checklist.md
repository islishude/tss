# CGGMP21 Protocol Checklist

This document maps each protocol phase from the CGGMP21 paper (IACR ePrint
2021/060) to this implementation. It is structured for independent review
readiness: each row maps a paper requirement to its code location and current
status.

## Keygen

### Round 1 (single round)

| Step                                                              | Paper § | Public inputs                                              | Witness               | Transcript inputs                                                  | Verifier checks                                                                                     | Code location                                                                                    | Status |
| ----------------------------------------------------------------- | ------- | ---------------------------------------------------------- | --------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------ | ------------- | --- | ------------ | --- | --------------------------------------- | ---- |
| Sample Shamir polynomial f_i(x) over secp256k1 order              | 3.1     | —                                                          | Coefficients (random) | —                                                                  | —                                                                                                   | `shamir.RandomPolynomial` via `StartKeygenWithOptions` in `keygen.go`                            | DONE   |
| Compute public commitments C_i = \[c_i0\]G, ..., \[c_i(t-1)\]G    | 3.1     | —                                                          | Coefficients          | —                                                                  | —                                                                                                   | `secp.ScalarBaseMult` per coefficient in `keygen.go`                                             | DONE   |
| Generate Paillier keypair (N = p·q with safe primes p≡q≡3 mod 4)  | 3.1     | —                                                          | p, q                  | —                                                                  | —                                                                                                   | `pai.GenerateKey` in `keygen.go`                                                                 | DONE   |
| Prove Paillier modulus (Π^fac)                                    | 3.1     | N, party id                                                | p, q                  | Outer proof domain, party id, N bit-length, small-factor digest    | Modulus bit length, odd composite, small-factor digest, Fiat-Shamir challenge, Σ-protocol sqrt-of-1 | `zkpai.ProveModulus` / `zkpai.VerifyModulus` in `keygen.go`, `proofs.go`                         | DONE   |
| Prove secp256k1 share (Schnorr)                                   | 3.1     | Public verification share V_i                              | Secret share x_i      | Outer proof domain, public key, point, commitment, transcript hash | Point decoding, Fiat-Shamir challenge, Schnorr relation                                             | `schnorr.Prove` / `schnorr.Verify` in `keygen.go`                                                | DONE   |
| HD chain code contribution (optional)                             | —       | chain_code_i (32 bytes)                                    | Random bytes          | XOR-aggregated into key share                                      | Length 32                                                                                           | `keygen.go` (EnableHD path)                                                                      | DONE   |
| Broadcast commitments + Paillier public key + Π^fac + chain code  | 3.1     | All of the above                                           | —                     | —                                                                  | Payload decode, field completeness                                                                  | `marshalKeygenCommitmentsPayload` / `unmarshalKeygenCommitmentsPayload` in `payload_encoding.go` | DONE   |
| Send private Shamir shares point-to-point                         | 3.1     | —                                                          | f_i(j)                | —                                                                  | Confidential envelope, correct recipient                                                            | `keygen.go` share delivery loop                                                                  | DONE   |
| Receive and verify private shares against commitments             | 3.1     | Commitments C_j                                            | —                     | —                                                                  | f_j(i)·G = Σ c_jk·i^k                                                                               | `shamir.VerifyShare` in `HandleKeygenMessage`                                                    | DONE   |
| Compute aggregated secret share x_i = Σ f_j(i)                    | 3.1     | —                                                          | —                     | —                                                                  | —                                                                                                   | `keygen.go` final aggregation                                                                    | DONE   |
| Compute keygen transcript hash                                    | 3.1     | All commitments, all Paillier public keys, all chain codes | —                     | SHA-256(domain_label                                               |                                                                                                     | commitments                                                                                      |        | paillier_keys |     | chain_codes) | —   | `keygen.go` `keygenTranscriptHashLabel` | DONE |
| Store complete KeyShare (share + commitments + Paillier + proofs) | 3.1     | —                                                          | —                     | —                                                                  | Canonical TLV encoding via `MarshalBinary`                                                          | `encoding.go` KeyShare marshal/unmarshal                                                         | DONE   |

### Keygen Abort Conditions

| Condition                               | Round | Evidence       | Code location                       |
| --------------------------------------- | ----- | -------------- | ----------------------------------- |
| Duplicate commitments from same sender  | 1     | No (duplicate) | `HandleKeygenMessage`               |
| Duplicate share from same sender        | 1     | No (duplicate) | `HandleKeygenMessage`               |
| Malformed commitment payload            | 1     | ProtocolError  | `unmarshalKeygenCommitmentsPayload` |
| Malformed share payload                 | 1     | ProtocolError  | `unmarshalKeygenSharePayload`       |
| Invalid Paillier public key             | 1     | Blame.Evidence | `pai.PublicKey.Validate`            |
| Invalid modulus proof (Π^fac)           | 1     | Blame.Evidence | `zkpai.VerifyModulus`               |
| Share verification failure              | 1     | Blame.Evidence | `shamir.VerifyShare`                |
| Chain code length mismatch (HD)         | 1     | ProtocolError  | `keygen.go`                         |
| Wrong session, round, sender membership | 1     | ProtocolError  | `env.ValidateBasic`                 |

## Presign

### Round 1 — Published

| Step                                                  | Paper § | Public inputs       | Witness           | Transcript inputs                                                                                   | Verifier checks                                                                           | Code location                                                   | Status                                                               |
| ----------------------------------------------------- | ------- | ------------------- | ----------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------- | ---- |
| Sample k_i, gamma_i (random nonces)                   | 4.1     | —                   | k_i, gamma_i      | —                                                                                                   | —                                                                                         | `secp.RandomScalar` in `StartPresign`                           | DONE                                                                 |
| Compute Gamma_i = gamma_i·G                           | 4.1     | Gamma_i             | gamma_i           | —                                                                                                   | —                                                                                         | `secp.ScalarBaseMult` in `StartPresign`                         | DONE                                                                 |
| Encrypt k_i under own Paillier key: Enc_i(k_i)        | 4.1     | Enc_i(k_i)          | k_i, randomness ρ | —                                                                                                   | —                                                                                         | `pai.Encrypt` via `mta.Start`                                   | DONE                                                                 |
| Prove Enc_i(k_i) with EncScalarProof (Π^Eq)           | 4.1     | Enc_i(k_i), Gamma_i | k_i, ρ            | Outer proof domain, Paillier PK, ciphertext, scalar commitment, cipher commitment, point commitment | Cipher validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation | `zkpai.ProveEncScalar` / `zkpai.VerifyEncScalar` in `mta.Start` | DONE                                                                 |
| Prove Enc_i(k_i) with EncRangeProof (                 | k_i     | < q)                | 4.1               | Bound q                                                                                             | k_i                                                                                       | Independent Fiat-Shamir challenge, transcript hash              | Transcript linkage, response linkage, order bound, digest, challenge | `zkpai.ProveEncRange` / `zkpai.VerifyEncRange` in `mta.Start` | DONE |
| Broadcast Gamma_i + Enc_i(k_i) + proofs + Paillier PK | 4.1     | All of the above    | —                 | —                                                                                                   | Payload decode, Paillier key match with keygen                                            | `marshalPresignRound1Payload` / `unmarshalPresignRound1Payload` | DONE                                                                 |

### Round 2 — Pairwise MtA

| Step                                                                                       | Paper § | Public inputs                         | Witness                           | Transcript inputs                                                                                                         | Verifier checks                                                                            | Code location                                               | Status |
| ------------------------------------------------------------------------------------------ | ------- | ------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | ------ | ------------------------------------- | ---- |
| Compute round-1 echo hash                                                                  | 4.2     | —                                     | —                                 | SHA-256(echo_label                                                                                                        |                                                                                            | all round-1 payload hashes)                                 | —      | `presignRound1EchoLabel` in `sign.go` | DONE |
| MtA for delta (k × gamma): Respond to Enc_j(k_j) with Enc_j(k_j·gamma_i + beta_ij)         | 4.2     | Response ciphertext, MTAResponseProof | gamma_i, beta_ij, β randomness    | Outer proof domain, Paillier PK, input ciphertext, response ciphertext, scalar commit, beta commit, cipher commit, nonces | Cipher validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relations | `mta.Respond` with constant-time `paillierct` in `mta.go`   | DONE   |
| MtA for sigma (k × x): Respond to Enc_j(k_j) with Enc_j(k_j·xBar_i + betaHat_ij)           | 4.2     | Response ciphertext, MTAResponseProof | xBar_i, betaHat_ij, β' randomness | Same as above with "sigma" kind label                                                                                     | Same as above                                                                              | `mta.Respond` with constant-time `paillierct` in `mta.go`   | DONE   |
| MtA Finish (receive delta response): Decrypt, verify proof, derive alpha_ij, beta_ji       | 4.2     | —                                     | Paillier λ, μ                     | Decryption via constant-time `paillierct.Decrypt`                                                                         | Proof verification, echo hash equality                                                     | `mta.Finish` in `mta.go`, `sign.go` presign round 2 handler | DONE   |
| MtA Finish (receive sigma response): Decrypt, verify proof, derive alphaHat_ij, betaHat_ji | 4.2     | —                                     | Paillier λ, μ                     | Decryption via constant-time `paillierct.Decrypt`                                                                         | Proof verification, echo hash equality                                                     | `mta.Finish` in `mta.go`, `sign.go` presign round 2 handler | DONE   |
| Send pairwise delta/sigma responses + echo hash                                            | 4.2     | Response messages + echo              | —                                 | —                                                                                                                         | Point-to-point confidential envelopes                                                      | `marshalPresignRound2Payload`                               | DONE   |

### Round 3 — delta_i broadcast

| Step                                                            | Paper § | Public inputs                                          | Witness                           | Transcript inputs     | Verifier checks                       | Code location                                        | Status |
| --------------------------------------------------------------- | ------- | ------------------------------------------------------ | --------------------------------- | --------------------- | ------------------------------------- | ---------------------------------------------------- | ------ | ------- | --- | ----------------------------------------- | ---- |
| Compute delta_i = k_i·gamma_i + Σ alpha_ij + Σ beta_ji          | 4.3     | delta_i                                                | k_i, gamma_i, all alpha, all beta | —                     | —                                     | `sign.go` delta computation                          | DONE   |
| Broadcast delta_i                                               | 4.3     | delta_i                                                | —                                 | —                     | —                                     | `marshalPresignRound3Payload`                        | DONE   |
| Compute group delta = Σ delta_i                                 | 4.3     | —                                                      | —                                 | —                     | —                                     | `sign.go` completion                                 | DONE   |
| Compute R = delta⁻¹ · Gamma (where Gamma = Σ Gamma_i)           | 4.3     | —                                                      | —                                 | —                     | —                                     | `secp` point/scalar operations                       | DONE   |
| Compute r = R.x mod q                                           | 4.3     | —                                                      | —                                 | —                     | —                                     | `secp` field operations                              | DONE   |
| Compute presign transcript hash                                 | 4.3     | All round 1 payloads, all round 2 payloads, all deltas | —                                 | SHA-256(presign_label |                                       | ordered round 1/2 payloads                           |        | deltas) | —   | `presignTranscriptHashLabel` in `sign.go` | DONE |
| Store Presign record (k_i, chi_i, R, r, delta, transcript hash) | 4.3     | —                                                      | —                                 | —                     | Canonical TLV encoding, consumed flag | `MarshalBinary` / `UnmarshalBinary` in `encoding.go` | DONE   |

### Presign Abort Conditions

| Condition                                  | Round | Evidence       | Code location                   |
| ------------------------------------------ | ----- | -------------- | ------------------------------- |
| Duplicate round 1 / 2 / 3 from same sender | 1-3   | No (duplicate) | `HandlePresignMessage`          |
| Malformed Gamma point                      | 1     | Blame.Evidence | `unmarshalPresignRound1Payload` |
| Paillier key mismatch with keygen          | 1     | Blame.Evidence | `HandlePresignMessage` round 1  |
| Invalid EncScalarProof / EncRangeProof     | 1     | Blame.Evidence | `mta.VerifyStart`               |
| Round-1 echo hash mismatch                 | 2     | Blame.Evidence | `HandlePresignMessage` round 2  |
| Invalid MTAResponseProof (delta or sigma)  | 2     | Blame.Evidence | `mta.Finish` → `VerifyResponse` |
| Missing round-2 response from any signer   | 2     | ProtocolError  | `HandlePresignMessage`          |
| Malformed delta_i scalar                   | 3     | Blame.Evidence | `unmarshalPresignRound3Payload` |
| Group commitment R is identity             | —     | ProtocolError  | presign completion              |

## Online Signing

### Round 1 (single round)

| Step                                                                     | Paper § | Public inputs        | Witness    | Transcript inputs | Verifier checks               | Code location                                   | Status |
| ------------------------------------------------------------------------ | ------- | -------------------- | ---------- | ----------------- | ----------------------------- | ----------------------------------------------- | ------ |
| Mark presign consumed (nonce-reuse guard)                                | 5       | —                    | —          | —                 | —                             | `MarkPresignConsumed` in `presign_lifecycle.go` | DONE   |
| Compute s_i = m·k_i + r·chi_i mod q                                      | 5       | s_i                  | k_i, chi_i | —                 | —                             | `StartSignDigest` in `sign.go`                  | DONE   |
| Optionally add additive shift: s_i = m·k_i + r·(chi_i + k_i·shift) mod q | 5       | s_i, shift           | —          | —                 | Shifted public key derivation | `StartSignDigestWithOptions`                    | DONE   |
| Broadcast s_i + presign transcript hash                                  | 5       | s_i, transcript hash | —          | —                 | —                             | `marshalSignPartialPayload`                     | DONE   |
| Verify received s_i: presign transcript hash match                       | 5       | —                    | —          | —                 | `sha256.Equal`                | `HandleSignMessage`                             | DONE   |
| Aggregate s = Σ s_i mod q                                                | 5       | —                    | —          | —                 | —                             | `sign.go` aggregation                           | DONE   |
| Apply low-S normalization (s ← min(s, q-s))                              | 5       | —                    | —          | —                 | —                             | `sign.go` lowS path                             | DONE   |
| Verify ECDSA signature (r, s) against derived public key                 | 5       | —                    | —          | —                 | `secp.VerifyDigest`           | `sign.go`                                       | DONE   |

### Online Signing Abort Conditions

| Condition                               | Round | Evidence       | Code location         |
| --------------------------------------- | ----- | -------------- | --------------------- |
| Presign already consumed                | 1     | ProtocolError  | `MarkPresignConsumed` |
| Presign transcript hash mismatch        | 1     | Blame.Evidence | `HandleSignMessage`   |
| Duplicate partial from same signer      | 1     | No (duplicate) | `HandleSignMessage`   |
| Aggregate ECDSA verification failure    | —     | Blame.Evidence | `sign.go` aggregation |
| Wrong session, round, sender membership | 1     | ProtocolError  | `env.ValidateBasic`   |

## MtA Protocol (internal/mta)

| Step                                                                    | Paper § | Public inputs                      | Witness    | Verifier checks                                                       | Code location                        | Status |
| ----------------------------------------------------------------------- | ------- | ---------------------------------- | ---------- | --------------------------------------------------------------------- | ------------------------------------ | ------ |
| Start: Enc(a) + EncScalarProof + EncRangeProof                          | 4.2     | ciphertext, enc_proof, range_proof | a, ρ       | Cipher validity, enc proof, range proof                               | `mta.Start` / `mta.VerifyStart`      | DONE   |
| Respond: c_resp = Enc(beta + a·b) + MTAResponseProof                    | 4.2     | response_ciphertext, proof         | b, beta, β | Constant-time c^b via `paillierct`, proof verification                | `mta.Respond` / `mta.VerifyResponse` | DONE   |
| Finish: Decrypt c_resp → alpha = Dec(c_resp) mod q, with ZK proof check | 4.2     | —                                  | λ, μ       | Constant-time Decrypt via `paillierct`, proof check, alpha derivation | `mta.Finish`                         | DONE   |

### Constant-Time Paillier Private-Key Operations

| Operation                        | Implementation                                                       | Location                             | Status |
| -------------------------------- | -------------------------------------------------------------------- | ------------------------------------ | ------ |
| c^λ mod n² (Decrypt)             | `filippo.io/bigmod` with ciphertext blinding                         | `internal/paillier/paillierct/ct.go` | DONE   |
| c^b mod n² (MtA Respond)         | `filippo.io/bigmod` (no blinding — ZK proof verifies exact relation) | `internal/paillier/paillierct/ct.go` | DONE   |
| Fixed-length big-endian encoding | `secret.Scalar` type                                                 | `internal/secret/secret.go`          | DONE   |

## Proof Inventory

| Proof                    | Paper § | Statement                                             | Witness    | Fields                                                                                                               | Location                                                              | Status |
| ------------------------ | ------- | ----------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------ |
| Π^fac (ModulusProof)     | 5.1     | Knowledge of N = p·q with p≡q≡3 mod 4                 | p, q       | NBits, SmallFactorCheck, TranscriptHash, Commitment, Challenge, Response                                             | `internal/zk/paillier/proofs.go` `ProveModulus` / `VerifyModulus`     | DONE   |
| Π^Eq (EncScalarProof)    | 4.1     | Enc(a) and a·G share scalar a                         | a, ρ       | Ciphertext, ScalarCommitment, CipherCommitment, PointCommitment, Challenge, Response                                 | `internal/zk/paillier/proofs.go` `ProveEncScalar` / `VerifyEncScalar` | DONE   |
| EncRangeProof            | 4.1     | \|a\| < q (secp256k1 order)                           | a          | Bound, Challenge, Response, TranscriptHash (independent Fiat-Shamir, not coupled to EncScalarProof)                  | `internal/zk/paillier/proofs.go` `ProveEncRange` / `VerifyEncRange`   | DONE   |
| Π^mta (MTAResponseProof) | 4.2     | c_resp = Enc(beta + a·b) given Enc(a)                 | b, beta, β | ScalarCommitment, BetaCommitment, CipherCommitment, Nonce1, Nonce2, Response, Challenge, CipherDelta, TranscriptHash | `internal/zk/paillier/proofs.go` `ProveResponse` / `VerifyResponse`   | DONE   |
| Π^log (LogProof)         | 6.2     | Enc(a) and A = a·G share scalar a (used in resharing) | a, ρ       | Point, CipherCommitment, PointCommitment, Response, Randomness, TranscriptHash                                       | `internal/zk/paillier/proofs.go` `ProveLog` / `VerifyLog`             | DONE   |
| SchnorrProof             | 3.1     | Knowledge of discrete log of V_i = x_i·G              | x_i        | Point, Commitment, Challenge, Response, TranscriptHash                                                               | `internal/zk/schnorr/schnorr.go`                                      | DONE   |

### Missing CGGMP21 Proofs (Not Yet Implemented)

| Proof | Paper § | Purpose                                   | Notes                                                                             |
| ----- | ------- | ----------------------------------------- | --------------------------------------------------------------------------------- |
| Π^prm | 3.1     | Primality proof for Paillier modulus      | GenerateKey uses safe primes; currently validated via Π^fac and structural checks |
| Π^Enc | 4.1     | Encryption proof (full range + knowledge) | Currently covered by Π^Eq + EncRangeProof combination                             |

## Resharing

| Step                                                    | Paper § | Public inputs         | Witness               | Transcript inputs                                   | Verifier checks                                                          | Code location                                        | Status |
| ------------------------------------------------------- | ------- | --------------------- | --------------------- | --------------------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------- | ------ |
| Sample zero-constant-term polynomial                    | 6.1     | —                     | Coefficients (random) | —                                                   | —                                                                        | `shamir.RandomPolynomial(..., 0)` in `reshare.go`    | DONE   |
| Generate new Paillier keypair                           | 6.1     | —                     | p', q'                | —                                                   | —                                                                        | `pai.GenerateKey` in `reshare.go`                    | DONE   |
| Prove new modulus (Π^fac)                               | 6.1     | N', party id          | p', q'                | Reshare Paillier domain                             | Same as keygen Π^fac                                                     | `zkpai.ProveModulus` with `resharePaillierDomain`    | DONE   |
| Prove old share equals new verification share (Π^log)   | 6.2     | Enc(x_i_old), V_i_new | x_i, ρ                | Point, cipher commit, point commit, transcript hash | Point decoding, Fiat-Shamir challenge, Paillier relation, curve relation | `zkpai.ProveLog` / `zkpai.VerifyLog` in `reshare.go` | DONE   |
| Broadcast commitments + new Paillier PK + Π^fac + Π^log | 6.1-6.2 | All of the above      | —                     | Reshare transcript hash                             | Payload decode                                                           | `reshare.go`                                         | DONE   |
| Deliver private shares point-to-point                   | 6.1     | —                     | shares                | —                                                   | Confidential envelope                                                    | `reshare.go`                                         | DONE   |
| Verify incoming shares against commitments              | 6.1     | Commitments           | —                     | —                                                   | `shamir.VerifyShare`                                                     | `reshare.go`                                         | DONE   |
| Compute new share = old_share + Σ received_shares       | 6.1     | —                     | —                     | —                                                   | —                                                                        | `reshare.go`                                         | DONE   |

## Identifiable Abort Evidence

| Evidence field                            | Bound to                   | When populated                         | Code location |
| ----------------------------------------- | -------------------------- | -------------------------------------- | ------------- |
| parties_hash                              | Ordered participant set    | Keygen, reshare verification failures  | `evidence.go` |
| signer_set_hash                           | Ordered signer set         | Presign, signing verification failures | `evidence.go` |
| public_key_hash                           | Group public key           | All verification failures              | `evidence.go` |
| keygen_transcript_hash                    | Keygen transcript          | Presign failures (when available)      | `evidence.go` |
| presign_transcript_hash                   | Presign transcript         | Online signing failures                | `evidence.go` |
| paillier_public_keys_hash                 | All Paillier public keys   | Paillier-related failures              | `evidence.go` |
| commitments_hash                          | Group commitments          | Keygen commitment validation failures  | `evidence.go` |
| delta_response_hash / sigma_response_hash | MtA response payloads      | MtA proof verification failures        | `evidence.go` |
| r_hash / s_hash / digest_hash             | ECDSA signature components | Aggregate verification failures        | `evidence.go` |

Evidence NEVER contains: private shares, nonces (k_i, gamma_i), Paillier private key material (λ, μ, p, q), presign secret material, or raw secret-bearing payloads.

## Domain Separation Summary

| Protocol phase              | Domain label                                   | Code location |
| --------------------------- | ---------------------------------------------- | ------------- |
| Keygen commitments          | `cggmp21-secp256k1-keygen-commitments-v1`      | `keygen.go`   |
| Keygen transcript           | `cggmp21-secp256k1-keygen-transcript-v1`       | `keygen.go`   |
| Presign transcript          | `cggmp21-secp256k1-presign-transcript-v1`      | `sign.go`     |
| Presign round-1 echo        | `cggmp21-secp256k1-presign-round1-echo-v1`     | `sign.go`     |
| MtA delta response evidence | `cggmp21-secp256k1-mta-response-evidence-v1`   | `sign.go`     |
| Aggregate sign evidence     | `cggmp21-secp256k1-aggregate-sign-evidence-v1` | `sign.go`     |
| Reshare transcript          | `cggmp21-secp256k1-reshare-transcript-v1`      | `reshare.go`  |
| Reshare Paillier modulus    | `reshare.paillier-modulus` (outer domain)      | `domain.go`   |
| MtA start (delta/sigma)     | Outer proof domain (per-initiator)             | `domain.go`   |
| Modulus proof               | Outer proof domain (per-party)                 | `domain.go`   |
| Π^log (reshare)             | Outer proof domain                             | `domain.go`   |
| Schnorr share proof         | Outer proof domain                             | `domain.go`   |
| Party set hash              | `cggmp21-secp256k1-party-set-v1`               | `evidence.go` |
| Paillier public shares hash | `cggmp21-secp256k1-paillier-public-shares-v1`  | `evidence.go` |

## Remaining Review Items

| Item                                                   | Priority | Notes                                                                                  |
| ------------------------------------------------------ | -------- | -------------------------------------------------------------------------------------- |
| Add Π^prm (primality proof)                            | P0       | Currently rely on GenerateKey safe-prime enforcement + Π^fac structural checks         |
| Add Π^Enc (full encryption proof)                      | P0       | Currently covered by Π^Eq + EncRangeProof combination; need equivalence proof          |
| Independent cryptographic review of all proofs         | P0       | Required before removing experimental warning                                          |
| Identifiable abort completeness review                 | P0       | All public-input evidence fields implemented; review against full CGGMP21 abort matrix |
| BIP32 / SLIP10 path derivation                         | P2       | Not in v1 scope                                                                        |
| Proactive refresh (periodic, without group-key change) | P2       | Resharing infrastructure exists; proactive scheduling not implemented                  |
