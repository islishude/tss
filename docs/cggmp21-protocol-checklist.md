# CGGMP21 Protocol Checklist

This document maps each protocol phase from the CGGMP21 paper (IACR ePrint
2021/060) to this implementation. It is structured for independent review
readiness: each row maps a paper requirement to its code location and current
status.

## Keygen

### Round 1 (single round)

| Step                                                              | Paper § | Public inputs                                              | Witness               | Transcript inputs                                                                       | Verifier checks                                                                                     | Code location                                                                                    | Status |
| ----------------------------------------------------------------- | ------- | ---------------------------------------------------------- | --------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------ |
| Sample Shamir polynomial f_i(x) over secp256k1 order              | 3.1     | —                                                          | Coefficients (random) | —                                                                                       | —                                                                                                   | `shamir.RandomPolynomial` via `StartKeygenWithOptions` in `keygen.go`                            | DONE   |
| Compute public commitments C_i = \[c_i0\]G, ..., \[c_i(t-1)\]G    | 3.1     | —                                                          | Coefficients          | —                                                                                       | —                                                                                                   | `secp.ScalarBaseMult` per coefficient in `keygen.go`                                             | DONE   |
| Generate Paillier keypair (N = p·q with safe primes p≡q≡3 mod 4)  | 3.1     | —                                                          | p, q                  | —                                                                                       | —                                                                                                   | `pai.GenerateKey` in `keygen.go`                                                                 | DONE   |
| Prove Paillier modulus (Π^fac)                                    | 3.1     | N, party id                                                | p, q                  | Outer proof domain, party id, N bit-length, small-factor digest                         | Modulus bit length, odd composite, small-factor digest, Fiat-Shamir challenge, Σ-protocol sqrt-of-1 | `zkpai.ProveModulus` / `zkpai.VerifyModulus` in `keygen.go`, `proofs.go`                         | DONE   |
| Prove secp256k1 share (Schnorr)                                   | 3.1     | Public verification share V_i                              | Secret share x_i      | Outer proof domain, public key, point, commitment, transcript hash                      | Point decoding, Fiat-Shamir challenge, Schnorr relation                                             | `schnorr.Prove` / `schnorr.Verify` in `keygen.go`                                                | DONE   |
| HD chain code contribution (optional)                             | —       | chain_code_i (32 bytes)                                    | Random bytes          | XOR-aggregated into key share                                                           | Length 32                                                                                           | `keygen.go` (EnableHD path)                                                                      | DONE   |
| Broadcast commitments + Paillier public key + Π^fac + chain code  | 3.1     | All of the above                                           | —                     | —                                                                                       | Payload decode, field completeness                                                                  | `marshalKeygenCommitmentsPayload` / `unmarshalKeygenCommitmentsPayload` in `payload_encoding.go` | DONE   |
| Send private Shamir shares point-to-point                         | 3.1     | —                                                          | f_i(j)                | —                                                                                       | Confidential envelope, correct recipient                                                            | `keygen.go` share delivery loop                                                                  | DONE   |
| Receive and verify private shares against commitments             | 3.1     | Commitments C_j                                            | —                     | —                                                                                       | f_j(i)·G = Σ c_jk·i^k                                                                               | `shamir.VerifyShare` in `HandleKeygenMessage`                                                    | DONE   |
| Compute aggregated secret share x_i = Σ f_j(i)                    | 3.1     | —                                                          | —                     | —                                                                                       | —                                                                                                   | `keygen.go` final aggregation                                                                    | DONE   |
| Compute keygen transcript hash                                    | 3.1     | All commitments, all Paillier public keys, all chain codes | —                     | <code>SHA-256(domain_label \|\| commitments \|\| paillier_keys \|\| chain_codes)</code> | —                                                                                                   | <code>keygen.go</code> <code>keygenTranscriptHashLabel</code>                                    | DONE   |
| Store complete KeyShare (share + commitments + Paillier + proofs) | 3.1     | —                                                          | —                     | —                                                                                       | Canonical TLV encoding via `MarshalBinary`                                                          | `encoding.go` KeyShare marshal/unmarshal                                                         | DONE   |

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

| Step                                                       | Paper § | Public inputs       | Witness           | Transcript inputs                                                                                   | Verifier checks                                                                           | Code location                                                                                  | Status |
| ---------------------------------------------------------- | ------- | ------------------- | ----------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------ |
| Sample k_i, gamma_i (random nonces)                        | 4.1     | —                   | k_i, gamma_i      | —                                                                                                   | —                                                                                         | `secp.RandomScalar` in `StartPresign`                                                          | DONE   |
| Compute Gamma_i = gamma_i·G                                | 4.1     | Gamma_i             | gamma_i           | —                                                                                                   | —                                                                                         | `secp.ScalarBaseMult` in `StartPresign`                                                        | DONE   |
| Encrypt k_i under own Paillier key: Enc_i(k_i)             | 4.1     | Enc_i(k_i)          | k_i, randomness ρ | —                                                                                                   | —                                                                                         | `pai.Encrypt` via `mta.Start`                                                                  | DONE   |
| Prove Enc_i(k_i) with EncScalarProof (Π^Eq)                | 4.1     | Enc_i(k_i), Gamma_i | k_i, ρ            | Outer proof domain, Paillier PK, ciphertext, scalar commitment, cipher commitment, point commitment | Cipher validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation | `zkpai.ProveEncScalar` / `zkpai.VerifyEncScalar` in `mta.Start`                                | DONE   |
| Prove Enc_i(k_i) with EncRangeProof (<code>k_i < q</code>) | 4.1     | Bound q             | k_i               | Independent Fiat-Shamir challenge, transcript hash                                                  | Transcript linkage, response linkage, order bound, digest, challenge                      | <code>zkpai.ProveEncRange</code> / <code>zkpai.VerifyEncRange</code> in <code>mta.Start</code> | DONE   |
| Broadcast Gamma_i + Enc_i(k_i) + proofs + Paillier PK      | 4.1     | All of the above    | —                 | —                                                                                                   | Payload decode, Paillier key match with keygen                                            | `marshalPresignRound1Payload` / `unmarshalPresignRound1Payload`                                | DONE   |

### Round 2 — Pairwise MtA

| Step                                                                                       | Paper § | Public inputs                         | Witness                           | Transcript inputs                                                                                                         | Verifier checks                                                                            | Code location                                                                                | Status |
| ------------------------------------------------------------------------------------------ | ------- | ------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- | ------ |
| Compute round-1 echo hash                                                                  | 4.2     | —                                     | —                                 | <code>SHA-256(echo_label \|\| all round-1 payload hashes)</code>                                                          | —                                                                                          | <code>presignRound1EchoLabel</code> in <code>sign.go</code>                                  | DONE   |
| MtA for delta (k × gamma): Respond to Enc_j(k_j) with Enc_j(k_j·gamma_i + beta_ij)         | 4.2     | Response ciphertext, MTAResponseProof | gamma_i, beta_ij, β randomness    | Outer proof domain, Paillier PK, input ciphertext, response ciphertext, scalar commit, beta commit, cipher commit, nonces | Cipher validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relations | <code>mta.Respond</code> with constant-time <code>paillierct</code> in <code>mta.go</code>   | DONE   |
| MtA for sigma (k × x): Respond to Enc_j(k_j) with Enc_j(k_j·xBar_i + betaHat_ij)           | 4.2     | Response ciphertext, MTAResponseProof | xBar_i, betaHat_ij, β' randomness | Same as above with "sigma" kind label                                                                                     | Same as above                                                                              | <code>mta.Respond</code> with constant-time <code>paillierct</code> in <code>mta.go</code>   | DONE   |
| MtA Finish (receive delta response): Decrypt, verify proof, derive alpha_ij, beta_ji       | 4.2     | —                                     | Paillier λ, μ                     | Decryption via constant-time <code>paillierct.Decrypt</code>                                                              | Proof verification, echo hash equality                                                     | <code>mta.Finish</code> in <code>mta.go</code>, <code>sign.go</code> presign round 2 handler | DONE   |
| MtA Finish (receive sigma response): Decrypt, verify proof, derive alphaHat_ij, betaHat_ji | 4.2     | —                                     | Paillier λ, μ                     | Decryption via constant-time <code>paillierct.Decrypt</code>                                                              | Proof verification, echo hash equality                                                     | <code>mta.Finish</code> in <code>mta.go</code>, <code>sign.go</code> presign round 2 handler | DONE   |
| Send pairwise delta/sigma responses + echo hash                                            | 4.2     | Response messages + echo              | —                                 | —                                                                                                                         | Point-to-point confidential envelopes                                                      | <code>marshalPresignRound2Payload</code>                                                     | DONE   |

### Round 3 — delta_i broadcast

| Step                                                            | Paper § | Public inputs                                          | Witness                           | Transcript inputs                                                               | Verifier checks                       | Code location                                                   | Status |
| --------------------------------------------------------------- | ------- | ------------------------------------------------------ | --------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------------------- | ------ |
| Compute delta_i = k_i·gamma_i + Σ alpha_ij + Σ beta_ji          | 4.3     | delta_i                                                | k_i, gamma_i, all alpha, all beta | —                                                                               | —                                     | `sign.go` delta computation                                     | DONE   |
| Broadcast delta_i                                               | 4.3     | delta_i                                                | —                                 | —                                                                               | —                                     | `marshalPresignRound3Payload`                                   | DONE   |
| Compute group delta = Σ delta_i                                 | 4.3     | —                                                      | —                                 | —                                                                               | —                                     | `sign.go` completion                                            | DONE   |
| Compute R = delta⁻¹ · Gamma (where Gamma = Σ Gamma_i)           | 4.3     | —                                                      | —                                 | —                                                                               | —                                     | `secp` point/scalar operations                                  | DONE   |
| Compute r = R.x mod q                                           | 4.3     | —                                                      | —                                 | —                                                                               | —                                     | `secp` field operations                                         | DONE   |
| Compute presign transcript hash                                 | 4.3     | All round 1 payloads, all round 2 payloads, all deltas | —                                 | <code>SHA-256(presign_label \|\| ordered round 1/2 payloads \|\| deltas)</code> | —                                     | <code>presignTranscriptHashLabel</code> in <code>sign.go</code> | DONE   |
| Store Presign record (k_i, chi_i, R, r, delta, transcript hash) | 4.3     | —                                                      | —                                 | —                                                                               | Canonical TLV encoding, consumed flag | `MarshalBinary` / `UnmarshalBinary` in `encoding.go`            | DONE   |

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

| Step                                                                                 | Paper § | Public inputs                      | Witness                                           | Verifier checks                                                                  | Code location                                              | Status |
| ------------------------------------------------------------------------------------ | ------- | ---------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------ |
| Start: <code>Enc(a)</code> + EncScalarProof + EncRangeProof                          | 4.2     | ciphertext, enc_proof, range_proof | <code>a</code>, <code>ρ</code>                    | Cipher validity, enc proof, range proof                                          | <code>mta.Start</code> / <code>mta.VerifyStart</code>      | DONE   |
| Respond: <code>c_resp = Enc(beta + a·b)</code> + MTAResponseProof                    | 4.2     | response_ciphertext, proof         | <code>b</code>, <code>beta</code>, <code>β</code> | Constant-time <code>c^b</code> via <code>paillierct</code>, proof verification   | <code>mta.Respond</code> / <code>mta.VerifyResponse</code> | DONE   |
| Finish: Decrypt <code>c_resp → alpha = Dec(c_resp) mod q</code>, with ZK proof check | 4.2     | —                                  | <code>λ</code>, <code>μ</code>                    | Constant-time Decrypt via <code>paillierct</code>, proof check, alpha derivation | <code>mta.Finish</code>                                    | DONE   |

### Constant-Time Paillier Private-Key Operations

| Operation                             | Implementation                                                                  | Location                                        | Status |
| ------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------- | ------ |
| <code>c^λ mod n²</code> (Decrypt)     | <code>filippo.io/bigmod</code> with ciphertext blinding                         | <code>internal/paillier/paillierct/ct.go</code> | DONE   |
| <code>c^b mod n²</code> (MtA Respond) | <code>filippo.io/bigmod</code> (no blinding — ZK proof verifies exact relation) | <code>internal/paillier/paillierct/ct.go</code> | DONE   |
| Fixed-length big-endian encoding      | <code>secret.Scalar</code> type                                                 | <code>internal/secret/secret.go</code>          | DONE   |

## Proof Inventory

| Proof                    | Paper § | Statement                                                                                    | Witness                                           | Fields                                                                                                               | Location                                                                                               | Status |
| ------------------------ | ------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------ |
| Π^fac (ModulusProof)     | 5.1     | Knowledge of <code>N = p·q</code> with <code>p≡q≡3 mod 4</code>                              | <code>p</code>, <code>q</code>                    | NBits, SmallFactorCheck, TranscriptHash, Commitment, Challenge, Response                                             | <code>internal/zk/paillier/proofs.go</code> <code>ProveModulus</code> / <code>VerifyModulus</code>     | DONE   |
| Π^Eq (EncScalarProof)    | 4.1     | <code>Enc(a)</code> and <code>a·G</code> share scalar <code>a</code>                         | <code>a</code>, <code>ρ</code>                    | Ciphertext, ScalarCommitment, CipherCommitment, PointCommitment, Challenge, Response                                 | <code>internal/zk/paillier/proofs.go</code> <code>ProveEncScalar</code> / <code>VerifyEncScalar</code> | DONE   |
| EncRangeProof            | 4.1     | <code>\|a\| < q</code> (secp256k1 order)                                                     | <code>a</code>                                    | Bound, Challenge, Response, TranscriptHash (independent Fiat-Shamir, not coupled to EncScalarProof)                  | <code>internal/zk/paillier/proofs.go</code> <code>ProveEncRange</code> / <code>VerifyEncRange</code>   | DONE   |
| Π^mta (MTAResponseProof) | 4.2     | <code>c_resp = Enc(beta + a·b)</code> given <code>Enc(a)</code>                              | <code>b</code>, <code>beta</code>, <code>β</code> | ScalarCommitment, BetaCommitment, CipherCommitment, Nonce1, Nonce2, Response, Challenge, CipherDelta, TranscriptHash | <code>internal/zk/paillier/proofs.go</code> <code>ProveResponse</code> / <code>VerifyResponse</code>   | DONE   |
| Π^log (LogProof)         | 6.2     | <code>Enc(a)</code> and <code>A = a·G</code> share scalar <code>a</code> (used in resharing) | <code>a</code>, <code>ρ</code>                    | Point, CipherCommitment, PointCommitment, Response, Randomness, TranscriptHash                                       | <code>internal/zk/paillier/proofs.go</code> <code>ProveLog</code> / <code>VerifyLog</code>             | DONE   |
| SchnorrProof             | 3.1     | Knowledge of discrete log of <code>V_i = x_i·G</code>                                        | <code>x_i</code>                                  | Point, Commitment, Challenge, Response, TranscriptHash                                                               | <code>internal/zk/schnorr/schnorr.go</code>                                                            | DONE   |

### Missing CGGMP21 Proofs (Not Yet Implemented)

| Proof | Paper § | Purpose                                   | Notes                                                                             |
| ----- | ------- | ----------------------------------------- | --------------------------------------------------------------------------------- |
| Π^prm | 3.1     | Primality proof for Paillier modulus      | GenerateKey uses safe primes; currently validated via Π^fac and structural checks |
| Π^Enc | 4.1     | Encryption proof (full range + knowledge) | Currently covered by Π^Eq + EncRangeProof combination                             |

## Resharing

| Step                                                    | Paper § | Public inputs         | Witness                          | Transcript inputs                                   | Verifier checks                                                          | Code location                                                                         | Status |
| ------------------------------------------------------- | ------- | --------------------- | -------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- | ------ |
| Sample zero-constant-term polynomial                    | 6.1     | —                     | Coefficients (random)            | —                                                   | —                                                                        | <code>shamir.RandomPolynomial(..., 0)</code> in <code>reshare.go</code>               | DONE   |
| Generate new Paillier keypair                           | 6.1     | —                     | <code>p'</code>, <code>q'</code> | —                                                   | —                                                                        | <code>pai.GenerateKey</code> in <code>reshare.go</code>                               | DONE   |
| Prove new modulus (Π^fac)                               | 6.1     | N', party id          | <code>p'</code>, <code>q'</code> | Reshare Paillier domain                             | Same as keygen Π^fac                                                     | <code>zkpai.ProveModulus</code> with <code>resharePaillierDomain</code>               | DONE   |
| Prove old share equals new verification share (Π^log)   | 6.2     | Enc(x_i_old), V_i_new | <code>x_i</code>, <code>ρ</code> | Point, cipher commit, point commit, transcript hash | Point decoding, Fiat-Shamir challenge, Paillier relation, curve relation | <code>zkpai.ProveLog</code> / <code>zkpai.VerifyLog</code> in <code>reshare.go</code> | DONE   |
| Broadcast commitments + new Paillier PK + Π^fac + Π^log | 6.1-6.2 | All of the above      | —                                | Reshare transcript hash                             | Payload decode                                                           | <code>reshare.go</code>                                                               | DONE   |
| Deliver private shares point-to-point                   | 6.1     | —                     | shares                           | —                                                   | Confidential envelope                                                    | <code>reshare.go</code>                                                               | DONE   |
| Verify incoming shares against commitments              | 6.1     | Commitments           | —                                | —                                                   | <code>shamir.VerifyShare</code>                                          | <code>reshare.go</code>                                                               | DONE   |
| Compute new share = old_share + Σ received_shares       | 6.1     | —                     | —                                | —                                                   | —                                                                        | <code>reshare.go</code>                                                               | DONE   |

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

| Protocol phase              | Domain label                                              | Code location            |
| --------------------------- | --------------------------------------------------------- | ------------------------ |
| Keygen commitments          | <code>cggmp21-secp256k1-keygen-commitments-v1</code>      | <code>keygen.go</code>   |
| Keygen transcript           | <code>cggmp21-secp256k1-keygen-transcript-v1</code>       | <code>keygen.go</code>   |
| Presign transcript          | <code>cggmp21-secp256k1-presign-transcript-v1</code>      | <code>sign.go</code>     |
| Presign round-1 echo        | <code>cggmp21-secp256k1-presign-round1-echo-v1</code>     | <code>sign.go</code>     |
| MtA delta response evidence | <code>cggmp21-secp256k1-mta-response-evidence-v1</code>   | <code>sign.go</code>     |
| Aggregate sign evidence     | <code>cggmp21-secp256k1-aggregate-sign-evidence-v1</code> | <code>sign.go</code>     |
| Reshare transcript          | <code>cggmp21-secp256k1-reshare-transcript-v1</code>      | <code>reshare.go</code>  |
| Reshare Paillier modulus    | <code>reshare.paillier-modulus</code> (outer domain)      | <code>domain.go</code>   |
| MtA start (delta/sigma)     | Outer proof domain (per-initiator)                        | <code>domain.go</code>   |
| Modulus proof               | Outer proof domain (per-party)                            | <code>domain.go</code>   |
| Π^log (reshare)             | Outer proof domain                                        | <code>domain.go</code>   |
| Schnorr share proof         | Outer proof domain                                        | <code>domain.go</code>   |
| Party set hash              | <code>cggmp21-secp256k1-party-set-v1</code>               | <code>evidence.go</code> |
| Paillier public shares hash | <code>cggmp21-secp256k1-paillier-public-shares-v1</code>  | <code>evidence.go</code> |

## Remaining Review Items

| Item                                                   | Priority | Notes                                                                                  |
| ------------------------------------------------------ | -------- | -------------------------------------------------------------------------------------- |
| Add Π^prm (primality proof)                            | P0       | Currently rely on GenerateKey safe-prime enforcement + Π^fac structural checks         |
| Add Π^Enc (full encryption proof)                      | P0       | Currently covered by Π^Eq + EncRangeProof combination; need equivalence proof          |
| Independent cryptographic review of all proofs         | P0       | Required before removing experimental warning                                          |
| Identifiable abort completeness review                 | P0       | All public-input evidence fields implemented; review against full CGGMP21 abort matrix |
| BIP32 / SLIP10 path derivation                         | P2       | BIP32 implemented for secp256k1; SLIP10 not in v1 scope                                |
| Proactive refresh (periodic, without group-key change) | P2       | RefreshScheduler with configurable interval and transport interface implemented        |
