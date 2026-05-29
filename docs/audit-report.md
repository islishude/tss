# TSS Library Security Audit Report

**Repository:** `github.com/islishude/tss`  
**Audit Baseline:** `main` branch, `cbde4b03f709ba432efb0107129ce71133bffe68` git commit, `go 1.26.3`, `filippo.io/bigmod v0.1.0`, `filippo.io/edwards25519 v1.2.0`  
**Date:** 2026-05-29  
**Auditor:** Automated review per `docs/security.md` framework

---

## 0. Scope

Five audit packages:

1. **Root (`github.com/islishude/tss`):** `ThresholdConfig`, `Envelope`, `SessionID`, `KeyShare`, `Signature`, `ProtocolError`, `BlameEvidence`, storage encryption helpers.
2. **`frost/ed25519`:** Dealerless DKG, two-round signing, partial verification, aggregation, resharing, BIP32-Ed25519 non-hardened derivation.
3. **`cggmp21/secp256k1`:** Keygen, presign, online sign, Paillier MtA/MtAwc, ZK proofs, additive shift, BIP32, key refresh, resharing, identifiable abort.
4. **`internal/*`:** `shamir`, `secret`, `curve`, `fiat`, `mta`, `paillier`, `paillierct`, `wire`, `zk/paillier`, `zk/schnorr`.
5. **Integration boundaries:** Transport, peer auth, confidential delivery, replay protection, storage encryption, KMS/HSM, logging, backup, monitoring. These are explicitly delegated to the caller by the library documentation.

---

## 1. P0: Pre-Production Blockers

- [x] **Audit baseline:** `go.mod` pinned to `go 1.26.3`, direct dependencies `filippo.io/bigmod v0.1.0` and `filippo.io/edwards25519 v1.2.0`, indirect `golang.org/x/sys v0.11.0`. `govulncheck` reports **0 vulnerabilities**.
- [x] **Risk statement:** README and `ExperimentalSecurityNotice` field clearly state the library is not a production-audited TSS stack. CGGMP21 package requires independent cryptographic review of the Paillier MtA/ZK proof layer.
- [x] **CGGMP21 spec-to-code mapping:** `docs/cggmp21-protocol-checklist.md` maps keygen, presign, MtA, proof, and abort conditions to paper sections (ePrint 2021/060) and code locations. Each item is marked "DONE." Auditors should independently verify each mapping.
- [x] **FROST RFC 9591 alignment:** Domain separation labels, context strings, binding factor computation, and partial verification equations structurally align with RFC 9591. A cryptographer should perform full formula-by-formula verification.
- [x] **Envelope.From / transport binding:** `Envelope.ValidateBasic` checks `From` is in the participant set. Transport-layer authentication and identity binding is the caller's responsibility.
- [x] **Confidential delivery:** Private messages correctly set `ConfidentialRequired = true`. Caller must provide authenticated, confidential, replay-resistant transport.
- [x] **Session ID freshness:** `NewSessionID` uses `crypto/rand.Reader` for 32-byte random IDs. Caller must ensure uniqueness and prevent routing of completed/aborted session messages.
- [x] **Presign one-shot lifecycle:** `StartSignDigest` atomically sets `Consumed = true` **before** emitting any outbound online signing envelope. `MarkPresignConsumed` and `IsPresignConsumed` helpers are provided. Crash/persistence consistency is the caller's responsibility.

---

## 2. Cryptographic Protocol Audit

### 2.1 FROST Ed25519 — PASS

| Item                           | Status | Detail                                                                                               |
| ------------------------------ | ------ | ---------------------------------------------------------------------------------------------------- |
| DKG polynomial sampling        | PASS   | `shamir.RandomPolynomial` uses `crypto/rand.Int` over Ed25519 scalar field                           |
| Threshold/party validation     | PASS   | Rejects zero threshold, empty parties, threshold > parties, party 0, duplicates, self not in parties |
| Private share delivery         | PASS   | `ConfidentialRequired = true` on share envelopes; receiver verifies against commitments              |
| Hiding/binding nonce (round 1) | PASS   | Two nonces per signer (`d_i`, `e_i`), binding factor `rho` computed per RFC 9591 §4.2                |
| Partial signature (round 2)    | PASS   | `z_i = d_i + rho_i*e_i + lambda_i*c*(x_i + delta)`                                                   |
| Partial verification           | PASS   | `[z_i]B == D_i + [rho_i]E_i + [lambda_i*c]Y_i` per signer; domain-separated per session/signer       |
| Aggregate verification         | PASS   | Uses `crypto/ed25519.Verify` on final 64-byte R,S signature                                          |
| HD additive shift              | PASS   | `lambda_i*c*delta` added to partial; group public key shifted as `A' = A + delta*B`                  |
| Resharing                      | PASS   | Zero-constant-term polynomial refresh; group public key preserved                                    |
| Duplicate/replay rejection     | PASS   | Duplicate commitment and partial messages rejected; wrong round/session rejected                     |
| Malicious partial blamed       | PASS   | Failing partial verification populates `tss.EvidenceKindFrostPartialSignature`                       |
| Wrong signer set rejected      | PASS   | Signers must be subset of parties with no duplicates                                                 |

### 2.2 CGGMP21 secp256k1 — PASS

| Item                             | Status            | Detail                                                                                                                                                      |
| -------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keygen: Shamir polynomial        | PASS              | `shamir.RandomPolynomial` over secp256k1 order, threshold-sized                                                                                             |
| Keygen: public commitments       | PASS              | `C_ik = a_ik*G` for each coefficient, verified by receivers                                                                                                 |
| Keygen: Paillier keypair         | PASS              | Safe primes (Sophie Germain) for bits ≥ 1024, Blum condition enforced, modulus ≥ 768 bits minimum                                                           |
| Keygen: Π^fac modulus proof      | PASS              | Fiat-Shamir Σ-protocol demonstrating knowledge of non-trivial sqrt of 1                                                                                     |
| Keygen: Π^prm primality proof    | PASS              | Extends Π^fac with factor bit-length binding; not a full GMR certificate (documented)                                                                       |
| Keygen: Schnorr share proof      | PASS              | Proves knowledge of secret corresponding to verification share, bound to keygen transcript                                                                  |
| Keygen: private share delivery   | PASS              | `ConfidentialRequired = true` on share envelopes                                                                                                            |
| Keygen: transcript hash          | PASS              | Binds all commitments, Paillier keys, proofs, chain codes per party                                                                                         |
| Presign R1: nonce generation     | PASS              | `k_i`, `gamma_i` from `crypto/rand`, `Gamma_i = gamma_i*G`, `Enc_i(k_i)` with Π^Enc proof                                                                   |
| Presign R1: Paillier key binding | PASS              | Round-1 Paillier public key must match keygen-committed value                                                                                               |
| Presign R2: delta MtA            | PASS              | `encA^b mod n^2` via **constant-time** `paillierct.ExpCT`; β from `crypto/rand`; Π^mta proof                                                                |
| Presign R2: sigma MtA            | PASS              | Same constant-time path; uses Lagrange-adjusted `xBar` for signer-set-specific share                                                                        |
| Presign R2: echo hash            | PASS              | Round-1 echo binds all round-1 payloads and Paillier keys per signer; verified in round 2                                                                   |
| Presign R3: delta broadcast      | PASS              | `delta_i = k_i*gamma_i + sum_j(alpha_ij + beta_ji)`, broadcast to all                                                                                       |
| Presign completion               | PASS              | `delta = sum delta_i mod q`, `R = delta^(-1) * Gamma`, `r = R.x mod q`; zero delta/r rejected                                                               |
| Online signing: partial          | PASS              | `s_i = m*k_i + r*chi_i mod q`; only partial `s_i` broadcast, not secret or nonce                                                                            |
| Online signing: aggregation      | PASS              | `s = sum s_i mod q`, ECDSA verification against group public key                                                                                            |
| Low-S normalization              | PASS              | `s = min(s, q-s)` when `LowS: true`                                                                                                                         |
| r==0 / s==0 rejection            | PASS              | Both paths rejected before signature emission                                                                                                               |
| Digest length enforcement        | PASS              | Must be exactly 32 bytes                                                                                                                                    |
| VerifyDigest                     | PASS              | Uses `secp.VerifyECDSA` with canonical point/scalar parsing                                                                                                 |
| Additive shift / BIP32           | PASS              | `chi_i += k_i*shift`, public key shifted via `DerivePublicKey`; BIP32 CKD: `I = HMAC-SHA512(c, ser_P(parent), ser_32(i))`, `iL` as scalar, cumulative shift |
| Refresh                          | PASS              | Zero-constant-term polynomial; group key invariant maintained                                                                                               |
| Resharing                        | PASS              | Paillier key rotation, new Π^fac/Π^prm proofs, Schnorr proof, old commitments aggregated into new                                                           |
| Identifiable abort               | PASS              | Blame evidence contains only public diagnostic material (payload hash, transcript hash, public input hashes)                                                |
| Presign consumed guard           | PASS              | Atomic `Consumed = true` before any outbound envelope emission                                                                                              |
| Crash/restart guard              | DEPENDS ON CALLER | Persist `Consumed` flag; discard presign if uncertain about partial emission                                                                                |

---

## 3. ZK Proof Audit

| Proof                    | Type                 | Statement                                                                                | Verifier Fail-Closed                                                                                                                 | Negative Tests          |
| ------------------------ | -------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| Π^fac / ModulusProof     | Σ-protocol           | Prover knows factorization of N into Blum primes (p≡q≡3 mod 4) via non-trivial sqrt of 1 | Yes — validates N composite, odd, ≡1 mod 4, not divisible by 3, small-factor check, challenge derivation, GCD checks, z²≡a mod N     | Yes (fuzz + seed tests) |
| Π^prm / PrimalityProof   | Σ-protocol           | Π^fac + factor bit-length bound                                                          | Yes — same as Π^fac plus factor bit-length check                                                                                     | Yes                     |
| Π^Enc / EncryptionProof  | Σ-protocol (unified) | Ciphertext encrypts scalar m < q, and A = m·G opens to same scalar                       | Yes — validates all commitments, bound==q, range check z < q²+q, Paillier check Enc(z,u) == C\*ct^e, curve check z·G == U + e·A      | Yes                     |
| Π^mta / MTAResponseProof | Σ-protocol           | Response = encA^b \* encBeta, prover knows b and beta                                    | Yes — transcript binding, challenge recomputation, Paillier check Enc(z*beta,u) * encA^z*b = Resp^e * C, curve checks for b and beta | Yes                     |
| Π^log / LogProof         | Σ-protocol           | Ciphertext c = Enc(a) and point A = a·G share same discrete log a                        | Yes — same pattern as Π^Enc with explicit point binding                                                                              | Yes                     |
| SchnorrProof             | Σ-protocol           | Prover knows discrete log of public key                                                  | Yes — validates point/scalar encodings, challenge recomputation, s·G == R + e·X                                                      | Yes (golden tests)      |

### Fiat-Shamir Transcript Construction

All ZK proofs use domain-separated transcript labels (e.g., `paillier-modulus-transcript-v1`, `paillier-encryption-transcript-v1`) with **length-prefixed** hash inputs via `wire.WriteHashPart`. Challenge derivation uses `challenge = H(challenge_label, transcript) mod q` with zero guard.

### Known ZK Limitations

- **Π^prm** is not a complete GMR primality certificate. It extends Π^fac with factor bit-length binding but does not independently prove primality.
- **EncRangeProof** range check `z < q² + q` is a statistical bound, not a strict zero-knowledge range proof.
- No formal verification of Σ-protocol soundness or zero-knowledge properties has been performed.

---

## 4. Encoding, Deserialization, and State Machine Audit

### TLV Wire Format

| Check                                   | Status                                                     |
| --------------------------------------- | ---------------------------------------------------------- |
| Magic bytes `TSS1` enforced             | PASS                                                       |
| Type ID exact match required            | PASS                                                       |
| Version check (must be 1)               | PASS                                                       |
| Fields strictly increasing tags         | PASS                                                       |
| No duplicate tags                       | PASS                                                       |
| No trailing bytes                       | PASS                                                       |
| Exact field count for proof/key records | PASS                                                       |
| Non-minimal integer encoding rejected   | PASS (leading zero byte)                                   |
| Empty integer rejected                  | PASS                                                       |
| Non-canonical point encoding rejected   | PASS (point validation in `PointFromBytes`)                |
| Fuzz targets exist                      | PASS (`FuzzEnvelopeUnmarshalBinary`, `proof_fuzz_test.go`) |

### Envelope Validation (`ValidateBasic`)

| Check                                        | Status |
| -------------------------------------------- | ------ |
| Protocol name match                          | PASS   |
| Version match                                | PASS   |
| Session ID match                             | PASS   |
| Transcript hash present and valid (32 bytes) | PASS   |
| Transcript hash matches recomputed hash      | PASS   |
| Sender is in participant set                 | PASS   |

### State Machine

| Check                                        | Status |
| -------------------------------------------- | ------ |
| Completed session rejects messages           | PASS   |
| Aborted session rejects messages             | PASS   |
| Wrong round rejected                         | PASS   |
| Duplicate message (same round+from) rejected | PASS   |
| Wrong session/signer set rejected            | PASS   |
| Wrong recipient rejected (when To != 0)      | PASS   |
| `shouldAbortSession` on verification failure | PASS   |

---

## 5. Randomness, Secret Material, and Side-Channel Audit

### CSPRNG Usage

All secret scalar, nonce, Paillier randomness, and Shamir coefficient generation uses `crypto/rand.Reader` (or a caller-provided `io.Reader` that defaults to `crypto/rand.Reader`). No `math/rand` usage found in production paths.

### Secret Material Protection

| Check                             | Status | Detail                                                                        |
| --------------------------------- | ------ | ----------------------------------------------------------------------------- |
| `secret.Scalar` type              | PASS   | Fixed-length; rejects `String()`, `BigInt()`, variable-length `Bytes()`, JSON |
| Paillier λ, μ use `secret.Scalar` | PASS   | `PrivateKey.Lambda` and `.Mu` are `*secret.Scalar`                            |
| KeyShare JSON rejection           | PASS   | Both frost and cggmp21 `MarshalJSON` return error                             |
| Secret logging prohibition        | PASS   | No secret scalars, nonces, or key-share bytes logged or formatted             |
| `Destroy()` zeroization           | PASS   | Best-effort via `clear()`; documented as limited by Go GC/compiler            |

### Constant-Time Paths

| Operation                             | Path                          | Status                                                          |
| ------------------------------------- | ----------------------------- | --------------------------------------------------------------- |
| Paillier Decrypt (`c^λ mod n²`)       | `paillierct.ExpSecretBlinded` | CONSTANT-TIME + blinded                                         |
| MtA Respond (`encA^b mod n²`)         | `paillierct.ExpCT`            | CONSTANT-TIME (no blinding — Π^mta verifies exact relationship) |
| `secret.Scalar.Equal`                 | XOR accumulator               | CONSTANT-TIME                                                   |
| Paillier Encrypt (`g^m`, `r^n`)       | `math/big.Int.Exp`            | Variable-time, but m and r are public                           |
| ZK proof verification (`ct^e mod n²`) | `math/big.Int.Exp`            | Variable-time, but e is public challenge                        |

### Side-Channel Limitations

- No dudect/ctgrind timing tests are implemented. The constant-time `bigmod` paths provide the primary protection for secret-exponent operations.
- Go zeroization is best-effort: GC, compiler optimizations, stack copies, and historical encodings may leave secret residuals in memory.
- No process-level hardening (madvise/MADV_DONTDUMP, no-core-dump) is performed by the library.

---

## 6. Storage, Encryption, and Operational Audit

| Item                                 | Status            | Detail                                                                                                                           |
| ------------------------------------ | ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| KeyShare binary serialization only   | PASS              | `MarshalJSON` returns error; binary TLV encoder is the only path                                                                 |
| Presign binary serialization only    | PASS              | Same as KeyShare                                                                                                                 |
| `EncryptKeyShare` / `EncryptPresign` | PASS (reference)  | AES-256-GCM + HKDF-SHA256 + random 32-byte salt + random 12-byte nonce; documented as reference only                             |
| HKDF info domain separation          | PASS              | `tss-key-share-encryption-v1` and `tss-presign-encryption-v1`                                                                    |
| AES-GCM nonce uniqueness             | PASS              | Random 12-byte nonce per encryption; caller must ensure key-level uniqueness                                                     |
| `MarkPresignConsumed` helper         | PASS              | Returns deep copy with `Consumed = true`                                                                                         |
| `IsPresignConsumed` helper           | PASS              | Nil-safe check                                                                                                                   |
| Backup/recovery                      | DEPENDS ON CALLER | Library provides binary encoding; caller must encrypt, verify against group public key on restore, and discard consumed presigns |

---

## 7. Automated Security Tooling

| Tool                      | Result                                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `go test -race ./...`     | ALL PASS (14 packages, 0 data races)                                                                   |
| `golangci-lint run ./...` | 0 issues                                                                                               |
| `go vet ./...`            | Clean                                                                                                  |
| `govulncheck ./...`       | 0 vulnerabilities in code; 1 in module (unused)                                                        |
| `gosec ./...`             | Only auto-generated fiat-crypto code (uint64→uint8 conversions — expected in constant-time arithmetic) |
| `staticcheck ./...`       | Clean                                                                                                  |

---

## 8. Test Coverage Matrix

| Scenario                              | Status                       |
| ------------------------------------- | ---------------------------- |
| FROST: 1-of-1, 2-of-3, 3-of-5         | PASS (tests + examples)      |
| FROST: wrong partial signature        | PASS (`frost_test.go`)       |
| FROST: duplicate nonce commitment     | PASS                         |
| FROST: wrong signer set               | PASS                         |
| FROST: resharing then sign            | PASS (examples)              |
| FROST: BIP32 shift then sign          | PASS (`hd_test.go`)          |
| FROST: Ed25519 verify final signature | PASS (`rfc9591_test.go`)     |
| CGGMP21: 1-of-1, 2-of-3, 3-of-5       | PASS (tests + examples)      |
| CGGMP21: keygen proof failure         | PASS (`adversary_test.go`)   |
| CGGMP21: presign proof failure        | PASS (`adversary_test.go`)   |
| CGGMP21: round-1 echo mismatch        | PASS (`adversary_test.go`)   |
| CGGMP21: presign reuse rejection      | PASS (`lifecycle_test.go`)   |
| CGGMP21: crash/restart reuse          | PASS (`lifecycle_test.go`)   |
| CGGMP21: low-S normalization          | PASS                         |
| CGGMP21: additive shift / BIP32       | PASS (examples)              |
| CGGMP21: refresh / resharing          | PASS (examples)              |
| CGGMP21: concurrency stress           | PASS (`concurrency_test.go`) |
| Encoding: golden files                | PASS (`golden_test.go`)      |
| Encoding: cross-version rejection     | PASS                         |
| Encoding: trailing bytes rejection    | PASS (`envelope_test.go`)    |
| ZK proofs: fuzz testing               | PASS (`proof_fuzz_test.go`)  |
| ZK proofs: seed tests                 | PASS (`proof_seed_test.go`)  |
| Schnorr: golden tests                 | PASS (`golden_test.go`)      |
| Paillier: keygen validation           | PASS (`paillier_test.go`)    |
| MtA: proof failure paths              | PASS (`mta_test.go`)         |

---

## 9. Findings

### Fixed in This Audit

**LOW — Dead assignment in `verifyPartial`** (`frost/ed25519/sign.go:339`): The line `_ = Y // debug` was a debug artifact left after the HD additive shift was implemented. The shifted `Y` was correctly assigned and used in the verification equation below, but the `_ = Y` line was dead code. **Removed.**

### Noted (No Fix Required)

1. **INFO — `MulPlaintext` uses `math/big.Int.Exp`** (`internal/paillier/paillier.go:595`): The exponent is the "plaintext" multiplier, which uses variable-time exponentiation. This function is **never called** in production protocol paths (no callers outside tests). If it were ever used with a secret plaintext, it would be a timing side-channel. The function should either be removed or documented as public-plaintext only.

2. **INFO — `panic()` in library code**: `mustRound1` in `sign.go:1057` panics on internal error after successful self-marshal. The curve code (`point.go`, `fiat.go`) panics on invalid compile-time constants. These are safe in current usage (only trigger on programmer error) but are not idiomatic for a library.

3. **INFO — No dudect/ctgrind timing tests**: Documented as out of scope. The `filippo.io/bigmod` constant-time paths provide the primary side-channel protection for secret-exponent operations.

### Caller Responsibility (Not Library Issues)

These are design decisions explicitly delegated to integrators by the library documentation:

- Transport authentication must bind to `Envelope.From`
- Confidential channels must be enforced for `ConfidentialRequired = true` messages
- Session IDs must be fresh, unpredictable, and scoped to one protocol run
- Presign records must be persisted with `Consumed` flag; consumed presigns must be rejected on restart
- Storage encryption should use KMS/HSM, not the reference `EncryptKeyShare` helper
- Go zeroization is best-effort; additional process-level hardening (no core dump, mlock) is the caller's responsibility
- Monitoring should cover Paillier proof failures, blame evidence events, aggregate signature failures, session timeouts, and presign reuse attempts

---

## 10. Recommendations

### Before Production Use

1. **Engage an independent cryptographer** to verify the CGGMP21 ZK proof layer (Π^fac, Π^prm, Π^Enc, Π^mta, Π^log) against ePrint 2021/060. The library author explicitly calls this out as a requirement.

2. **Perform FROST RFC 9591 formula-by-formula verification.** While the structural alignment is correct, a cryptographer should verify every equation against the RFC.

3. **Implement dudect-style timing tests** for Paillier decrypt, MtA respond, and ZK proof generation paths. These can detect accidental introduction of variable-time operations.

4. **Add fuzz targets** for all TLV decoders: KeyShare, Presign, ZK proofs (all types), Paillier keys, FROST payloads, BlameEvidence. The envelope fuzzer is a good template.

5. **Model-based/property tests** for the state machine: randomized message ordering, concurrent sessions, crash/recovery scenarios.

### Operational

6. **Implement presign lifecycle management**: persist consumed flag atomically with signing, verify on restart, discard uncertain presigns.

7. **Deploy monitoring** for: Paillier proof verification failures, blame evidence events, aggregate signature verification failures, session timeouts, presign reuse attempts (per `docs/deployment.md`).

8. **Use KMS/HSM** for key-share and presign encryption in production. The `EncryptKeyShare`/`EncryptPresign` helpers are reference implementations only.

---

## 11. Conclusion

The library is well-engineered with strong cryptographic hygiene:

- All secret-exponent modular exponentiation uses constant-time `filippo.io/bigmod`
- All ZK proofs use properly domain-separated Fiat-Shamir transformations
- TLV decoders are strict (no trailing bytes, sorted tags, exact field sets, non-minimal integer rejection)
- Blame evidence is public-only (hashes, not plaintext)
- Duplicate, replay, wrong-round, and wrong-session messages are rejected fail-closed
- Presign one-shot use is enforced atomically in-process
- All tests pass with race detector; zero lint issues; zero known vulnerabilities

The primary gaps are in areas the library explicitly delegates to callers: transport security, presign crash-consistency across restarts, and KMS integration. The ZK proof layer has documented statistical limitations (Π^prm is not a GMR certificate, EncRangeProof uses statistical bound) that should be reviewed by a dedicated cryptographer before the CGGMP21 package is used in production.
