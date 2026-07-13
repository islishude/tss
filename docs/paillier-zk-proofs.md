# Paillier ZK Proof Notes

The Paillier proof package supports the CGGMP21-style secp256k1 path. These
records are deterministic, transcript-bound proof shells used by the local MtA
implementation.

## Status

- Active proof types: <code>ModulusProof</code> (CGGMP24 Πmod),
  <code>FactorProof</code> (CGGMP21 Πfac),
  <code>RingPedersenProof</code> (CGGMP24 Πprm),
  <code>EncProof</code> (Πenc), <code>AffGProof</code> (Πaff-g), and
  <code>LogStarProof</code> (Πlog\*).
- Retired `EncryptionProof`, `MTAResponseProof`, and `LogProof` types, wire
  decoders, golden vectors, and compatibility tests have been removed.
- All proofs receive explicit <code>SecurityParams</code> (Ell, EllPrime,
  Epsilon, ChallengeBits, MinPaillierBits) from the CGGMP21 plan/session.
- <code>MinPaillierBits</code> is enforced for both Paillier public moduli and
  Ring-Pedersen auxiliary moduli. These are independent public parameters even
  when protocol material currently generates them together.
- Integer responses use canonical signed-magnitude encoding; verifier range
  checks precede all algebraic equation checks.
- MtA decryption decodes the Paillier plaintext with the centered representative
  (`m` for `m <= N/2`, otherwise `m-N`) before reduction modulo the secp256k1
  order. This preserves negative affine masks proved by Πaff-g; unsigned
  reduction modulo `N` is not equivalent.
- All proofs use Ring-Pedersen commitments to hide integer witnesses.
  Commitment nonces are sampled from the configured <code>SecurityParams</code> ranges.
- Witness scalars and Paillier randomness use fixed-width `secret.Scalar`;
  signed masks use `secret.SignedInt`. Public proof responses remain `big.Int`.
- Proof payloads are canonical TLV records through <code>internal/wire</code> at
  version 1.
- The package has not yet received independent cryptographic review. The audit
  guide ([docs/audit-guide.md](audit-guide.md)) maps the active proof surface to
  facilitate such a review.

## Proof Inventory

| Proof                                 | Statement                                                                                                                                                                                     | Witness                                                                                                         | Transcript inputs                                                                                                               | Verifier checks                                                                                                                                                                                                      | Wire type                                    | Status                                                |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------- |
| Πmod (<code>ModulusProof</code>)      | CGGMP24 proof for a Paillier-Blum modulus. Contains <code>w</code> and exactly 128 verifier-derived rounds <code>(x_i,a_i,b_i,z_i)</code>; it never carries prover-supplied <code>y_i</code>. | Paillier prime factors <code>p</code>, <code>q</code> where <code>p ≡ q ≡ 3 (mod 4)</code>.                     | Typed proof transcript: proof tag, curve, proof version, outer domain, party id, Paillier public key, <code>w</code>.           | Structural validation, odd composite N, <code>w,x_i,z_i ∈ Z\*\_N</code>, <code>Jacobi(w,N)=-1</code>, bit checks, <code>z_i^N=y_i</code>, and <code>x_i^4=(-1)^a w^b y_i</code>.                                     | <code>zk.paillier.modulus-proof</code>       | Active (keygen, reshare, refresh)                     |
| Πfac (<code>FactorProof</code>)       | Prover Paillier modulus `N_i` relative to receiver auxiliary parameters `(N_j,S_j,T_j)`; proves bounded factors and their product.                                                            | Paillier factors `p,q` with `2^Ell < p,q < 2^Ell sqrt(N_i)` plus signed masks.                                  | Security parameters, lifecycle domain, prover/verifier identities, both moduli, receiver bases, and `P,Q,A,B,T`.                | Canonical/unit/range checks and all three Ring-Pedersen equations for the two factors and `pq=N_i`; zero Fiat-Shamir challenges are retried/rejected.                                                                | <code>zk.paillier.factor-proof</code>        | Active (receiver-specific keygen, refresh, reshare)   |
| Πprm (<code>RingPedersenProof</code>) | CGGMP24 proof of Ring-Pedersen parameters <code>(N,s,t)</code>, proving knowledge of λ such that <code>s=t^λ mod N</code>.                                                                    | Ring-Pedersen secret λ.                                                                                         | Typed proof transcript: proof tag, curve, proof version, outer domain, party id, canonical parameter bytes, commitments.        | Validates <code>(N,s,t)</code>, <code>N</code> against <code>SecurityParams.MinPaillierBits</code>, exact 128 rounds, verifier-derived challenge bits, response bounds, and <code>t^z = commitment·s^e mod N</code>. | <code>zk.paillier.ring-pedersen-proof</code> | Active (keygen, reshare, refresh)                     |
| Πenc (<code>EncProof</code>)          | Paillier encryption of a plaintext in ±2^Ell, with Ring-Pedersen commitment under the verifier's auxiliary parameters.                                                                        | Scalar <code>k</code>, Paillier randomness <code>ρ</code>.                                                      | Typed transcript: curve, proof tag, version, SecurityParams, state, prover N, verifier N/S/T, K, S, A, C.                       | Ciphertext/point/RP membership, z1/z3 range, challenge recomputation, Paillier equation, RP equation.                                                                                                                | <code>zk.paillier.enc-proof</code>           | Primitive retained and tested; no active protocol use |
| Πaff-g (<code>AffGProof</code>)       | MtA response: D = x⊙C ⊕ Enc(y;ρ), X=x·G, Y=Enc(y), YPoint=y·G, and AlphaPoint=x·K+YPoint.                                                                                                     | Scalar <code>x</code>, fixed-width signed integer <code>y</code> in ±2^EllPrime, randomness <code>ρ, ρY</code>. | Typed transcript binds both Paillier keys, verifier parameters, ciphertexts, K/X, YPoint/AlphaPoint, and all proof commitments. | Membership/range checks, two Paillier equations, two Ring-Pedersen equations, and three curve equations sharing the integer responses.                                                                               | <code>zk.paillier.aff-g-proof</code>         | Active (presign round 2 via <code>mta.Respond</code>) |
| Πlog\* (<code>LogStarProof</code>)    | Paillier ciphertext and curve point share discrete log in range, with Ring-Pedersen commitment under verifier parameters.                                                                     | Scalar <code>x</code>, Paillier randomness <code>ρ</code>.                                                      | Typed transcript: curve, proof tag, version, SecurityParams, state, Paillier N, verifier N/S/T, C, X, B, S, A, Y, D.            | Ciphertext/point/RP membership, z1/z3 range, challenge recomputation, Paillier equation, curve equation, RP equation.                                                                                                | <code>zk.paillier.logstar-proof</code>       | Active (presign round 1, keygen, reshare, refresh)    |

## Usage by Protocol Phase

| Phase           | Proofs used                                          | Code location                                                                                                      |
| --------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Keygen          | Πmod, Πfac, Πprm (Ring-Pedersen), Πlog\*             | <code>keygen.go</code>, <code>internal/zk/paillier/factor.go</code>, <code>internal/zk/paillier/logstar.go</code>  |
| Presign round 1 | Πlog\* (LogStarProof, per verifier)                  | <code>presign_round1.go</code>, <code>internal/mta/start.go</code>, <code>internal/zk/paillier/logstar.go</code>   |
| Presign round 2 | Πaff-g (AffGProof , pairwise, delta and sigma kinds) | <code>sign.go</code>, <code>internal/mta/mta.go</code>, <code>internal/zk/paillier/affg.go</code>                  |
| Reshare         | Πmod, Πfac, Πprm, Πlog\*                             | <code>reshare.go</code>, <code>internal/zk/paillier/factor.go</code>, <code>internal/zk/paillier/logstar.go</code> |
| Refresh         | Πmod, Πfac, Πprm, Πlog\*                             | <code>refresh.go</code>, <code>internal/zk/paillier/factor.go</code>, <code>internal/zk/paillier/logstar.go</code> |

## Decoder Boundary

Production proof decoders only accept TLV. They reject JSON payloads, wrong
proof type identifiers, duplicate or unsorted fields, trailing bytes,
non-canonical integers, malformed proof records, oversized MtA response
scalars, and malformed curve points. Public-key-aware MtA verification also
caps ciphertext commitments and randomness to the Paillier modulus size before
converting them to big integers. There is no proof conversion
helper in the production package; callers must regenerate unsupported proof
bytes through the current keygen and presign flows.

## Constant-Time Operations

All Paillier private-key operations use <code>filippo.io/bigmod</code> via
<code>internal/paillier/paillierct</code>:

| Operation                             | Implementation                                                                 | Location                                   |
| ------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------ |
| <code>c^λ mod n²</code> (Decrypt)     | <code>paillierct.ExpSecretBlinded</code> with ciphertext blinding              | <code>internal/paillier/paillier.go</code> |
| <code>c^b mod n²</code> (MtA Respond) | <code>paillierct.ExpCT</code> (no blinding — ZK proof verifies exact relation) | <code>internal/mta/mta.go</code>           |

This table covers secret-exponent operations only. The package does not claim
that all Paillier arithmetic is constant-time.

## Blockers Before Production Use

- Review the outer proof-domain fields against the final CGGMP21 message schedule.
- Complete an independent cryptographic review of the Paillier/ZK layer and
  identifiable-abort behavior.

## Security Audit Coverage

The proof system has been systematically audited through a multi-phase test
campaign (see `internal/zk/paillier/*_test.go` and
`cggmp21/secp256k1/proof_omission_test.go`). Each phase targets a specific
security property required for production CGGMP TSS.

### Phase 1: Special Soundness (Σ-Protocol Extractor)

**Covered by**: `extractor_test.go` (Tier 1)

Every Σ-protocol proof type has a corresponding test demonstrating that two
accepting transcripts with identical commitments but different challenges allow
witness extraction:

- `TestEncProofSpecialSoundness` — extracts `k`
- `TestAffGProofSpecialSoundness` — extracts `x` and `y`
- `TestLogStarProofSpecialSoundness` — extracts `x`

These tests use a deterministic RNG (`replayReader`) to produce identical
commitments with different challenges via distinct domain labels.

### Phase 2: Challenge Distribution (Fiat-Shamir Soundness)

**Covered by**: `challenge_distribution_test.go` (Tier 3, `slowcrypto`)

- Πmod challenge (y_i) bit distribution via chi-squared test (10000 samples)
- Πprm single-bit challenge binomial test (100 proofs × 128 rounds = 12800 bits)
- Πprm bit independence (lag-1 autocorrelation test)
- New proof ChallengeSigned distribution (5000 challenges, 128-bit chi-squared)
- Modular bias test for ChallengeSigned (MSB uniformity)

### Phase 3: Range Bound Boundary Precision

**Covered by**: `range_boundary_test.go` (Tier 0/1)

- `InSignedPowerOfTwo` accepts at ±2^bits, rejects at ±(2^bits+1)
- `InUnsignedPowerOfTwo` accepts [0, 2^bits), rejects at 2^bits
- `inMultRange` accepts at ±N·2^bits, rejects at ±(N·2^bits+1)
- Every new proof type: out-of-range responses rejected at exact boundary

### Phase 4: Parameter Consistency

**Covered by**: `params_consistency_test.go` (Tier 0/1)

- DefaultSecurityParams values match documentation (Ell=256, EllPrime=848, Epsilon=230, ChallengeBits=128, MinPaillierBits=3072)
- EncRange() = Ell + max(ChallengeBits, Epsilon) = 486
- AffGRange() = EllPrime + max(ChallengeBits, Epsilon) = 1078
- Statistical hiding analysis: ~358 bits with production params
- ChallengeBits ≤ 256 (SHA-256 output limit)
- Every new proof transcript binds all SecurityParams fields, including
  EllPrime and MinPaillierBits even when a specific proof does not otherwise
  consume that field in its range equation
- Package-local test security parameters are strictly weaker than production

### Phase 5: Witness-Statement Relation Completeness

**Covered by**: `relation_audit_test.go` (Tier 1)

- Every EncProof/AffGProof/LogStarProof statement field is transcript-bound
- Every algebraic verification equation tested independently
- Statement Y == proof Y check in AffGProof
- Wrong public key / wrong ciphertext / wrong verifier aux all rejected
- Paillier key domain separation (all proof tags verified distinct)

### Phase 6: Adversarial Proof Construction

**Covered by**: `adversarial_test.go` (Tier 1)

- EncProof rejects S=N (non-unit) and S=1 (trivial commitment)
- Cross-proof field substitution (z1 from proof A in proof B) rejected
- Proof replay across different statements (C, D, ciphertext) rejected
- Proof replay across different domains rejected
- Zero-witness edge cases handled correctly (k=0, y=0)
- Ring-Pedersen commitment collision resistance verified
- Non-unit commitments (0, N, N²) rejected for all proof types
- Degenerate Ring-Pedersen parameters (S=1) rejected
- Parameter downgrade attack: 512-bit proof rejected under 3072-bit params

### Phase 7: Protocol-Level Proof Omission

**Covered by**: `proof_omission_test.go` (Tier 2, `integration`)

- Corrupted Πmod → keygen Handle returns error
- Corrupted Πprm → keygen Handle returns error
- Corrupted PaillierPublicKey → keygen Handle returns error
- bit-flipped Πmod/Πprm → rejected at protocol level
- Missing LogStarProof → KeyShare.MarshalBinary returns error
- Tampered LogStarProof → KeyShare.MarshalBinary returns error
- Missing ShareProof (Schnorr) → KeyShare.MarshalBinary returns error
- Missing PaillierProof → KeyShare.MarshalBinary returns error
- Missing RingPedersenProof → KeyShare.MarshalBinary returns error

### Phase 8: Challenge Zero Guard

**Covered by**: `challenge_zero_test.go` (Tier 0)

- New `Transcript.ChallengeSigned()` (transcript.go) REJECTS zero with error
- 1-bit challenge zero-guard tested: ~50% rejection rate confirmed

### Known Limitations

1. **Πmod proof** verifier-derived y_i values use `expandHash` which may have
   subtle biases when deriving values in Z\*\_N for small N. With production
   (3072-bit) moduli, the rejection sampling rate is negligible.

2. **Statistical hiding** with production params provides ~358 bits of hiding
   (EncRange − ChallengeBits = 486 − 128). This exceeds the 128-bit target
   but is less than the 128-bit statistical security parameter (ε=230) might
   suggest when considered as an additive bound.

### Files

| File                                       | Tier | Contents                              |
| ------------------------------------------ | ---- | ------------------------------------- |
| `extractor_test.go`                        | 1    | Special soundness extractor tests     |
| `challenge_distribution_test.go`           | 3    | Challenge distribution (slowcrypto)   |
| `range_boundary_test.go`                   | 0/1  | Range bound boundary precision        |
| `params_consistency_test.go`               | 0/1  | Parameter consistency verification    |
| `relation_audit_test.go`                   | 1    | Witness-statement relation audit      |
| `adversarial_test.go`                      | 1    | Adversarial proof construction        |
| `challenge_zero_test.go`                   | 0    | Challenge zero guard audit            |
| `cggmp21/secp256k1/proof_omission_test.go` | 2    | Protocol-level omission (integration) |
