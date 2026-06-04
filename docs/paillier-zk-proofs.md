# Paillier ZK Proof Notes

The Paillier proof package supports the CGGMP21-style secp256k1 path. These
records are deterministic, transcript-bound proof shells used by the local MtA
implementation.

## Status

- Active proof types: <code>ModulusProof</code> (CGGMP24 Πmod),
  <code>RingPedersenProof</code> (CGGMP24 Πprm),
  <code>EncProof</code> (Πenc), <code>AffGProof</code> (Πaff-g), and
  <code>LogStarProof</code> (Πlog\*).
- Legacy v1 types (<code>EncryptionProof</code>, <code>MTAResponseProof</code>,
  <code>LogProof</code>) remain in <code>proofs.go</code>; only
  <code>EncryptionProof</code> is still consumed (by the MtA Start broadcast path).
- All proofs use <code>SecurityParams</code> (Ell, EllPrime, Epsilon, ChallengeBits,
  MinPaillierBits) configured via <code>ActiveSecurityParams()</code>.
- Integer responses use canonical signed-magnitude encoding; verifier range
  checks precede all algebraic equation checks.
- All proofs use Ring-Pedersen commitments to hide integer witnesses.
  Commitment nonces are sampled from the configured <code>SecurityParams</code> ranges.
- Proof payloads are canonical TLV records through <code>internal/wire</code> at
  version 1.
- The package still requires independent cryptographic review before the
  <code>cggmp21/secp256k1</code> experimental warning can be removed.

## Proof Inventory

| Proof                                 | Statement                                                                                                                                                                                     | Witness                                                                                     | Transcript inputs                                                                                                                         | Verifier checks                                                                                                                                                                  | Wire type                                    | Status                                                |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------- |
| Πmod (<code>ModulusProof</code>)      | CGGMP24 proof for a Paillier-Blum modulus. Contains <code>w</code> and exactly 128 verifier-derived rounds <code>(x_i,a_i,b_i,z_i)</code>; it never carries prover-supplied <code>y_i</code>. | Paillier prime factors <code>p</code>, <code>q</code> where <code>p ≡ q ≡ 3 (mod 4)</code>. | Typed proof transcript: proof tag, curve, proof version, outer domain, party id, Paillier public key, <code>w</code>.                     | Structural validation, odd composite N, <code>w,x_i,z_i ∈ Z\*\_N</code>, <code>Jacobi(w,N)=-1</code>, bit checks, <code>z_i^N=y_i</code>, and <code>x_i^4=(-1)^a w^b y_i</code>. | <code>zk.paillier.modulus-proof</code>       | Active (keygen, reshare, refresh)                     |
| Πprm (<code>RingPedersenProof</code>) | CGGMP24 proof of Ring-Pedersen parameters <code>(N,s,t)</code>, proving knowledge of λ such that <code>s=t^λ mod N</code>.                                                                    | Ring-Pedersen secret λ.                                                                     | Typed proof transcript: proof tag, curve, proof version, outer domain, party id, canonical parameter bytes, commitments.                  | Validates <code>(N,s,t)</code>, exact 128 rounds, verifier-derived challenge bits, response bounds, and <code>t^z = commitment·s^e mod N</code>.                                 | <code>zk.paillier.ring-pedersen-proof</code> | Active (keygen, reshare, refresh)                     |
| Πenc (<code>EncProof</code>)          | Paillier encryption of a plaintext in ±2^Ell, with Ring-Pedersen commitment under the verifier's auxiliary parameters.                                                                        | Scalar <code>k</code>, Paillier randomness <code>ρ</code>.                                  | Typed transcript: curve, proof tag, version, SecurityParams, state, prover N, verifier N/S/T, K, S, A, C.                                 | Ciphertext/point/RP membership, z1/z3 range, challenge recomputation, Paillier equation, RP equation.                                                                            | <code>zk.paillier.enc-proof-</code>          | Active (available; MtA Start uses v1 for broadcast)   |
| Πaff-g (<code>AffGProof</code>)       | MtA response: D = x⊙C ⊕ Enc(y;ρ) with X=x·G and Y=Enc(y), using verifier's Ring-Pedersen params. Y is carried in the proof so the initiator can verify equation 3.                            | Scalars <code>x, y</code>, randomness <code>ρ, ρY</code>.                                   | Typed transcript: curve, proof tag, version, SecurityParams, state, receiver/prover N, verifier N/S/T, C, D, Y, X, A, Bx, By, E, S, F, T. | 6 membership checks, 4 range checks, 5 algebraic equations (2 Paillier, 1 curve, 2 RP).                                                                                          | <code>zk.paillier.aff-g-proof-</code>        | Active (presign round 2 via <code>mta.Respond</code>) |
| Πlog\* (<code>LogStarProof</code>)    | Paillier ciphertext and curve point share discrete log in range, with Ring-Pedersen commitment under the prover's own parameters.                                                             | Scalar <code>x</code>, Paillier randomness <code>ρ</code>.                                  | Typed transcript: curve, proof tag, version, SecurityParams, state, Paillier N, verifier N/S/T, C, X, B, S, A, Y, D.                      | Ciphertext/point/RP membership, z1/z3 range, challenge recomputation, Paillier equation, curve equation, RP equation.                                                            | <code>zk.paillier.logstar-proof-</code>      | Active (keygen, reshare, refresh)                     |

Legacy v1 proofs (<code>EncryptionProof</code>, <code>MTAResponseProof</code>, <code>LogProof</code>) use the wire types <code>zk.paillier.encryption-proof</code>, <code>zk.paillier.mta-response-proof</code>, and <code>zk.paillier.log-proof</code> respectively. Only <code>EncryptionProof</code> is still consumed (by the MtA Start broadcast path where per-verifier Ring-Pedersen commitments are impractical; the witness k_i is ephemeral).

## Usage by Protocol Phase

| Phase           | Proofs used                                                | Code location                                                                                     |
| --------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Keygen          | Πmod, Πprm (Ring-Pedersen), Πlog\* (LogStarProof )         | <code>keygen.go</code>, <code>internal/zk/paillier/logstar.go</code>                              |
| Presign round 1 | EncryptionProof v1 (per-party, via <code>mta.Start</code>) | <code>sign.go</code>, <code>internal/mta/mta.go</code>                                            |
| Presign round 2 | Πaff-g (AffGProof , pairwise, delta and sigma kinds)       | <code>sign.go</code>, <code>internal/mta/mta.go</code>, <code>internal/zk/paillier/affg.go</code> |
| Reshare         | Πmod, Πprm, Πlog\* (LogStarProof )                         | <code>reshare.go</code>, <code>internal/zk/paillier/logstar.go</code>                             |
| Refresh         | Πmod, Πprm, Πlog\* (LogStarProof )                         | <code>refresh.go</code>, <code>internal/zk/paillier/logstar.go</code>                             |

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

## Blockers Before Production Use

- Review the outer proof-domain fields against the final CGGMP21 message schedule.
- Confirm identifiable-abort evidence contains enough public context to blame
  malformed proof senders without leaking private shares, nonces, or Paillier
  secret-key material.
- Complete an independent cryptographic review of the Paillier/ZK layer and
  identifiable-abort behavior.
