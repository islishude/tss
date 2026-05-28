# Paillier ZK Proof Notes

The Paillier proof package supports the experimental CGGMP21-style secp256k1
path. These records are deterministic, transcript-bound proof shells used by
the local MtA implementation. They are not a claim of a production-audited
CGGMP21 proof set.

## Status

- Proof payloads are canonical TLV records through `internal/wire`.
- Proof integer fields are minimal positive big-endian values.
- secp256k1 point fields must decode through the curve package before a proof
  is accepted.
- Transcript, digest, and challenge labels are fixed constants in
  `internal/zk/paillier`. The CGGMP21 caller supplies an outer proof domain
  that binds protocol name, library version, session id, threshold, ordered
  participant set, signer set when applicable, sender, receiver, proof kind,
  group public key, keygen transcript hash, and Paillier public key.
- The package still requires independent cryptographic review before the
  `cggmp21/secp256k1` experimental warning can be removed.

## Proof Inventory

| Proof              | Statement                                                                                                                            | Witness                                              | Transcript inputs                                                                                                                     | Verifier checks                                                                                                                                      | Remaining review gap                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `ModulusProof`     | Proves knowledge of factorization of N = p·q via Σ-protocol with non-trivial square root of 1 modulo N (Blum integer factorization). | Paillier prime factors p, q where p ≡ q ≡ 3 (mod 4). | Outer proof domain, party id, N bit-length, small-factor digest.                                                                      | Public key validation, modulus bit length, odd composite check, small-factor digest match, transcript hash, Fiat-Shamir challenge digest.            | Needs independent review against the final CGGMP21 Π^fac statement.                      |
| `EncScalarProof`   | A Paillier ciphertext and secp256k1 commitment open to the same scalar.                                                              | Scalar and Paillier randomness.                      | Outer proof domain, public key, ciphertext, scalar commitment, cipher commitment, point commitment.                                   | Ciphertext validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation.                                                       | Needs review against the final CGGMP21 signing proof requirements.                       |
| `EncRangeProof`    | The encrypted scalar is less than the secp256k1 order. Uses an independent Fiat-Shamir challenge (not coupled to `EncScalarProof`).  | Same scalar as `EncScalarProof`.                     | Bound, challenge, response, encrypted-scalar transcript hash.                                                                         | Transcript linkage, response linkage, order bound, digest, challenge, response size cap.                                                             | The range check is a consistency shell and does not replace a reviewed range proof.      |
| `MTAResponseProof` | An MtA response encrypts the responder product share plus beta and matches public commitments.                                       | Responder scalar, beta share, beta randomness.       | Outer proof domain, public key, input ciphertext, response ciphertext, scalar commitment, beta commitment, cipher commitment, nonces. | Ciphertext validity, point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation, curve relations.                                     | Needs independent review for identifiable abort and complete CGGMP21 MtA proof coverage. |
| `LogProof` (Π^log) | A Paillier ciphertext and secp256k1 curve point share the same discrete logarithm. Used in CGGMP21 resharing (Section 6.2).          | Scalar a and Paillier randomness.                    | Point, cipher commitment, point commitment, response, randomness, transcript hash.                                                    | Point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation `c_commit · Enc(0)^challenge ≡ Enc(response; randomness)`, curve relation. | Needs independent review against the final CGGMP21 Π^log statement.                      |

The `ProveModulus` function uses a Σ-protocol that proves knowledge of a non-trivial
square root of 1 modulo N — equivalent to knowing the factorization of N into
primes p, q ≡ 3 (mod 4). The `smallFactorDigest` precomputation (`sha256(2||3||…||maxSmallPrime)`)
is used to catch N divisible by a small prime before the full proof verification,
and the digest is bound into the transcript.

## Decoder Boundary

Production proof decoders only accept TLV. They reject JSON payloads, wrong
proof type identifiers, duplicate or unsorted fields, trailing bytes,
non-minimal integers, and malformed curve points. There is no proof conversion
helper in the production package; callers must regenerate unsupported proof
bytes through the current keygen and presign flows.

## Blockers Before Production Use

- Add the remaining CGGMP21 proofs (Π^prm, Π^Enc) and prove equivalence of the
  current proof set against the final CGGMP21 Paillier/MtA/ZK requirements.
- Review the outer proof-domain fields against the final CGGMP21 message schedule,
  including the new Π^log proof used in resharing.
- Confirm identifiable-abort evidence contains enough public context to blame
  malformed proof senders without leaking private shares, nonces, or Paillier
  secret-key material.
- Complete an independent cryptographic review of the Paillier/ZK layer and
  identifiable-abort behavior.
