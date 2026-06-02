# Paillier ZK Proof Notes

The Paillier proof package supports the CGGMP21-style secp256k1 path. These
records are deterministic, transcript-bound proof shells used by the local MtA
implementation.

## Status

- Seven proof types: <code>ModulusProof</code> (Π^fac), <code>PrimalityProof</code> (Π^prm),
  <code>EncryptionProof</code> (Π^Enc), <code>EncScalarProof</code> (Π^Eq),
  <code>EncRangeProof</code>, <code>MTAResponseProof</code> (Π^mta), and
  <code>LogProof</code> (Π^log).
- Proof payloads are canonical TLV records through <code>internal/wire</code>.
- Proof integer fields are minimal positive big-endian values.
- secp256k1 point fields must decode through the curve package before a proof
  is accepted.
- Transcript, digest, and challenge labels are fixed constants in
  <code>internal/zk/paillier</code>. The CGGMP21 caller supplies an outer proof domain
  that binds protocol name, library version, session id, threshold, ordered
  participant set, signer set when applicable, sender, receiver, proof kind,
  group public key, keygen transcript hash, and Paillier public key.
- The package still requires independent cryptographic review before the
  <code>cggmp21/secp256k1</code> experimental warning can be removed.

## Proof Inventory

| Proof                                 | Statement                                                                                                                                                                        | Witness                                                                                     | Transcript inputs                                                                                                                     | Verifier checks                                                                                                                                 | Wire type                                   | Status                                                |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------- |
| Π^fac (<code>ModulusProof</code>)     | Proves knowledge of factorization N = p·q by opening verifier-derived Jacobi +1 challenges as square roots of x or -x modulo N.                                                  | Paillier prime factors <code>p</code>, <code>q</code> where <code>p ≡ q ≡ 3 (mod 4)</code>. | Outer proof domain, party id, N bit-length, small-factor digest, verifier seed.                                                       | Public key validation, modulus bit length, odd composite check, small-factor digest match, transcript hash, challenge hash, 128 root equations. | <code>zk.paillier.modulus-proof</code>      | Active (keygen, reshare, refresh)                     |
| Π^prm (<code>PrimalityProof</code>)   | Extends Π^fac: proves factors have approximately equal bit-length.                                                                                                               | Same as Π^fac.                                                                              | Outer proof domain, party id, factor bit-length bound, verifier seed.                                                                 | Same root-opening checks as Π^fac plus factor bit-length ∈ [N.BitLen()/2 - 1, N.BitLen()/2 + 1].                                                | <code>zk.paillier.primality-proof</code>    | Active (keygen, reshare, refresh)                     |
| Π^Enc (<code>EncryptionProof</code>)  | Unified proof: a Paillier ciphertext and secp256k1 commitment open to the same scalar, and the scalar is less than the group order <code>q</code>. Single Fiat-Shamir challenge. | Scalar <code>k_i</code>, Paillier randomness <code>ρ</code>.                                | Outer proof domain, public key, ciphertext, scalar commitment, cipher commitment, point commitment, bound <code>q</code>.             | Ciphertext validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation, range bound <code>z < q² + q</code>.             | <code>zk.paillier.encryption-proof</code>   | Active (presign round 1 via <code>mta.Start</code>)   |
| Π^Eq (<code>EncScalarProof</code>)    | Legacy split form: a Paillier ciphertext and secp256k1 commitment open to the same scalar. No range bound.                                                                       | Scalar and Paillier randomness.                                                             | Outer proof domain, public key, ciphertext, scalar commitment, cipher commitment, point commitment.                                   | Ciphertext validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation.                                                  | <code>zk.paillier.enc-scalar-proof</code>   | Legacy (not used in current protocol flows)           |
| <code>EncRangeProof</code>            | Legacy split form: the encrypted scalar is less than the secp256k1 order. Uses an independent Fiat-Shamir challenge (not coupled to Π^Eq).                                       | Same scalar as Π^Eq.                                                                        | Bound <code>q</code>, challenge, response, encrypted-scalar transcript hash.                                                          | Transcript linkage, response linkage, order bound, digest, challenge, response size cap.                                                        | <code>zk.paillier.enc-range-proof</code>    | Legacy (not used in current protocol flows)           |
| Π^mta (<code>MTAResponseProof</code>) | An MtA response encrypts the responder product share plus beta and matches public commitments.                                                                                   | Responder scalar <code>b</code>, beta share, beta randomness <code>β</code>.                | Outer proof domain, public key, input ciphertext, response ciphertext, scalar commitment, beta commitment, cipher commitment, nonces. | Ciphertext validity, point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation, curve relations.                                | <code>zk.paillier.mta-response-proof</code> | Active (presign round 2 via <code>mta.Respond</code>) |
| Π^log (<code>LogProof</code>)         | A Paillier ciphertext and secp256k1 curve point share the same discrete logarithm.                                                                                               | Scalar <code>a</code>, Paillier randomness <code>ρ</code>.                                  | Point, cipher commitment, point commitment, response, randomness, transcript hash.                                                    | Point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation, curve relation.                                                      | <code>zk.paillier.log-proof</code>          | Implemented, not yet wired                            |

The <code>ProveModulus</code> function samples a verifier seed, derives 128 independent
Jacobi +1 challenges from the transcript, and opens each challenge as a square
root of either x or -x modulo N. For a Blum modulus, exactly one of those targets
is a quadratic residue, so opening every round demonstrates factorization
knowledge without revealing p or q. <code>ProvePrimality</code> extends this by additionally
binding the factor bit-length into the transcript (proving p and q have
approximately equal size).

The <code>smallFactorDigest</code> precomputation (<code>sha256(2||3||…||maxSmallPrime)</code>)
is used to catch N divisible by a small prime before the full proof verification,
and the digest is bound into the transcript.

The current protocol flows use the unified <code>ProveEncryption</code> / <code>VerifyEncryption</code>
(Π^Enc) for presign round 1. The older split functions <code>ProveEncScalarAndRange</code> /
<code>VerifyEncScalarAndRange</code> exist but are no longer called from the CGGMP21 flows.

## Usage by Protocol Phase

| Phase           | Proofs used                                                   | Code location                                          |
| --------------- | ------------------------------------------------------------- | ------------------------------------------------------ |
| Keygen          | Π^fac, Π^prm (per-party); Π^fac re-proved for stored KeyShare | <code>keygen.go</code>                                 |
| Presign round 1 | Π^Enc (per-party, via <code>mta.Start</code>)                 | <code>sign.go</code>, <code>internal/mta/mta.go</code> |
| Presign round 2 | Π^mta (pairwise, delta and sigma kinds)                       | <code>sign.go</code>, <code>internal/mta/mta.go</code> |
| Reshare         | Π^fac, Π^prm (new Paillier key)                               | <code>reshare.go</code>                                |
| Refresh         | Π^fac, Π^prm (new Paillier key)                               | <code>refresh.go</code>                                |

## Decoder Boundary

Production proof decoders only accept TLV. They reject JSON payloads, wrong
proof type identifiers, duplicate or unsorted fields, trailing bytes,
non-minimal integers, malformed root-opening records, oversized MtA response
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

- Wire Π^log into the reshare flow (implemented, not yet called).
- Review the outer proof-domain fields against the final CGGMP21 message schedule.
- Confirm identifiable-abort evidence contains enough public context to blame
  malformed proof senders without leaking private shares, nonces, or Paillier
  secret-key material.
- Complete an independent cryptographic review of the Paillier/ZK layer and
  identifiable-abort behavior.
