# Paillier ZK Proof Notes

The Paillier proof package supports the CGGMP21-style secp256k1 path. These
records are deterministic, transcript-bound proof shells used by the local MtA
implementation.

## Status

- Active proof types: <code>ModulusProof</code> (CGGMP24 Πmod),
  <code>RingPedersenProof</code> (CGGMP24 Πprm),
  <code>EncryptionProof</code> (Π^Enc), <code>MTAResponseProof</code> (Π^mta), and
  <code>LogProof</code> (Π^log).
- Proof payloads are canonical TLV records through <code>internal/wire</code>.
- Paillier integers are fixed-width encodings derived from <code>N</code> or
  <code>N²</code>; scalar responses are canonical positive big-endian values.
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

| Proof                                 | Statement                                                                                                                                                                                     | Witness                                                                                     | Transcript inputs                                                                                                                     | Verifier checks                                                                                                                                                                  | Wire type                                    | Status                                                |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------- |
| Πmod (<code>ModulusProof</code>)      | CGGMP24 proof for a Paillier-Blum modulus. Contains <code>w</code> and exactly 128 verifier-derived rounds <code>(x_i,a_i,b_i,z_i)</code>; it never carries prover-supplied <code>y_i</code>. | Paillier prime factors <code>p</code>, <code>q</code> where <code>p ≡ q ≡ 3 (mod 4)</code>. | Typed proof transcript: proof tag, curve, proof version, outer domain, party id, Paillier public key, <code>w</code>.                 | Structural validation, odd composite N, <code>w,x_i,z_i ∈ Z\*\_N</code>, <code>Jacobi(w,N)=-1</code>, bit checks, <code>z_i^N=y_i</code>, and <code>x_i^4=(-1)^a w^b y_i</code>. | <code>zk.paillier.modulus-proof</code>       | Active (keygen, reshare, refresh)                     |
| Πprm (<code>RingPedersenProof</code>) | CGGMP24 proof of Ring-Pedersen parameters <code>(N,s,t)</code>, proving knowledge of λ such that <code>s=t^λ mod N</code>.                                                                    | Ring-Pedersen secret λ.                                                                     | Typed proof transcript: proof tag, curve, proof version, outer domain, party id, canonical parameter bytes, commitments.              | Validates <code>(N,s,t)</code>, exact 128 rounds, verifier-derived challenge bits, response bounds, and <code>t^z = commitment·s^e mod N</code>.                                 | <code>zk.paillier.ring-pedersen-proof</code> | Active (keygen, reshare, refresh)                     |
| Π^Enc (<code>EncryptionProof</code>)  | Unified proof: a Paillier ciphertext and secp256k1 commitment open to the same scalar, and the scalar is less than the group order <code>q</code>. Single Fiat-Shamir challenge.              | Scalar <code>k_i</code>, Paillier randomness <code>ρ</code>.                                | Outer proof domain, public key, ciphertext, scalar commitment, cipher commitment, point commitment, bound <code>q</code>.             | Ciphertext validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation, range bound <code>z < q² + q</code>.                                              | <code>zk.paillier.encryption-proof</code>    | Active (presign round 1 via <code>mta.Start</code>)   |
| Π^mta (<code>MTAResponseProof</code>) | An MtA response encrypts the responder product share plus beta and matches public commitments.                                                                                                | Responder scalar <code>b</code>, beta share, beta randomness <code>β</code>.                | Outer proof domain, public key, input ciphertext, response ciphertext, scalar commitment, beta commitment, cipher commitment, nonces. | Ciphertext validity, point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation, curve relations.                                                                 | <code>zk.paillier.mta-response-proof</code>  | Active (presign round 2 via <code>mta.Respond</code>) |
| Π^log (<code>LogProof</code>)         | A Paillier ciphertext and secp256k1 curve point share the same discrete logarithm.                                                                                                            | Scalar <code>a</code>, Paillier randomness <code>ρ</code>.                                  | Point, cipher commitment, point commitment, response, randomness, transcript hash.                                                    | Point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation, curve relation.                                                                                       | <code>zk.paillier.log-proof</code>           | Active (keygen, reshare, refresh)                     |

The current protocol flows use the unified <code>ProveEncryption</code> / <code>VerifyEncryption</code>
(Π^Enc) for presign round 1. The older split EncScalar/EncRange production and
wire paths have been removed.

## Usage by Protocol Phase

| Phase           | Proofs used                                   | Code location                                          |
| --------------- | --------------------------------------------- | ------------------------------------------------------ |
| Keygen          | Πmod, Πprm (Ring-Pedersen), Π^log             | <code>keygen.go</code>                                 |
| Presign round 1 | Π^Enc (per-party, via <code>mta.Start</code>) | <code>sign.go</code>, <code>internal/mta/mta.go</code> |
| Presign round 2 | Π^mta (pairwise, delta and sigma kinds)       | <code>sign.go</code>, <code>internal/mta/mta.go</code> |
| Reshare         | Πmod, Πprm (Ring-Pedersen), Π^log             | <code>reshare.go</code>                                |
| Refresh         | Πmod, Πprm (Ring-Pedersen), Π^log             | <code>refresh.go</code>                                |

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
