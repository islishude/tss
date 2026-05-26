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

| Proof              | Statement                                                                                                      | Witness                                        | Transcript inputs                                                                                                                     | Verifier checks                                                                                                  | Remaining review gap                                                                     |
| ------------------ | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `ModulusProof`     | The Paillier public key is bound to the keygen or key-share transcript and passes local modulus sanity checks. | None beyond public key generation.             | Outer proof domain, party id, public key bytes, small-factor digest.                                                                  | Public key validation, modulus bit length, odd composite check, small-factor digest, transcript hash, digest.    | This is a local shell, not a CGGMP21 modulus proof of correct key generation.            |
| `EncScalarProof`   | A Paillier ciphertext and secp256k1 commitment open to the same scalar.                                        | Scalar and Paillier randomness.                | Outer proof domain, public key, ciphertext, scalar commitment, cipher commitment, point commitment.                                   | Ciphertext validity, point decoding, Fiat-Shamir challenge, Paillier relation, curve relation.                   | Needs review against the final CGGMP21 signing proof requirements.                       |
| `EncRangeProof`    | The encrypted scalar response is paired with the secp256k1 order bound.                                        | Same response as `EncScalarProof`.             | Bound, challenge, response, encrypted-scalar transcript hash.                                                                         | Transcript linkage, response linkage, order bound, digest, challenge, response size cap.                         | The range shell is a consistency check and does not replace a reviewed range proof.      |
| `MTAResponseProof` | An MtA response encrypts the responder product share plus beta and matches public commitments.                 | Responder scalar, beta share, beta randomness. | Outer proof domain, public key, input ciphertext, response ciphertext, scalar commitment, beta commitment, cipher commitment, nonces. | Ciphertext validity, point decoding, transcript hash, Fiat-Shamir challenge, Paillier relation, curve relations. | Needs independent review for identifiable abort and complete CGGMP21 MtA proof coverage. |

## Decoder Boundary

Production proof decoders only accept TLV. They reject JSON payloads, wrong
proof type identifiers, duplicate or unsorted fields, trailing bytes,
non-minimal integers, and malformed curve points. There is no proof conversion
helper in the production package; callers must regenerate unsupported proof
bytes through the current keygen and presign flows.

## Blockers Before Production Use

- Replace or prove equivalence of the current shells against the final
  CGGMP21 Paillier/MtA/ZK proof set.
- Replace the current shell statements with the final CGGMP21 proof statements
  and review the outer proof-domain fields against the final message schedule.
- Confirm identifiable-abort evidence contains enough public context to blame
  malformed proof senders without leaking private shares, nonces, or Paillier
  secret-key material.
- Complete an independent cryptographic review of the Paillier/ZK layer and
  identifiable-abort behavior.
