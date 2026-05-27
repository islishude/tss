// Package paillier contains Paillier zero-knowledge proofs used by the
// CGGMP21-style secp256k1 signing path.
//
// The package exposes transcript-bound, canonical binary proof payloads for
// the local MtA implementation:
//
//   - ModulusProof is a Fiat-Shamir Σ-protocol proving knowledge of the
//     factorization of a Blum integer N = p·q with p ≡ q ≡ 3 (mod 4).
//     The proof demonstrates knowledge of a non-trivial square root of 1
//     modulo N, which is equivalent to knowing the factorization.
//   - EncScalarProof proves that a Paillier ciphertext and a secp256k1 curve
//     commitment open to the same scalar witness.
//   - EncRangeProof independently proves that a Paillier ciphertext encrypts
//     a scalar less than the secp256k1 order, using its own Fiat-Shamir
//     challenge and transcript distinct from EncScalarProof.
//   - MTAResponseProof binds an MtA response ciphertext to the encrypted input
//     scalar, the responder scalar commitment, and the beta share commitment.
//
// Integer fields are encoded as minimal positive big-endian values so
// equivalent leading-zero aliases are rejected, and curve point fields must
// be accepted by the secp256k1 point decoder.  Transcript and challenge
// labels are fixed package constants so changes to proof domains are
// explicit review points.
package paillier
