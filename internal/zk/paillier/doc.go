// Package paillier contains the Paillier proof shells used by the
// CGGMP21-style secp256k1 signing path.
//
// The package exposes transcript-bound, canonical binary proof payloads for
// the local MtA implementation:
//
//   - ModulusProof binds a Paillier public modulus to keygen transcript
//     context and rejects malformed public keys, prime moduli, even moduli,
//     and small-factor digest mismatches.
//   - EncScalarProof proves that a Paillier ciphertext and a secp256k1 curve
//     commitment open to the same scalar witness.
//   - EncRangeProof is paired with EncScalarProof and binds the scalar response
//     to the secp256k1 order bound used by the signing protocol.
//   - MTAResponseProof binds an MtA response ciphertext to the encrypted input
//     scalar, the responder scalar commitment, and the beta share commitment.
//
// These proof structures are still explicitly unaudited. They are designed to
// keep protocol transcripts deterministic and fail closed while the full
// CGGMP21 proof set is reviewed. Integer fields are encoded as minimal
// positive big-endian values so equivalent leading-zero aliases are rejected.
package paillier
