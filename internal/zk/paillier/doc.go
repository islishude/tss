// Package paillier contains Paillier zero-knowledge proofs used by the
// CGGMP21-style secp256k1 signing path.
//
// The package exposes transcript-bound, canonical binary proof payloads for
// the local MtA implementation:
//
//   - ModulusProof is CGGMP24 Πmod for a Paillier-Blum modulus.
//   - RingPedersenProof is CGGMP24 Πprm for Ring-Pedersen parameters.
//   - EncryptionProof proves that a Paillier ciphertext and a secp256k1 curve
//     commitment open to the same scalar witness with a secp256k1-order bound.
//   - LogProof (Π^log) proves that a Paillier ciphertext and a secp256k1 curve
//     point share the same discrete logarithm, per CGGMP21 Section 6.2.
//   - MTAResponseProof binds an MtA response ciphertext to the encrypted input
//     scalar, the responder scalar commitment, and the beta share commitment.
//
// Paillier statement and commitment integers are encoded at fixed public-key
// widths; scalar responses are canonical positive big-endian values. Curve
// point fields must be accepted by the secp256k1 point decoder. Transcript and challenge
// labels are fixed package constants so changes to proof domains are
// explicit review points.
package paillier
