// Package paillier contains Paillier zero-knowledge proofs used by the
// CGGMP21-style secp256k1 signing path.
//
// The package exposes transcript-bound, canonical binary proof payloads for
// the local MtA implementation:
//
//   - ModulusProof is CGGMP24 Πmod for a Paillier-Blum modulus.
//   - RingPedersenProof is CGGMP24 Πprm for Ring-Pedersen parameters.
//   - EncProof (Πenc, ) proves that a Paillier ciphertext encrypts a
//     plaintext in the range ±2^Ell, using Ring-Pedersen commitments and
//     large integer masks for statistical zero-knowledge.
//   - AffGProof (Πaff-g, ) proves that an MtA response was correctly
//     computed: D = x ⊙ C ⊕ Enc_Nj(y; rho) with X = x·G and Y = Enc_Ni(y).
//     Uses Ring-Pedersen commitments and binds both Paillier keys.
//   - LogStarProof (Πlog*, ) proves that a Paillier ciphertext and a
//     secp256k1 curve point share the same discrete logarithm in range,
//     using Ring-Pedersen commitment to hide the integer witness.
//
// All proofs use SecurityParams to configure statistical and computational
// security parameters, including the minimum bit length for both Paillier public
// moduli and Ring-Pedersen auxiliary moduli. A typed Transcript API derives
// Fiat-Shamir challenges from every SecurityParams field, signed integer
// encoding keeps witness responses canonical, and structural/membership checks
// run before algebraic equation verification.
package paillier
