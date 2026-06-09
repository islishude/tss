// Package signprep provides the CGGMP21 signprep proof (Пsignprep) for
// secp256k1. It proves that a signer's published KPoint and ChiPoint during
// presign round 3 correspond to its private nonce k_i and its derived signing
// key contribution chi_i, and that both are consistent with the presign
// transcript accepted by that signer.
//
// The proof uses a unified Fiat-Shamir transcript binding Schnorr
// proofs-of-knowledge for KPoint and the MTA correction term MPoint, together
// with a DLEQ proof that the same k_i is used in the ChiPoint derivation
// equation:
//
//	ChiPoint = k_i * (XBarPoint + shift*G) + MPoint
//
// where XBarPoint is derived from the signer's public verification share and
// Lagrange coefficient.
//
// # Security properties
//
//   - Cross-session replay is prevented by binding the session ID.
//   - Cross-context replay is prevented by binding the presign context hash.
//   - Cross-signer replay is prevented by binding the signer's party ID.
//   - Signer-set substitution is prevented by binding the sorted signer list.
//   - Proof substitution is prevented by binding KPoint and ChiPoint into
//     the proof transcript.
//   - The proof does not reveal k_i, chi_i, or MTA intermediate secrets.
package signprep
