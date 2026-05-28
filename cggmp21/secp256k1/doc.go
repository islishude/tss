// Package secp256k1 exposes the CGGMP21/secp256k1 threshold ECDSA API.
//
// Keygen uses Shamir shares, public commitments, Paillier key material, and
// proof bindings. Signing avoids reconstructing private key or nonce shares and
// uses Paillier MtA/MtAwc-style product sharing. The ZK proof layer has been
// prepared for independent cryptographic review; see docs/audit-guide.md.
package secp256k1
