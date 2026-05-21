// Package secp256k1 exposes the planned GG20/secp256k1 threshold ECDSA API.
//
// Keygen uses Shamir shares, public commitments, Paillier key material, and
// proof bindings. Signing avoids reconstructing private key or nonce shares and
// uses Paillier MtA/MtAwc-style product sharing. The package remains marked
// experimental because the proof system is intentionally minimal and still
// requires independent cryptographic review before production use.
package secp256k1
