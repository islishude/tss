// Package secp256k1 exposes the planned GG20/secp256k1 threshold ECDSA API.
//
// The current keygen uses Shamir shares and public commitments, and the signing
// path is intentionally marked experimental: it reconstructs signing secrets
// from threshold shares instead of implementing the full GG20 Paillier MtA and
// zero-knowledge proof machinery. Do not use this package as production GG20
// threshold ECDSA until that MPC signing path has been completed and audited.
package secp256k1
