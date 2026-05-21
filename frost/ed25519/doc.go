// Package ed25519 implements a dealerless FROST-style threshold Ed25519 flow.
//
// It performs Shamir/Pedersen-style DKG over the Ed25519 prime-order subgroup,
// two-round signing with binding nonces, partial signature verification, and
// aggregation into signatures accepted by crypto/ed25519.Verify.
package ed25519
