// Package bip32util provides shared constants, sentinel errors, and helpers
// for BIP32 derivation that are used by both secp256k1 and ed25519 HD packages.
//
// This package does not implement derivation logic — each curve package provides
// its own [DeriveNonHardenedBIP32] or [DeriveNonHardenedBIP32Extended].
package bip32util

import "errors"

// Sentinel errors for BIP32 derivation.
var (
	// ErrChainCodeRequired is returned when a nil or empty chain code is provided.
	ErrChainCodeRequired = errors.New("chain code required")

	// ErrInvalidChainCodeLength is returned when the chain code is not 32 bytes.
	ErrInvalidChainCodeLength = errors.New("chain code must be 32 bytes")

	// ErrInvalidPublicKey is returned when the public key is not a valid curve point.
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrHardenedDerivationUnsupported is returned when a hardened index is
	// encountered in a non-hardened-only derivation context.
	ErrHardenedDerivationUnsupported = errors.New("hardened BIP32 derivation unsupported")

	// ErrInvalidChild is returned when BIP32 derivation produces a zero or
	// out-of-range scalar.
	ErrInvalidChild = errors.New("invalid BIP32 child")

	// ErrDerivationDepthOverflow is returned when the path exceeds 255 indices.
	ErrDerivationDepthOverflow = errors.New("BIP32 depth overflow")

	// ErrInvalidExtendedPublicKey is returned when an extended public key fails
	// validation (bad version, invalid point, etc.).
	ErrInvalidExtendedPublicKey = errors.New("invalid extended public key")
)
