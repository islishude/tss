package ed25519

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
)

// DeriveNonHardenedBIP32 performs non-hardened BIP32-Ed25519 child key
// derivation following the Khovratovich-Law / Cardano ED25519-BIP32 scheme.
// It returns a [DerivationResult] containing the child public key, cumulative
// additive shift, and child chain code.
//
// Only non-hardened indices (i < 2^31) are supported. If path is nil or empty,
// the parent key is returned unchanged with a zero additive shift.
func DeriveNonHardenedBIP32(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	return bip32util.DeriveEd25519KhovratovichLaw(publicKey, chainCode, path, opts...)
}

// DerivePublicKey returns the child Ed25519 public key produced by adding
// the additive scalar shift times the base point to publicKey.
func DerivePublicKey(publicKey, additiveShift []byte) ([]byte, error) {
	return bip32util.DeriveEd25519PublicKey(publicKey, additiveShift)
}
