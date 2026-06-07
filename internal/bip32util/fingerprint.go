package bip32util

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160" //nolint:all // BIP32 requires RIPEMD160 for parent fingerprint
)

// ComputeFingerprint returns the BIP32 parent fingerprint: the first 4 bytes of
// RIPEMD160(SHA256(compressedPubKey)). This is curve-agnostic — it works for
// both 33-byte secp256k1 and 32-byte ed25519 public keys.
func ComputeFingerprint(pubKey []byte) [4]byte {
	sha := sha256.Sum256(pubKey)
	ripe := ripemd160.New() //nolint:all // BIP32 requires RIPEMD160 for parent fingerprint
	ripe.Write(sha[:])
	h := ripe.Sum(nil)
	var fp [4]byte
	copy(fp[:], h[:4])
	return fp
}
