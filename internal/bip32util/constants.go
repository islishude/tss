package bip32util

// HardenedKeyStart is the first index reserved for hardened BIP32 derivation.
// Non-hardened indices are in [0, HardenedKeyStart).
const HardenedKeyStart = 1 << 31

// Extended public key version bytes (mainnet / testnet xpub).
var (
	// XPubVersion is the BIP32 mainnet extended public key version.
	XPubVersion = [4]byte{0x04, 0x88, 0xB2, 0x1E}

	// TPubVersion is the BIP32 testnet extended public key version.
	TPubVersion = [4]byte{0x04, 0x35, 0x87, 0xCF}
)

// IsKnownVersion reports whether v is a recognized xpub/tpub version.
func IsKnownVersion(v [4]byte) bool {
	return v == XPubVersion || v == TPubVersion
}
