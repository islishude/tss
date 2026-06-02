package secp256k1

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// HardenedKeyStart is the first index reserved for hardened BIP32 derivation.
// Non-hardened indices are in [0, HardenedKeyStart).
const HardenedKeyStart = 1 << 31

// DeriveBIP32 performs non-hardened BIP32 CKD (child key derivation) for
// threshold ECDSA keys. It returns the child public key, the cumulative
// additive shift that StartPresignWithContext binds into the Presign, and the
// child chain code. Only non-hardened indices (i < 2^31) are supported since
// hardened derivation requires the private key which no single party has
// in a threshold setting.
//
// The publicKey and chainCode should come from KeyShare.PublicKey and
// KeyShare.ChainCode respectively. The path represents BIP32 indices from
// the master key down to the desired child.
//
// Example: for path m/0/1/2, call DeriveBIP32(pubKey, chainCode, []uint32{0, 1, 2})
//
// If chainCode is nil or empty, DeriveBIP32 returns an error.
func DeriveBIP32(publicKey, chainCode []byte, path []uint32) (childPublicKey, additiveShift, childChainCode []byte, err error) {
	if len(chainCode) == 0 {
		return nil, nil, nil, errors.New("chain code required for BIP32 derivation")
	}
	if len(chainCode) != 32 {
		return nil, nil, nil, fmt.Errorf("chain code must be 32 bytes, got %d", len(chainCode))
	}
	if len(path) == 0 {
		return nil, nil, nil, errors.New("empty derivation path")
	}
	// Validate the master public key.
	if _, err := secp.PointFromBytes(publicKey); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid public key: %w", err)
	}
	parentPub := publicKey
	parentChain := chainCode
	cumShift := secp.ScalarZero()
	for _, idx := range path {
		if idx >= HardenedKeyStart {
			return nil, nil, nil, fmt.Errorf("hardened index %d not supported in threshold BIP32 derivation", idx)
		}
		// ser_P(parent) || ser_32(i)
		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], idx)
		mac := hmac.New(sha512.New, parentChain)
		mac.Write(parentPub)
		mac.Write(idxBytes[:])
		I := mac.Sum(nil)
		iL, err := secp.ParseScalar(I[:32])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid BIP32 derivation at index %d: %w", idx, err)
		}
		if iL.IsZero() {
			return nil, nil, nil, fmt.Errorf("BIP32 derivation produced zero scalar at index %d", idx)
		}
		cumShift = secp.ScalarAdd(cumShift, iL)
		childPub, err := DerivePublicKey(publicKey, secp.ScalarBytes(cumShift))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("child public key derivation at index %d: %w", idx, err)
		}
		parentPub = childPub
		parentChain = I[32:]
	}
	return parentPub, secp.ScalarBytes(cumShift), parentChain, nil
}
