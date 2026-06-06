package ed25519

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// HardenedKeyStart is the first index reserved for hardened BIP32 derivation.
// Non-hardened indices are in [0, HardenedKeyStart).
const HardenedKeyStart = 1 << 31

// hmacF implements the two-round HMAC-SHA512 construction from the
// Khovratovich-Law ED25519-BIP32 paper: F(k, x) = HMAC(k, HMAC(k, x)).
func hmacF(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	inner := mac.Sum(nil)
	mac.Reset()
	mac.Write(inner)
	return mac.Sum(nil)
}

// DeriveBIP32 performs non-hardened BIP32-Ed25519 child key derivation
// following the Khovratovich-Law / Cardano ED25519-BIP32 scheme. It returns
// the child public key, the cumulative additive shift (suitable for
// SignOptions.AdditiveShift), and the child chain code. Only non-hardened
// indices (i < 2^31) are supported since hardened derivation requires the
// private key which no single party holds in a threshold setting.
//
// The publicKey and chainCode should come from KeyShare.PublicKey and
// KeyShare.ChainCode respectively.
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
	// depth uses uint8 in the standard BIP32 serialization, so we limit path length to 255.
	if len(path) > math.MaxUint8 {
		return nil, nil, nil, fmt.Errorf("derivation path too long: %d indices", len(path))
	}
	if _, err := edcurve.PointFromBytes(publicKey); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	parentPub := publicKey
	parentChain := chainCode
	cumShift := new(big.Int)
	order := edcurve.Order()

	for _, idx := range path {
		if idx >= HardenedKeyStart {
			return nil, nil, nil, fmt.Errorf("hardened index %d not supported in threshold BIP32 derivation", idx)
		}

		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], idx)

		// Save A_par for chain code derivation before it is updated.
		prevPub := parentPub

		// Z = F(c_par, 0x02 || A_par || ser_32(i))
		z := hmacF(parentChain, append(append([]byte{0x02}, prevPub...), idxBytes[:]...))

		// zL = 8 * LE_OS2IP(Z[0:28])  — cofactor clearing via *8
		zL := leBytesToBig(z[:28])
		zL.Mul(zL, big.NewInt(8))
		zL.Mod(zL, order)
		if zL.Sign() == 0 {
			return nil, nil, nil, fmt.Errorf("BIP32 derivation produced zero scalar at index %d", idx)
		}

		cumShift.Add(cumShift, zL)
		cumShift.Mod(cumShift, order)

		shiftBytes, err := scalarBytes(cumShift)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("scalar encoding at index %d: %w", idx, err)
		}
		childPub, err := DerivePublicKey(publicKey, shiftBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("child public key derivation at index %d: %w", idx, err)
		}
		parentPub = childPub

		// child chain: F(c_par, 0x03 || A_par || ser_32(i))[32:64]
		cc := hmacF(parentChain, append(append([]byte{0x03}, prevPub...), idxBytes[:]...))
		parentChain = append([]byte(nil), cc[32:]...)
	}

	shiftBytes, err := scalarBytes(cumShift)
	if err != nil {
		return nil, nil, nil, err
	}
	return parentPub, shiftBytes, parentChain, nil
}

// leBytesToBig interprets b as a little-endian unsigned integer.
func leBytesToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
