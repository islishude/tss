package ed25519

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// hmacSHA512 implements single-round HMAC-SHA512, matching the Cardano
// ED25519-BIP32 reference implementation.
func hmacSHA512(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// DeriveNonHardenedBIP32 performs non-hardened BIP32-Ed25519 child key
// derivation following the Khovratovich-Law / Cardano ED25519-BIP32 scheme.
// It returns a [DerivationResult] containing the child public key, cumulative
// additive shift, and child chain code.
//
// Only non-hardened indices (i < 2^31) are supported. If path is nil or empty,
// the parent key is returned unchanged with a zero additive shift.
func DeriveNonHardenedBIP32(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if len(chainCode) == 0 {
		return nil, tss.ErrChainCodeRequired
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", tss.ErrInvalidChainCodeLength, len(chainCode))
	}
	if _, err := edcurve.PointFromBytes(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", tss.ErrInvalidPublicKey, err)
	}

	cfg := tss.ResolveDeriveConfig(opts)

	// Empty path: return parent node.
	if len(path) == 0 {
		zeroShift := make([]byte, 32)
		return &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeEd25519KhovratovichLaw,
			ChildPublicKey: slices.Clone(publicKey),
			AdditiveShift:  zeroShift,
			ChildChainCode: slices.Clone(chainCode),
			RequestedPath:  nil,
			ResolvedPath:   nil,
			Depth:          0,
			ChildNumber:    0,
		}, nil
	}

	// depth uses uint8 in BIP32 serialization.
	if len(path) > math.MaxUint8 {
		return nil, tss.ErrDerivationDepthOverflow
	}

	parentChain := slices.Clone(chainCode)
	cumShift := new(big.Int)
	order := edcurve.Order()
	resolvedPath := make(tss.DerivationPath, 0, len(path))
	var parentFingerprint [4]byte
	var finalChildNumber uint32

	for i, idx := range path {
		if idx >= tss.HardenedKeyStart {
			return nil, fmt.Errorf("%w at path segment %d: index %d",
				tss.ErrHardenedDerivationUnsupported, i, idx)
		}

		// Compute the current intermediate parent public key.
		shiftBytes, err := scalarBytes(cumShift)
		if err != nil {
			return nil, err
		}
		intermediatePub, err := DerivePublicKey(publicKey, shiftBytes)
		if err != nil {
			return nil, err
		}

		// Record the fingerprint of this parent before deriving the child.
		parentFingerprint = bip32util.ComputeFingerprint(intermediatePub)

		origIdx := idx
		_, tweak, childChain, usedIdx, err := deriveChildEd25519(intermediatePub, parentChain, idx, cfg)
		if err != nil {
			return nil, fmt.Errorf("%w at path segment %d (index %d): %w",
				tss.ErrInvalidChild, i, origIdx, err)
		}
		cumShift.Add(cumShift, tweak)
		cumShift.Mod(cumShift, order)
		resolvedPath = append(resolvedPath, usedIdx)
		parentChain = childChain
		finalChildNumber = usedIdx
	}

	shiftBytes, err := scalarBytes(cumShift)
	if err != nil {
		return nil, err
	}

	// Compute the final child public key from the root + cumulative shift.
	childPub, err := DerivePublicKey(publicKey, shiftBytes)
	if err != nil {
		return nil, err
	}

	return &tss.DerivationResult{
		Scheme:            tss.DerivationSchemeEd25519KhovratovichLaw,
		ChildPublicKey:    childPub,
		AdditiveShift:     shiftBytes,
		ChildChainCode:    parentChain,
		RequestedPath:     path.Clone(),
		ResolvedPath:      resolvedPath,
		Depth:             uint8(len(resolvedPath)),
		ParentFingerprint: parentFingerprint,
		ChildNumber:       finalChildNumber,
	}, nil
}

// deriveChildEd25519 performs a single non-hardened BIP32-Ed25519 CKDpub step.
// It returns childPub = nil for the caller to compute via cumulative shift
// (additive derivation: rootPub + cumShift·B equals the final child).
func deriveChildEd25519(parentPub, parentChain []byte, idx uint32, cfg tss.DeriveConfig) (
	childPub []byte,
	tweak *big.Int,
	childChain []byte,
	usedIdx uint32,
	err error,
) {
	order := edcurve.Order()

	for {
		if idx >= tss.HardenedKeyStart {
			return nil, nil, nil, idx, fmt.Errorf(
				"%w: attempted hardened index %d during skip",
				tss.ErrHardenedDerivationUnsupported, idx,
			)
		}

		var idxBytes [4]byte
		binary.LittleEndian.PutUint32(idxBytes[:], idx)

		// Z = HMAC-SHA512(key=c_par, data=0x02 || A_par || ser32LE(i))
		z := hmacSHA512(parentChain, append(append([]byte{0x02}, parentPub...), idxBytes[:]...))

		// zL = 8 * LE_OS2IP(Z[0:28]) — cofactor clearing via *8
		zL := leBytesToBig(z[:28])
		zL.Mul(zL, big.NewInt(8))
		zL.Mod(zL, order)
		if zL.Sign() == 0 {
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, nil, nil, idx, fmt.Errorf(
				"%w: zero scalar at index %d", tss.ErrInvalidChild, idx,
			)
		}

		// child chain: HMAC-SHA512(key=c_par, data=0x03 || A_par || ser32LE(i))[32:64]
		cc := hmacSHA512(parentChain, append(append([]byte{0x03}, parentPub...), idxBytes[:]...))
		childChain = slices.Clone(cc[32:])

		return nil, zL, childChain, idx, nil
	}
}

// leBytesToBig interprets b as a little-endian unsigned integer.
func leBytesToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
