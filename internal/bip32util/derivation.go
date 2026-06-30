package bip32util

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// DeriveSecp256k1 performs non-hardened BIP32 CKDpub over secp256k1.
func DeriveSecp256k1(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if len(chainCode) == 0 {
		return nil, tss.ErrChainCodeRequired
	}
	if len(chainCode) != ChainCodeSize {
		return nil, fmt.Errorf("%w: got %d bytes", tss.ErrInvalidChainCodeLength, len(chainCode))
	}
	if _, err := secp.PointFromBytes(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", tss.ErrInvalidPublicKey, err)
	}

	cfg := tss.ResolveDeriveConfig(opts)
	if path.IsMaster() {
		return &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: slices.Clone(publicKey),
			AdditiveShift:  secp.ScalarZero().Bytes(),
			ChildChainCode: slices.Clone(chainCode),
		}, nil
	}
	if len(path) > math.MaxUint8 {
		return nil, fmt.Errorf("%w: path has %d indices (max 255)", tss.ErrDerivationDepthOverflow, len(path))
	}

	parentPub := slices.Clone(publicKey)
	parentChain := slices.Clone(chainCode)
	cumShift := secp.ScalarZero()
	resolvedPath := make(tss.DerivationPath, 0, len(path))
	var parentFingerprint [4]byte
	var finalChildNumber uint32

	for i, idx := range path {
		if idx >= tss.HardenedKeyStart {
			return nil, fmt.Errorf("%w: index %d at path element", tss.ErrHardenedDerivationUnsupported, idx)
		}

		origIdx := idx
		childPub, tweak, childChain, fp, usedIdx, err := deriveSecp256k1Child(parentPub, parentChain, idx, cfg)
		if err != nil {
			return nil, fmt.Errorf("%w at path segment %d (index %d): %w", tss.ErrInvalidChild, i, origIdx, err)
		}
		cumShift = secp.ScalarAdd(cumShift, tweak)
		parentFingerprint = fp
		finalChildNumber = usedIdx
		resolvedPath = append(resolvedPath, usedIdx)
		parentPub = childPub
		parentChain = childChain
	}

	return &tss.DerivationResult{
		Scheme:            tss.DerivationSchemeBIP32Secp256k1,
		ChildPublicKey:    parentPub,
		AdditiveShift:     cumShift.Bytes(),
		ChildChainCode:    parentChain,
		RequestedPath:     path.Clone(),
		ResolvedPath:      resolvedPath,
		Depth:             uint8(len(resolvedPath)),
		ParentFingerprint: parentFingerprint,
		ChildNumber:       finalChildNumber,
	}, nil
}

// DeriveEd25519KhovratovichLaw performs non-hardened public derivation using
// the Khovratovich-Law/Cardano Ed25519-BIP32 construction.
func DeriveEd25519KhovratovichLaw(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if len(chainCode) == 0 {
		return nil, tss.ErrChainCodeRequired
	}
	if len(chainCode) != ChainCodeSize {
		return nil, fmt.Errorf("%w: got %d bytes", tss.ErrInvalidChainCodeLength, len(chainCode))
	}
	if _, err := edcurve.PointFromBytes(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", tss.ErrInvalidPublicKey, err)
	}

	cfg := tss.ResolveDeriveConfig(opts)
	if path.IsMaster() {
		return &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeEd25519KhovratovichLaw,
			ChildPublicKey: slices.Clone(publicKey),
			AdditiveShift:  make([]byte, edcurve.ScalarSize),
			ChildChainCode: slices.Clone(chainCode),
		}, nil
	}
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

		shiftBytes, err := ed25519ScalarBytes(cumShift)
		if err != nil {
			return nil, err
		}
		intermediatePub, err := DeriveEd25519PublicKey(publicKey, shiftBytes)
		if err != nil {
			return nil, err
		}
		parentFingerprint = ComputeFingerprint(intermediatePub)

		origIdx := idx
		tweak, childChain, usedIdx, err := deriveEd25519Child(intermediatePub, parentChain, idx, cfg)
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

	shiftBytes, err := ed25519ScalarBytes(cumShift)
	if err != nil {
		return nil, err
	}
	childPub, err := DeriveEd25519PublicKey(publicKey, shiftBytes)
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

// DeriveEd25519PublicKey applies an additive Ed25519 scalar shift to publicKey.
func DeriveEd25519PublicKey(publicKey, additiveShift []byte) ([]byte, error) {
	base, err := edcurve.PointFromBytes(publicKey)
	if err != nil {
		return nil, err
	}
	if len(additiveShift) == 0 {
		return base.Bytes(), nil
	}
	shift, err := edcurve.ScalarFromCanonical(additiveShift)
	if err != nil {
		return nil, fmt.Errorf("invalid additive shift: %w", err)
	}
	shifted := edcurve.AddPoints(base, fed.NewIdentityPoint().ScalarBaseMult(shift))
	if edcurve.IsIdentity(shifted) {
		return nil, fmt.Errorf("%w: derived public key is identity", tss.ErrInvalidPublicKey)
	}
	return shifted.Bytes(), nil
}

func deriveSecp256k1Child(parentPub, parentChain []byte, idx uint32, cfg tss.DeriveConfig) (
	childPub []byte,
	tweak secp.Scalar,
	childChain []byte,
	fingerprint [4]byte,
	usedIdx uint32,
	err error,
) {
	fp := ComputeFingerprint(parentPub)

	parentPubPoint, err := secp.PointFromBytes(parentPub)
	if err != nil {
		return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf("%w: invalid parent public key: %w", tss.ErrInvalidPublicKey, err)
	}

	hmacFn := HMACSHA512
	if cfg.HMACFunc != nil {
		hmacFn = cfg.HMACFunc
	}

	for {
		if idx >= tss.HardenedKeyStart {
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"%w: attempted hardened index %d during skip", tss.ErrHardenedDerivationUnsupported, idx,
			)
		}

		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], idx)

		I := hmacFn(parentChain, append(parentPub, idxBytes[:]...))
		if len(I) != sha512.Size {
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf("HMACFunc: got %d bytes, want 64", len(I))
		}
		iL, iR := I[:32], I[32:]

		tweak, err := secp.ScalarFromBytes(iL)
		if err != nil || tweak.IsZero() {
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"%w: zero or out-of-range scalar at index %d", tss.ErrInvalidChild, idx,
			)
		}

		childPoint := secp.Add(parentPubPoint, secp.ScalarBaseMult(tweak))
		if childPoint.Inf != 0 {
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"%w: child point at infinity at index %d", tss.ErrInvalidChild, idx,
			)
		}

		childPubBytes, err := secp.PointBytes(childPoint)
		if err != nil {
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"encoding child public key at index %d: %w", idx, err,
			)
		}

		return childPubBytes, tweak, slices.Clone(iR), fp, idx, nil
	}
}

func deriveEd25519Child(parentPub, parentChain []byte, idx uint32, cfg tss.DeriveConfig) (
	tweak *big.Int,
	childChain []byte,
	usedIdx uint32,
	err error,
) {
	order := edcurve.Order()

	hmacFn := HMACSHA512
	if cfg.HMACFunc != nil {
		hmacFn = cfg.HMACFunc
	}

	for {
		if idx >= tss.HardenedKeyStart {
			return nil, nil, idx, fmt.Errorf(
				"%w: attempted hardened index %d during skip",
				tss.ErrHardenedDerivationUnsupported, idx,
			)
		}

		var idxBytes [4]byte
		binary.LittleEndian.PutUint32(idxBytes[:], idx)

		z := hmacFn(parentChain, append(append([]byte{0x02}, parentPub...), idxBytes[:]...))
		if len(z) != sha512.Size {
			return nil, nil, idx, fmt.Errorf("HMACFunc: got %d bytes, want 64", len(z))
		}

		zL := leBytesToBig(z[:28])
		zL.Mul(zL, big.NewInt(8))
		zL.Mod(zL, order)
		if zL.Sign() == 0 {
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, nil, idx, fmt.Errorf(
				"%w: zero scalar at index %d", tss.ErrInvalidChild, idx,
			)
		}

		cc := hmacFn(parentChain, append(append([]byte{0x03}, parentPub...), idxBytes[:]...))
		if len(cc) != sha512.Size {
			return nil, nil, idx, fmt.Errorf("HMACFunc: got %d bytes, want 64", len(cc))
		}

		return zL, slices.Clone(cc[32:]), idx, nil
	}
}

func ed25519ScalarBytes(x *big.Int) ([]byte, error) {
	s, err := edcurve.ScalarFromBig(x)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

func leBytesToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
