package bip32util

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
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
	if !cfg.InvalidChildMode.Valid() {
		return nil, fmt.Errorf("%w: %d", tss.ErrInvalidChildMode, cfg.InvalidChildMode)
	}
	if path.IsMaster() {
		return &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: bytes.Clone(publicKey),
			AdditiveShift:  secp.ScalarZero().Bytes(),
			ChildChainCode: bytes.Clone(chainCode),
		}, nil
	}
	if len(path) > math.MaxUint8 {
		return nil, fmt.Errorf("%w: path has %d indices (max 255)", tss.ErrDerivationDepthOverflow, len(path))
	}

	parentPub := bytes.Clone(publicKey)
	parentChain := bytes.Clone(chainCode)
	cumShift := secp.ScalarZero()
	resolvedPath := make(tss.DerivationPath, 0, len(path))
	var parentFingerprint [4]byte
	var finalChildNumber uint32

	if cfg.HMACFunc == nil {
		cfg.HMACFunc = HMACSHA512
	}

	for i, idx := range path {
		if idx >= tss.HardenedKeyStart {
			return nil, fmt.Errorf("%w: index %d at path element", tss.ErrHardenedDerivationUnsupported, idx)
		}

		childPub, tweak, childChain, usedIdx, err := deriveSecp256k1Child(parentPub, parentChain, idx, cfg)
		if err != nil {
			return nil, fmt.Errorf("%w at path segment %d (index %d): %w", tss.ErrInvalidChild, i, idx, err)
		}
		cumShift = secp.ScalarAdd(cumShift, tweak)
		parentFingerprint = ComputeFingerprint(parentPub)
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
	parentPoint, err := edcurve.PointFromBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tss.ErrInvalidPublicKey, err)
	}

	cfg := tss.ResolveDeriveConfig(opts)
	if !cfg.InvalidChildMode.Valid() {
		return nil, fmt.Errorf("%w: %d", tss.ErrInvalidChildMode, cfg.InvalidChildMode)
	}
	if path.IsMaster() {
		return &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeEd25519KhovratovichLaw,
			ChildPublicKey: bytes.Clone(publicKey),
			AdditiveShift:  make([]byte, edcurve.ScalarSize),
			ChildChainCode: bytes.Clone(chainCode),
		}, nil
	}
	if len(path) > math.MaxUint8 {
		return nil, tss.ErrDerivationDepthOverflow
	}

	parentChain := bytes.Clone(chainCode)
	cumShift := edcurve.ScalarZero()
	resolvedPath := make(tss.DerivationPath, 0, len(path))
	var parentFingerprint [4]byte
	var finalChildNumber uint32

	if cfg.HMACFunc == nil {
		cfg.HMACFunc = HMACSHA512
	}

	for i, idx := range path {
		if idx >= tss.HardenedKeyStart {
			return nil, fmt.Errorf("%w at path segment %d: index %d",
				tss.ErrHardenedDerivationUnsupported, i, idx)
		}

		intermediatePub, err := deriveEd25519PublicKey(parentPoint, cumShift)
		if err != nil {
			return nil, err
		}
		parentFingerprint = ComputeFingerprint(intermediatePub)

		tweak, childChain, usedIdx, err := deriveEd25519Child(intermediatePub, parentChain, idx, cfg)
		if err != nil {
			return nil, fmt.Errorf("%w at path segment %d (index %d): %w",
				tss.ErrInvalidChild, i, idx, err)
		}
		cumShift.Add(cumShift, tweak)
		resolvedPath = append(resolvedPath, usedIdx)
		parentChain = childChain
		finalChildNumber = usedIdx
	}

	shiftBytes := cumShift.Bytes()
	childPub, err := deriveEd25519PublicKey(parentPoint, cumShift)
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

func deriveSecp256k1Child(parentPub, parentChain []byte, idx uint32, cfg tss.DeriveConfig) (childPub []byte, tweak secp.Scalar, childChain []byte, usedIdx uint32, err error) {
	parentPubPoint, err := secp.PointFromBytes(parentPub)
	if err != nil {
		return nil, secp.Scalar{}, nil, idx, fmt.Errorf("%w: invalid parent public key: %w", tss.ErrInvalidPublicKey, err)
	}

	for {
		if idx >= tss.HardenedKeyStart {
			return nil, secp.Scalar{}, nil, idx, fmt.Errorf(
				"%w: attempted hardened index %d during skip", tss.ErrHardenedDerivationUnsupported, idx,
			)
		}

		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], idx)

		I := cfg.HMACFunc(parentChain, slices.Concat(parentPub, idxBytes[:]))
		if len(I) != sha512.Size {
			return nil, secp.Scalar{}, nil, idx, fmt.Errorf("HMACFunc: got %d bytes, want 64", len(I))
		}
		iL, iR := I[:32], I[32:]

		tweak, err := secp.ScalarFromBytesAllowZero(iL)
		if err != nil {
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, secp.Scalar{}, nil, idx, fmt.Errorf(
				"%w: out-of-range scalar at index %d", tss.ErrInvalidChild, idx,
			)
		}

		childPoint := secp.Add(parentPubPoint, secp.ScalarBaseMult(tweak))
		if childPoint.Inf != 0 {
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, secp.Scalar{}, nil, idx, fmt.Errorf(
				"%w: child point at infinity at index %d", tss.ErrInvalidChild, idx,
			)
		}

		childPubBytes, err := secp.PointBytes(childPoint)
		if err != nil {
			return nil, secp.Scalar{}, nil, idx, fmt.Errorf(
				"encoding child public key at index %d: %w", idx, err,
			)
		}

		return childPubBytes, tweak, bytes.Clone(iR), idx, nil
	}
}

func deriveEd25519Child(parentPub, parentChain []byte, idx uint32, cfg tss.DeriveConfig) (tweak *fed.Scalar, childChain []byte, usedIdx uint32, err error) {
	parentPoint, err := edcurve.PointFromBytes(parentPub)
	if err != nil {
		return nil, nil, idx, fmt.Errorf("%w: invalid parent public key: %w", tss.ErrInvalidPublicKey, err)
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

		z := cfg.HMACFunc(parentChain, slices.Concat([]byte{0x02}, parentPub, idxBytes[:]))
		if len(z) != sha512.Size {
			return nil, nil, idx, fmt.Errorf("HMACFunc: got %d bytes, want 64", len(z))
		}

		candidate, err := ed25519TweakScalarFromZLeft(z[:28])
		if err != nil {
			return nil, nil, idx, err
		}
		childPoint := edcurve.AddPoints(parentPoint, fed.NewIdentityPoint().ScalarBaseMult(candidate))
		if edcurve.IsIdentity(childPoint) {
			candidate.Set(fed.NewScalar())
			if cfg.InvalidChildMode == tss.SkipInvalidChild {
				idx++
				continue
			}
			return nil, nil, idx, fmt.Errorf(
				"%w: child public key is identity at index %d", tss.ErrInvalidChild, idx,
			)
		}

		cc := cfg.HMACFunc(parentChain, slices.Concat([]byte{0x03}, parentPub, idxBytes[:]))
		if len(cc) != sha512.Size {
			return nil, nil, idx, fmt.Errorf("HMACFunc: got %d bytes, want 64", len(cc))
		}
		return candidate, bytes.Clone(cc[32:]), idx, nil
	}
}

func deriveEd25519PublicKey(base *fed.Point, additiveShift *fed.Scalar) ([]byte, error) {
	shifted := edcurve.AddPoints(base, fed.NewIdentityPoint().ScalarBaseMult(additiveShift))
	if edcurve.IsIdentity(shifted) {
		return nil, fmt.Errorf("%w: derived public key is identity", tss.ErrInvalidPublicKey)
	}
	return shifted.Bytes(), nil
}

func ed25519TweakScalarFromZLeft(zLeft []byte) (*fed.Scalar, error) {
	var raw [edcurve.ScalarSize]byte
	var carry byte
	for i, b := range zLeft {
		raw[i] = (b << 3) | carry
		carry = b >> 5
	}
	if len(zLeft) < len(raw) {
		raw[len(zLeft)] = carry
	}
	return edcurve.ScalarFromCanonical(raw[:])
}
