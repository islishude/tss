package secp256k1

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// DeriveNonHardenedBIP32 performs non-hardened BIP32 public derivation for
// threshold ECDSA keys. It returns the child public key, the cumulative
// additive shift bound by NewPresignPlan, and the child
// chain code.
//
// Only non-hardened indices (i < 2^31) are supported. If path is nil or empty,
// the parent key is returned unchanged with a zero additive shift.
//
// Use DeriveNonHardenedBIP32Extended for the full DerivationResult including
// resolved path, depth, fingerprint, and child number.
func DeriveNonHardenedBIP32(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	return deriveNonHardenedBIP32(publicKey, chainCode, path, opts...)
}

// DeriveNonHardenedBIP32Extended performs non-hardened BIP32 public derivation
// and returns the full [DerivationResult] including resolved path, depth,
// parent fingerprint, and child number.
func DeriveNonHardenedBIP32Extended(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	return deriveNonHardenedBIP32(publicKey, chainCode, path, opts...)
}

func deriveNonHardenedBIP32(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if len(chainCode) == 0 {
		return nil, tss.ErrChainCodeRequired
	}
	if len(chainCode) != bip32util.ChainCodeSize {
		return nil, fmt.Errorf("%w: got %d bytes", tss.ErrInvalidChainCodeLength, len(chainCode))
	}
	if _, err := secp.PointFromBytes(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", tss.ErrInvalidPublicKey, err)
	}

	cfg := tss.ResolveDeriveConfig(opts)

	// Empty path: return parent node.
	if len(path) == 0 {
		zeroShift := secp.ScalarZero().Bytes()
		return &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: slices.Clone(publicKey),
			AdditiveShift:  slices.Clone(zeroShift),
			ChildChainCode: slices.Clone(chainCode),
			RequestedPath:  nil,
			ResolvedPath:   nil,
			Depth:          0,
			ChildNumber:    0,
		}, nil
	}

	// depth uses uint8 in BIP32 serialization.
	if len(path) > math.MaxUint8 {
		return nil, fmt.Errorf("%w: path has %d indices (max 255)", tss.ErrDerivationDepthOverflow, len(path))
	}

	parentPub := slices.Clone(publicKey)
	parentChain := slices.Clone(chainCode)
	cumShift := secp.ScalarZero()
	resolvedPath := make(tss.DerivationPath, 0, len(path))
	var parentFingerprint [4]byte
	finalChildNumber := uint32(0)

	for i, idx := range path {
		if idx >= tss.HardenedKeyStart {
			return nil, fmt.Errorf("%w: index %d at path element", tss.ErrHardenedDerivationUnsupported, idx)
		}

		origIdx := idx
		childPub, tweak, childChain, fp, usedIdx, err := deriveChild(parentPub, parentChain, idx, cfg)
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

// deriveChild performs a single non-hardened BIP32 CKDpub step.
// It returns the child public key, the tweak scalar, the child chain code,
// the parent fingerprint, and the actual index used.
func deriveChild(parentPub, parentChain []byte, idx uint32, cfg tss.DeriveConfig) (
	childPub []byte,
	tweak secp.Scalar,
	childChain []byte,
	fingerprint [4]byte,
	usedIdx uint32,
	err error,
) {
	fp := bip32util.ComputeFingerprint(parentPub)

	parentPubPoint, err := secp.PointFromBytes(parentPub)
	if err != nil {
		return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf("%w: invalid parent public key: %w", tss.ErrInvalidPublicKey, err)
	}

	hmacFn := bip32util.HMACSHA512
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

		// I = HMAC-SHA512(key=parentChain, data=serP(parentPub) || ser32(idx))
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

		// childPub = parentPub + tweak*G
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

// ---------------------------------------------------------------------------
// ExtendedPublicKey — BIP32 xpub / tpub metadata and serialization
// ---------------------------------------------------------------------------

// ExtendedPublicKey is a BIP32 extended public key (xpub / tpub). It carries
// the metadata necessary for wallet-level serialization and non-hardened
// public derivation.
//
// ExtendedPublicKey does not hold any private key material — it only supports
// non-hardened CKDpub.
type ExtendedPublicKey struct {
	Version           [4]byte
	Depth             uint8
	ParentFingerprint [4]byte
	ChildNumber       uint32
	ChainCode         [bip32util.ChainCodeSize]byte
	PublicKey         []byte // 33-byte compressed secp256k1 public key
}

// Validate checks that the extended public key has a recognized version, a
// valid curve point, and consistent metadata.
func (x ExtendedPublicKey) Validate() error {
	if !bip32util.IsKnownVersion(x.Version) {
		return fmt.Errorf("%w: unknown version 0x%08X", tss.ErrInvalidExtendedPublicKey,
			binary.BigEndian.Uint32(x.Version[:]))
	}
	if len(x.PublicKey) != secp.PubkeyLength {
		return fmt.Errorf("%w: public key must be %d bytes, got %d", tss.ErrInvalidExtendedPublicKey, secp.PubkeyLength, len(x.PublicKey))
	}
	if _, err := secp.PointFromBytes(x.PublicKey); err != nil {
		return fmt.Errorf("%w: %w", tss.ErrInvalidExtendedPublicKey, err)
	}
	if len(x.ChainCode) != bip32util.ChainCodeSize {
		return fmt.Errorf("%w: chain code must be %d bytes", tss.ErrInvalidExtendedPublicKey, bip32util.ChainCodeSize)
	}
	return nil
}

// Serialize returns the 78-byte BIP32 extended key payload (without Base58Check
// encoding):
//
//	4 bytes: version
//	1 byte:  depth
//	4 bytes: parent fingerprint
//	4 bytes: child number
//	32 bytes: chain code
//	33 bytes: public key
func (x ExtendedPublicKey) Serialize() ([]byte, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, bip32util.BIP32ExtendedKeyPayloadLen)
	buf = append(buf, x.Version[:]...)
	buf = append(buf, x.Depth)
	buf = append(buf, x.ParentFingerprint[:]...)
	buf = append(buf, byte(x.ChildNumber>>24), byte(x.ChildNumber>>16),
		byte(x.ChildNumber>>8), byte(x.ChildNumber))
	buf = append(buf, x.ChainCode[:]...)
	buf = append(buf, x.PublicKey...)
	return buf, nil
}

// String returns the Base58Check-encoded extended public key (e.g. "xpub...").
func (x ExtendedPublicKey) String() (string, error) {
	payload, err := x.Serialize()
	if err != nil {
		return "", err
	}
	return bip32util.Base58CheckEncode(payload), nil
}

// ParseExtendedPublicKey decodes a Base58Check-encoded extended public key
// (xpub / tpub) and validates the resulting key.
func ParseExtendedPublicKey(s string) (*ExtendedPublicKey, error) {
	payload, err := bip32util.Base58CheckDecode(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tss.ErrInvalidExtendedPublicKey, err)
	}
	if len(payload) != bip32util.BIP32ExtendedKeyPayloadLen {
		return nil, fmt.Errorf("%w: payload must be %d bytes, got %d", tss.ErrInvalidExtendedPublicKey, bip32util.BIP32ExtendedKeyPayloadLen, len(payload))
	}

	var x ExtendedPublicKey
	copy(x.Version[:], payload[0:4])
	x.Depth = payload[4]
	copy(x.ParentFingerprint[:], payload[5:9])
	x.ChildNumber = binary.BigEndian.Uint32(payload[9:13])
	copy(x.ChainCode[:], payload[13:45])
	x.PublicKey = make([]byte, secp.PubkeyLength)
	copy(x.PublicKey, payload[45:])

	if err := x.Validate(); err != nil {
		return nil, err
	}
	return &x, nil
}

// Derive performs non-hardened BIP32 public derivation from this extended
// public key. It returns the child extended public key and the cumulative
// additive shift from this key to the child key.
//
// Hardened indices are rejected.
func (x ExtendedPublicKey) Derive(path tss.DerivationPath, opts ...tss.DeriveOption) (*ExtendedPublicKey, []byte, error) {
	if err := x.Validate(); err != nil {
		return nil, nil, err
	}
	if path.IsMaster() {
		child := x
		child.PublicKey = slices.Clone(x.PublicKey)
		return &child, secp.ScalarZero().Bytes(), nil
	}
	if int(x.Depth)+len(path) > math.MaxUint8 {
		return nil, nil, fmt.Errorf("%w: parent depth %d plus path length %d exceeds 255", tss.ErrDerivationDepthOverflow, x.Depth, len(path))
	}

	result, err := deriveNonHardenedBIP32(x.PublicKey, x.ChainCode[:], path, opts...)
	if err != nil {
		return nil, nil, err
	}
	if int(x.Depth)+int(result.Depth) > math.MaxUint8 {
		return nil, nil, fmt.Errorf("%w: parent depth %d plus resolved path length %d exceeds 255", tss.ErrDerivationDepthOverflow, x.Depth, result.Depth)
	}

	child := &ExtendedPublicKey{
		Version:           x.Version,
		Depth:             x.Depth + result.Depth,
		ParentFingerprint: result.ParentFingerprint,
		ChildNumber:       result.ChildNumber,
		ChainCode:         [32]byte(result.ChildChainCode),
		PublicKey:         result.ChildPublicKey,
	}
	return child, result.AdditiveShift, nil
}
