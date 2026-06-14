package secp256k1

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// hmacSHA512 is the HMAC-SHA512 function used for BIP32 derivation. It is
// exposed as a package-level variable so that tests can inject a fake HMAC
// to trigger invalid-child conditions.
var hmacSHA512 = func(key, data []byte) (il, ir []byte) {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	I := mac.Sum(nil)
	return I[:32], I[32:]
}

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
func DeriveNonHardenedBIP32(publicKey, chainCode []byte, path []uint32, opts ...bip32util.DeriveOption) (*bip32util.DerivationResult, error) {
	return deriveNonHardenedBIP32(publicKey, chainCode, path, opts...)
}

// DeriveNonHardenedBIP32Extended performs non-hardened BIP32 public derivation
// and returns the full [DerivationResult] including resolved path, depth,
// parent fingerprint, and child number.
func DeriveNonHardenedBIP32Extended(publicKey, chainCode []byte, path []uint32, opts ...bip32util.DeriveOption) (*bip32util.DerivationResult, error) {
	return deriveNonHardenedBIP32(publicKey, chainCode, path, opts...)
}

func deriveNonHardenedBIP32(publicKey, chainCode []byte, path []uint32, opts ...bip32util.DeriveOption) (*bip32util.DerivationResult, error) {
	if len(chainCode) == 0 {
		return nil, bip32util.ErrChainCodeRequired
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", bip32util.ErrInvalidChainCodeLength, len(chainCode))
	}
	if _, err := secp.PointFromBytes(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", bip32util.ErrInvalidPublicKey, err)
	}

	requestedPath := slices.Clone(path)
	cfg := bip32util.ResolveDeriveConfig(opts)

	// Empty path: return parent node.
	if len(path) == 0 {
		zeroShift := secp.ScalarZero().Bytes()
		return &bip32util.DerivationResult{
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
		return nil, fmt.Errorf("%w: path has %d indices (max 255)", bip32util.ErrDerivationDepthOverflow, len(path))
	}

	parentPub := slices.Clone(publicKey)
	parentChain := slices.Clone(chainCode)
	cumShift := secp.ScalarZero()
	resolvedPath := make([]uint32, 0, len(path))
	var parentFingerprint [4]byte
	finalChildNumber := uint32(0)

	for i, idx := range path {
		if idx >= bip32util.HardenedKeyStart {
			return nil, fmt.Errorf("%w: index %d at path element", bip32util.ErrHardenedDerivationUnsupported, idx)
		}

		origIdx := idx
		childPub, tweak, childChain, fp, usedIdx, err := deriveChild(parentPub, parentChain, idx, cfg)
		if err != nil {
			return nil, fmt.Errorf("%w at path segment %d (index %d): %w", bip32util.ErrInvalidChild, i, origIdx, err)
		}
		cumShift = secp.ScalarAdd(cumShift, tweak)
		parentFingerprint = fp
		finalChildNumber = usedIdx
		resolvedPath = append(resolvedPath, usedIdx)
		parentPub = childPub
		parentChain = childChain
	}

	return &bip32util.DerivationResult{
		ChildPublicKey:    parentPub,
		AdditiveShift:     cumShift.Bytes(),
		ChildChainCode:    parentChain,
		RequestedPath:     requestedPath,
		ResolvedPath:      resolvedPath,
		Depth:             uint8(len(resolvedPath)),
		ParentFingerprint: parentFingerprint,
		ChildNumber:       finalChildNumber,
	}, nil
}

// deriveChild performs a single non-hardened BIP32 CKDpub step.
// It returns the child public key, the tweak scalar, the child chain code,
// the parent fingerprint, and the actual index used.
func deriveChild(parentPub, parentChain []byte, idx uint32, cfg bip32util.DeriveConfig) (
	childPub []byte,
	tweak secp.Scalar,
	childChain []byte,
	fingerprint [4]byte,
	usedIdx uint32,
	err error,
) {
	fp := bip32util.ComputeFingerprint(parentPub)

	for {
		if idx >= bip32util.HardenedKeyStart {
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"%w: attempted hardened index %d during skip", bip32util.ErrHardenedDerivationUnsupported, idx,
			)
		}

		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], idx)

		// I = HMAC-SHA512(key=parentChain, data=serP(parentPub) || ser32(idx))
		iL, iR := hmacSHA512(parentChain, append(parentPub, idxBytes[:]...))

		tweak, err := secp.ScalarFromBytes(iL)
		if err != nil || tweak.IsZero() {
			if cfg.InvalidChildMode == bip32util.SkipInvalidChild {
				idx++
				continue
			}
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"%w: zero or out-of-range scalar at index %d", bip32util.ErrInvalidChild, idx,
			)
		}

		parentPubScalar, err := secp.PointFromBytes(parentPub)
		if err != nil {
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf("%w: invalid parent public key: %w", bip32util.ErrInvalidPublicKey, err)
		}

		// childPub = parentPub + tweak*G
		childPoint := secp.Add(parentPubScalar, secp.ScalarBaseMult(tweak))
		if childPoint.Inf != 0 {
			if cfg.InvalidChildMode == bip32util.SkipInvalidChild {
				idx++
				continue
			}
			return nil, secp.Scalar{}, nil, fp, idx, fmt.Errorf(
				"%w: child point at infinity at index %d", bip32util.ErrInvalidChild, idx,
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
	ChainCode         [32]byte
	PublicKey         []byte // 33-byte compressed secp256k1 public key
}

// Validate checks that the extended public key has a recognized version, a
// valid curve point, and consistent metadata.
func (x ExtendedPublicKey) Validate() error {
	if !bip32util.IsKnownVersion(x.Version) {
		return fmt.Errorf("%w: unknown version 0x%08X", bip32util.ErrInvalidExtendedPublicKey,
			binary.BigEndian.Uint32(x.Version[:]))
	}
	if len(x.PublicKey) != 33 {
		return fmt.Errorf("%w: public key must be 33 bytes, got %d", bip32util.ErrInvalidExtendedPublicKey,
			len(x.PublicKey))
	}
	if _, err := secp.PointFromBytes(x.PublicKey); err != nil {
		return fmt.Errorf("%w: %w", bip32util.ErrInvalidExtendedPublicKey, err)
	}
	if len(x.ChainCode) != 32 {
		return fmt.Errorf("%w: chain code must be 32 bytes", bip32util.ErrInvalidExtendedPublicKey)
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
	buf := make([]byte, 0, 78)
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
		return nil, fmt.Errorf("%w: %w", bip32util.ErrInvalidExtendedPublicKey, err)
	}
	if len(payload) != 78 {
		return nil, fmt.Errorf("%w: payload must be 78 bytes, got %d", bip32util.ErrInvalidExtendedPublicKey, len(payload))
	}

	var x ExtendedPublicKey
	copy(x.Version[:], payload[0:4])
	x.Depth = payload[4]
	copy(x.ParentFingerprint[:], payload[5:9])
	x.ChildNumber = binary.BigEndian.Uint32(payload[9:13])
	copy(x.ChainCode[:], payload[13:45])
	x.PublicKey = make([]byte, 33)
	copy(x.PublicKey, payload[45:78])

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
func (x ExtendedPublicKey) Derive(path []uint32, opts ...bip32util.DeriveOption) (*ExtendedPublicKey, []byte, error) {
	if err := x.Validate(); err != nil {
		return nil, nil, err
	}
	if len(path) == 0 {
		child := x
		child.PublicKey = slices.Clone(x.PublicKey)
		return &child, secp.ScalarZero().Bytes(), nil
	}
	if int(x.Depth)+len(path) > math.MaxUint8 {
		return nil, nil, fmt.Errorf("%w: parent depth %d plus path length %d exceeds 255", bip32util.ErrDerivationDepthOverflow, x.Depth, len(path))
	}

	result, err := deriveNonHardenedBIP32(x.PublicKey, x.ChainCode[:], path, opts...)
	if err != nil {
		return nil, nil, err
	}
	if int(x.Depth)+int(result.Depth) > math.MaxUint8 {
		return nil, nil, fmt.Errorf("%w: parent depth %d plus resolved path length %d exceeds 255", bip32util.ErrDerivationDepthOverflow, x.Depth, result.Depth)
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
