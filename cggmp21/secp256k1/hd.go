package secp256k1

import (
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
func DeriveNonHardenedBIP32(publicKey, chainCode []byte, path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	return bip32util.DeriveSecp256k1(publicKey, chainCode, path, opts...)
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
	if x.Depth == 0 && (x.ParentFingerprint != [4]byte{} || x.ChildNumber != 0) {
		return fmt.Errorf("%w: master key must have zero parent fingerprint and child number", tss.ErrInvalidExtendedPublicKey)
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

	result, err := bip32util.DeriveSecp256k1(x.PublicKey, x.ChainCode[:], path, opts...)
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
