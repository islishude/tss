package tss

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/islishude/tss/internal/wire"
)

const (
	signingContextWireType   = "tss.signing-context"
	derivationResultWireType = "tss.derivation-result"
)

// HardenedKeyStart is the first index reserved for hardened BIP32 derivation.
// Online signing APIs currently accept only indices below this value.
const HardenedKeyStart uint32 = 1 << 31

// DerivationScheme identifies the public child-key derivation algorithm.
type DerivationScheme string

const (
	// DerivationSchemeBIP32Secp256k1 is standard non-hardened BIP32 CKDpub over secp256k1.
	DerivationSchemeBIP32Secp256k1 DerivationScheme = "bip32-secp256k1"
	// DerivationSchemeEd25519KhovratovichLaw is the Cardano/Khovratovich-Law Ed25519-BIP32 public derivation scheme.
	DerivationSchemeEd25519KhovratovichLaw DerivationScheme = "ed25519-bip32-khovratovich-law"
)

var (
	// ErrChainCodeRequired reports that a key share or derivation input lacks chain code.
	ErrChainCodeRequired = errors.New("chain code required")
	// ErrInvalidChainCodeLength reports that a chain code is not exactly 32 bytes.
	ErrInvalidChainCodeLength = errors.New("invalid chain code length")
	// ErrInvalidPublicKey reports that a derivation input public key is not valid for the scheme.
	ErrInvalidPublicKey = errors.New("invalid public key")
	// ErrHardenedDerivationUnsupported reports that an online signing path contains a hardened index.
	ErrHardenedDerivationUnsupported = errors.New("hardened derivation unsupported")
	// ErrInvalidChild reports that public derivation produced an invalid child.
	ErrInvalidChild = errors.New("invalid child derivation")
	// ErrDerivationDepthOverflow reports that a path exceeds the BIP32 255-level depth.
	ErrDerivationDepthOverflow = errors.New("derivation depth overflow")
	// ErrInvalidExtendedPublicKey is returned when an extended public key fails
	// validation (bad version, invalid point, etc.).
	ErrInvalidExtendedPublicKey = errors.New("invalid extended public key")
)

// DerivationPath is a non-hardened HD derivation path. Nil and empty paths are
// the master path "m".
type DerivationPath []uint32

// ParseDerivationPath parses paths in the form "m" or "m/0/1/2".
func ParseDerivationPath(s string) (DerivationPath, error) {
	if s == "m" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "m/") {
		return nil, fmt.Errorf("invalid derivation path %q", s)
	}
	parts := strings.Split(s[2:], "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid derivation path %q", s)
	}
	out := make(DerivationPath, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid derivation path %q", s)
		}
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H") {
			return nil, fmt.Errorf("%w: %q", ErrHardenedDerivationUnsupported, part)
		}
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid derivation path element %q: %w", part, err)
		}
		out = append(out, uint32(v))
	}
	if err := out.ValidateNonHardened(); err != nil {
		return nil, err
	}
	return out, nil
}

// MustParseDerivationPath parses s and panics on error.
func MustParseDerivationPath(s string) DerivationPath {
	path, err := ParseDerivationPath(s)
	if err != nil {
		panic(err)
	}
	return path
}

// String returns the canonical path string, using "m" for the master path.
func (p DerivationPath) String() string {
	if len(p) == 0 {
		return "m"
	}
	var b strings.Builder
	b.WriteByte('m')
	for _, index := range p {
		b.WriteByte('/')
		b.WriteString(strconv.FormatUint(uint64(index), 10))
	}
	return b.String()
}

// Clone returns a caller-owned copy of the path.
func (p DerivationPath) Clone() DerivationPath {
	if len(p) == 0 {
		return nil
	}
	return append(DerivationPath(nil), p...)
}

// ValidateNonHardened rejects hardened indices.
func (p DerivationPath) ValidateNonHardened() error {
	for i, index := range p {
		if index >= HardenedKeyStart {
			return fmt.Errorf("%w at path element %d: index %d", ErrHardenedDerivationUnsupported, i, index)
		}
	}
	return nil
}

// IsMaster reports whether the path is the master path.
func (p DerivationPath) IsMaster() bool {
	return len(p) == 0
}

// InvalidChildMode controls behavior when public derivation produces an invalid child.
type InvalidChildMode uint8

const (
	// ErrorOnInvalidChild returns an error immediately when an invalid child is encountered.
	ErrorOnInvalidChild InvalidChildMode = iota
	// SkipInvalidChild increments the index and retries until a valid child or hardened range.
	SkipInvalidChild
)

// DeriveOption is a functional option for HD public derivation.
type DeriveOption interface {
	applyDeriveOption(*DeriveConfig)
}

// DeriveConfig is the resolved configuration for HD public derivation.
type DeriveConfig struct {
	InvalidChildMode InvalidChildMode
	// HMACFunc is an optional custom HMAC-SHA512 function. When nil (the default),
	// the normal crypto/hmac-based SHA512 implementation is used.
	// The function must return exactly 64 bytes.
	HMACFunc func(key, data []byte) []byte
}

type invalidChildOption struct{ mode InvalidChildMode }

func (o invalidChildOption) applyDeriveOption(cfg *DeriveConfig) {
	cfg.InvalidChildMode = o.mode
}

// WithInvalidChildMode sets the invalid child handling strategy.
func WithInvalidChildMode(mode InvalidChildMode) DeriveOption {
	return invalidChildOption{mode: mode}
}

type hmacFuncOption struct{ fn func(key, data []byte) []byte }

func (o hmacFuncOption) applyDeriveOption(cfg *DeriveConfig) {
	cfg.HMACFunc = o.fn
}

// WithHMACFunc sets a custom HMAC-SHA512 function for BIP32 public derivation.
// When fn is nil or the option is not passed, the default crypto/hmac-based
// SHA512 implementation is used.
func WithHMACFunc(fn func(key, data []byte) []byte) DeriveOption {
	return hmacFuncOption{fn: fn}
}

// ResolveDeriveConfig resolves derivation options into a concrete config.
func ResolveDeriveConfig(opts []DeriveOption) DeriveConfig {
	cfg := DeriveConfig{InvalidChildMode: ErrorOnInvalidChild}
	for _, opt := range opts {
		if opt != nil {
			opt.applyDeriveOption(&cfg)
		}
	}
	return cfg
}

// DerivationRequest describes a requested public child-key derivation.
type DerivationRequest struct {
	Scheme           DerivationScheme `json:"scheme" wire:"1,string"`
	Path             DerivationPath   `json:"path" wire:"2,u32list"`
	InvalidChildMode InvalidChildMode `json:"invalid_child_mode" wire:"3,u8"`
	ResolvedPath     DerivationPath   `json:"resolved_path,omitempty" wire:"4,u32list"`
}

// Clone returns a caller-owned copy of the request.
func (r DerivationRequest) Clone() DerivationRequest {
	r.Path = r.Path.Clone()
	r.ResolvedPath = r.ResolvedPath.Clone()
	return r
}

// DerivationResult is the result of resolving a public child-key derivation.
type DerivationResult struct {
	Scheme            DerivationScheme `json:"scheme" wire:"1,string"`
	ChildPublicKey    []byte           `json:"child_public_key" wire:"2,bytes"`
	ChildChainCode    []byte           `json:"child_chain_code" wire:"3,bytes,len=32"`
	RequestedPath     DerivationPath   `json:"requested_path" wire:"4,u32list"`
	ResolvedPath      DerivationPath   `json:"resolved_path" wire:"5,u32list"`
	Depth             uint8            `json:"depth" wire:"6,u8"`
	ParentFingerprint [4]byte          `json:"parent_fingerprint" wire:"7,bytes,len=4"`
	ChildNumber       uint32           `json:"child_number" wire:"8,u32"`
	AdditiveShift     []byte           `json:"additive_shift,omitempty" wire:"9,bytes"`
}

// Clone returns a caller-owned copy of the derivation result.
func (r *DerivationResult) Clone() *DerivationResult {
	if r == nil {
		return nil
	}
	out := *r
	out.ChildPublicKey = append([]byte(nil), r.ChildPublicKey...)
	out.ChildChainCode = append([]byte(nil), r.ChildChainCode...)
	out.RequestedPath = r.RequestedPath.Clone()
	out.ResolvedPath = r.ResolvedPath.Clone()
	out.AdditiveShift = append([]byte(nil), r.AdditiveShift...)
	return &out
}

// Destroy clears derivation result buffers and resets metadata in place.
func (r *DerivationResult) Destroy() {
	if r == nil {
		return
	}
	clear(r.ChildPublicKey)
	clear(r.ChildChainCode)
	clear(r.RequestedPath)
	clear(r.ResolvedPath)
	clear(r.AdditiveShift)
	r.Scheme = ""
	r.ChildPublicKey = nil
	r.ChildChainCode = nil
	r.RequestedPath = nil
	r.ResolvedPath = nil
	r.Depth = 0
	r.ParentFingerprint = [4]byte{}
	r.ChildNumber = 0
	r.AdditiveShift = nil
}

// Equal reports whether r and other are the same derivation result.
// Both nil receivers compare equal. A nil receiver and a non-nil other
// are not equal.
func (r *DerivationResult) Equal(other *DerivationResult) bool {
	if r == nil || other == nil {
		return r == nil && other == nil
	}
	return r.Scheme == other.Scheme &&
		bytes.Equal(r.ChildPublicKey, other.ChildPublicKey) &&
		bytes.Equal(r.ChildChainCode, other.ChildChainCode) &&
		slices.Equal(r.RequestedPath, other.RequestedPath) &&
		slices.Equal(r.ResolvedPath, other.ResolvedPath) &&
		r.Depth == other.Depth &&
		r.ParentFingerprint == other.ParentFingerprint &&
		r.ChildNumber == other.ChildNumber &&
		bytes.Equal(r.AdditiveShift, other.AdditiveShift)
}

// WireType returns the canonical wire type identifier for DerivationResult.
func (DerivationResult) WireType() string { return derivationResultWireType }

// WireVersion returns the wire format version for DerivationResult.
func (DerivationResult) WireVersion() uint16 { return Version }

// Validate checks structural invariants for a derivation result.
func (r *DerivationResult) Validate() error {
	if r == nil {
		return errors.New("nil derivation result")
	}
	if r.Scheme == "" {
		return errors.New("missing derivation scheme")
	}
	if len(r.ChildPublicKey) == 0 {
		return errors.New("missing child public key")
	}
	if len(r.ChildChainCode) != 32 {
		return ErrInvalidChainCodeLength
	}
	if err := r.RequestedPath.ValidateNonHardened(); err != nil {
		return err
	}
	if err := r.ResolvedPath.ValidateNonHardened(); err != nil {
		return err
	}
	if len(r.RequestedPath) != len(r.ResolvedPath) {
		return errors.New("requested and resolved path depth mismatch")
	}
	if r.Depth != uint8(len(r.ResolvedPath)) {
		return errors.New("derivation depth mismatch")
	}
	if len(r.AdditiveShift) != 0 && len(r.AdditiveShift) != 32 {
		return errors.New("additive shift must be empty or 32 bytes")
	}
	return nil
}

// MarshalBinary encodes the derivation result using the object-level wire codec.
func (r *DerivationResult) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil derivation result")
	}
	return wire.Marshal(r)
}

// VerificationKeyBytes returns a copy of ChildPublicKey.
func (r *DerivationResult) VerificationKeyBytes() []byte {
	if r == nil {
		return nil
	}
	return slices.Clone(r.ChildPublicKey)
}

// UnmarshalDerivationResult decodes a canonical derivation result record.
func UnmarshalDerivationResult(in []byte) (*DerivationResult, error) {
	if len(in) == 0 {
		return nil, errors.New("empty derivation result")
	}
	var r DerivationResult
	if err := wire.Unmarshal(in, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// SigningContext binds a signing request to key, chain, derivation, policy, and
// message domains without changing the message bytes being signed.
type SigningContext struct {
	KeyID         string            `json:"key_id" wire:"1,string"`
	ChainID       string            `json:"chain_id" wire:"2,string"`
	Derivation    DerivationRequest `json:"derivation" wire:"3,record"`
	PolicyDomain  string            `json:"policy_domain" wire:"4,string"`
	MessageDomain string            `json:"message_domain" wire:"5,string"`
}

// WireType returns the canonical wire type identifier for SigningContext.
func (SigningContext) WireType() string { return signingContextWireType }

// WireVersion returns the wire format version for SigningContext.
func (SigningContext) WireVersion() uint16 { return Version }

// Validate checks required context fields and the non-hardened derivation path.
func (c SigningContext) Validate() error {
	if c.KeyID == "" {
		return errors.New("signing context key id is required")
	}
	if c.ChainID == "" {
		return errors.New("signing context chain id is required")
	}
	if c.Derivation.Scheme == "" {
		return errors.New("signing context derivation scheme is required")
	}
	if err := c.Derivation.Path.ValidateNonHardened(); err != nil {
		return err
	}
	if err := c.Derivation.ResolvedPath.ValidateNonHardened(); err != nil {
		return err
	}
	if c.PolicyDomain == "" {
		return errors.New("signing context policy domain is required")
	}
	if c.MessageDomain == "" {
		return errors.New("signing context message domain is required")
	}
	return nil
}

// Clone returns a caller-owned copy of the context.
func (c SigningContext) Clone() SigningContext {
	c.Derivation = c.Derivation.Clone()
	return c
}

// DerivationPath returns a caller-owned copy of the requested path.
func (c SigningContext) DerivationPath() DerivationPath {
	return c.Derivation.Path.Clone()
}
