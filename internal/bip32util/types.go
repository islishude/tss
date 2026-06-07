package bip32util

// InvalidChildMode controls behaviour when BIP32 derivation produces an
// invalid child (zero or ≥ order scalar).
type InvalidChildMode int

const (
	// ErrorOnInvalidChild returns an error immediately when encountering an
	// invalid child index.
	ErrorOnInvalidChild InvalidChildMode = iota

	// SkipInvalidChild increments the index and retries derivation until a
	// valid child is found or the hardened range is reached.
	SkipInvalidChild
)

// DeriveOption is a functional option for BIP32 derivation functions.
type DeriveOption interface {
	applyDeriveOption(cfg *DeriveConfig)
}

// DeriveConfig holds the resolved options for derivation.
type DeriveConfig struct {
	InvalidChildMode InvalidChildMode
}

type invalidChildOption struct{ mode InvalidChildMode }

func (o invalidChildOption) applyDeriveOption(cfg *DeriveConfig) {
	cfg.InvalidChildMode = o.mode
}

// WithInvalidChildMode sets the strategy for handling invalid BIP32 children.
func WithInvalidChildMode(mode InvalidChildMode) DeriveOption {
	return invalidChildOption{mode: mode}
}

// ResolveDeriveConfig resolves a slice of DeriveOption into a concrete config.
func ResolveDeriveConfig(opts []DeriveOption) DeriveConfig {
	cfg := DeriveConfig{InvalidChildMode: ErrorOnInvalidChild}
	for _, o := range opts {
		o.applyDeriveOption(&cfg)
	}
	return cfg
}

// DerivationResult holds the full output of a non-hardened BIP32 derivation.
type DerivationResult struct {
	// ChildPublicKey is the child public key (33 bytes for secp256k1, 32 for ed25519).
	ChildPublicKey []byte

	// AdditiveShift is the cumulative scalar tweak that transforms the input
	// public key into ChildPublicKey (inputPub + shift·G = childPub).
	AdditiveShift []byte

	// ChildChainCode is the 32-byte chain code of the final child node.
	ChildChainCode []byte

	// RequestedPath is a clone of the path that was passed to the derivation
	// function.
	RequestedPath []uint32

	// ResolvedPath is the path that was actually used. It differs from
	// RequestedPath only when SkipInvalidChild mode skips invalid indices.
	ResolvedPath []uint32

	// Depth is the final node depth.
	Depth uint8

	// ParentFingerprint is the fingerprint of the parent key of the final
	// child node.
	ParentFingerprint [4]byte

	// ChildNumber is the index actually used for the final derivation step.
	// Zero for an empty path.
	ChildNumber uint32
}
