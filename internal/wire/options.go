package wire

// LimitSet maps semantic limit names to maximum values for field-level
// checks.  A tag that references a name not present in the LimitSet is
// treated as an error, preventing accidental omission of security caps.
//
// Common names used across the codebase:
//
//	field           - single bytes field
//	point           - curve point
//	session         - session identifier
//	parties         - party count
//	threshold       - threshold value
//	signers         - signer set size
//	paillier_proof  - Paillier proof payload
type LimitSet map[string]int

// MarshalOption configures Marshal behavior.
type MarshalOption interface {
	applyMarshal(*marshalConfig)
}

// UnmarshalOption configures Unmarshal behavior.
type UnmarshalOption interface {
	applyUnmarshal(*unmarshalConfig)
}

type marshalConfig struct {
	limitSet LimitSet
}

type unmarshalConfig struct {
	limits   Limits
	limitSet LimitSet
}

// WithLimitSetForMarshal provides field-level semantic caps checked
// during marshaling.  Tags that reference limit names not in the set
// will cause a marshal error.
func WithLimitSetForMarshal(ls LimitSet) MarshalOption {
	return withLimitSetForMarshal{ls}
}

type withLimitSetForMarshal struct{ ls LimitSet }

func (o withLimitSetForMarshal) applyMarshal(cfg *marshalConfig) { cfg.limitSet = o.ls }

// WithLimits overrides the TLV-level decode limits.  When omitted,
// DefaultLimits is used.
func WithLimits(l Limits) UnmarshalOption {
	return withLimitsOpt{l}
}

type withLimitsOpt struct{ l Limits }

func (o withLimitsOpt) applyUnmarshal(cfg *unmarshalConfig) { cfg.limits = o.l }

// WithLimitSet provides field-level semantic caps checked during
// unmarshaling.  Tags that reference limit names not in the set will
// cause an unmarshal error.
func WithLimitSet(ls LimitSet) UnmarshalOption {
	return withLimitSetOpt{ls}
}

type withLimitSetOpt struct{ ls LimitSet }

func (o withLimitSetOpt) applyUnmarshal(cfg *unmarshalConfig) { cfg.limitSet = o.ls }
