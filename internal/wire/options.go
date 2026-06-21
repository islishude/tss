package wire

// FieldLimits maps semantic limit names to maximum values for field-level
// checks.  A tag that references a name not present in the FieldLimits is
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
type FieldLimits map[string]int

// MarshalOption configures Marshal behavior.
type MarshalOption interface {
	applyMarshal(*marshalConfig)
}

// UnmarshalOption configures Unmarshal behavior.
type UnmarshalOption interface {
	applyUnmarshal(*unmarshalConfig)
}

type marshalConfig struct {
	fieldLimits FieldLimits
}

type unmarshalConfig struct {
	frameLimits FrameLimits
	fieldLimits FieldLimits
}

// WithFieldLimitsForMarshal provides field-level semantic caps checked
// during marshaling.  Tags that reference limit names not in the set
// will cause a marshal error.
func WithFieldLimitsForMarshal(fl FieldLimits) MarshalOption {
	return withFieldLimitsForMarshal{fl}
}

type withFieldLimitsForMarshal struct{ fl FieldLimits }

func (o withFieldLimitsForMarshal) applyMarshal(cfg *marshalConfig) { cfg.fieldLimits = o.fl }

// WithFrameLimits overrides non-zero TLV-level decode limits. Zero-valued
// members inherit the corresponding value from DefaultFrameLimits.
func WithFrameLimits(l FrameLimits) UnmarshalOption {
	return withFrameLimitsOpt{l}
}

type withFrameLimitsOpt struct{ l FrameLimits }

func (o withFrameLimitsOpt) applyUnmarshal(cfg *unmarshalConfig) { cfg.frameLimits = o.l }

// WithFieldLimits provides field-level semantic caps checked during
// unmarshaling.  Tags that reference limit names not in the set will
// cause an unmarshal error.
func WithFieldLimits(fl FieldLimits) UnmarshalOption {
	return withFieldLimitsOpt{fl}
}

type withFieldLimitsOpt struct{ fl FieldLimits }

func (o withFieldLimitsOpt) applyUnmarshal(cfg *unmarshalConfig) { cfg.fieldLimits = o.fl }
