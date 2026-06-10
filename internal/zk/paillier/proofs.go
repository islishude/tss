package paillier

import (
	"fmt"
)

// Marshal returns deterministic canonical binary proof payloads.
//
// Marshal covers legacy proof types used by the keygen and MtA Start flows:
// ModulusProof, RingPedersenProof, EncryptionProof, MTAResponseProof, and
// LogProof. The modern CGGMP-compatible proofs (EncProof, AffGProof,
// LogStarProof) each carry their own MarshalBinary method and are NOT
// dispatched through this function — passing one to Marshal will return an
// error. This is intentional: the modern proofs use a different TLV encoding
// path (object-level wire.Marshal) that is incompatible with the legacy
// hand-rolled marshaling helpers.
func Marshal(v any) ([]byte, error) {
	switch p := v.(type) {
	// Πmod — used during keygen, refresh, and reshare.
	case *ModulusProof:
		return marshalModulusProof(p)
	case ModulusProof:
		return marshalModulusProof(&p)
	// Πprm — used during keygen, refresh, and reshare.
	case *RingPedersenProof:
		return marshalRingPedersenProof(p)
	case RingPedersenProof:
		return marshalRingPedersenProof(&p)
	// Legacy Π^Enc — used only by the MtA Start broadcast Round 1 flow where
	// per-verifier Ring-Pedersen commitments are impractical. New code must
	// use EncProof via ProveEnc/VerifyEnc instead.
	//
	// Deprecated: MtA Start should migrate to EncProof with per-verifier proofs.
	case *EncryptionProof:
		return marshalEncryptionProof(p)
	case EncryptionProof:
		return marshalEncryptionProof(&p)
	// Legacy Π^mta — superseded by AffGProof. Only accepted by legacy verifiers.
	//
	// Deprecated: use AffGProof via ProveAffG/VerifyAffG instead.
	case *MTAResponseProof:
		return marshalMTAResponseProof(p)
	case MTAResponseProof:
		return marshalMTAResponseProof(&p)
	// Legacy Π^log — superseded by LogStarProof. Only accepted by legacy verifiers.
	//
	// Deprecated: use LogStarProof via ProveLogStar/VerifyLogStar instead.
	case *LogProof:
		return marshalLogProof(p)
	case LogProof:
		return marshalLogProof(&p)
	default:
		return nil, fmt.Errorf("unsupported Paillier proof type %T — modern proofs (EncProof, AffGProof, LogStarProof) use their own MarshalBinary method", v)
	}
}
