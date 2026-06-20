package paillier

import (
	"fmt"
)

// Marshal returns deterministic canonical binary proof payloads.
//
// Marshal covers the hand-rolled proof types used by key generation:
// ModulusProof and RingPedersenProof. The modern CGGMP-compatible proofs (EncProof, AffGProof,
// LogStarProof) each carry their own MarshalBinary method and are NOT
// dispatched through this function — passing one to Marshal will return an
// error. This is intentional: the modern proofs use a different TLV encoding
// path (object-level wire.Marshal) that is incompatible with the legacy
// hand-rolled marshaling helpers.
func Marshal(v any) ([]byte, error) {
	switch p := v.(type) {
	// Πmod — used during keygen, refresh, and reshare.
	case *ModulusProof:
		return p.MarshalBinary()
	case ModulusProof:
		return p.MarshalBinary()
	// Πprm — used during keygen, refresh, and reshare.
	case *RingPedersenProof:
		return p.MarshalBinary()
	case RingPedersenProof:
		return p.MarshalBinary()
	default:
		return nil, fmt.Errorf("unsupported Paillier proof type %T — modern proofs (EncProof, AffGProof, LogStarProof) use their own MarshalBinary method", v)
	}
}
