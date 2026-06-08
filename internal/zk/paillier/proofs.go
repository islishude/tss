package paillier

import (
	"fmt"
)

// Marshal returns deterministic canonical binary proof payloads.
func Marshal(v any) ([]byte, error) {
	switch p := v.(type) {
	case *ModulusProof:
		return marshalModulusProof(p)
	case ModulusProof:
		return marshalModulusProof(&p)
	case *MTAResponseProof:
		return marshalMTAResponseProof(p)
	case MTAResponseProof:
		return marshalMTAResponseProof(&p)
	case *LogProof:
		return marshalLogProof(p)
	case LogProof:
		return marshalLogProof(&p)
	case *RingPedersenProof:
		return marshalRingPedersenProof(p)
	case RingPedersenProof:
		return marshalRingPedersenProof(&p)
	case *EncryptionProof:
		return marshalEncryptionProof(p)
	case EncryptionProof:
		return marshalEncryptionProof(&p)
	default:
		return nil, fmt.Errorf("unsupported Paillier proof type %T", v)
	}
}
