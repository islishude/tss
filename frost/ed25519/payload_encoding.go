package ed25519

import (
	"crypto/sha256"
	"fmt"

	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

const (
	keygenCommitmentsPayloadWireType  = "frost.ed25519.payload.keygen.commitments"
	keygenSharePayloadWireType        = "frost.ed25519.payload.keygen.share"
	nonceCommitmentPayloadWireType    = "frost.ed25519.payload.sign.commitment"
	signPartialPayloadWireType        = "frost.ed25519.payload.sign.partial"
	reshareCommitmentsPayloadWireType = "frost.ed25519.payload.reshare.commitments"
	reshareSharePayloadWireType       = "frost.ed25519.payload.reshare.share"
)

// defaultPayloadFieldLimits returns the field limits for all FROST payload types.
func defaultPayloadFieldLimits() wire.FieldLimits {
	return DefaultLimits().fieldLimits()
}

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return nil, fmt.Errorf("chain code commit must be empty or 32 bytes, got %d", len(p.ChainCodeCommit))
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, fmt.Errorf("keygen commitments plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(defaultPayloadFieldLimits()))
}

func unmarshalKeygenCommitmentsPayload(in []byte) (keygenCommitmentsPayload, error) {
	var p keygenCommitmentsPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(defaultPayloadFieldLimits())); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return keygenCommitmentsPayload{}, fmt.Errorf("chain code commit must be empty or 32 bytes, got %d", len(p.ChainCodeCommit))
	}
	if len(p.PlanHash) != sha256.Size {
		return keygenCommitmentsPayload{}, fmt.Errorf("keygen commitments plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, fmt.Errorf("keygen share plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(defaultPayloadFieldLimits()))
}

func unmarshalKeygenSharePayload(in []byte) (keygenSharePayload, error) {
	var p keygenSharePayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(defaultPayloadFieldLimits())); err != nil {
		return keygenSharePayload{}, err
	}
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return keygenSharePayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return keygenSharePayload{}, fmt.Errorf("keygen share plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalNonceCommitmentPayload(p nonceCommitment) ([]byte, error) {
	if _, err := edcurve.PointFromBytes(p.D); err != nil {
		return nil, err
	}
	if _, err := edcurve.PointFromBytes(p.E); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, fmt.Errorf("nonce commitment plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(defaultPayloadFieldLimits()))
}

func unmarshalNonceCommitmentPayload(in []byte) (nonceCommitment, error) {
	var p nonceCommitment
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(defaultPayloadFieldLimits())); err != nil {
		return nonceCommitment{}, err
	}
	if _, err := edcurve.PointFromBytes(p.D); err != nil {
		return nonceCommitment{}, err
	}
	if _, err := edcurve.PointFromBytes(p.E); err != nil {
		return nonceCommitment{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nonceCommitment{}, fmt.Errorf("nonce commitment plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Z); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, fmt.Errorf("sign partial plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(defaultPayloadFieldLimits()))
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	var p signPartialPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(defaultPayloadFieldLimits())); err != nil {
		return signPartialPayload{}, err
	}
	if _, err := edcurve.ScalarFromCanonical(p.Z); err != nil {
		return signPartialPayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return signPartialPayload{}, fmt.Errorf("sign partial plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalReshareCommitmentsPayload(p reshareCommitmentsPayload) ([]byte, error) {
	if len(p.PlanHash) != sha256.Size {
		return nil, fmt.Errorf("reshare commitments plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(defaultPayloadFieldLimits()))
}

func unmarshalReshareCommitmentsPayload(in []byte) (reshareCommitmentsPayload, error) {
	var p reshareCommitmentsPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(defaultPayloadFieldLimits())); err != nil {
		return reshareCommitmentsPayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return reshareCommitmentsPayload{}, fmt.Errorf("reshare commitments plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, fmt.Errorf("reshare share plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(defaultPayloadFieldLimits()))
}

func unmarshalReshareSharePayload(in []byte) (reshareSharePayload, error) {
	var p reshareSharePayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(defaultPayloadFieldLimits())); err != nil {
		return reshareSharePayload{}, err
	}
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return reshareSharePayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return reshareSharePayload{}, fmt.Errorf("reshare share plan hash must be 32 bytes")
	}
	return p, nil
}
