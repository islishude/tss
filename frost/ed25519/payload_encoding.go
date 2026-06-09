package ed25519

import (
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

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return nil, fmt.Errorf("chain code commit must be empty or 32 bytes, got %d", len(p.ChainCodeCommit))
	}
	return wire.Marshal(p)
}

func unmarshalKeygenCommitmentsPayload(in []byte) (keygenCommitmentsPayload, error) {
	var p keygenCommitmentsPayload
	if err := wire.Unmarshal(in, &p); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return keygenCommitmentsPayload{}, fmt.Errorf("chain code commit must be empty or 32 bytes, got %d", len(p.ChainCodeCommit))
	}
	return p, nil
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

func unmarshalKeygenSharePayload(in []byte) (keygenSharePayload, error) {
	var p keygenSharePayload
	if err := wire.Unmarshal(in, &p); err != nil {
		return keygenSharePayload{}, err
	}
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return keygenSharePayload{}, err
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
	return wire.Marshal(p)
}

func unmarshalNonceCommitmentPayload(in []byte) (nonceCommitment, error) {
	var p nonceCommitment
	if err := wire.Unmarshal(in, &p); err != nil {
		return nonceCommitment{}, err
	}
	if _, err := edcurve.PointFromBytes(p.D); err != nil {
		return nonceCommitment{}, err
	}
	if _, err := edcurve.PointFromBytes(p.E); err != nil {
		return nonceCommitment{}, err
	}
	return p, nil
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Z); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	var p signPartialPayload
	if err := wire.Unmarshal(in, &p); err != nil {
		return signPartialPayload{}, err
	}
	if _, err := edcurve.ScalarFromCanonical(p.Z); err != nil {
		return signPartialPayload{}, err
	}
	return p, nil
}

func marshalReshareCommitmentsPayload(p reshareCommitmentsPayload) ([]byte, error) {
	return wire.Marshal(p)
}

func unmarshalReshareCommitmentsPayload(in []byte) (reshareCommitmentsPayload, error) {
	var p reshareCommitmentsPayload
	if err := wire.Unmarshal(in, &p); err != nil {
		return reshareCommitmentsPayload{}, err
	}
	return p, nil
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(p)
}

func unmarshalReshareSharePayload(in []byte) (reshareSharePayload, error) {
	var p reshareSharePayload
	if err := wire.Unmarshal(in, &p); err != nil {
		return reshareSharePayload{}, err
	}
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return reshareSharePayload{}, err
	}
	return p, nil
}
