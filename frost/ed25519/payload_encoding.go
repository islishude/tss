package ed25519

import (
	"fmt"

	"github.com/islishude/tss"

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

const (
	keygenCommitmentsPayloadFieldCommitments uint16 = 1
	keygenCommitmentsPayloadFieldChainCode   uint16 = 2
)

const keygenSharePayloadFieldShare uint16 = 1

const (
	nonceCommitmentPayloadFieldD uint16 = iota + 1
	nonceCommitmentPayloadFieldE
)

const signPartialPayloadFieldZ uint16 = 1

const (
	reshareCommitmentsPayloadFieldCommitments uint16 = 1
	reshareSharePayloadFieldShare             uint16 = 1
)

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return nil, fmt.Errorf("chain code commit must be empty or 32 bytes, got %d", len(p.ChainCodeCommit))
	}
	return wire.Marshal(tss.Version, keygenCommitmentsPayloadWireType, []wire.Field{
		{Tag: keygenCommitmentsPayloadFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
		{Tag: keygenCommitmentsPayloadFieldChainCode, Value: wire.NonNilBytes(p.ChainCodeCommit)},
	})
}

func unmarshalKeygenCommitmentsPayload(in []byte) (keygenCommitmentsPayload, error) {
	version, fields, err := wire.Unmarshal(in, keygenCommitmentsPayloadWireType)
	if err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if version != tss.Version {
		return keygenCommitmentsPayload{}, fmt.Errorf("unexpected keygen commitments payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, keygenCommitmentsPayloadFieldCommitments, keygenCommitmentsPayloadFieldChainCode); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	commitments, err := wire.BytesListField(fields, keygenCommitmentsPayloadFieldCommitments)
	if err != nil {
		return keygenCommitmentsPayload{}, err
	}
	chainCodeCommit := wire.MustField(fields, keygenCommitmentsPayloadFieldChainCode)
	if len(chainCodeCommit) != 0 && len(chainCodeCommit) != 32 {
		return keygenCommitmentsPayload{}, fmt.Errorf("chain code commit must be empty or 32 bytes, got %d", len(chainCodeCommit))
	}
	return keygenCommitmentsPayload{Commitments: commitments, ChainCodeCommit: chainCodeCommit}, nil
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keygenSharePayloadWireType, []wire.Field{
		{Tag: keygenSharePayloadFieldShare, Value: wire.NonNilBytes(p.Share)},
	})
}

func unmarshalKeygenSharePayload(in []byte) (keygenSharePayload, error) {
	version, fields, err := wire.Unmarshal(in, keygenSharePayloadWireType)
	if err != nil {
		return keygenSharePayload{}, err
	}
	if version != tss.Version {
		return keygenSharePayload{}, fmt.Errorf("unexpected keygen share payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, keygenSharePayloadFieldShare); err != nil {
		return keygenSharePayload{}, err
	}
	share := wire.MustField(fields, keygenSharePayloadFieldShare)
	if _, err := edcurve.ScalarFromCanonical(share); err != nil {
		return keygenSharePayload{}, err
	}
	return keygenSharePayload{Share: share}, nil
}

func marshalNonceCommitmentPayload(p nonceCommitment) ([]byte, error) {
	if _, err := edcurve.PointFromBytes(p.D); err != nil {
		return nil, err
	}
	if _, err := edcurve.PointFromBytes(p.E); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, nonceCommitmentPayloadWireType, []wire.Field{
		{Tag: nonceCommitmentPayloadFieldD, Value: wire.NonNilBytes(p.D)},
		{Tag: nonceCommitmentPayloadFieldE, Value: wire.NonNilBytes(p.E)},
	})
}

func unmarshalNonceCommitmentPayload(in []byte) (nonceCommitment, error) {
	version, fields, err := wire.Unmarshal(in, nonceCommitmentPayloadWireType)
	if err != nil {
		return nonceCommitment{}, err
	}
	if version != tss.Version {
		return nonceCommitment{}, fmt.Errorf("unexpected nonce commitment payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, nonceCommitmentPayloadFieldD, nonceCommitmentPayloadFieldE); err != nil {
		return nonceCommitment{}, err
	}
	p := nonceCommitment{
		D: wire.MustField(fields, nonceCommitmentPayloadFieldD),
		E: wire.MustField(fields, nonceCommitmentPayloadFieldE),
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
	return wire.Marshal(tss.Version, signPartialPayloadWireType, []wire.Field{
		{Tag: signPartialPayloadFieldZ, Value: wire.NonNilBytes(p.Z)},
	})
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	version, fields, err := wire.Unmarshal(in, signPartialPayloadWireType)
	if err != nil {
		return signPartialPayload{}, err
	}
	if version != tss.Version {
		return signPartialPayload{}, fmt.Errorf("unexpected sign partial payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, signPartialPayloadFieldZ); err != nil {
		return signPartialPayload{}, err
	}
	z := wire.MustField(fields, signPartialPayloadFieldZ)
	if _, err := edcurve.ScalarFromCanonical(z); err != nil {
		return signPartialPayload{}, err
	}
	return signPartialPayload{Z: z}, nil
}

func marshalReshareCommitmentsPayload(p reshareCommitmentsPayload) ([]byte, error) {
	return wire.Marshal(tss.Version, reshareCommitmentsPayloadWireType, []wire.Field{
		{Tag: reshareCommitmentsPayloadFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
	})
}

func unmarshalReshareCommitmentsPayload(in []byte) (reshareCommitmentsPayload, error) {
	version, fields, err := wire.Unmarshal(in, reshareCommitmentsPayloadWireType)
	if err != nil {
		return reshareCommitmentsPayload{}, err
	}
	if version != tss.Version {
		return reshareCommitmentsPayload{}, fmt.Errorf("unexpected reshare commitments payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, reshareCommitmentsPayloadFieldCommitments); err != nil {
		return reshareCommitmentsPayload{}, err
	}
	commitments, err := wire.BytesListField(fields, reshareCommitmentsPayloadFieldCommitments)
	if err != nil {
		return reshareCommitmentsPayload{}, err
	}
	return reshareCommitmentsPayload{Commitments: commitments}, nil
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, reshareSharePayloadWireType, []wire.Field{
		{Tag: reshareSharePayloadFieldShare, Value: wire.NonNilBytes(p.Share)},
	})
}

func unmarshalReshareSharePayload(in []byte) (reshareSharePayload, error) {
	version, fields, err := wire.Unmarshal(in, reshareSharePayloadWireType)
	if err != nil {
		return reshareSharePayload{}, err
	}
	if version != tss.Version {
		return reshareSharePayload{}, fmt.Errorf("unexpected reshare share payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, reshareSharePayloadFieldShare); err != nil {
		return reshareSharePayload{}, err
	}
	share := wire.MustField(fields, reshareSharePayloadFieldShare)
	if _, err := edcurve.ScalarFromCanonical(share); err != nil {
		return reshareSharePayload{}, err
	}
	return reshareSharePayload{Share: share}, nil
}
