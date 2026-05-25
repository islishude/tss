package ed25519

import (
	"fmt"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/wire"
)

const (
	keygenCommitmentsPayloadWireType = "frost.ed25519.payload.keygen.commitments"
	keygenSharePayloadWireType       = "frost.ed25519.payload.keygen.share"
	nonceCommitmentPayloadWireType   = "frost.ed25519.payload.sign.commitment"
	signPartialPayloadWireType       = "frost.ed25519.payload.sign.partial"
)

const keygenCommitmentsPayloadFieldCommitments uint16 = 1

const keygenSharePayloadFieldShare uint16 = 1

const (
	nonceCommitmentPayloadFieldD uint16 = iota + 1
	nonceCommitmentPayloadFieldE
)

const signPartialPayloadFieldZ uint16 = 1

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	return wire.Marshal(tss.Version, keygenCommitmentsPayloadWireType, []wire.Field{
		{Tag: keygenCommitmentsPayloadFieldCommitments, Value: encodeBytesList(p.Commitments)},
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
	if err := requireExactTags(fields, keygenCommitmentsPayloadFieldCommitments); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	commitments, err := decodeBytesListField(fields, keygenCommitmentsPayloadFieldCommitments)
	if err != nil {
		return keygenCommitmentsPayload{}, err
	}
	return keygenCommitmentsPayload{Commitments: commitments}, nil
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	if _, err := edcurve.ScalarFromCanonical(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keygenSharePayloadWireType, []wire.Field{
		{Tag: keygenSharePayloadFieldShare, Value: bytesOrEmpty(p.Share)},
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
	if err := requireExactTags(fields, keygenSharePayloadFieldShare); err != nil {
		return keygenSharePayload{}, err
	}
	share := mustWireField(fields, keygenSharePayloadFieldShare)
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
		{Tag: nonceCommitmentPayloadFieldD, Value: bytesOrEmpty(p.D)},
		{Tag: nonceCommitmentPayloadFieldE, Value: bytesOrEmpty(p.E)},
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
	if err := requireExactTags(fields, nonceCommitmentPayloadFieldD, nonceCommitmentPayloadFieldE); err != nil {
		return nonceCommitment{}, err
	}
	p := nonceCommitment{
		D: mustWireField(fields, nonceCommitmentPayloadFieldD),
		E: mustWireField(fields, nonceCommitmentPayloadFieldE),
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
		{Tag: signPartialPayloadFieldZ, Value: bytesOrEmpty(p.Z)},
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
	if err := requireExactTags(fields, signPartialPayloadFieldZ); err != nil {
		return signPartialPayload{}, err
	}
	z := mustWireField(fields, signPartialPayloadFieldZ)
	if _, err := edcurve.ScalarFromCanonical(z); err != nil {
		return signPartialPayload{}, err
	}
	return signPartialPayload{Z: z}, nil
}
