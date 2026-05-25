package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/codec"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	keygenCommitmentsPayloadWireType = "cggmp21.secp256k1.payload.keygen.commitments"
	keygenSharePayloadWireType       = "cggmp21.secp256k1.payload.keygen.share"
	presignRound1PayloadWireType     = "cggmp21.secp256k1.payload.presign.round1"
	presignRound2PayloadWireType     = "cggmp21.secp256k1.payload.presign.round2"
	presignRound3PayloadWireType     = "cggmp21.secp256k1.payload.presign.round3"
	signPartialPayloadWireType       = "cggmp21.secp256k1.payload.sign.partial"
)

const (
	keygenCommitmentsPayloadFieldCommitments uint16 = iota + 1
	keygenCommitmentsPayloadFieldPaillierPublicKey
	keygenCommitmentsPayloadFieldPaillierProof
	keygenCommitmentsPayloadFieldChainCode
)

const keygenSharePayloadFieldShare uint16 = 1

const (
	presignRound1PayloadFieldGamma uint16 = iota + 1
	presignRound1PayloadFieldEncK
	presignRound1PayloadFieldEncKProof
	presignRound1PayloadFieldEncKRangeProof
	presignRound1PayloadFieldPaillierPublicKey
)

const (
	presignRound2PayloadFieldDelta uint16 = iota + 1
	presignRound2PayloadFieldSigma
	presignRound2PayloadFieldRound1Echo
)

const presignRound3PayloadFieldDelta uint16 = 1

const (
	signPartialPayloadFieldS uint16 = iota + 1
	signPartialPayloadFieldPresignTranscript
)

func marshalKeygenCommitmentsPayload(p keygenCommitmentsPayload) ([]byte, error) {
	if err := validateCommitmentPoints(p.Commitments); err != nil {
		return nil, err
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalModulusProof(p.PaillierProof); err != nil {
		return nil, err
	}
	if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
		return nil, errors.New("chain code must be 32 bytes")
	}
	return wire.Marshal(tss.Version, keygenCommitmentsPayloadWireType, []wire.Field{
		{Tag: keygenCommitmentsPayloadFieldCommitments, Value: codec.EncodeBytesList(p.Commitments)},
		{Tag: keygenCommitmentsPayloadFieldPaillierPublicKey, Value: codec.NonNilBytes(p.PaillierPublicKey)},
		{Tag: keygenCommitmentsPayloadFieldPaillierProof, Value: codec.NonNilBytes(p.PaillierProof)},
		{Tag: keygenCommitmentsPayloadFieldChainCode, Value: codec.NonNilBytes(p.ChainCode)},
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
	if err := codec.RequireExactTags(fields, keygenCommitmentsPayloadFieldCommitments, keygenCommitmentsPayloadFieldPaillierPublicKey, keygenCommitmentsPayloadFieldPaillierProof, keygenCommitmentsPayloadFieldChainCode); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	commitments, err := codec.BytesListField(fields, keygenCommitmentsPayloadFieldCommitments)
	if err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if err := validateCommitmentPoints(commitments); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	p := keygenCommitmentsPayload{
		Commitments:       commitments,
		PaillierPublicKey: codec.MustField(fields, keygenCommitmentsPayloadFieldPaillierPublicKey),
		PaillierProof:     codec.MustField(fields, keygenCommitmentsPayloadFieldPaillierProof),
		ChainCode:         codec.MustField(fields, keygenCommitmentsPayloadFieldChainCode),
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalModulusProof(p.PaillierProof); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
		return keygenCommitmentsPayload{}, errors.New("chain code must be 32 bytes")
	}
	return p, nil
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	if _, err := secp.ParseScalar(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keygenSharePayloadWireType, []wire.Field{
		{Tag: keygenSharePayloadFieldShare, Value: codec.NonNilBytes(p.Share)},
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
	if err := codec.RequireExactTags(fields, keygenSharePayloadFieldShare); err != nil {
		return keygenSharePayload{}, err
	}
	share := codec.MustField(fields, keygenSharePayloadFieldShare)
	if _, err := secp.ParseScalar(share); err != nil {
		return keygenSharePayload{}, err
	}
	return keygenSharePayload{Share: share}, nil
}

func marshalPresignRound1Payload(p presignRound1Payload) ([]byte, error) {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return nil, err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalEncScalarProof(p.EncKProof); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalEncRangeProof(p.EncKRangeProof); err != nil {
		return nil, err
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignRound1PayloadWireType, []wire.Field{
		{Tag: presignRound1PayloadFieldGamma, Value: codec.NonNilBytes(p.Gamma)},
		{Tag: presignRound1PayloadFieldEncK, Value: codec.NonNilBytes(p.EncK)},
		{Tag: presignRound1PayloadFieldEncKProof, Value: codec.NonNilBytes(p.EncKProof)},
		{Tag: presignRound1PayloadFieldEncKRangeProof, Value: codec.NonNilBytes(p.EncKRangeProof)},
		{Tag: presignRound1PayloadFieldPaillierPublicKey, Value: codec.NonNilBytes(p.PaillierPublicKey)},
	})
}

func unmarshalPresignRound1Payload(in []byte) (presignRound1Payload, error) {
	version, fields, err := wire.Unmarshal(in, presignRound1PayloadWireType)
	if err != nil {
		return presignRound1Payload{}, err
	}
	if version != tss.Version {
		return presignRound1Payload{}, fmt.Errorf("unexpected presign round1 payload version %d", version)
	}
	if err := codec.RequireExactTags(fields, presignRound1PayloadFieldGamma, presignRound1PayloadFieldEncK, presignRound1PayloadFieldEncKProof, presignRound1PayloadFieldEncKRangeProof, presignRound1PayloadFieldPaillierPublicKey); err != nil {
		return presignRound1Payload{}, err
	}
	p := presignRound1Payload{
		Gamma:             codec.MustField(fields, presignRound1PayloadFieldGamma),
		EncK:              codec.MustField(fields, presignRound1PayloadFieldEncK),
		EncKProof:         codec.MustField(fields, presignRound1PayloadFieldEncKProof),
		EncKRangeProof:    codec.MustField(fields, presignRound1PayloadFieldEncKRangeProof),
		PaillierPublicKey: codec.MustField(fields, presignRound1PayloadFieldPaillierPublicKey),
	}
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return presignRound1Payload{}, err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := zkpai.UnmarshalEncScalarProof(p.EncKProof); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := zkpai.UnmarshalEncRangeProof(p.EncKRangeProof); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return presignRound1Payload{}, err
	}
	return p, nil
}

func marshalPresignRound2Payload(p presignRound2Payload) ([]byte, error) {
	delta, err := p.Delta.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sigma, err := p.Sigma.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(p.Round1Echo) != sha256.Size {
		return nil, errors.New("round1 echo must be 32 bytes")
	}
	return wire.Marshal(tss.Version, presignRound2PayloadWireType, []wire.Field{
		{Tag: presignRound2PayloadFieldDelta, Value: delta},
		{Tag: presignRound2PayloadFieldSigma, Value: sigma},
		{Tag: presignRound2PayloadFieldRound1Echo, Value: codec.NonNilBytes(p.Round1Echo)},
	})
}

func unmarshalPresignRound2Payload(in []byte) (presignRound2Payload, error) {
	version, fields, err := wire.Unmarshal(in, presignRound2PayloadWireType)
	if err != nil {
		return presignRound2Payload{}, err
	}
	if version != tss.Version {
		return presignRound2Payload{}, fmt.Errorf("unexpected presign round2 payload version %d", version)
	}
	if err := codec.RequireExactTags(fields, presignRound2PayloadFieldDelta, presignRound2PayloadFieldSigma, presignRound2PayloadFieldRound1Echo); err != nil {
		return presignRound2Payload{}, err
	}
	delta, err := mta.UnmarshalResponseMessage(codec.MustField(fields, presignRound2PayloadFieldDelta))
	if err != nil {
		return presignRound2Payload{}, err
	}
	sigma, err := mta.UnmarshalResponseMessage(codec.MustField(fields, presignRound2PayloadFieldSigma))
	if err != nil {
		return presignRound2Payload{}, err
	}
	echo := codec.MustField(fields, presignRound2PayloadFieldRound1Echo)
	if len(echo) != sha256.Size {
		return presignRound2Payload{}, errors.New("round1 echo must be 32 bytes")
	}
	return presignRound2Payload{Delta: *delta, Sigma: *sigma, Round1Echo: echo}, nil
}

func marshalPresignRound3Payload(p presignRound3Payload) ([]byte, error) {
	if _, err := secp.ParseScalar(p.Delta); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignRound3PayloadWireType, []wire.Field{
		{Tag: presignRound3PayloadFieldDelta, Value: codec.NonNilBytes(p.Delta)},
	})
}

func unmarshalPresignRound3Payload(in []byte) (presignRound3Payload, error) {
	version, fields, err := wire.Unmarshal(in, presignRound3PayloadWireType)
	if err != nil {
		return presignRound3Payload{}, err
	}
	if version != tss.Version {
		return presignRound3Payload{}, fmt.Errorf("unexpected presign round3 payload version %d", version)
	}
	if err := codec.RequireExactTags(fields, presignRound3PayloadFieldDelta); err != nil {
		return presignRound3Payload{}, err
	}
	delta := codec.MustField(fields, presignRound3PayloadFieldDelta)
	if _, err := secp.ParseScalar(delta); err != nil {
		return presignRound3Payload{}, err
	}
	return presignRound3Payload{Delta: delta}, nil
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	if _, err := secp.ParseScalar(p.S); err != nil {
		return nil, err
	}
	if len(p.PresignTranscript) != sha256.Size {
		return nil, errors.New("presign transcript must be 32 bytes")
	}
	return wire.Marshal(tss.Version, signPartialPayloadWireType, []wire.Field{
		{Tag: signPartialPayloadFieldS, Value: codec.NonNilBytes(p.S)},
		{Tag: signPartialPayloadFieldPresignTranscript, Value: codec.NonNilBytes(p.PresignTranscript)},
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
	if err := codec.RequireExactTags(fields, signPartialPayloadFieldS, signPartialPayloadFieldPresignTranscript); err != nil {
		return signPartialPayload{}, err
	}
	p := signPartialPayload{
		S:                 codec.MustField(fields, signPartialPayloadFieldS),
		PresignTranscript: codec.MustField(fields, signPartialPayloadFieldPresignTranscript),
	}
	if _, err := secp.ParseScalar(p.S); err != nil {
		return signPartialPayload{}, err
	}
	if len(p.PresignTranscript) != sha256.Size {
		return signPartialPayload{}, errors.New("presign transcript must be 32 bytes")
	}
	return p, nil
}

func validateCommitmentPoints(commitments [][]byte) error {
	if len(commitments) == 0 {
		return errors.New("empty commitments")
	}
	for i, commitment := range commitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid commitment %d: %w", i, err)
		}
	}
	return nil
}

func validatePositiveIntegerBytes(in []byte) error {
	if len(in) == 0 {
		return errors.New("empty integer")
	}
	if in[0] == 0 {
		return errors.New("non-minimal integer encoding")
	}
	if new(big.Int).SetBytes(in).Sign() <= 0 {
		return errors.New("integer must be positive")
	}
	return nil
}
