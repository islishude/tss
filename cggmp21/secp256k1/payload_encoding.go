package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	keygenCommitmentsPayloadWireType  = "cggmp21.secp256k1.payload.keygen.commitments"
	keygenSharePayloadWireType        = "cggmp21.secp256k1.payload.keygen.share"
	presignRound1PayloadWireType      = "cggmp21.secp256k1.payload.presign.round1"
	presignRound2PayloadWireType      = "cggmp21.secp256k1.payload.presign.round2"
	presignRound3PayloadWireType      = "cggmp21.secp256k1.payload.presign.round3"
	signPartialPayloadWireType        = "cggmp21.secp256k1.payload.sign.partial"
	reshareDealerCommitmentsWireType  = "cggmp21.secp256k1.payload.reshare.dealer_commitments"
	reshareSharePayloadWireType       = "cggmp21.secp256k1.payload.reshare.share"
	reshareReceiverMaterialWireType   = "cggmp21.secp256k1.payload.reshare.receiver_material"
	refreshCommitmentsPayloadWireType = "cggmp21.secp256k1.payload.refresh.commitments"
	refreshSharePayloadWireType       = "cggmp21.secp256k1.payload.refresh.share"
)

const (
	keygenCommitmentsPayloadFieldCommitments uint16 = iota + 1
	keygenCommitmentsPayloadFieldPaillierPublicKey
	keygenCommitmentsPayloadFieldPaillierProof
	keygenCommitmentsPayloadFieldChainCode
	keygenCommitmentsPayloadFieldRingPedersenParams
	keygenCommitmentsPayloadFieldRingPedersenProof
)

const keygenSharePayloadFieldShare uint16 = 1

const (
	presignRound1PayloadFieldGamma uint16 = iota + 1
	presignRound1PayloadFieldEncK
	presignRound1PayloadFieldEncKProof
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
	signPartialPayloadFieldPresignContext
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
	if _, err := zkpai.UnmarshalRingPedersenParams(p.RingPedersenParams); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof); err != nil {
		return nil, err
	}
	if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
		return nil, errors.New("chain code must be 32 bytes")
	}
	return wire.Marshal(tss.Version, keygenCommitmentsPayloadWireType, []wire.Field{
		{Tag: keygenCommitmentsPayloadFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
		{Tag: keygenCommitmentsPayloadFieldPaillierPublicKey, Value: wire.NonNilBytes(p.PaillierPublicKey)},
		{Tag: keygenCommitmentsPayloadFieldPaillierProof, Value: wire.NonNilBytes(p.PaillierProof)},
		{Tag: keygenCommitmentsPayloadFieldChainCode, Value: wire.NonNilBytes(p.ChainCode)},
		{Tag: keygenCommitmentsPayloadFieldRingPedersenParams, Value: wire.NonNilBytes(p.RingPedersenParams)},
		{Tag: keygenCommitmentsPayloadFieldRingPedersenProof, Value: wire.NonNilBytes(p.RingPedersenProof)},
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
	if err := wire.RequireExactTags(fields, keygenCommitmentsPayloadFieldCommitments, keygenCommitmentsPayloadFieldPaillierPublicKey, keygenCommitmentsPayloadFieldPaillierProof, keygenCommitmentsPayloadFieldChainCode, keygenCommitmentsPayloadFieldRingPedersenParams, keygenCommitmentsPayloadFieldRingPedersenProof); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	commitments, err := wire.BytesListField(fields, keygenCommitmentsPayloadFieldCommitments)
	if err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if err := validateCommitmentPoints(commitments); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	p := keygenCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  wire.MustField(fields, keygenCommitmentsPayloadFieldPaillierPublicKey),
		PaillierProof:      wire.MustField(fields, keygenCommitmentsPayloadFieldPaillierProof),
		ChainCode:          wire.MustField(fields, keygenCommitmentsPayloadFieldChainCode),
		RingPedersenParams: wire.MustField(fields, keygenCommitmentsPayloadFieldRingPedersenParams),
		RingPedersenProof:  wire.MustField(fields, keygenCommitmentsPayloadFieldRingPedersenProof),
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalModulusProof(p.PaillierProof); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenParams(p.RingPedersenParams); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
		return keygenCommitmentsPayload{}, errors.New("chain code must be 32 bytes")
	}
	return p, nil
}

func marshalKeygenSharePayload(p keygenSharePayload) ([]byte, error) {
	if _, err := secp.ScalarFromBytes(p.Share); err != nil {
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
	if _, err := secp.ScalarFromBytes(share); err != nil {
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
	if _, err := zkpai.UnmarshalEncryptionProof(p.EncKProof); err != nil {
		return nil, err
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignRound1PayloadWireType, []wire.Field{
		{Tag: presignRound1PayloadFieldGamma, Value: wire.NonNilBytes(p.Gamma)},
		{Tag: presignRound1PayloadFieldEncK, Value: wire.NonNilBytes(p.EncK)},
		{Tag: presignRound1PayloadFieldEncKProof, Value: wire.NonNilBytes(p.EncKProof)},
		{Tag: presignRound1PayloadFieldPaillierPublicKey, Value: wire.NonNilBytes(p.PaillierPublicKey)},
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
	if err := wire.RequireExactTags(fields, presignRound1PayloadFieldGamma, presignRound1PayloadFieldEncK, presignRound1PayloadFieldEncKProof, presignRound1PayloadFieldPaillierPublicKey); err != nil {
		return presignRound1Payload{}, err
	}
	p := presignRound1Payload{
		Gamma:             wire.MustField(fields, presignRound1PayloadFieldGamma),
		EncK:              wire.MustField(fields, presignRound1PayloadFieldEncK),
		EncKProof:         wire.MustField(fields, presignRound1PayloadFieldEncKProof),
		PaillierPublicKey: wire.MustField(fields, presignRound1PayloadFieldPaillierPublicKey),
	}
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return presignRound1Payload{}, err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := zkpai.UnmarshalEncryptionProof(p.EncKProof); err != nil {
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
		{Tag: presignRound2PayloadFieldRound1Echo, Value: wire.NonNilBytes(p.Round1Echo)},
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
	if err := wire.RequireExactTags(fields, presignRound2PayloadFieldDelta, presignRound2PayloadFieldSigma, presignRound2PayloadFieldRound1Echo); err != nil {
		return presignRound2Payload{}, err
	}
	delta, err := mta.UnmarshalResponseMessage(wire.MustField(fields, presignRound2PayloadFieldDelta))
	if err != nil {
		return presignRound2Payload{}, err
	}
	sigma, err := mta.UnmarshalResponseMessage(wire.MustField(fields, presignRound2PayloadFieldSigma))
	if err != nil {
		return presignRound2Payload{}, err
	}
	echo := wire.MustField(fields, presignRound2PayloadFieldRound1Echo)
	if len(echo) != sha256.Size {
		return presignRound2Payload{}, errors.New("round1 echo must be 32 bytes")
	}
	return presignRound2Payload{Delta: *delta, Sigma: *sigma, Round1Echo: echo}, nil
}

func marshalPresignRound3Payload(p presignRound3Payload) ([]byte, error) {
	if _, err := secp.ScalarFromBytes(p.Delta); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignRound3PayloadWireType, []wire.Field{
		{Tag: presignRound3PayloadFieldDelta, Value: wire.NonNilBytes(p.Delta)},
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
	if err := wire.RequireExactTags(fields, presignRound3PayloadFieldDelta); err != nil {
		return presignRound3Payload{}, err
	}
	delta := wire.MustField(fields, presignRound3PayloadFieldDelta)
	if _, err := secp.ScalarFromBytes(delta); err != nil {
		return presignRound3Payload{}, err
	}
	return presignRound3Payload{Delta: delta}, nil
}

func marshalSignPartialPayload(p signPartialPayload) ([]byte, error) {
	if _, err := secp.ScalarFromBytes(p.S); err != nil {
		return nil, err
	}
	if len(p.PresignTranscript) != sha256.Size {
		return nil, errors.New("presign transcript must be 32 bytes")
	}
	if len(p.PresignContext) != sha256.Size {
		return nil, errors.New("presign context must be 32 bytes")
	}
	return wire.Marshal(tss.Version, signPartialPayloadWireType, []wire.Field{
		{Tag: signPartialPayloadFieldS, Value: wire.NonNilBytes(p.S)},
		{Tag: signPartialPayloadFieldPresignTranscript, Value: wire.NonNilBytes(p.PresignTranscript)},
		{Tag: signPartialPayloadFieldPresignContext, Value: wire.NonNilBytes(p.PresignContext)},
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
	if err := wire.RequireExactTags(fields, signPartialPayloadFieldS, signPartialPayloadFieldPresignTranscript, signPartialPayloadFieldPresignContext); err != nil {
		return signPartialPayload{}, err
	}
	p := signPartialPayload{
		S:                 wire.MustField(fields, signPartialPayloadFieldS),
		PresignTranscript: wire.MustField(fields, signPartialPayloadFieldPresignTranscript),
		PresignContext:    wire.MustField(fields, signPartialPayloadFieldPresignContext),
	}
	if _, err := secp.ScalarFromBytes(p.S); err != nil {
		return signPartialPayload{}, err
	}
	if len(p.PresignTranscript) != sha256.Size {
		return signPartialPayload{}, errors.New("presign transcript must be 32 bytes")
	}
	if len(p.PresignContext) != sha256.Size {
		return signPartialPayload{}, errors.New("presign context must be 32 bytes")
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

const reshareDealerCommitmentsFieldCommitments uint16 = 1

const (
	reshareSharePayloadFieldDealer uint16 = iota + 1
	reshareSharePayloadFieldReceiver
	reshareSharePayloadFieldShare
	reshareSharePayloadFieldDealerCommitmentHash
)

const (
	reshareReceiverMaterialFieldPaillierPublicKey uint16 = iota + 1
	reshareReceiverMaterialFieldPaillierProof
	reshareReceiverMaterialFieldRingPedersenParams
	reshareReceiverMaterialFieldRingPedersenProof
)

func marshalReshareDealerCommitmentsPayload(p reshareDealerCommitmentsPayload) ([]byte, error) {
	return wire.Marshal(tss.Version, reshareDealerCommitmentsWireType, []wire.Field{
		{Tag: reshareDealerCommitmentsFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
	})
}

func unmarshalReshareDealerCommitmentsPayload(in []byte) (reshareDealerCommitmentsPayload, error) {
	version, fields, err := wire.Unmarshal(in, reshareDealerCommitmentsWireType)
	if err != nil {
		return reshareDealerCommitmentsPayload{}, err
	}
	if version != tss.Version {
		return reshareDealerCommitmentsPayload{}, fmt.Errorf("unexpected reshare dealer commitments payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, reshareDealerCommitmentsFieldCommitments); err != nil {
		return reshareDealerCommitmentsPayload{}, err
	}
	commitments, err := wire.BytesListField(fields, reshareDealerCommitmentsFieldCommitments)
	if err != nil {
		return reshareDealerCommitmentsPayload{}, err
	}
	return reshareDealerCommitmentsPayload{Commitments: commitments}, nil
}

func marshalReshareSharePayload(p reshareSharePayload) ([]byte, error) {
	if p.Dealer == 0 {
		return nil, errors.New("reshare share dealer is zero")
	}
	if p.Receiver == 0 {
		return nil, errors.New("reshare share receiver is zero")
	}
	if _, err := secp.ScalarFromBytes(p.Share); err != nil {
		return nil, err
	}
	if len(p.DealerCommitmentHash) != sha256.Size {
		return nil, errors.New("reshare share commitment hash must be 32 bytes")
	}
	return wire.Marshal(tss.Version, reshareSharePayloadWireType, []wire.Field{
		{Tag: reshareSharePayloadFieldDealer, Value: wire.Uint32(uint32(p.Dealer))},
		{Tag: reshareSharePayloadFieldReceiver, Value: wire.Uint32(uint32(p.Receiver))},
		{Tag: reshareSharePayloadFieldShare, Value: wire.NonNilBytes(p.Share)},
		{Tag: reshareSharePayloadFieldDealerCommitmentHash, Value: wire.NonNilBytes(p.DealerCommitmentHash)},
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
	if err := wire.RequireExactTags(fields, reshareSharePayloadFieldDealer, reshareSharePayloadFieldReceiver, reshareSharePayloadFieldShare, reshareSharePayloadFieldDealerCommitmentHash); err != nil {
		return reshareSharePayload{}, err
	}
	dealer, err := wire.Uint32Field(fields, reshareSharePayloadFieldDealer)
	if err != nil {
		return reshareSharePayload{}, fmt.Errorf("reshare share dealer: %w", err)
	}
	receiver, err := wire.Uint32Field(fields, reshareSharePayloadFieldReceiver)
	if err != nil {
		return reshareSharePayload{}, fmt.Errorf("reshare share receiver: %w", err)
	}
	if dealer == 0 {
		return reshareSharePayload{}, errors.New("reshare share dealer is zero")
	}
	if receiver == 0 {
		return reshareSharePayload{}, errors.New("reshare share receiver is zero")
	}
	share := wire.MustField(fields, reshareSharePayloadFieldShare)
	if _, err := secp.ScalarFromBytes(share); err != nil {
		return reshareSharePayload{}, err
	}
	commitmentHash := wire.MustField(fields, reshareSharePayloadFieldDealerCommitmentHash)
	if len(commitmentHash) != sha256.Size {
		return reshareSharePayload{}, errors.New("reshare share commitment hash must be 32 bytes")
	}
	return reshareSharePayload{
		Dealer:               tss.PartyID(dealer),
		Receiver:             tss.PartyID(receiver),
		Share:                share,
		DealerCommitmentHash: commitmentHash,
	}, nil
}

func marshalReshareReceiverMaterialPayload(p reshareReceiverMaterialPayload) ([]byte, error) {
	return wire.Marshal(tss.Version, reshareReceiverMaterialWireType, []wire.Field{
		{Tag: reshareReceiverMaterialFieldPaillierPublicKey, Value: wire.NonNilBytes(p.PaillierPublicKey)},
		{Tag: reshareReceiverMaterialFieldPaillierProof, Value: wire.NonNilBytes(p.PaillierProof)},
		{Tag: reshareReceiverMaterialFieldRingPedersenParams, Value: wire.NonNilBytes(p.RingPedersenParams)},
		{Tag: reshareReceiverMaterialFieldRingPedersenProof, Value: wire.NonNilBytes(p.RingPedersenProof)},
	})
}

func unmarshalReshareReceiverMaterialPayload(in []byte) (reshareReceiverMaterialPayload, error) {
	version, fields, err := wire.Unmarshal(in, reshareReceiverMaterialWireType)
	if err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	if version != tss.Version {
		return reshareReceiverMaterialPayload{}, fmt.Errorf("unexpected reshare receiver material payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, reshareReceiverMaterialFieldPaillierPublicKey, reshareReceiverMaterialFieldPaillierProof, reshareReceiverMaterialFieldRingPedersenParams, reshareReceiverMaterialFieldRingPedersenProof); err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	publicKey, err := wire.Require(fields, reshareReceiverMaterialFieldPaillierPublicKey)
	if err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	proof, err := wire.Require(fields, reshareReceiverMaterialFieldPaillierProof)
	if err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	ringPedersenParams, err := wire.Require(fields, reshareReceiverMaterialFieldRingPedersenParams)
	if err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	ringPedersenProof, err := wire.Require(fields, reshareReceiverMaterialFieldRingPedersenProof)
	if err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenParams(ringPedersenParams); err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(ringPedersenProof); err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	return reshareReceiverMaterialPayload{PaillierPublicKey: publicKey, PaillierProof: proof, RingPedersenParams: ringPedersenParams, RingPedersenProof: ringPedersenProof}, nil
}

const refreshCommitmentsPayloadFieldCommitments uint16 = 1
const refreshCommitmentsPayloadFieldPaillierPublicKey uint16 = 2
const refreshCommitmentsPayloadFieldPaillierProof uint16 = 3
const refreshCommitmentsPayloadFieldRingPedersenParams uint16 = 4
const refreshCommitmentsPayloadFieldRingPedersenProof uint16 = 5

const refreshSharePayloadFieldShare uint16 = 1

type refreshCommitmentsPayload struct {
	Commitments        [][]byte
	PaillierPublicKey  []byte
	PaillierProof      []byte
	RingPedersenParams []byte
	RingPedersenProof  []byte
}

type refreshSharePayload struct {
	Share []byte
}

func marshalRefreshCommitmentsPayload(p refreshCommitmentsPayload) ([]byte, error) {
	return wire.Marshal(tss.Version, refreshCommitmentsPayloadWireType, []wire.Field{
		{Tag: refreshCommitmentsPayloadFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
		{Tag: refreshCommitmentsPayloadFieldPaillierPublicKey, Value: wire.NonNilBytes(p.PaillierPublicKey)},
		{Tag: refreshCommitmentsPayloadFieldPaillierProof, Value: wire.NonNilBytes(p.PaillierProof)},
		{Tag: refreshCommitmentsPayloadFieldRingPedersenParams, Value: wire.NonNilBytes(p.RingPedersenParams)},
		{Tag: refreshCommitmentsPayloadFieldRingPedersenProof, Value: wire.NonNilBytes(p.RingPedersenProof)},
	})
}

func unmarshalRefreshCommitmentsPayload(in []byte) (refreshCommitmentsPayload, error) {
	version, fields, err := wire.Unmarshal(in, refreshCommitmentsPayloadWireType)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	if version != tss.Version {
		return refreshCommitmentsPayload{}, fmt.Errorf("unexpected refresh commitments payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, refreshCommitmentsPayloadFieldCommitments, refreshCommitmentsPayloadFieldPaillierPublicKey, refreshCommitmentsPayloadFieldPaillierProof, refreshCommitmentsPayloadFieldRingPedersenParams, refreshCommitmentsPayloadFieldRingPedersenProof); err != nil {
		return refreshCommitmentsPayload{}, err
	}
	commitments, err := wire.BytesListField(fields, refreshCommitmentsPayloadFieldCommitments)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	publicKey, err := wire.Require(fields, refreshCommitmentsPayloadFieldPaillierPublicKey)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	proof, err := wire.Require(fields, refreshCommitmentsPayloadFieldPaillierProof)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	ringPedersenParams, err := wire.Require(fields, refreshCommitmentsPayloadFieldRingPedersenParams)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	ringPedersenProof, err := wire.Require(fields, refreshCommitmentsPayloadFieldRingPedersenProof)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenParams(ringPedersenParams); err != nil {
		return refreshCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(ringPedersenProof); err != nil {
		return refreshCommitmentsPayload{}, err
	}
	return refreshCommitmentsPayload{Commitments: commitments, PaillierPublicKey: publicKey, PaillierProof: proof, RingPedersenParams: ringPedersenParams, RingPedersenProof: ringPedersenProof}, nil
}

func marshalRefreshSharePayload(p refreshSharePayload) ([]byte, error) {
	if _, err := secp.ScalarFromBytes(p.Share); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, refreshSharePayloadWireType, []wire.Field{
		{Tag: refreshSharePayloadFieldShare, Value: wire.NonNilBytes(p.Share)},
	})
}

func unmarshalRefreshSharePayload(in []byte) (refreshSharePayload, error) {
	version, fields, err := wire.Unmarshal(in, refreshSharePayloadWireType)
	if err != nil {
		return refreshSharePayload{}, err
	}
	if version != tss.Version {
		return refreshSharePayload{}, fmt.Errorf("unexpected refresh share payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, refreshSharePayloadFieldShare); err != nil {
		return refreshSharePayload{}, err
	}
	share := wire.MustField(fields, refreshSharePayloadFieldShare)
	if _, err := secp.ScalarFromBytes(share); err != nil {
		return refreshSharePayload{}, err
	}
	return refreshSharePayload{Share: share}, nil
}
