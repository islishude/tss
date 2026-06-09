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
	presignRound1ProofPayloadWireType = "cggmp21.secp256k1.payload.presign.round1-proof"
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
	presignRound1PayloadFieldPaillierPublicKey
)

const (
	presignRound1ProofPayloadFieldPublicHash uint16 = iota + 1
	presignRound1ProofPayloadFieldEncKProof
)

const (
	presignRound2PayloadFieldDelta uint16 = iota + 1
	presignRound2PayloadFieldSigma
	presignRound2PayloadFieldRound1Echo
)

const (
	presignRound3PayloadFieldDelta uint16 = iota + 1
	presignRound3PayloadFieldKPoint
	presignRound3PayloadFieldChiPoint
	presignRound3PayloadFieldProof
)

const (
	signPartialPayloadFieldS uint16 = iota + 1
	signPartialPayloadFieldPresignTranscript
	signPartialPayloadFieldPresignContext
	signPartialPayloadFieldDigestHash
	signPartialPayloadFieldPartialEquationHash
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
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return nil, errors.New("chain code must be 32 bytes")
	}
	return wire.Marshal(tss.Version, keygenCommitmentsPayloadWireType, []wire.Field{
		{Tag: keygenCommitmentsPayloadFieldCommitments, Value: wire.EncodeBytesList(p.Commitments)},
		{Tag: keygenCommitmentsPayloadFieldPaillierPublicKey, Value: wire.NonNilBytes(p.PaillierPublicKey)},
		{Tag: keygenCommitmentsPayloadFieldPaillierProof, Value: wire.NonNilBytes(p.PaillierProof)},
		{Tag: keygenCommitmentsPayloadFieldChainCode, Value: wire.NonNilBytes(p.ChainCodeCommit)},
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
	// Tags validated; access fields by index to avoid redundant linear scans.
	commitments, err := wire.DecodeBytesList(fields[0].Value)
	if err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if err := validateCommitmentPoints(commitments); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	p := keygenCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  fields[1].Value,
		PaillierProof:      fields[2].Value,
		ChainCodeCommit:    fields[3].Value,
		RingPedersenParams: fields[4].Value,
		RingPedersenProof:  fields[5].Value,
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
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
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
	share := fields[0].Value
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
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignRound1PayloadWireType, []wire.Field{
		{Tag: presignRound1PayloadFieldGamma, Value: wire.NonNilBytes(p.Gamma)},
		{Tag: presignRound1PayloadFieldEncK, Value: wire.NonNilBytes(p.EncK)},
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
	if err := wire.RequireExactTags(fields, presignRound1PayloadFieldGamma, presignRound1PayloadFieldEncK, presignRound1PayloadFieldPaillierPublicKey); err != nil {
		return presignRound1Payload{}, err
	}
	p := presignRound1Payload{
		Gamma:             fields[0].Value,
		EncK:              fields[1].Value,
		PaillierPublicKey: fields[2].Value,
	}
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return presignRound1Payload{}, err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := pai.UnmarshalPublicKey(p.PaillierPublicKey); err != nil {
		return presignRound1Payload{}, err
	}
	return p, nil
}

func marshalPresignRound1ProofPayload(p presignRound1ProofPayload) ([]byte, error) {
	if len(p.PublicRound1Hash) != sha256.Size {
		return nil, errors.New("round1 public hash must be 32 bytes")
	}
	if _, err := zkpai.UnmarshalEncProof(p.EncKProof); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignRound1ProofPayloadWireType, []wire.Field{
		{Tag: presignRound1ProofPayloadFieldPublicHash, Value: wire.NonNilBytes(p.PublicRound1Hash)},
		{Tag: presignRound1ProofPayloadFieldEncKProof, Value: wire.NonNilBytes(p.EncKProof)},
	})
}

func unmarshalPresignRound1ProofPayload(in []byte) (presignRound1ProofPayload, error) {
	version, fields, err := wire.Unmarshal(in, presignRound1ProofPayloadWireType)
	if err != nil {
		return presignRound1ProofPayload{}, err
	}
	if version != tss.Version {
		return presignRound1ProofPayload{}, fmt.Errorf("unexpected presign round1 proof payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, presignRound1ProofPayloadFieldPublicHash, presignRound1ProofPayloadFieldEncKProof); err != nil {
		return presignRound1ProofPayload{}, err
	}
	p := presignRound1ProofPayload{
		PublicRound1Hash: fields[0].Value,
		EncKProof:        fields[1].Value,
	}
	if len(p.PublicRound1Hash) != sha256.Size {
		return presignRound1ProofPayload{}, errors.New("round1 public hash must be 32 bytes")
	}
	if _, err := zkpai.UnmarshalEncProof(p.EncKProof); err != nil {
		return presignRound1ProofPayload{}, err
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
	delta, err := mta.UnmarshalResponseMessage(fields[0].Value)
	if err != nil {
		return presignRound2Payload{}, err
	}
	sigma, err := mta.UnmarshalResponseMessage(fields[1].Value)
	if err != nil {
		return presignRound2Payload{}, err
	}
	echo := fields[2].Value
	if len(echo) != sha256.Size {
		return presignRound2Payload{}, errors.New("round1 echo must be 32 bytes")
	}
	return presignRound2Payload{Delta: *delta, Sigma: *sigma, Round1Echo: echo}, nil
}

func marshalPresignRound3Payload(p presignRound3Payload) ([]byte, error) {
	if _, err := secp.ScalarFromBytes(p.Delta); err != nil {
		return nil, err
	}
	if _, err := secp.PointFromBytes(p.KPoint); err != nil {
		return nil, err
	}
	if _, err := secp.PointFromBytes(p.ChiPoint); err != nil {
		return nil, err
	}
	limits := DefaultLimits()
	if len(p.Proof) == 0 {
		return nil, errors.New("empty signprep proof")
	}
	if len(p.Proof) > limits.MaxCGGMP21SignPrepProofBytes {
		return nil, fmt.Errorf("signprep proof too large: %d > %d", len(p.Proof), limits.MaxCGGMP21SignPrepProofBytes)
	}
	return wire.Marshal(tss.Version, presignRound3PayloadWireType, []wire.Field{
		{Tag: presignRound3PayloadFieldDelta, Value: wire.NonNilBytes(p.Delta)},
		{Tag: presignRound3PayloadFieldKPoint, Value: wire.NonNilBytes(p.KPoint)},
		{Tag: presignRound3PayloadFieldChiPoint, Value: wire.NonNilBytes(p.ChiPoint)},
		{Tag: presignRound3PayloadFieldProof, Value: wire.NonNilBytes(p.Proof)},
	})
}

func unmarshalPresignRound3Payload(in []byte) (presignRound3Payload, error) {
	limits := DefaultLimits()
	if len(in) > limits.MaxCGGMP21SignVerifyShareBytes*2 {
		return presignRound3Payload{}, fmt.Errorf("presign round3 payload too large: %d", len(in))
	}
	version, fields, err := wire.Unmarshal(in, presignRound3PayloadWireType)
	if err != nil {
		return presignRound3Payload{}, err
	}
	if version != tss.Version {
		return presignRound3Payload{}, fmt.Errorf("unexpected presign round3 payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, presignRound3PayloadFieldDelta, presignRound3PayloadFieldKPoint, presignRound3PayloadFieldChiPoint, presignRound3PayloadFieldProof); err != nil {
		return presignRound3Payload{}, err
	}
	p := presignRound3Payload{
		Delta:    fields[0].Value,
		KPoint:   fields[1].Value,
		ChiPoint: fields[2].Value,
		Proof:    fields[3].Value,
	}
	if _, err := secp.ScalarFromBytes(p.Delta); err != nil {
		return presignRound3Payload{}, err
	}
	if _, err := secp.PointFromBytes(p.KPoint); err != nil {
		return presignRound3Payload{}, err
	}
	if _, err := secp.PointFromBytes(p.ChiPoint); err != nil {
		return presignRound3Payload{}, err
	}
	if len(p.Proof) == 0 {
		return presignRound3Payload{}, errors.New("empty signprep proof")
	}
	if len(p.Proof) > limits.MaxCGGMP21SignPrepProofBytes {
		return presignRound3Payload{}, fmt.Errorf("signprep proof too large: %d > %d", len(p.Proof), limits.MaxCGGMP21SignPrepProofBytes)
	}
	return p, nil
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
	if len(p.DigestHash) != sha256.Size {
		return nil, errors.New("digest hash must be 32 bytes")
	}
	if len(p.PartialEquationHash) != sha256.Size {
		return nil, errors.New("partial equation hash must be 32 bytes")
	}
	return wire.Marshal(tss.Version, signPartialPayloadWireType, []wire.Field{
		{Tag: signPartialPayloadFieldS, Value: wire.NonNilBytes(p.S)},
		{Tag: signPartialPayloadFieldPresignTranscript, Value: wire.NonNilBytes(p.PresignTranscript)},
		{Tag: signPartialPayloadFieldPresignContext, Value: wire.NonNilBytes(p.PresignContext)},
		{Tag: signPartialPayloadFieldDigestHash, Value: wire.NonNilBytes(p.DigestHash)},
		{Tag: signPartialPayloadFieldPartialEquationHash, Value: wire.NonNilBytes(p.PartialEquationHash)},
	})
}

func unmarshalSignPartialPayload(in []byte) (signPartialPayload, error) {
	limits := DefaultLimits()
	if len(in) > limits.MaxCGGMP21SignPartialPayloadBytes {
		return signPartialPayload{}, fmt.Errorf("sign partial payload too large: %d > %d", len(in), limits.MaxCGGMP21SignPartialPayloadBytes)
	}
	version, fields, err := wire.Unmarshal(in, signPartialPayloadWireType)
	if err != nil {
		return signPartialPayload{}, err
	}
	if version != tss.Version {
		return signPartialPayload{}, fmt.Errorf("unexpected sign partial payload version %d", version)
	}
	if err := wire.RequireExactTags(fields, signPartialPayloadFieldS, signPartialPayloadFieldPresignTranscript, signPartialPayloadFieldPresignContext, signPartialPayloadFieldDigestHash, signPartialPayloadFieldPartialEquationHash); err != nil {
		return signPartialPayload{}, err
	}
	p := signPartialPayload{
		S:                   fields[0].Value,
		PresignTranscript:   fields[1].Value,
		PresignContext:      fields[2].Value,
		DigestHash:          fields[3].Value,
		PartialEquationHash: fields[4].Value,
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
	if len(p.DigestHash) != sha256.Size {
		return signPartialPayload{}, errors.New("digest hash must be 32 bytes")
	}
	if len(p.PartialEquationHash) != sha256.Size {
		return signPartialPayload{}, errors.New("partial equation hash must be 32 bytes")
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
	commitments, err := wire.DecodeBytesList(fields[0].Value)
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
	dealer, err := wire.DecodeUint32(fields[0].Value)
	if err != nil {
		return reshareSharePayload{}, fmt.Errorf("reshare share dealer: %w", err)
	}
	receiver, err := wire.DecodeUint32(fields[1].Value)
	if err != nil {
		return reshareSharePayload{}, fmt.Errorf("reshare share receiver: %w", err)
	}
	if dealer == 0 {
		return reshareSharePayload{}, errors.New("reshare share dealer is zero")
	}
	if receiver == 0 {
		return reshareSharePayload{}, errors.New("reshare share receiver is zero")
	}
	share := fields[2].Value
	if _, err := secp.ScalarFromBytes(share); err != nil {
		return reshareSharePayload{}, err
	}
	commitmentHash := fields[3].Value
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
	publicKey := fields[0].Value
	proof := fields[1].Value
	ringPedersenParams := fields[2].Value
	ringPedersenProof := fields[3].Value
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
	// Tags validated; access fields by index to avoid redundant linear scans.
	commitments, err := wire.DecodeBytesList(fields[0].Value)
	if err != nil {
		return refreshCommitmentsPayload{}, err
	}
	publicKey := fields[1].Value
	proof := fields[2].Value
	ringPedersenParams := fields[3].Value
	ringPedersenProof := fields[4].Value
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
	share := fields[0].Value
	if _, err := secp.ScalarFromBytes(share); err != nil {
		return refreshSharePayload{}, err
	}
	return refreshSharePayload{Share: share}, nil
}

// envelope creates a protocol envelope with the cggmp21-secp256k1 protocol id
// and current wire version.
func envelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType tss.PayloadType, payload []byte, confidential bool) (tss.Envelope, error) {
	e, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   config.SessionID,
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     payload,
	})
	if err != nil {
		return tss.Envelope{}, err
	}
	if confidential {
		e.Security.Confidential = true
	}
	return e, nil
}
