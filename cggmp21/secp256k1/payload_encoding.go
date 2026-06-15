package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
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

func marshalKeygenCommitmentsPayloadWithLimits(p keygenCommitmentsPayload, limits Limits) ([]byte, error) {
	if err := validateCommitmentPoints(p.Commitments); err != nil {
		return nil, err
	}
	if _, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, limits.Paillier.MaxModulusBits); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalModulusProof(p.PaillierProof); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, limits.Paillier.MaxModulusBits); err != nil {
		return nil, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof); err != nil {
		return nil, err
	}
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return nil, errors.New("chain code must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("keygen plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalKeygenCommitmentsPayloadWithLimits(in []byte, limits Limits) (keygenCommitmentsPayload, error) {
	var p keygenCommitmentsPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if err := validateCommitmentPoints(p.Commitments); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, limits.Paillier.MaxModulusBits); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalModulusProof(p.PaillierProof); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, limits.Paillier.MaxModulusBits); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof); err != nil {
		return keygenCommitmentsPayload{}, err
	}
	if len(p.ChainCodeCommit) != 0 && len(p.ChainCodeCommit) != 32 {
		return keygenCommitmentsPayload{}, errors.New("chain code must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return keygenCommitmentsPayload{}, errors.New("keygen plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalKeygenSharePayloadWithLimits(p keygenSharePayload, limits Limits) ([]byte, error) {
	if err := validateScalarRangeStrict(p.Share); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("keygen plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalKeygenSharePayloadWithLimits(in []byte, limits Limits) (keygenSharePayload, error) {
	var p keygenSharePayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return keygenSharePayload{}, err
	}
	if err := validateScalarRangeStrict(p.Share); err != nil {
		return keygenSharePayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return keygenSharePayload{}, errors.New("keygen plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalPresignRound1PayloadWithLimits(p presignRound1Payload, limits Limits) ([]byte, error) {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return nil, err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return nil, err
	}
	if _, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, limits.Paillier.MaxModulusBits); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("presign round1 plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalPresignRound1PayloadWithLimits(in []byte, limits Limits) (presignRound1Payload, error) {
	var p presignRound1Payload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return presignRound1Payload{}, err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return presignRound1Payload{}, err
	}
	if _, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, limits.Paillier.MaxModulusBits); err != nil {
		return presignRound1Payload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return presignRound1Payload{}, errors.New("presign round1 plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalPresignRound1ProofPayloadWithLimits(p presignRound1ProofPayload, limits Limits) ([]byte, error) {
	if len(p.PublicRound1Hash) != sha256.Size {
		return nil, errors.New("round1 public hash must be 32 bytes")
	}
	if _, err := zkpai.UnmarshalEncProof(p.EncKProof); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("presign round1 proof plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalPresignRound1ProofPayloadWithLimits(in []byte, limits Limits) (presignRound1ProofPayload, error) {
	var p presignRound1ProofPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return presignRound1ProofPayload{}, err
	}
	if len(p.PublicRound1Hash) != sha256.Size {
		return presignRound1ProofPayload{}, errors.New("round1 public hash must be 32 bytes")
	}
	if _, err := zkpai.UnmarshalEncProof(p.EncKProof); err != nil {
		return presignRound1ProofPayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return presignRound1ProofPayload{}, errors.New("presign round1 proof plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalPresignRound2PayloadWithLimits(p presignRound2Payload, limits Limits) ([]byte, error) {
	if len(p.Round1Echo) != sha256.Size {
		return nil, errors.New("round1 echo must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("presign round2 plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalPresignRound2PayloadWithLimits(in []byte, limits Limits) (presignRound2Payload, error) {
	var p presignRound2Payload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return presignRound2Payload{}, err
	}
	if len(p.Round1Echo) != sha256.Size {
		return presignRound2Payload{}, errors.New("round1 echo must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return presignRound2Payload{}, errors.New("presign round2 plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalPresignRound3PayloadWithLimits(p presignRound3Payload, limits Limits) ([]byte, error) {
	if err := validateScalarRangeStrict(p.Delta); err != nil {
		return nil, err
	}
	if _, err := secp.PointFromBytes(p.KPoint); err != nil {
		return nil, err
	}
	if _, err := secp.PointFromBytes(p.ChiPoint); err != nil {
		return nil, err
	}
	if len(p.Proof) == 0 {
		return nil, errors.New("empty signprep proof")
	}
	if len(p.Proof) > limits.SignPrep.MaxProofBytes {
		return nil, fmt.Errorf("signprep proof too large: %d > %d", len(p.Proof), limits.SignPrep.MaxProofBytes)
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("presign round3 plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalPresignRound3PayloadWithLimits(in []byte, limits Limits) (presignRound3Payload, error) {
	if len(in) > limits.SignPrep.MaxVerifyShareBytes*2 {
		return presignRound3Payload{}, fmt.Errorf("presign round3 payload too large: %d", len(in))
	}
	var p presignRound3Payload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return presignRound3Payload{}, err
	}
	if err := validateScalarRangeStrict(p.Delta); err != nil {
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
	if len(p.Proof) > limits.SignPrep.MaxProofBytes {
		return presignRound3Payload{}, fmt.Errorf("signprep proof too large: %d > %d", len(p.Proof), limits.SignPrep.MaxProofBytes)
	}
	if len(p.PlanHash) != sha256.Size {
		return presignRound3Payload{}, errors.New("presign round3 plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalSignPartialPayloadWithLimits(p signPartialPayload, limits Limits) ([]byte, error) {
	if err := validateScalarRangeAllowZero(p.S); err != nil {
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
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("sign partial plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalSignPartialPayloadWithLimits(in []byte, limits Limits) (signPartialPayload, error) {
	if len(in) > limits.SignPrep.MaxSignPartialPayloadBytes {
		return signPartialPayload{}, fmt.Errorf("sign partial payload too large: %d > %d", len(in), limits.SignPrep.MaxSignPartialPayloadBytes)
	}
	var p signPartialPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return signPartialPayload{}, err
	}
	if err := validateScalarRangeAllowZero(p.S); err != nil {
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
	if len(p.PlanHash) != sha256.Size {
		return signPartialPayload{}, errors.New("sign partial plan hash must be 32 bytes")
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

func marshalReshareDealerCommitmentsPayloadWithLimits(p reshareDealerCommitmentsPayload, limits Limits) ([]byte, error) {
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("reshare dealer commitments plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalReshareDealerCommitmentsPayloadWithLimits(in []byte, limits Limits) (reshareDealerCommitmentsPayload, error) {
	var p reshareDealerCommitmentsPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return reshareDealerCommitmentsPayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return reshareDealerCommitmentsPayload{}, errors.New("reshare dealer commitments plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalReshareSharePayloadWithLimits(p reshareSharePayload, limits Limits) ([]byte, error) {
	if p.Dealer == 0 {
		return nil, errors.New("reshare share dealer is zero")
	}
	if p.Receiver == 0 {
		return nil, errors.New("reshare share receiver is zero")
	}
	if err := validateScalarRangeStrict(p.Share); err != nil {
		return nil, err
	}
	if len(p.DealerCommitmentHash) != sha256.Size {
		return nil, errors.New("reshare share commitment hash must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("reshare share plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalReshareSharePayloadWithLimits(in []byte, limits Limits) (reshareSharePayload, error) {
	var p reshareSharePayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return reshareSharePayload{}, err
	}
	if p.Dealer == 0 {
		return reshareSharePayload{}, errors.New("reshare share dealer is zero")
	}
	if p.Receiver == 0 {
		return reshareSharePayload{}, errors.New("reshare share receiver is zero")
	}
	if err := validateScalarRangeStrict(p.Share); err != nil {
		return reshareSharePayload{}, err
	}
	if len(p.DealerCommitmentHash) != sha256.Size {
		return reshareSharePayload{}, errors.New("reshare share commitment hash must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return reshareSharePayload{}, errors.New("reshare share plan hash must be 32 bytes")
	}
	return p, nil
}

func marshalReshareReceiverMaterialPayloadWithLimits(p reshareReceiverMaterialPayload, limits Limits) ([]byte, error) {
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("reshare receiver material plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalReshareReceiverMaterialPayloadWithLimits(in []byte, limits Limits) (reshareReceiverMaterialPayload, error) {
	var p reshareReceiverMaterialPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, limits.Paillier.MaxModulusBits); err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof); err != nil {
		return reshareReceiverMaterialPayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return reshareReceiverMaterialPayload{}, errors.New("reshare receiver material plan hash must be 32 bytes")
	}
	return p, nil
}

type refreshCommitmentsPayload struct {
	Commitments        [][]byte `wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PaillierPublicKey  []byte   `wire:"2,bytes,max_bytes=paillier_public_key"`
	PaillierProof      []byte   `wire:"3,bytes,max_bytes=zk_proof"`
	RingPedersenParams []byte   `wire:"4,bytes,max_bytes=ring_pedersen_params"`
	RingPedersenProof  []byte   `wire:"5,bytes,max_bytes=paillier_proof"`
	PlanHash           []byte   `wire:"6,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for refreshCommitmentsPayload.
func (refreshCommitmentsPayload) WireType() string { return refreshCommitmentsPayloadWireType }

// WireVersion returns the wire format version for refreshCommitmentsPayload.
func (refreshCommitmentsPayload) WireVersion() uint16 { return tss.Version }

type refreshSharePayload struct {
	Share    *big.Int `wire:"1,bigpos,max_bytes=scalar"`
	PlanHash []byte   `wire:"2,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for refreshSharePayload.
func (refreshSharePayload) WireType() string { return refreshSharePayloadWireType }

// WireVersion returns the wire format version for refreshSharePayload.
func (refreshSharePayload) WireVersion() uint16 { return tss.Version }

func marshalRefreshCommitmentsPayloadWithLimits(p refreshCommitmentsPayload, limits Limits) ([]byte, error) {
	if err := validateRefreshCommitments(p.Commitments, len(p.Commitments)); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("refresh plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalRefreshCommitmentsPayloadWithLimits(in []byte, limits Limits) (refreshCommitmentsPayload, error) {
	var p refreshCommitmentsPayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return refreshCommitmentsPayload{}, err
	}
	if len(p.Commitments) == 0 {
		return refreshCommitmentsPayload{}, errors.New("empty refresh commitments")
	}
	if len(p.PlanHash) != sha256.Size {
		return refreshCommitmentsPayload{}, errors.New("refresh plan hash must be 32 bytes")
	}
	if _, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, limits.Paillier.MaxModulusBits); err != nil {
		return refreshCommitmentsPayload{}, err
	}
	if _, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof); err != nil {
		return refreshCommitmentsPayload{}, err
	}
	return p, nil
}

func marshalRefreshSharePayloadWithLimits(p refreshSharePayload, limits Limits) ([]byte, error) {
	if err := validateScalarRangeStrict(p.Share); err != nil {
		return nil, err
	}
	if len(p.PlanHash) != sha256.Size {
		return nil, errors.New("refresh plan hash must be 32 bytes")
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalRefreshSharePayloadWithLimits(in []byte, limits Limits) (refreshSharePayload, error) {
	var p refreshSharePayload
	if err := wire.Unmarshal(in, &p, wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return refreshSharePayload{}, err
	}
	if err := validateScalarRangeStrict(p.Share); err != nil {
		return refreshSharePayload{}, err
	}
	if len(p.PlanHash) != sha256.Size {
		return refreshSharePayload{}, errors.New("refresh plan hash must be 32 bytes")
	}
	return p, nil
}

// envelope creates a protocol envelope with the cggmp21-secp256k1 protocol id
// and current wire version.
func envelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType tss.PayloadType, payload []byte) (tss.Envelope, error) {
	return tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   config.SessionID,
		Round:       round,
		From:        from,
		To:          to,
		PayloadType: payloadType,
		Payload:     payload,
	})
}
