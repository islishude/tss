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
	keygenCommitmentsPayloadWireType     = "cggmp21.secp256k1.payload.keygen.commitments"
	keygenSharePayloadWireType           = "cggmp21.secp256k1.payload.keygen.share"
	presignRound1PayloadWireType         = "cggmp21.secp256k1.payload.presign.round1"
	presignRound1ProofPayloadWireType    = "cggmp21.secp256k1.payload.presign.round1-proof"
	presignRound2PayloadWireType         = "cggmp21.secp256k1.payload.presign.round2"
	presignRound3PayloadWireType         = "cggmp21.secp256k1.payload.presign.round3"
	presignIdentificationPayloadWireType = "cggmp21.secp256k1.payload.presign.identification"
	signIdentificationPayloadWireType    = "cggmp21.secp256k1.payload.sign.identification"
	signPartialPayloadWireType           = "cggmp21.secp256k1.payload.sign.partial"
	reshareDealerCommitmentsWireType     = "cggmp21.secp256k1.payload.reshare.dealer_commitments"
	reshareSharePayloadWireType          = "cggmp21.secp256k1.payload.reshare.share"
	reshareReceiverMaterialWireType      = "cggmp21.secp256k1.payload.reshare.receiver_material"
	refreshCommitmentsPayloadWireType    = "cggmp21.secp256k1.payload.refresh.commitments"
	refreshSharePayloadWireType          = "cggmp21.secp256k1.payload.refresh.share"
)

const (
	keygenCommitmentsPayloadWireVersion     uint16 = 1
	keygenSharePayloadWireVersion           uint16 = 1
	presignRound1PayloadWireVersion         uint16 = 1
	presignRound1ProofPayloadWireVersion    uint16 = 1
	presignRound2PayloadWireVersion         uint16 = 1
	presignRound3PayloadWireVersion         uint16 = 1
	presignIdentificationPayloadWireVersion uint16 = 1
	signIdentificationPayloadWireVersion    uint16 = 1
	signPartialPayloadWireVersion           uint16 = 1
	reshareDealerCommitmentsWireVersion     uint16 = 1
	reshareSharePayloadWireVersion          uint16 = 1
	reshareReceiverMaterialWireVersion      uint16 = 1
	refreshCommitmentsPayloadWireVersion    uint16 = 1
	refreshSharePayloadWireVersion          uint16 = 1
)

type payloadValidatorWithLimits interface {
	ValidateWithLimits(Limits) error
}

func marshalPayloadWithLimits[T any](p T, limits Limits) ([]byte, error) {
	if err := validatePayloadWithLimits(p, limits); err != nil {
		return nil, err
	}
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalPayloadWithLimits[T any](dst *T, in []byte, limits Limits) error {
	var decoded T
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.Payload.MaxMessageBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := validatePayloadWithLimits(decoded, limits); err != nil {
		return err
	}
	*dst = decoded
	return nil
}

func validatePayloadWithLimits[T any](p T, limits Limits) error {
	if v, ok := any(p).(payloadValidatorWithLimits); ok {
		return v.ValidateWithLimits(limits)
	}
	if v, ok := any(&p).(payloadValidatorWithLimits); ok {
		return v.ValidateWithLimits(limits)
	}
	return nil
}

func validatePaillierPublicKeyWithLimits(pk *pai.PublicKey, limits Limits) error {
	if pk == nil {
		return errors.New("nil Paillier public key")
	}
	if pk.N != nil && pk.N.BitLen() > limits.Paillier.MaxModulusBits {
		return fmt.Errorf("paillier modulus too large: %d > %d", pk.N.BitLen(), limits.Paillier.MaxModulusBits)
	}
	return pk.Validate()
}

func validateRingPedersenParamsWithLimits(params *zkpai.RingPedersenParams, limits Limits) error {
	if params == nil {
		return errors.New("nil Ring-Pedersen parameters")
	}
	if params.N != nil && params.N.BitLen() > limits.Paillier.MaxModulusBits {
		return fmt.Errorf("ring-pedersen modulus too large: %d > %d", params.N.BitLen(), limits.Paillier.MaxModulusBits)
	}
	return zkpai.ValidateRingPedersenParams(params)
}

// MarshalBinary encodes the keygen commitments payload.
func (p keygenCommitmentsPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the keygen commitments payload with limits.
func (p keygenCommitmentsPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the keygen commitments payload.
func (p *keygenCommitmentsPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the keygen commitments payload with limits.
func (p *keygenCommitmentsPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the keygen commitments payload structure.
func (p keygenCommitmentsPayload) Validate() error {
	if err := validateCommitmentPoints(p.Commitments); err != nil {
		return err
	}
	if p.PaillierPublicKey == nil {
		return errors.New("nil Paillier public key")
	}
	if p.PaillierProof == nil {
		return errors.New("nil Paillier proof")
	}
	if err := p.PaillierProof.Validate(); err != nil {
		return err
	}
	if p.RingPedersenParams == nil {
		return errors.New("nil Ring-Pedersen parameters")
	}
	if p.RingPedersenProof == nil {
		return errors.New("nil Ring-Pedersen proof")
	}
	if err := p.RingPedersenProof.Validate(); err != nil {
		return err
	}
	if len(p.ChainCodeCommit) != sha256.Size {
		return errors.New("chain code must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("keygen plan hash must be 32 bytes")
	}
	return nil
}

// ValidateWithLimits checks the keygen commitments payload with resource limits.
func (p keygenCommitmentsPayload) ValidateWithLimits(limits Limits) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := validatePaillierPublicKeyWithLimits(p.PaillierPublicKey, limits); err != nil {
		return err
	}
	if err := validateRingPedersenParamsWithLimits(p.RingPedersenParams, limits); err != nil {
		return err
	}
	return nil
}

// MarshalBinary encodes the keygen share payload.
func (p keygenSharePayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the keygen share payload with limits.
func (p keygenSharePayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the keygen share payload.
func (p *keygenSharePayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the keygen share payload with limits.
func (p *keygenSharePayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the keygen share payload structure.
func (p keygenSharePayload) Validate() error {
	if err := validatePositiveIntegerBytes(p.Ciphertext); err != nil {
		return err
	}
	if err := p.Proof.Validate(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("keygen plan hash must be 32 bytes")
	}
	return nil
}

// MarshalBinary encodes the presign round-one payload.
func (p presignRound1Payload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the presign round-one payload with limits.
func (p presignRound1Payload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the presign round-one payload.
func (p *presignRound1Payload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the presign round-one payload with limits.
func (p *presignRound1Payload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the presign round-one payload structure.
func (p presignRound1Payload) Validate() error {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return err
	}
	if _, err := secp.PointFromBytes(p.KPoint); err != nil {
		return err
	}
	if err := validatePositiveIntegerBytes(p.EncK); err != nil {
		return err
	}
	if err := validatePositiveIntegerBytes(p.EncGamma); err != nil {
		return err
	}
	if p.PaillierPublicKey == nil {
		return errors.New("nil Paillier public key")
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("presign round1 plan hash must be 32 bytes")
	}
	return nil
}

// ValidateWithLimits checks the presign round-one payload with resource limits.
func (p presignRound1Payload) ValidateWithLimits(limits Limits) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return validatePaillierPublicKeyWithLimits(p.PaillierPublicKey, limits)
}

// MarshalBinary encodes the presign round-one proof payload.
func (p presignRound1ProofPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the presign round-one proof payload with limits.
func (p presignRound1ProofPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the presign round-one proof payload.
func (p *presignRound1ProofPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the presign round-one proof payload with limits.
func (p *presignRound1ProofPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the presign round-one proof payload structure.
func (p presignRound1ProofPayload) Validate() error {
	if len(p.PublicRound1Hash) != sha256.Size {
		return errors.New("round1 public hash must be 32 bytes")
	}
	if err := p.EncKProof.Validate(); err != nil {
		return err
	}
	if err := p.EncGammaProof.Validate(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("presign round1 proof plan hash must be 32 bytes")
	}
	return nil
}

// MarshalBinary encodes the presign round-two payload.
func (p presignRound2Payload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the presign round-two payload with limits.
func (p presignRound2Payload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the presign round-two payload.
func (p *presignRound2Payload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the presign round-two payload with limits.
func (p *presignRound2Payload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the presign round-two payload structure.
func (p presignRound2Payload) Validate() error {
	if len(p.Round1Echo) != sha256.Size {
		return errors.New("round1 echo must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("presign round2 plan hash must be 32 bytes")
	}
	return nil
}

// MarshalBinary encodes the presign round-three payload.
func (p presignRound3Payload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the presign round-three payload with limits.
func (p presignRound3Payload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the presign round-three payload.
func (p *presignRound3Payload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the presign round-three payload with limits.
func (p *presignRound3Payload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if len(in) > limits.SignPrep.MaxVerifyShareBytes*2 {
		return fmt.Errorf("presign round3 payload too large: %d", len(in))
	}
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the presign round-three payload structure.
func (p presignRound3Payload) Validate() error {
	if err := validateSecretScalarStrict(p.Delta); err != nil {
		return err
	}
	if _, err := secp.PointBytes(p.KPoint); err != nil {
		return fmt.Errorf("invalid KPoint: %w", err)
	}
	if _, err := secp.PointBytes(p.ChiPoint); err != nil {
		return fmt.Errorf("invalid ChiPoint: %w", err)
	}
	if err := p.Proof.Validate(); err != nil {
		return fmt.Errorf("invalid signprep proof: %w", err)
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("presign round3 plan hash must be 32 bytes")
	}
	var previous tss.PartyID
	for i, commitment := range p.Round2Commitments {
		if commitment.Recipient == 0 {
			return errors.New("presign round3 commitment recipient must be non-zero")
		}
		if i > 0 && commitment.Recipient <= previous {
			return errors.New("presign round3 commitments must be strictly sorted")
		}
		if len(commitment.Hash) != sha256.Size {
			return errors.New("presign round3 commitment hash must be 32 bytes")
		}
		previous = commitment.Recipient
	}
	previous = 0
	for i := range p.MTAContributions {
		contribution := &p.MTAContributions[i]
		if contribution.Peer == 0 {
			return errors.New("presign MTA contribution peer must be non-zero")
		}
		if i > 0 && contribution.Peer <= previous {
			return errors.New("presign MTA contributions must be strictly sorted")
		}
		if err := contribution.Inbound.Validate(); err != nil {
			return fmt.Errorf("invalid inbound sigma contribution: %w", err)
		}
		if err := contribution.Outbound.Validate(); err != nil {
			return fmt.Errorf("invalid outbound sigma contribution: %w", err)
		}
		if err := contribution.InboundDelta.Validate(); err != nil {
			return fmt.Errorf("invalid inbound delta contribution: %w", err)
		}
		if err := contribution.OutboundDelta.Validate(); err != nil {
			return fmt.Errorf("invalid outbound delta contribution: %w", err)
		}
		if len(contribution.InboundEnvelope) == 0 || len(contribution.OutboundEnvelope) == 0 {
			return errors.New("presign MTA contribution is missing signed round2 envelopes")
		}
		previous = contribution.Peer
	}
	return nil
}

// ValidateWithLimits checks the presign round-three payload with resource limits.
func (p presignRound3Payload) ValidateWithLimits(limits Limits) error {
	if err := p.Validate(); err != nil {
		return err
	}
	proofBytes, err := p.Proof.MarshalBinary()
	if err != nil {
		return err
	}
	if len(proofBytes) > limits.SignPrep.MaxProofBytes {
		return fmt.Errorf("signprep proof too large: %d > %d", len(proofBytes), limits.SignPrep.MaxProofBytes)
	}
	return nil
}

// MarshalBinary encodes the sign partial payload.
func (p signPartialPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the sign partial payload with limits.
func (p signPartialPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the sign partial payload.
func (p *signPartialPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the sign partial payload with limits.
func (p *signPartialPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if len(in) > limits.SignPrep.MaxSignPartialPayloadBytes {
		return fmt.Errorf("sign partial payload too large: %d > %d", len(in), limits.SignPrep.MaxSignPartialPayloadBytes)
	}
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the sign partial payload structure.
func (p signPartialPayload) Validate() error {
	if err := validateSecretScalarAllowZero(p.S); err != nil {
		return err
	}
	if len(p.PresignTranscript) != sha256.Size {
		return errors.New("presign transcript must be 32 bytes")
	}
	if len(p.PresignContext) != sha256.Size {
		return errors.New("presign context must be 32 bytes")
	}
	if len(p.DigestHash) != sha256.Size {
		return errors.New("digest hash must be 32 bytes")
	}
	if len(p.PartialEquationHash) != sha256.Size {
		return errors.New("partial equation hash must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("sign partial plan hash must be 32 bytes")
	}
	return nil
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

// MarshalBinary encodes the reshare dealer commitments payload.
func (p reshareDealerCommitmentsPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the reshare dealer commitments payload with limits.
func (p reshareDealerCommitmentsPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the reshare dealer commitments payload.
func (p *reshareDealerCommitmentsPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the reshare dealer commitments payload with limits.
func (p *reshareDealerCommitmentsPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the reshare dealer commitments payload structure.
func (p reshareDealerCommitmentsPayload) Validate() error {
	if err := validateCommitmentPoints(p.Commitments); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("reshare dealer commitments plan hash must be 32 bytes")
	}
	return nil
}

// MarshalBinary encodes the reshare share payload.
func (p reshareSharePayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the reshare share payload with limits.
func (p reshareSharePayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the reshare share payload.
func (p *reshareSharePayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the reshare share payload with limits.
func (p *reshareSharePayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the reshare share payload structure.
func (p reshareSharePayload) Validate() error {
	if p.Dealer == 0 {
		return errors.New("reshare share dealer is zero")
	}
	if p.Receiver == 0 {
		return errors.New("reshare share receiver is zero")
	}
	if len(p.Ciphertext) == 0 {
		return errors.New("reshare share ciphertext is empty")
	}
	if err := p.Proof.Validate(); err != nil {
		return fmt.Errorf("invalid reshare share proof: %w", err)
	}
	if len(p.DealerCommitmentHash) != sha256.Size {
		return errors.New("reshare share commitment hash must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("reshare share plan hash must be 32 bytes")
	}
	return nil
}

// MarshalBinary encodes the reshare receiver material payload.
func (p reshareReceiverMaterialPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the reshare receiver material payload with limits.
func (p reshareReceiverMaterialPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the reshare receiver material payload.
func (p *reshareReceiverMaterialPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the reshare receiver material payload with limits.
func (p *reshareReceiverMaterialPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the reshare receiver material payload structure.
func (p reshareReceiverMaterialPayload) Validate() error {
	if err := p.PaillierProof.Validate(); err != nil {
		return err
	}
	if err := p.RingPedersenProof.Validate(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("reshare receiver material plan hash must be 32 bytes")
	}
	return nil
}

// ValidateWithLimits checks the reshare receiver material payload with resource limits.
func (p reshareReceiverMaterialPayload) ValidateWithLimits(limits Limits) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := validatePaillierPublicKeyWithLimits(&p.PaillierPublicKey, limits); err != nil {
		return err
	}
	if err := validateRingPedersenParamsWithLimits(&p.RingPedersenParams, limits); err != nil {
		return err
	}
	return nil
}

type refreshCommitmentsPayload struct {
	Commitments        [][]byte                  `wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	PaillierPublicKey  *pai.PublicKey            `wire:"2,nested,max_bytes=paillier_public_key"`
	PaillierProof      *zkpai.ModulusProof       `wire:"3,nested,max_bytes=zk_proof"`
	RingPedersenParams *zkpai.RingPedersenParams `wire:"4,nested,max_bytes=ring_pedersen_params"`
	RingPedersenProof  *zkpai.RingPedersenProof  `wire:"5,nested,max_bytes=paillier_proof"`
	PlanHash           []byte                    `wire:"6,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for refreshCommitmentsPayload.
func (refreshCommitmentsPayload) WireType() string { return refreshCommitmentsPayloadWireType }

// WireVersion returns the wire format version for refreshCommitmentsPayload.
func (refreshCommitmentsPayload) WireVersion() uint16 {
	return refreshCommitmentsPayloadWireVersion
}

type refreshSharePayload struct {
	Ciphertext []byte             `wire:"1,bytes,max_bytes=paillier_ciphertext"`
	Proof      zkpai.LogStarProof `wire:"2,nested,max_bytes=zk_proof"`
	PlanHash   []byte             `wire:"3,bytes,len=32"`
}

// WireType returns the canonical wire type identifier for refreshSharePayload.
func (refreshSharePayload) WireType() string { return refreshSharePayloadWireType }

// WireVersion returns the wire format version for refreshSharePayload.
func (refreshSharePayload) WireVersion() uint16 { return refreshSharePayloadWireVersion }

// MarshalBinary encodes the refresh commitments payload.
func (p refreshCommitmentsPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the refresh commitments payload with limits.
func (p refreshCommitmentsPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the refresh commitments payload.
func (p *refreshCommitmentsPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the refresh commitments payload with limits.
func (p *refreshCommitmentsPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the refresh commitments payload structure.
func (p refreshCommitmentsPayload) Validate() error {
	if err := validateRefreshCommitments(p.Commitments, len(p.Commitments)); err != nil {
		return err
	}
	if p.PaillierPublicKey == nil {
		return errors.New("nil Paillier public key")
	}
	if p.PaillierProof == nil {
		return errors.New("nil Paillier proof")
	}
	if err := p.PaillierProof.Validate(); err != nil {
		return err
	}
	if p.RingPedersenParams == nil {
		return errors.New("nil Ring-Pedersen parameters")
	}
	if p.RingPedersenProof == nil {
		return errors.New("nil Ring-Pedersen proof")
	}
	if err := p.RingPedersenProof.Validate(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("refresh plan hash must be 32 bytes")
	}
	return nil
}

// ValidateWithLimits checks the refresh commitments payload with resource limits.
func (p refreshCommitmentsPayload) ValidateWithLimits(limits Limits) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := validatePaillierPublicKeyWithLimits(p.PaillierPublicKey, limits); err != nil {
		return err
	}
	if err := validateRingPedersenParamsWithLimits(p.RingPedersenParams, limits); err != nil {
		return err
	}
	return nil
}

// MarshalBinary encodes the refresh share payload.
func (p refreshSharePayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the refresh share payload with limits.
func (p refreshSharePayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the refresh share payload.
func (p *refreshSharePayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the refresh share payload with limits.
func (p *refreshSharePayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the refresh share payload structure.
func (p refreshSharePayload) Validate() error {
	if err := validatePositiveIntegerBytes(p.Ciphertext); err != nil {
		return err
	}
	if err := p.Proof.Validate(); err != nil {
		return err
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("refresh plan hash must be 32 bytes")
	}
	return nil
}

// newEnvelope creates a protocol envelope with the cggmp21-secp256k1 protocol ID.
func newEnvelope(config tss.ThresholdConfig, round uint8, from, to tss.PartyID, payloadType tss.PayloadType, payload []byte) (tss.Envelope, error) {
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
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
	if config.EnvelopeSigner == nil {
		return env, nil
	}
	return tss.SignEnvelope(env, config.EnvelopeSigner)
}

func requireLocalEnvelopeSigner(guard *tss.EnvelopeGuard, signer tss.EnvelopeSigner) error {
	if guard != nil && guard.RequiresSenderSignatures() && signer == nil {
		return tss.ErrMissingEnvelopeSigner
	}
	return nil
}
