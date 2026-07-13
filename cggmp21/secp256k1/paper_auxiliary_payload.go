package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const (
	auxInfoCommitmentPayloadWireType             = "cggmp21.secp256k1.payload.auxinfo.commitment"
	auxInfoRevealPayloadWireType                 = "cggmp21.secp256k1.payload.auxinfo.reveal"
	auxInfoProofsPayloadWireType                 = "cggmp21.secp256k1.payload.auxinfo.proofs"
	auxInfoDirectPayloadWireType                 = "cggmp21.secp256k1.payload.auxinfo.direct"
	auxInfoDecryptionErrorPayloadWireType        = "cggmp21.secp256k1.payload.auxinfo.decryption-error"
	auxInfoPayloadWireVersion             uint16 = 1
)

type auxInfoCommitmentPayload struct {
	Commitment []byte `wire:"1,bytes,len=32"`
	PlanHash   []byte `wire:"2,bytes,len=32"`
}

// WireType returns the Figure 7 commitment wire type.
func (auxInfoCommitmentPayload) WireType() string { return auxInfoCommitmentPayloadWireType }

// WireVersion returns the Figure 7 commitment wire version.
func (auxInfoCommitmentPayload) WireVersion() uint16 { return auxInfoPayloadWireVersion }

// MarshalBinary encodes a Figure 7 commitment payload.
func (p auxInfoCommitmentPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 7 commitment payload with limits.
func (p auxInfoCommitmentPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 7 commitment payload.
func (p *auxInfoCommitmentPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 7 commitment payload with limits.
func (p *auxInfoCommitmentPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 7 commitment payload.
func (p auxInfoCommitmentPayload) Validate() error {
	if len(p.Commitment) != sha256.Size {
		return errors.New("auxinfo commitment must be 32 bytes")
	}
	if len(p.PlanHash) != sha256.Size {
		return errors.New("auxinfo commitment plan hash must be 32 bytes")
	}
	return nil
}

type auxInfoRevealPayload struct {
	PolynomialCommitments [][]byte                  `wire:"1,byteslist,max_bytes=point,max_items=threshold"`
	DHKeys                []auxInfoDHKey            `wire:"2,recordlist,max_items=parties"`
	SchnorrCommitments    [][]byte                  `wire:"3,byteslist,max_bytes=point,max_items=threshold"`
	ModulusCommitment     []byte                    `wire:"4,bytes,max_bytes=paillier_modulus"`
	PaillierPublicKey     *pai.PublicKey            `wire:"5,nested,max_bytes=paillier_public_key"`
	RingPedersenParams    *zkpai.RingPedersenParams `wire:"6,nested,max_bytes=ring_pedersen_params"`
	RingPedersenProof     *zkpai.RingPedersenProof  `wire:"7,nested,max_bytes=paillier_proof"`
	RIDContribution       []byte                    `wire:"8,bytes,len=32"`
	Decommitment          []byte                    `wire:"9,bytes,len=32"`
	PlanHash              []byte                    `wire:"10,bytes,len=32"`
}

// WireType returns the Figure 7 reveal wire type.
func (auxInfoRevealPayload) WireType() string { return auxInfoRevealPayloadWireType }

// WireVersion returns the Figure 7 reveal wire version.
func (auxInfoRevealPayload) WireVersion() uint16 { return auxInfoPayloadWireVersion }

// MarshalBinary encodes a Figure 7 reveal payload.
func (p auxInfoRevealPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 7 reveal payload with limits.
func (p auxInfoRevealPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 7 reveal payload.
func (p *auxInfoRevealPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 7 reveal payload with limits.
func (p *auxInfoRevealPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 7 reveal payload.
func (p auxInfoRevealPayload) Validate() error { return p.ValidateWithLimits(DefaultLimits()) }

// ValidateWithLimits checks a Figure 7 reveal payload with limits.
func (p auxInfoRevealPayload) ValidateWithLimits(limits Limits) error {
	if len(p.PolynomialCommitments) == 0 || len(p.PolynomialCommitments) != len(p.SchnorrCommitments) {
		return errors.New("auxinfo polynomial and Schnorr commitment vectors must be non-empty and equal length")
	}
	if len(p.PolynomialCommitments) > limits.Threshold.MaxThreshold {
		return errors.New("auxinfo polynomial commitment vector exceeds threshold limit")
	}
	for i, commitment := range p.PolynomialCommitments {
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid auxinfo polynomial commitment %d: %w", i, err)
		}
		if _, err := secp.PointFromBytes(p.SchnorrCommitments[i]); err != nil {
			return fmt.Errorf("invalid auxinfo Schnorr commitment %d: %w", i, err)
		}
	}
	if len(p.DHKeys) > limits.Threshold.MaxParties-1 {
		return errors.New("auxinfo DH key vector exceeds party limit")
	}
	last := tss.PartyID(0)
	for i, key := range p.DHKeys {
		if key.Party == tss.BroadcastPartyId || (i > 0 && key.Party <= last) {
			return errors.New("auxinfo DH keys must use non-zero strictly increasing parties")
		}
		if _, err := secp.PointFromBytes(key.PublicKey); err != nil {
			return fmt.Errorf("invalid auxinfo DH key for party %d: %w", key.Party, err)
		}
		last = key.Party
	}
	if len(p.ModulusCommitment) == 0 {
		return errors.New("empty auxinfo modulus commitment")
	}
	if err := validatePaillierPublicKeyWithLimits(p.PaillierPublicKey, limits); err != nil {
		return err
	}
	if err := validateRingPedersenParamsWithLimits(p.RingPedersenParams, limits); err != nil {
		return err
	}
	if p.PaillierPublicKey.N.Cmp(p.RingPedersenParams.N) == 0 {
		return errors.New("auxinfo Paillier and Ring-Pedersen moduli must differ")
	}
	if p.RingPedersenProof == nil {
		return errors.New("nil auxinfo Ring-Pedersen proof")
	}
	if err := p.RingPedersenProof.Validate(); err != nil {
		return err
	}
	if len(p.RIDContribution) != sha256.Size || len(p.Decommitment) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid auxinfo reveal fixed-width field")
	}
	return nil
}

type auxInfoSchnorrProof struct {
	Commitment []byte `wire:"1,bytes,max_bytes=point"`
	Response   []byte `wire:"2,bytes,max_bytes=scalar"`
}

func auxInfoSchnorrProofFrom(proof *schnorr.Proof) auxInfoSchnorrProof {
	if proof == nil {
		return auxInfoSchnorrProof{}
	}
	return auxInfoSchnorrProof{Commitment: append([]byte(nil), proof.Commitment...), Response: append([]byte(nil), proof.Response...)}
}

func (p auxInfoSchnorrProof) proof() *schnorr.Proof {
	return &schnorr.Proof{Commitment: append([]byte(nil), p.Commitment...), Response: append([]byte(nil), p.Response...)}
}

func (p auxInfoSchnorrProof) validate() error { return p.proof().Validate() }

type auxInfoProofsPayload struct {
	Proofs   []auxInfoSchnorrProof `wire:"1,recordlist,max_items=threshold"`
	RID      tss.SessionID         `wire:"2,bytes,len=32"`
	EpochID  []byte                `wire:"3,bytes,len=32"`
	PlanHash []byte                `wire:"4,bytes,len=32"`
}

// WireType returns the Figure 7 Schnorr-proofs wire type.
func (auxInfoProofsPayload) WireType() string { return auxInfoProofsPayloadWireType }

// WireVersion returns the Figure 7 Schnorr-proofs wire version.
func (auxInfoProofsPayload) WireVersion() uint16 { return auxInfoPayloadWireVersion }

// MarshalBinary encodes a Figure 7 Schnorr-proofs payload.
func (p auxInfoProofsPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 7 Schnorr-proofs payload with limits.
func (p auxInfoProofsPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 7 Schnorr-proofs payload.
func (p *auxInfoProofsPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 7 Schnorr-proofs payload with limits.
func (p *auxInfoProofsPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 7 Schnorr-proofs payload.
func (p auxInfoProofsPayload) Validate() error { return p.ValidateWithLimits(DefaultLimits()) }

// ValidateWithLimits checks a Figure 7 Schnorr-proofs payload with limits.
func (p auxInfoProofsPayload) ValidateWithLimits(limits Limits) error {
	if len(p.Proofs) == 0 || len(p.Proofs) > limits.Threshold.MaxThreshold {
		return errors.New("invalid auxinfo Schnorr proof count")
	}
	for i, proof := range p.Proofs {
		if err := proof.validate(); err != nil {
			return fmt.Errorf("invalid auxinfo Schnorr proof %d: %w", i, err)
		}
	}
	if !p.RID.Valid() || len(p.EpochID) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid auxinfo proof binding")
	}
	return nil
}

type auxInfoDirectPayload struct {
	ModulusProof *zkpai.ModulusProof `wire:"1,nested,max_bytes=paillier_proof"`
	FactorProof  *zkpai.FactorProof  `wire:"2,nested,max_bytes=zk_proof"`
	MaskedShare  []byte              `wire:"3,bytes,len=32"`
	RID          tss.SessionID       `wire:"4,bytes,len=32"`
	EpochID      []byte              `wire:"5,bytes,len=32"`
	PlanHash     []byte              `wire:"6,bytes,len=32"`
}

// WireType returns the Figure 7 direct-message wire type.
func (auxInfoDirectPayload) WireType() string { return auxInfoDirectPayloadWireType }

// WireVersion returns the Figure 7 direct-message wire version.
func (auxInfoDirectPayload) WireVersion() uint16 { return auxInfoPayloadWireVersion }

// MarshalBinary encodes a Figure 7 direct-message payload.
func (p auxInfoDirectPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes a Figure 7 direct-message payload with limits.
func (p auxInfoDirectPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a Figure 7 direct-message payload.
func (p *auxInfoDirectPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a Figure 7 direct-message payload with limits.
func (p *auxInfoDirectPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks a Figure 7 direct-message payload.
func (p auxInfoDirectPayload) Validate() error {
	if p.ModulusProof == nil || p.FactorProof == nil {
		return errors.New("nil auxinfo direct proof")
	}
	if err := p.ModulusProof.Validate(); err != nil {
		return err
	}
	if err := p.FactorProof.Validate(); err != nil {
		return err
	}
	if len(p.MaskedShare) != secp.ScalarSize {
		return errors.New("auxinfo masked share must be 32 bytes")
	}
	if _, err := secp.ScalarFromBytesAllowZero(p.MaskedShare); err != nil {
		return fmt.Errorf("invalid auxinfo masked share: %w", err)
	}
	if !p.RID.Valid() || len(p.EpochID) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid auxinfo direct binding")
	}
	return nil
}

// auxInfoDecryptionErrorPayload is the only Figure 7 wire record allowed to
// reveal an ephemeral DH exponent. The witness is broadcast solely to verify a
// decryption-error accusation and must never be copied into generic evidence,
// logs, errors, snapshots, or long-lived session state.
type auxInfoDecryptionErrorPayload struct {
	Accused              tss.PartyID   `wire:"1,u32"`
	DHExponent           []byte        `wire:"2,bytes,len=32"`
	SignedDirectEnvelope []byte        `wire:"3,bytes,max_bytes=envelope"`
	SID                  tss.SessionID `wire:"4,bytes,len=32"`
	RID                  tss.SessionID `wire:"5,bytes,len=32"`
	EpochID              []byte        `wire:"6,bytes,len=32"`
	PlanHash             []byte        `wire:"7,bytes,len=32"`
}

// WireType returns the canonical Figure 7 decryption-error wire type.
func (auxInfoDecryptionErrorPayload) WireType() string {
	return auxInfoDecryptionErrorPayloadWireType
}

// WireVersion returns the canonical Figure 7 decryption-error wire version.
func (auxInfoDecryptionErrorPayload) WireVersion() uint16 { return auxInfoPayloadWireVersion }

// MarshalBinary encodes the dedicated Figure 7 decryption-error witness.
func (p auxInfoDecryptionErrorPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the dedicated Figure 7 decryption-error witness with limits.
func (p auxInfoDecryptionErrorPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes the dedicated Figure 7 decryption-error witness.
func (p *auxInfoDecryptionErrorPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the dedicated Figure 7 decryption-error witness with limits.
func (p *auxInfoDecryptionErrorPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the dedicated Figure 7 decryption-error witness structure.
func (p auxInfoDecryptionErrorPayload) Validate() error {
	return p.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks the witness structure and canonical embedded envelope.
func (p auxInfoDecryptionErrorPayload) ValidateWithLimits(limits Limits) error {
	if p.Accused == tss.BroadcastPartyId {
		return errors.New("auxinfo decryption-error accusation has no accused party")
	}
	if _, err := secp.ScalarFromBytes(p.DHExponent); err != nil {
		return errors.New("invalid auxinfo decryption-error DH exponent")
	}
	if !p.SID.Valid() || !p.RID.Valid() || len(p.EpochID) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid auxinfo decryption-error binding")
	}
	if len(p.SignedDirectEnvelope) == 0 || len(p.SignedDirectEnvelope) > limits.Payload.MaxMessageBytes {
		return errors.New("invalid auxinfo decryption-error signed envelope size")
	}
	envelopeLimits := tss.DefaultEnvelopeLimits()
	direct, err := tss.UnmarshalEnvelopeWithLimits(p.SignedDirectEnvelope, envelopeLimits)
	if err != nil {
		return errors.New("invalid auxinfo decryption-error signed envelope")
	}
	canonical, err := direct.MarshalBinaryWithLimits(envelopeLimits)
	if err != nil {
		return errors.New("invalid auxinfo decryption-error signed envelope")
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, p.SignedDirectEnvelope) || len(direct.SenderSignature) == 0 {
		return errors.New("non-canonical or unsigned auxinfo decryption-error direct envelope")
	}
	return nil
}

func (p *auxInfoDecryptionErrorPayload) destroy() {
	if p == nil {
		return
	}
	clear(p.DHExponent)
	clear(p.SignedDirectEnvelope)
	clear(p.SID[:])
	clear(p.RID[:])
	clear(p.EpochID)
	clear(p.PlanHash)
}

func figure7Commitment(stableSID, runSessionID tss.SessionID, sender tss.PartyID, reveal auxInfoRevealPayload, limits Limits) ([]byte, error) {
	if !stableSID.Valid() || !runSessionID.Valid() || sender == tss.BroadcastPartyId {
		return nil, errors.New("invalid auxinfo reveal identity")
	}
	if err := reveal.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	paillierKey, err := reveal.PaillierPublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ringParams, err := reveal.RingPedersenParams.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ringProof, err := reveal.RingPedersenProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	t := transcript.New(figure7CommitmentLabel)
	t.AppendBytes("stable_sid", stableSID[:])
	t.AppendBytes("run_session_id", runSessionID[:])
	t.AppendUint32("sender", sender)
	t.AppendBytesList("polynomial_commitments", reveal.PolynomialCommitments)
	for _, key := range reveal.DHKeys {
		t.AppendUint32("dh_recipient", key.Party)
		t.AppendBytes("dh_public_key", key.PublicKey)
	}
	t.AppendBytesList("schnorr_commitments", reveal.SchnorrCommitments)
	t.AppendBytes("modulus_commitment", reveal.ModulusCommitment)
	t.AppendBytes("paillier_public_key", paillierKey)
	t.AppendBytes("ring_pedersen_params", ringParams)
	t.AppendBytes("ring_pedersen_proof", ringProof)
	t.AppendBytes("rid_contribution", reveal.RIDContribution)
	t.AppendBytes("decommitment", reveal.Decommitment)
	t.AppendBytes("plan_hash", reveal.PlanHash)
	return t.Sum(), nil
}
