package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	proofDomainVersion = "cggmp21-secp256k1-proof-domain-v1"

	// Domain labels identify the protocol phase for domain separation.
	domainLabelKeygenModulus         = "keygen.modulus"
	domainLabelKeySharePaillier      = "keyshare.paillier-modulus"
	domainLabelResharePaillier       = "reshare.paillier-modulus"
	domainLabelReshareRingPedersen   = "reshare.ring-pedersen"
	domainLabelReshareFactor         = "reshare.factor"
	domainLabelRefreshPaillier       = "refresh.paillier-modulus"
	domainLabelChildPaillier         = "child-derivation.paillier-modulus"
	domainLabelReshareEncryptedShare = "reshare.encrypted-share"
)

type domainBuilder struct {
	t *transcript.Builder
}

type lifecycleBinding struct {
	SessionID tss.SessionID
	Threshold int
	Parties   tss.PartySet
	Sender    tss.PartyID
	PlanHash  []byte
}

// keyShareBinding is the post-protocol context for the local Paillier modulus
// proof retained by a sign-ready KeyShare. Figure 7 proofs cannot directly bind
// the final transcript because that transcript contains those proofs. The local
// party therefore creates one fresh modulus proof after the transcript is fixed.
type keyShareBinding struct {
	ProofDomain          string
	SessionID            tss.SessionID
	Threshold            int
	Parties              tss.PartySet
	Sender               tss.PartyID
	PublicKey            []byte
	KeygenTranscriptHash []byte
	StableSID            tss.SessionID
	RID                  tss.SessionID
	EpochID              []byte
	AuxiliaryDigest      []byte
	SourceEpochID        []byte
	PlanHash             []byte
}

func newDomainBuilder(label string) (*domainBuilder, error) {
	if label == "" {
		return nil, errors.New("missing proof domain label")
	}
	t := transcript.New(proofDomainVersion)
	t.AppendString("protocol", string(tss.ProtocolCGGMP21Secp256k1))
	t.AppendUint32("version", uint32(tss.ProtocolVersion))
	t.AppendString("proof_label", label)
	return &domainBuilder{t: t}, nil
}

func requireHash32(name string, value []byte) error {
	if len(value) != sha256.Size {
		return fmt.Errorf("%s must be %d bytes, got %d", name, sha256.Size, len(value))
	}
	return nil
}

func validateDomainParticipants(threshold int, parties tss.PartySet) error {
	if threshold <= 0 {
		return errors.New("proof domain threshold must be positive")
	}
	if len(parties) == 0 {
		return errors.New("proof domain parties must not be empty")
	}
	if threshold > len(parties) {
		return fmt.Errorf("proof domain threshold %d exceeds party count %d", threshold, len(parties))
	}
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return fmt.Errorf("proof domain parties: %w", err)
	}
	return nil
}

func requireDomainParty(name string, party tss.PartyID, parties tss.PartySet) error {
	if party == tss.BroadcastPartyId {
		return fmt.Errorf("proof domain %s must not be zero", name)
	}
	if !parties.Contains(party) {
		return fmt.Errorf("proof domain %s %d is not a participant", name, party)
	}
	return nil
}

func (b *domainBuilder) appendLifecycleBinding(binding lifecycleBinding) error {
	if err := validateDomainParticipants(binding.Threshold, binding.Parties); err != nil {
		return err
	}
	if !binding.SessionID.Valid() {
		return errors.New("proof domain lifecycle session id must not be zero")
	}
	if err := requireDomainParty("sender", binding.Sender, binding.Parties); err != nil {
		return err
	}
	b.t.AppendBytes("session_id", binding.SessionID[:])
	b.t.AppendUint32("threshold", uint32(binding.Threshold))
	b.t.AppendUint32List("parties", tss.SortParties(binding.Parties))
	b.t.AppendUint32List("signers", nil)
	b.t.AppendUint32("sender", binding.Sender)
	b.t.AppendUint32("receiver", 0)
	b.t.AppendBytes("public_key", nil)
	b.t.AppendBytes("keygen_transcript_hash", nil)
	return nil
}

func (b *domainBuilder) appendKeyShareBinding(binding keyShareBinding) error {
	if err := validateDomainParticipants(binding.Threshold, binding.Parties); err != nil {
		return err
	}
	if binding.ProofDomain == "" {
		return errors.New("key-share proof domain kind is required")
	}
	if !binding.SessionID.Valid() || !binding.StableSID.Valid() || !binding.RID.Valid() {
		return errors.New("key-share proof domain session or epoch identity is invalid")
	}
	if err := requireDomainParty("sender", binding.Sender, binding.Parties); err != nil {
		return err
	}
	if len(binding.PublicKey) == 0 {
		return errors.New("key-share proof domain public key is required")
	}
	if err := requireHash32("keygen transcript hash", binding.KeygenTranscriptHash); err != nil {
		return err
	}
	if err := requireHash32("epoch id", binding.EpochID); err != nil {
		return err
	}
	if err := requireHash32("epoch auxiliary digest", binding.AuxiliaryDigest); err != nil {
		return err
	}
	if len(binding.SourceEpochID) != 0 {
		if err := requireHash32("source epoch id", binding.SourceEpochID); err != nil {
			return err
		}
	}
	b.t.AppendBytes("session_id", binding.SessionID[:])
	b.t.AppendUint32("threshold", uint32(binding.Threshold))
	b.t.AppendUint32List("parties", binding.Parties)
	b.t.AppendUint32List("signers", nil)
	b.t.AppendUint32("sender", binding.Sender)
	b.t.AppendUint32("receiver", 0)
	b.t.AppendBytes("public_key", binding.PublicKey)
	b.t.AppendBytes("keygen_transcript_hash", binding.KeygenTranscriptHash)
	b.t.AppendString("lifecycle_proof_domain", binding.ProofDomain)
	b.t.AppendBytes("stable_sid", binding.StableSID[:])
	b.t.AppendBytes("rid", binding.RID[:])
	b.t.AppendBytes("epoch_id", binding.EpochID)
	b.t.AppendBytes("epoch_auxiliary_digest", binding.AuxiliaryDigest)
	b.t.AppendBytes("source_epoch_id", binding.SourceEpochID)
	return nil
}

func (b *domainBuilder) appendPaillierStatement(pk *pai.PublicKey, limits Limits) error {
	raw, err := canonicalWireMessageBytes(pk, limits)
	if err != nil {
		return fmt.Errorf("paillier public key domain statement: %w", err)
	}
	b.t.AppendBytes("paillier_public_key", raw)
	b.t.AppendBytes("ring_pedersen_params", nil)
	return nil
}

func (b *domainBuilder) appendRingPedersenStatement(params *zkpai.RingPedersenParams, limits Limits) error {
	raw, err := canonicalWireMessageBytes(params, limits)
	if err != nil {
		return fmt.Errorf("Ring-Pedersen params domain statement: %w", err)
	}
	b.t.AppendBytes("paillier_public_key", nil)
	b.t.AppendBytes("ring_pedersen_params", raw)
	return nil
}

func (b *domainBuilder) appendNoPresignContext() {
	b.t.AppendBytes("presign_context_hash", nil)
}

func (b *domainBuilder) appendLifecyclePlanHash(hash []byte) error {
	if err := requireHash32("lifecycle plan hash", hash); err != nil {
		return err
	}
	b.t.AppendBytes("lifecycle_plan_hash", hash)
	return nil
}

func (b *domainBuilder) sum() []byte {
	return b.t.Sum()
}

func lifecycleFromConfig(config tss.ThresholdConfig, sender tss.PartyID, planHash []byte) lifecycleBinding {
	return lifecycleBinding{
		SessionID: config.SessionID,
		Threshold: config.Threshold,
		Parties:   config.Parties,
		Sender:    sender,
		PlanHash:  planHash,
	}
}

func paillierDomain(label string, binding lifecycleBinding, pk *pai.PublicKey, limits Limits) ([]byte, error) {
	b, err := newDomainBuilder(label)
	if err != nil {
		return nil, err
	}
	if err := b.appendLifecycleBinding(binding); err != nil {
		return nil, err
	}
	if err := b.appendPaillierStatement(pk, limits); err != nil {
		return nil, err
	}
	b.appendNoPresignContext()
	if err := b.appendLifecyclePlanHash(binding.PlanHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func ringPedersenDomain(label string, binding lifecycleBinding, params *zkpai.RingPedersenParams, limits Limits) ([]byte, error) {
	b, err := newDomainBuilder(label)
	if err != nil {
		return nil, err
	}
	if err := b.appendLifecycleBinding(binding); err != nil {
		return nil, err
	}
	if err := b.appendRingPedersenStatement(params, limits); err != nil {
		return nil, err
	}
	b.appendNoPresignContext()
	if err := b.appendLifecyclePlanHash(binding.PlanHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func factorProofDomain(label string, config tss.ThresholdConfig, prover, verifier tss.PartyID, proverPK *pai.PublicKey, verifierAux *zkpai.RingPedersenParams, planHash []byte, limits Limits) ([]byte, error) {
	if err := validateDomainParticipants(config.Threshold, config.Parties); err != nil {
		return nil, err
	}
	if err := requireDomainParty("prover", prover, config.Parties); err != nil {
		return nil, err
	}
	if err := requireDomainParty("verifier", verifier, config.Parties); err != nil {
		return nil, err
	}
	if prover == verifier {
		return nil, errors.New("factor proof prover and verifier must differ")
	}
	if err := requireHash32("plan hash", planHash); err != nil {
		return nil, err
	}
	b, err := newDomainBuilder(label)
	if err != nil {
		return nil, err
	}
	b.t.AppendBytes("session_id", config.SessionID[:])
	b.t.AppendUint32("threshold", uint32(config.Threshold))
	b.t.AppendUint32List("parties", config.Parties)
	b.t.AppendUint32List("signers", nil)
	b.t.AppendUint32("sender", prover)
	b.t.AppendUint32("receiver", verifier)
	b.t.AppendBytes("public_key", nil)
	b.t.AppendBytes("keygen_transcript_hash", nil)
	pkRaw, err := canonicalWireMessageBytes(proverPK, limits)
	if err != nil {
		return nil, err
	}
	rpRaw, err := canonicalWireMessageBytes(verifierAux, limits)
	if err != nil {
		return nil, err
	}
	b.t.AppendBytes("paillier_public_key", pkRaw)
	b.t.AppendBytes("ring_pedersen_params", rpRaw)
	b.appendNoPresignContext()
	if err := b.appendLifecyclePlanHash(planHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func reshareFactorProofDomain(config tss.ThresholdConfig, prover, verifier tss.PartyID, proverPK *pai.PublicKey, verifierAux *zkpai.RingPedersenParams, planHash []byte, limits Limits) ([]byte, error) {
	return factorProofDomain(domainLabelReshareFactor, config, prover, verifier, proverPK, verifierAux, planHash, limits)
}

func keyShareFactorProofDomain(key *KeyShare, prover tss.PartyID) ([]byte, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	if key.state.Epoch == nil {
		return nil, errors.New("key share factor proof domain requires epoch context")
	}
	return figure7FactorDomain(key.state.Epoch.SID, key.state.PaillierProofSessionID, key.state.Epoch.RID, key.state.Epoch.EpochID, key.state.Parties, key.state.Threshold, prover, key.state.Party, key.state.PlanHash)
}

func reshareEncryptedShareDomain(sessionID tss.SessionID, threshold int, dealers, receivers tss.PartySet, sender, receiver tss.PartyID, targetIdentifier []byte, receiverPK *pai.PublicKey, planHash []byte, limits Limits) ([]byte, error) {
	if err := validateDomainParticipants(threshold, receivers); err != nil {
		return nil, err
	}
	if len(dealers) == 0 {
		return nil, errors.New("empty reshare dealer set")
	}
	if err := requireDomainParty("sender", sender, dealers); err != nil {
		return nil, err
	}
	if err := requireDomainParty("receiver", receiver, receivers); err != nil {
		return nil, err
	}
	if err := requireHash32("plan hash", planHash); err != nil {
		return nil, err
	}
	b, err := newDomainBuilder(domainLabelReshareEncryptedShare)
	if err != nil {
		return nil, err
	}
	b.t.AppendBytes("session_id", sessionID[:])
	b.t.AppendUint32("threshold", uint32(threshold))
	b.t.AppendUint32List("parties", dealers)
	b.t.AppendUint32List("signers", receivers)
	b.t.AppendUint32("sender", sender)
	b.t.AppendUint32("receiver", receiver)
	if _, err := shamir.IdentifierFromBytes(targetIdentifier); err != nil {
		return nil, err
	}
	b.t.AppendBytes("target_identifier", targetIdentifier)
	b.t.AppendBytes("public_key", nil)
	b.t.AppendBytes("keygen_transcript_hash", nil)
	if err := b.appendPaillierStatement(receiverPK, limits); err != nil {
		return nil, err
	}
	b.appendNoPresignContext()
	if err := b.appendLifecyclePlanHash(planHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func keySharePaillierProofDomain(key *KeyShare) ([]byte, error) {
	return keySharePaillierProofDomainWithLimits(key, DefaultLimits())
}

func keySharePaillierProofDomainWithLimits(key *KeyShare, limits Limits) ([]byte, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	if key.state.Epoch == nil {
		return nil, errors.New("key share Paillier proof domain requires epoch context")
	}
	if err := key.state.validateEpochBinding(limits); err != nil {
		return nil, fmt.Errorf("key share Paillier proof domain epoch binding: %w", err)
	}
	data, err := key.partyDataFor(key.state.Party)
	if err != nil {
		return nil, err
	}
	if data.PaillierPublicKey == nil {
		return nil, errors.New("key share Paillier proof domain: missing public key")
	}
	sourceEpochID, _ := key.state.Epoch.SourceEpochIDBytes()
	binding := keyShareBinding{
		ProofDomain:          key.state.PaillierProofDomain,
		SessionID:            key.state.PaillierProofSessionID,
		Threshold:            key.state.Threshold,
		Parties:              key.state.Parties,
		Sender:               key.state.Party,
		PublicKey:            key.state.PublicKey,
		KeygenTranscriptHash: key.state.KeygenTranscriptHash,
		StableSID:            key.state.Epoch.SID,
		RID:                  key.state.Epoch.RID,
		EpochID:              key.state.Epoch.EpochID,
		AuxiliaryDigest:      key.state.Epoch.AuxiliaryDigest,
		SourceEpochID:        sourceEpochID,
		PlanHash:             key.state.PlanHash,
	}
	b, err := newDomainBuilder(domainLabelKeySharePaillier)
	if err != nil {
		return nil, err
	}
	if err := b.appendKeyShareBinding(binding); err != nil {
		return nil, err
	}
	if err := b.appendPaillierStatement(data.PaillierPublicKey, limits); err != nil {
		return nil, err
	}
	b.appendNoPresignContext()
	if err := b.appendLifecyclePlanHash(binding.PlanHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func keyShareRingPedersenProofDomain(key *KeyShare, party tss.PartyID, params *zkpai.RingPedersenParams) ([]byte, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	if params == nil {
		return nil, errors.New("key share Ring-Pedersen proof domain: missing parameters")
	}
	if key.state.Epoch == nil {
		return nil, errors.New("key share Ring-Pedersen proof domain requires epoch context")
	}
	encoded, err := params.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return figure7RingPedersenDomain(key.state.Epoch.SID, key.state.PaillierProofSessionID, key.state.Parties, key.state.Threshold, party, encoded, key.state.PlanHash)
}

func resharePaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, pk *pai.PublicKey, planHash []byte, limits Limits) ([]byte, error) {
	return paillierDomain(domainLabelResharePaillier, lifecycleFromConfig(config, sender, planHash), pk, limits)
}

func reshareRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params *zkpai.RingPedersenParams, planHash []byte, limits Limits) ([]byte, error) {
	return ringPedersenDomain(domainLabelReshareRingPedersen, lifecycleFromConfig(config, sender, planHash), params, limits)
}
