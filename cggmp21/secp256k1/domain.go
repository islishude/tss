package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	proofDomainVersion = "cggmp21-secp256k1-proof-domain-v1"

	// Domain labels identify the protocol phase for domain separation.
	domainLabelKeygenModulus        = "keygen.modulus"
	domainLabelKeygenRingPedersen   = "keygen.ring-pedersen"
	domainLabelKeySharePaillier     = "keyshare.paillier-modulus"
	domainLabelPresignMTAStartProof = "presign.mta-start.enc-proof"
	domainLabelPresignMTADelta      = "presign.mta-response.delta"
	domainLabelPresignMTASigma      = "presign.mta-response.sigma"
	domainLabelResharePaillier      = "reshare.paillier-modulus"
	domainLabelReshareRingPedersen  = "reshare.ring-pedersen"
	domainLabelRefreshPaillier      = "refresh.paillier-modulus"
	domainLabelRefreshRingPedersen  = "refresh.ring-pedersen"
	domainLabelKeyShareLogProof     = "keyshare.log-proof"
	domainLabelReshareLogProof      = "reshare.log-proof"
	domainLabelRefreshLogProof      = "refresh.log-proof"
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

type keyShareBinding struct {
	SessionID            tss.SessionID
	Threshold            int
	Parties              tss.PartySet
	Sender               tss.PartyID
	PublicKey            []byte
	KeygenTranscriptHash []byte
	PlanHash             []byte
}

type presignBinding struct {
	SessionID            tss.SessionID
	Threshold            int
	Parties              tss.PartySet
	Signers              tss.PartySet
	Sender               tss.PartyID
	Receiver             tss.PartyID
	PublicKey            []byte
	KeygenTranscriptHash []byte
	PresignContextHash   []byte
	PlanHash             []byte
}

type logProofBinding struct {
	SessionID         tss.SessionID
	Threshold         int
	Parties           tss.PartySet
	Sender            tss.PartyID
	VerificationShare []byte
	TranscriptHash    []byte
	PlanHash          []byte
}

type mtaResponseKind string

const (
	mtaResponseKindDelta mtaResponseKind = domainLabelPresignMTADelta
	mtaResponseKindSigma mtaResponseKind = domainLabelPresignMTASigma
)

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
	if binding.SessionID == (tss.SessionID{}) {
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
	if err := requireDomainParty("sender", binding.Sender, binding.Parties); err != nil {
		return err
	}
	if len(binding.PublicKey) == 0 {
		return errors.New("proof domain public key is required")
	}
	if err := requireHash32("keygen transcript hash", binding.KeygenTranscriptHash); err != nil {
		return err
	}
	b.t.AppendBytes("session_id", binding.SessionID[:])
	b.t.AppendUint32("threshold", uint32(binding.Threshold))
	b.t.AppendUint32List("parties", tss.SortParties(binding.Parties))
	b.t.AppendUint32List("signers", nil)
	b.t.AppendUint32("sender", binding.Sender)
	b.t.AppendUint32("receiver", 0)
	b.t.AppendBytes("public_key", binding.PublicKey)
	b.t.AppendBytes("keygen_transcript_hash", binding.KeygenTranscriptHash)
	return nil
}

func (b *domainBuilder) appendPresignBinding(binding presignBinding) error {
	if err := validateDomainParticipants(binding.Threshold, binding.Parties); err != nil {
		return err
	}
	if binding.SessionID == (tss.SessionID{}) {
		return errors.New("proof domain presign session id must not be zero")
	}
	if err := wire.ValidateStrictSortedIDs(binding.Signers); err != nil {
		return fmt.Errorf("proof domain signers: %w", err)
	}
	if len(binding.Signers) < binding.Threshold {
		return fmt.Errorf("proof domain signer count %d is below threshold %d", len(binding.Signers), binding.Threshold)
	}
	for _, signer := range binding.Signers {
		if !binding.Parties.Contains(signer) {
			return fmt.Errorf("proof domain signer %d is not a participant", signer)
		}
	}
	if err := requireDomainParty("sender", binding.Sender, binding.Signers); err != nil {
		return err
	}
	if err := requireDomainParty("receiver", binding.Receiver, binding.Signers); err != nil {
		return err
	}
	if binding.Sender == binding.Receiver {
		return errors.New("proof domain sender and receiver must differ")
	}
	if len(binding.PublicKey) == 0 {
		return errors.New("proof domain public key is required")
	}
	if err := requireHash32("keygen transcript hash", binding.KeygenTranscriptHash); err != nil {
		return err
	}
	b.t.AppendBytes("session_id", binding.SessionID[:])
	b.t.AppendUint32("threshold", uint32(binding.Threshold))
	b.t.AppendUint32List("parties", tss.SortParties(binding.Parties))
	b.t.AppendUint32List("signers", tss.SortParties(binding.Signers))
	b.t.AppendUint32("sender", binding.Sender)
	b.t.AppendUint32("receiver", binding.Receiver)
	b.t.AppendBytes("public_key", binding.PublicKey)
	b.t.AppendBytes("keygen_transcript_hash", binding.KeygenTranscriptHash)
	return nil
}

func (b *domainBuilder) appendLogProofBinding(binding logProofBinding) error {
	if err := validateDomainParticipants(binding.Threshold, binding.Parties); err != nil {
		return err
	}
	if binding.SessionID == (tss.SessionID{}) {
		return errors.New("proof domain log session id must not be zero")
	}
	if err := requireDomainParty("sender", binding.Sender, binding.Parties); err != nil {
		return err
	}
	if len(binding.VerificationShare) == 0 {
		return errors.New("proof domain verification share is required")
	}
	if err := requireHash32("transcript hash", binding.TranscriptHash); err != nil {
		return err
	}
	b.t.AppendBytes("session_id", binding.SessionID[:])
	b.t.AppendUint32("threshold", uint32(binding.Threshold))
	b.t.AppendUint32List("parties", tss.SortParties(binding.Parties))
	b.t.AppendUint32List("signers", nil)
	b.t.AppendUint32("sender", binding.Sender)
	b.t.AppendUint32("receiver", 0)
	b.t.AppendBytes("public_key", binding.VerificationShare)
	b.t.AppendBytes("keygen_transcript_hash", binding.TranscriptHash)
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

func (b *domainBuilder) appendPresignContext(hash []byte) error {
	if err := requireHash32("presign context hash", hash); err != nil {
		return err
	}
	b.t.AppendBytes("presign_context_hash", hash)
	return nil
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

func keyShareDomainBinding(key *KeyShare, sessionID tss.SessionID, sender tss.PartyID, statementPublicKey, transcriptHash []byte) (keyShareBinding, error) {
	if key == nil || key.state == nil {
		return keyShareBinding{}, errors.New("nil key share")
	}
	return keyShareBinding{
		SessionID:            sessionID,
		Threshold:            key.state.threshold,
		Parties:              key.state.parties,
		Sender:               sender,
		PublicKey:            statementPublicKey,
		KeygenTranscriptHash: transcriptHash,
		PlanHash:             key.state.planHash,
	}, nil
}

func presignDomainBinding(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, sender, receiver tss.PartyID, presignContextHash, planHash []byte) (presignBinding, error) {
	if key == nil || key.state == nil {
		return presignBinding{}, errors.New("nil key share")
	}
	return presignBinding{
		SessionID:            sessionID,
		Threshold:            key.state.threshold,
		Parties:              key.state.parties,
		Signers:              signers,
		Sender:               sender,
		Receiver:             receiver,
		PublicKey:            key.state.publicKey,
		KeygenTranscriptHash: key.state.keygenTranscriptHash,
		PresignContextHash:   presignContextHash,
		PlanHash:             planHash,
	}, nil
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

func mtaPaillierDomain(label string, binding presignBinding, pk *pai.PublicKey, limits Limits) ([]byte, error) {
	b, err := newDomainBuilder(label)
	if err != nil {
		return nil, err
	}
	if err := b.appendPresignBinding(binding); err != nil {
		return nil, err
	}
	if err := b.appendPaillierStatement(pk, limits); err != nil {
		return nil, err
	}
	if err := b.appendPresignContext(binding.PresignContextHash); err != nil {
		return nil, err
	}
	if err := b.appendLifecyclePlanHash(binding.PlanHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func logProofDomainWithBinding(label string, binding logProofBinding, pk *pai.PublicKey, limits Limits) ([]byte, error) {
	b, err := newDomainBuilder(label)
	if err != nil {
		return nil, err
	}
	if err := b.appendLogProofBinding(binding); err != nil {
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

func keygenModulusDomain(config tss.ThresholdConfig, sender tss.PartyID, pk *pai.PublicKey, planHash []byte, limits Limits) ([]byte, error) {
	return paillierDomain(domainLabelKeygenModulus, lifecycleFromConfig(config, sender, planHash), pk, limits)
}

func keygenRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params *zkpai.RingPedersenParams, planHash []byte, limits Limits) ([]byte, error) {
	return ringPedersenDomain(domainLabelKeygenRingPedersen, lifecycleFromConfig(config, sender, planHash), params, limits)
}

func keySharePaillierProofDomain(key *KeyShare, limits Limits) ([]byte, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	data, err := key.partyDataFor(key.state.party)
	if err != nil {
		return nil, err
	}
	if data.paillierPublicKey == nil {
		return nil, errors.New("key share paillier proof domain: missing public key")
	}
	binding, err := keyShareDomainBinding(key, tss.SessionID{}, key.state.party, key.state.publicKey, key.state.keygenTranscriptHash)
	if err != nil {
		return nil, err
	}
	b, err := newDomainBuilder(domainLabelKeySharePaillier)
	if err != nil {
		return nil, err
	}
	if err := b.appendKeyShareBinding(binding); err != nil {
		return nil, err
	}
	if err := b.appendPaillierStatement(data.paillierPublicKey, limits); err != nil {
		return nil, err
	}
	b.appendNoPresignContext()
	if err := b.appendLifecyclePlanHash(binding.PlanHash); err != nil {
		return nil, err
	}
	return b.sum(), nil
}

func keyShareRingPedersenProofDomain(key *KeyShare, party tss.PartyID, params *zkpai.RingPedersenParams, limits Limits) ([]byte, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	if params == nil {
		return nil, errors.New("key share Ring-Pedersen proof domain: missing parameters")
	}
	binding := lifecycleBinding{
		SessionID: key.state.paillierProofSessionID,
		Threshold: key.state.threshold,
		Parties:   key.state.parties,
		Sender:    party,
		PlanHash:  key.state.planHash,
	}
	switch key.state.paillierProofDomain {
	case domainLabelKeygenModulus:
		return ringPedersenDomain(domainLabelKeygenRingPedersen, binding, params, limits)
	case domainLabelRefreshPaillier:
		return ringPedersenDomain(domainLabelRefreshRingPedersen, binding, params, limits)
	case domainLabelResharePaillier:
		return ringPedersenDomain(domainLabelReshareRingPedersen, binding, params, limits)
	default:
		return nil, fmt.Errorf("unsupported Ring-Pedersen proof domain %q", key.state.paillierProofDomain)
	}
}

func mtaStartProofDomain(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, prover, verifier tss.PartyID, proverPaillierPublicKey *pai.PublicKey, presignContextHash, planHash []byte, limits Limits) ([]byte, error) {
	binding, err := presignDomainBinding(key, sessionID, signers, prover, verifier, presignContextHash, planHash)
	if err != nil {
		return nil, err
	}
	return mtaPaillierDomain(domainLabelPresignMTAStartProof, binding, proverPaillierPublicKey, limits)
}

func resharePaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, pk *pai.PublicKey, planHash []byte, limits Limits) ([]byte, error) {
	return paillierDomain(domainLabelResharePaillier, lifecycleFromConfig(config, sender, planHash), pk, limits)
}

func reshareRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params *zkpai.RingPedersenParams, planHash []byte, limits Limits) ([]byte, error) {
	return ringPedersenDomain(domainLabelReshareRingPedersen, lifecycleFromConfig(config, sender, planHash), params, limits)
}

func refreshPaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, pk *pai.PublicKey, planHash []byte, limits Limits) ([]byte, error) {
	return paillierDomain(domainLabelRefreshPaillier, lifecycleFromConfig(config, sender, planHash), pk, limits)
}

func refreshRingPedersenDomain(config tss.ThresholdConfig, sender tss.PartyID, params *zkpai.RingPedersenParams, planHash []byte, limits Limits) ([]byte, error) {
	return ringPedersenDomain(domainLabelRefreshRingPedersen, lifecycleFromConfig(config, sender, planHash), params, limits)
}

func mtaDeltaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, initiator, responder tss.PartyID, initiatorPaillierPublicKey *pai.PublicKey, presignContextHash, planHash []byte, limits Limits) ([]byte, error) {
	return mtaResponseProofDomain(mtaResponseKindDelta, key, sessionID, signers, initiator, responder, initiatorPaillierPublicKey, presignContextHash, planHash, limits)
}

func mtaSigmaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, initiator, responder tss.PartyID, initiatorPaillierPublicKey *pai.PublicKey, presignContextHash, planHash []byte, limits Limits) ([]byte, error) {
	return mtaResponseProofDomain(mtaResponseKindSigma, key, sessionID, signers, initiator, responder, initiatorPaillierPublicKey, presignContextHash, planHash, limits)
}

func mtaResponseProofDomain(kind mtaResponseKind, key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, initiator, responder tss.PartyID, initiatorPaillierPublicKey *pai.PublicKey, presignContextHash, planHash []byte, limits Limits) ([]byte, error) {
	binding, err := presignDomainBinding(key, sessionID, signers, responder, initiator, presignContextHash, planHash)
	if err != nil {
		return nil, err
	}
	switch kind {
	case mtaResponseKindDelta, mtaResponseKindSigma:
		return mtaPaillierDomain(string(kind), binding, initiatorPaillierPublicKey, limits)
	default:
		return nil, fmt.Errorf("unsupported MtA response domain kind %q", kind)
	}
}

func logProofDomain(key *KeyShare, pk *pai.PublicKey, verificationShare, transcriptHash []byte, limits Limits) ([]byte, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	if pk == nil {
		return nil, errors.New("nil paillier public key")
	}
	label := domainLabelKeyShareLogProof
	switch key.state.paillierProofDomain {
	case domainLabelResharePaillier:
		label = domainLabelReshareLogProof
	case domainLabelRefreshPaillier:
		label = domainLabelRefreshLogProof
	}
	binding := logProofBinding{
		SessionID:         key.state.paillierProofSessionID,
		Threshold:         key.state.threshold,
		Parties:           key.state.parties,
		Sender:            key.state.party,
		VerificationShare: verificationShare,
		TranscriptHash:    transcriptHash,
		PlanHash:          key.state.planHash,
	}
	return logProofDomainWithBinding(label, binding, pk, limits)
}
