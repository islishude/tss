package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const paperKeygenTranscriptHashLabel = "cggmp21-secp256k1-paper-keygen-transcript-v1"

type paperKeygenMessageKey struct {
	round       uint8
	from        tss.PartyID
	to          tss.PartyID
	payloadType tss.PayloadType
}

func newPaperKeygenMessageKey(env tss.Envelope) paperKeygenMessageKey {
	return paperKeygenMessageKey{round: env.Round, from: env.From, to: env.To, payloadType: env.PayloadType}
}

func startPaperKeygenResolved(
	config tss.ThresholdConfig,
	limits Limits,
	securityParams SecurityParams,
	planHash []byte,
	contribution *secret.Scalar,
	chainContribution []byte,
	importPlan *TrustedDealerImportPlan,
	guard *tss.EnvelopeGuard,
) (*KeygenSession, []tss.Envelope, error) {
	figure6, out, err := startFigure6(figure6StartOption{
		Config:            config,
		Limits:            limits,
		PlanHash:          planHash,
		Contribution:      contribution,
		ChainContribution: chainContribution,
	})
	if err != nil {
		return nil, nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			figure6.destroy()
			clearEnvelopePayloads(out)
		}
	}()
	if importPlan != nil {
		commitment, ok := importPlan.commitmentFor(config.Self)
		if !ok {
			return nil, nil, errors.New("trusted-dealer plan omitted local Figure 6 commitment")
		}
		localSlot := figure6.slots[config.Self]
		if localSlot == nil || localSlot.reveal == nil ||
			!bytes.Equal(localSlot.chainCodeCommit, commitment.ChainCodeCommit) ||
			!bytes.Equal(localSlot.reveal.PublicShare, commitment.ConstantCommitment) {
			return nil, nil, errors.New("trusted-dealer contribution does not match local Figure 6 commitment")
		}
	}
	session := &KeygenSession{
		cfg:                config,
		limits:             limits,
		securityParams:     securityParams,
		planHash:           bytes.Clone(planHash),
		importPlan:         cloneCGGMPTrustedDealerPlan(importPlan),
		state:              keygenCollectingRound1,
		guard:              guard,
		figure6:            figure6,
		paperConfirmations: make(map[tss.PartyID]*KeygenConfirmation, len(config.Parties)),
		paperAccepted:      make(map[paperKeygenMessageKey]struct{}, 4*len(config.Parties)),
	}
	if figure6.completed() {
		if importPlan != nil && !bytes.Equal(figure6.result.publicKey, importPlan.state.PublicKey) {
			return nil, nil, errors.New("trusted-dealer Figure 6 public key mismatch")
		}
		auxInfo, auxOut, err := session.startPaperAuxInfo(figure6.result)
		if err != nil {
			return nil, nil, fmt.Errorf("start singleton Figure 7 after Figure 6: %w", err)
		}
		auxOwned := true
		defer func() {
			clearEnvelopePayloads(auxOut)
			if auxOwned {
				auxInfo.destroy()
			}
		}()
		if !auxInfo.completed() {
			return nil, nil, errors.New("singleton Figure 7 did not complete locally")
		}
		pending, err := session.preparePaperPendingKeyShare(auxInfo.result)
		if err != nil {
			return nil, nil, fmt.Errorf("prepare singleton paper keygen result: %w", err)
		}
		defer pending.destroy()
		session.auxInfo = auxInfo
		auxOwned = false
		figure6.releaseContribution()
		clear(pending.confirmationEnvelope.Payload)
		session.commitPaperPendingKeyShare(pending)
	}
	cleanup = false
	return session, out, nil
}

func clearEnvelopePayloads(envelopes []tss.Envelope) {
	for i := range envelopes {
		clear(envelopes[i].Payload)
	}
}

func (s *KeygenSession) handlePaperKeygenLocked(env tss.InboundEnvelope) ([]tss.Envelope, error) {
	base := env.Envelope()
	key := newPaperKeygenMessageKey(base)
	if _, ok := s.paperAccepted[key]; ok {
		if err := s.validateInbound(env); err != nil {
			return nil, err
		}
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, errors.New("paper keygen message slot is already accepted"))
	}

	switch base.PayloadType {
	case payloadFigure6Commitment, payloadFigure6Reveal, payloadFigure6Proof:
		return s.handlePaperFigure6Locked(env, key)
	case payloadAuxInfoCommitment, payloadAuxInfoReveal, payloadAuxInfoProofs, payloadAuxInfoDirect, payloadAuxInfoDecryptionError:
		return s.handlePaperAuxInfoLocked(env, key)
	case payloadKeygenConfirmation:
		return s.handlePaperKeygenConfirmationLocked(env, key)
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, fmt.Errorf("unexpected paper keygen payload type %q", base.PayloadType))
	}
}

func (s *KeygenSession) handlePaperFigure6Locked(env tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	base := env.Envelope()
	if s.figure6 == nil || s.auxInfo != nil || s.pending != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("figure 6 message arrived outside figure 6"))
	}
	if err := validatePaperKeygenRound(base, s.figure6.scheduleForPayload(base.PayloadType)); err != nil {
		return nil, err
	}
	if err := s.verifyTrustedDealerFigure6Envelope(base); err != nil {
		return nil, paperFigure6PreparationError(base, s.cfg.Parties, err)
	}
	prepared, err := s.figure6.prepareInbound(base)
	if err != nil {
		return nil, paperFigure6PreparationError(base, s.cfg.Parties, err)
	}
	defer prepared.destroy()

	var nextAux *auxInfoState
	var nextOut []tss.Envelope
	nextOwned := false
	if prepared.result != nil {
		if s.importPlan != nil && !bytes.Equal(prepared.result.publicKey, s.importPlan.state.PublicKey) {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("trusted-dealer Figure 6 public key mismatch"))
		}
		nextAux, nextOut, err = s.startPaperAuxInfo(prepared.result)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, base.Round, s.cfg.Self, fmt.Errorf("start Figure 7 after Figure 6: %w", err))
		}
		nextOwned = true
		defer func() {
			if nextOwned {
				nextAux.destroy()
				clearEnvelopePayloads(nextOut)
			}
		}()
	}
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	if err := prepared.apply(); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, base.Round, s.cfg.Self, fmt.Errorf("commit Figure 6 transition: %w", err))
	}
	s.paperAccepted[key] = struct{}{}
	if nextAux != nil {
		s.auxInfo = nextAux
		s.figure6.releaseContribution()
		nextOwned = false
	}
	return append(prepared.out, nextOut...), nil
}

func (s *KeygenSession) startPaperAuxInfo(result *figure6Result) (*auxInfoState, []tss.Envelope, error) {
	if s == nil || result == nil {
		return nil, nil, errors.New("missing Figure 6 result")
	}
	return startAuxInfo(auxInfoStartOption{
		Config:            s.cfg,
		StableSID:         s.cfg.SessionID,
		Limits:            s.limits,
		SecurityParams:    s.securityParams,
		EnvelopeVerifier:  s.guard.EnvelopeVerifier,
		PaillierBits:      s.paperPaillierBits(),
		PlanHash:          s.planHash,
		ExpectedPublicKey: result.publicKey,
		Contribution:      result.contribution,
		Schedule: auxInfoSchedule{
			CommitmentRound: keygenAuxInfoCommitmentRound,
			RevealRound:     keygenAuxInfoRevealRound,
			ProofRound:      keygenAuxInfoProofRound,
		},
	})
}

func (s *KeygenSession) paperPaillierBits() int {
	if s != nil && s.importPlan != nil && s.importPlan.state != nil {
		return s.importPlan.state.PaillierBits
	}
	return int(s.securityParams.MinPaillierBits)
}

func (s *figure6State) scheduleForPayload(payloadType tss.PayloadType) uint8 {
	switch payloadType {
	case payloadFigure6Commitment:
		return keygenFigure6CommitmentRound
	case payloadFigure6Reveal:
		return keygenFigure6RevealRound
	case payloadFigure6Proof:
		return keygenFigure6ProofRound
	default:
		return invalidRound
	}
}

func validatePaperKeygenRound(env tss.Envelope, expected uint8) error {
	if expected == invalidRound || env.Round != expected {
		return tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, fmt.Errorf("payload %q is in the wrong paper keygen round", env.PayloadType))
	}
	return nil
}

func paperKeygenPreparationError(env tss.Envelope, err error) error {
	if errors.Is(err, tss.ErrDuplicateMessage) {
		return tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, err)
	}
	return tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
}

func paperFigure6PreparationError(env tss.Envelope, parties tss.PartySet, err error) error {
	partiesField := rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(parties, partySetHashLabel))
	switch {
	case errors.Is(err, errFigure6MalformedPayload):
		return protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenCommitment,
			"malformed Figure 6 message",
			tss.NewPartySet(env.From),
			err,
			partiesField,
		)
	case errors.Is(err, errFigure6AttributableFailure):
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenCommitment,
			"invalid Figure 6 message",
			tss.NewPartySet(env.From),
			err,
			partiesField,
		)
	default:
		return paperKeygenPreparationError(env, err)
	}
}

func (s *KeygenSession) verifyTrustedDealerFigure6Envelope(env tss.Envelope) error {
	if s.importPlan == nil {
		return nil
	}
	commitment, ok := s.importPlan.commitmentFor(env.From)
	if !ok {
		return fmt.Errorf("trusted-dealer plan omitted party %d", env.From)
	}
	switch env.PayloadType {
	case payloadFigure6Commitment:
		payload, err := tss.DecodeBinaryWithLimits[figure6CommitmentPayload](env.Payload, s.limits)
		if err != nil {
			return figure6MalformedPayload(err)
		}
		if !bytes.Equal(payload.ChainCodeCommit, commitment.ChainCodeCommit) {
			return figure6AttributableFailure(errors.New("trusted-dealer Figure 6 chain-code commitment mismatch"))
		}
	case payloadFigure6Reveal:
		payload, err := tss.DecodeBinaryWithLimits[figure6RevealPayload](env.Payload, s.limits)
		if err != nil {
			return figure6MalformedPayload(err)
		}
		if !bytes.Equal(payload.PublicShare, commitment.ConstantCommitment) {
			return figure6AttributableFailure(errors.New("trusted-dealer Figure 6 additive contribution mismatch"))
		}
	}
	return nil
}

func (s *KeygenSession) handlePaperAuxInfoLocked(env tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	base := env.Envelope()
	if s.auxInfo == nil || s.pending != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("AuxInfo message arrived outside Figure 7"))
	}
	prepared, err := s.auxInfo.prepareInbound(base)
	if err != nil {
		return nil, paperKeygenPreparationError(base, err)
	}
	defer prepared.destroy()

	var pending *preparedPaperPendingKeyShare
	if prepared.result != nil {
		pending, err = s.preparePaperPendingKeyShare(prepared.result)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		defer pending.destroy()
	}
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	if err := prepared.apply(); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, base.Round, s.cfg.Self, fmt.Errorf("commit Figure 7 transition: %w", err))
	}
	s.paperAccepted[key] = struct{}{}
	if prepared.failure != nil {
		s.terminalFigure7Failure(prepared.failure)
		return prepared.out, nil
	}
	if pending == nil {
		return prepared.out, nil
	}
	s.commitPaperPendingKeyShare(pending)
	return append(prepared.out, pending.confirmationEnvelope), nil
}

type preparedPaperPendingKeyShare struct {
	share                *KeyShare
	confirmation         *KeygenConfirmation
	confirmationEnvelope tss.Envelope
	final                *preparedPaperFinalKeyShare
	committed            bool
}

func (p *preparedPaperPendingKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
	}
	if p.confirmation != nil {
		clear(p.confirmation.ChainCode)
	}
	clear(p.confirmationEnvelope.Payload)
	if p.final != nil {
		p.final.destroy()
	}
}

func (s *KeygenSession) preparePaperPendingKeyShare(result *auxInfoResult) (*preparedPaperPendingKeyShare, error) {
	if result == nil || s.figure6 == nil || s.figure6.local == nil || len(s.figure6.local.chainCode) != bip32util.ChainCodeSize {
		return nil, errors.New("incomplete paper keygen completion state")
	}
	if !bytes.Equal(result.publicKey, s.figure6.result.publicKey) {
		return nil, errors.New("figure 7 public key does not match figure 6 output")
	}
	transcriptHash, err := s.paperKeygenTranscriptHash(result)
	if err != nil {
		return nil, err
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, result.secret)
	if err != nil {
		return nil, err
	}
	localPublic, ok := result.epoch.PublicShare(s.cfg.Self)
	if !ok || !bytes.Equal(proofPublic, localPublic.PublicKey) {
		return nil, errors.New("paper keygen local share proof public key mismatch")
	}
	snapshot := result.clone()
	defer snapshot.destroy()
	pending := &KeyShare{state: &keyShareState{
		SecurityParams:         s.securityParams,
		Party:                  s.cfg.Self,
		Threshold:              s.cfg.Threshold,
		Parties:                s.cfg.Parties.Clone(),
		PublicKey:              bytes.Clone(snapshot.publicKey),
		Secret:                 snapshot.secret,
		GroupCommitments:       snapshot.commitments,
		PartyData:              snapshot.partyData,
		PaillierPrivateKey:     snapshot.paillier,
		ShareProof:             shareProof.Clone(),
		KeygenTranscriptHash:   transcriptHash,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelKeygenModulus,
		PlanHash:               bytes.Clone(s.planHash),
		Epoch:                  snapshot.epoch,
	}}
	snapshot.secret = nil
	snapshot.commitments = nil
	snapshot.partyData = nil
	snapshot.paillier = nil
	snapshot.epoch = nil
	prepared := &preparedPaperPendingKeyShare{share: pending}
	cleanup := true
	defer func() {
		if cleanup {
			prepared.destroy()
		}
	}()
	if err := finalizeSignReadyKeyShareProofs(s.cfg.Reader(), pending, s.limits); err != nil {
		return nil, err
	}

	validationShare := cloneKeyShareValue(pending)
	validationShare.state.ChainCode = bytes.Clone(s.figure6.local.chainCode)
	if err := validationShare.validateWithoutConfirmations(s.limits); err != nil {
		validationShare.Destroy()
		return nil, fmt.Errorf("validate paper keygen pending share: %w", err)
	}
	validationShare.Destroy()
	for party, confirmation := range s.paperConfirmations {
		if err := verifyConfirmationBinding(pending, confirmation); err != nil {
			return nil, fmt.Errorf("buffered confirmation from party %d: %w", party, err)
		}
	}
	confirmation, err := newKeygenCommitRevealConfirmation(pending, s.figure6.local.chainCode, s.limits)
	if err != nil {
		return nil, err
	}
	prepared.confirmation = confirmation
	encoded, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	prepared.confirmationEnvelope, err = newEnvelope(s.cfg, keygenPaperConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	candidates := clonePaperConfirmationMap(s.paperConfirmations)
	defer destroyPaperConfirmationMap(candidates)
	candidates[s.cfg.Self] = confirmation.Clone()
	if len(candidates) == len(s.cfg.Parties) {
		prepared.final, err = s.buildPaperFinalKeyShare(pending, candidates)
		if err != nil {
			return nil, err
		}
	}
	cleanup = false
	return prepared, nil
}

func (s *KeygenSession) commitPaperPendingKeyShare(prepared *preparedPaperPendingKeyShare) {
	s.pending = prepared.share
	s.paperConfirmations[s.cfg.Self] = prepared.confirmation
	s.state = keygenAwaitingConfirmations
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	if s.figure6 != nil && s.figure6.local != nil {
		s.figure6.releaseContribution()
		clear(s.figure6.local.chainCode)
		s.figure6.local.chainCode = nil
	}
	prepared.committed = true
	if prepared.final != nil {
		s.commitPaperFinalKeyShare(prepared.final)
	}
}

func (s *KeygenSession) paperKeygenTranscriptHash(result *auxInfoResult) ([]byte, error) {
	if s.figure6 == nil || s.figure6.result == nil || result == nil || result.epoch == nil {
		return nil, errors.New("incomplete paper keygen transcript state")
	}
	t := transcript.New(paperKeygenTranscriptHashLabel)
	t.AppendBytes("sid", s.cfg.SessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("rho", s.figure6.result.rho[:])
	t.AppendBytes("group_public_key", s.figure6.result.publicKey)
	for _, party := range s.cfg.Parties {
		slot := s.figure6.slots[party]
		if slot == nil || slot.commitment == nil || slot.chainCodeCommit == nil || slot.reveal == nil || slot.proof == nil {
			return nil, fmt.Errorf("incomplete Figure 6 transcript for party %d", party)
		}
		revealBytes, err := slot.reveal.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		proofBytes, err := slot.proof.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			clear(revealBytes)
			return nil, err
		}
		t.AppendUint32("party", party)
		t.AppendBytes("figure6_commitment", slot.commitment)
		t.AppendBytes("chain_code_commitment", slot.chainCodeCommit)
		t.AppendBytes("figure6_reveal", revealBytes)
		t.AppendBytes("figure6_proof", proofBytes)
		clear(revealBytes)
		clear(proofBytes)
	}
	t.AppendBytes("auxinfo_transcript_hash", result.transcriptHash)
	t.AppendBytes("epoch_id", result.epoch.EpochID)
	return t.Sum(), nil
}

type receivedKeygenConfirmation struct {
	env       tss.Envelope
	msg       *KeygenConfirmation
	canonical []byte
}

func (s *KeygenSession) parseKeygenConfirmation(env tss.Envelope) (*receivedKeygenConfirmation, error) {
	confirmation := new(KeygenConfirmation)
	if err := confirmation.UnmarshalBinaryWithLimits(env.Payload, s.limits); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	canonical, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		clear(confirmation.ChainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical keygen confirmation"))
	}
	return &receivedKeygenConfirmation{env: env, msg: confirmation, canonical: canonical}, nil
}

func (s *KeygenSession) handlePaperKeygenConfirmationLocked(env tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	base := env.Envelope()
	if base.Round != keygenPaperConfirmationRound || base.To != tss.BroadcastPartyId {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("paper keygen confirmation in wrong round or delivery mode"))
	}
	if s.figure6 == nil || s.figure6.result == nil || s.auxInfo == nil && s.pending == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("paper keygen confirmation arrived before Figure 6 completed"))
	}
	received, err := s.parseKeygenConfirmation(base)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			clear(received.msg.ChainCode)
		}
	}()
	if received.msg.Sender != base.From {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, base.Round, base.From, errors.New("paper keygen confirmation sender mismatch"))
	}
	if err := requirePlanHash("paper keygen confirmation", received.msg.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if received.msg.SessionID != s.cfg.SessionID || received.msg.Threshold != s.cfg.Threshold ||
		!slices.Equal(received.msg.Parties, s.cfg.Parties) || !bytes.Equal(received.msg.PublicKey, s.figure6.result.publicKey) {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("paper keygen confirmation public binding mismatch"))
	}
	slot := s.figure6.slots[base.From]
	if slot == nil || slot.chainCodeCommit == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, base.Round, base.From, errors.New("paper keygen confirmation has no Figure 6 commitment"))
	}
	if err := verifyConfirmationCommitRevealChainCode(s.cfg.SessionID, base.From, received.msg.ChainCode, slot.chainCodeCommit); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
	}
	if existing := s.paperConfirmations[base.From]; existing != nil {
		existingBytes, marshalErr := existing.MarshalBinaryWithLimits(s.limits)
		if marshalErr == nil && bytes.Equal(existingBytes, received.canonical) {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, base.Round, base.From, tss.ErrDuplicateMessage)
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, errors.New("conflicting paper keygen confirmation"))
	}
	if s.pending != nil {
		if err := verifyConfirmationBinding(s.pending, received.msg); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
	}
	candidates := clonePaperConfirmationMap(s.paperConfirmations)
	defer destroyPaperConfirmationMap(candidates)
	candidates[base.From] = received.msg.Clone()
	var final *preparedPaperFinalKeyShare
	if s.pending != nil && len(candidates) == len(s.cfg.Parties) {
		final, err = s.buildPaperFinalKeyShare(s.pending, candidates)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, base.Round, base.From, err)
		}
		defer final.destroy()
	}
	if err := s.validateInbound(env); err != nil {
		return nil, err
	}
	s.paperConfirmations[base.From] = received.msg
	s.paperAccepted[key] = struct{}{}
	owned = false
	if final != nil {
		s.commitPaperFinalKeyShare(final)
	}
	return nil, nil
}

type preparedPaperFinalKeyShare struct {
	share               *KeyShare
	confirmationSetHash []byte
	committed           bool
}

func (p *preparedPaperFinalKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
	}
	clear(p.confirmationSetHash)
}

func (s *KeygenSession) buildPaperFinalKeyShare(pending *KeyShare, confirmations map[tss.PartyID]*KeygenConfirmation) (*preparedPaperFinalKeyShare, error) {
	if pending == nil || len(confirmations) != len(s.cfg.Parties) {
		return nil, errors.New("incomplete paper keygen confirmation set")
	}
	ordered := make([]*KeygenConfirmation, len(s.cfg.Parties))
	reveals := make(map[tss.PartyID][]byte, len(s.cfg.Parties))
	for i, party := range s.cfg.Parties {
		confirmation := confirmations[party]
		if confirmation == nil {
			return nil, fmt.Errorf("missing paper keygen confirmation from party %d", party)
		}
		ordered[i] = confirmation.Clone()
		reveals[party] = bytes.Clone(confirmation.ChainCode)
	}
	defer func() {
		for _, confirmation := range ordered {
			clear(confirmation.ChainCode)
		}
		for party, reveal := range reveals {
			clear(reveal)
			delete(reveals, party)
		}
	}()
	if err := verifyKeygenConfirmationSetBinding(pending, ordered); err != nil {
		return nil, err
	}
	for _, confirmation := range ordered {
		slot := s.figure6.slots[confirmation.Sender]
		if slot == nil {
			return nil, fmt.Errorf("missing Figure 6 slot for party %d", confirmation.Sender)
		}
		if err := verifyConfirmationCommitRevealChainCode(s.cfg.SessionID, confirmation.Sender, confirmation.ChainCode, slot.chainCodeCommit); err != nil {
			return nil, err
		}
	}
	chainCode, err := bip32util.AggregateChainCode(s.cfg.Parties, reveals)
	if err != nil {
		return nil, err
	}
	if s.importPlan != nil && !bytes.Equal(chainCode, s.importPlan.state.ChainCode) {
		clear(chainCode)
		return nil, errors.New("trusted-dealer import aggregate chain code mismatch")
	}
	finalShare := cloneKeyShareValue(pending)
	finalShare.state.ChainCode = chainCode
	if err := attachKeygenConfirmations(finalShare, ordered); err != nil {
		finalShare.Destroy()
		return nil, err
	}
	if err := finalShare.ValidateWithLimits(s.limits); err != nil {
		finalShare.Destroy()
		return nil, err
	}
	return &preparedPaperFinalKeyShare{share: finalShare, confirmationSetHash: keygenConfirmationSetHash(ordered)}, nil
}

func (s *KeygenSession) commitPaperFinalKeyShare(prepared *preparedPaperFinalKeyShare) {
	if prepared == nil {
		return
	}
	if s.pending != nil {
		s.pending.Destroy()
		s.pending = nil
	}
	if s.figure6 != nil {
		s.figure6.destroy()
		s.figure6 = nil
	}
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	destroyPaperConfirmationMap(s.paperConfirmations)
	s.paperConfirmations = nil
	s.keyShare = prepared.share
	s.completed = true
	s.state = keygenConfirmed
	prepared.committed = true
	publicKeyHash := sha256.Sum256(s.keyShare.state.PublicKey)
	s.cfg.Logger().Info(s.cfg.Ctx(), "paper keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", publicKeyHash[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", prepared.confirmationSetHash[:8]),
	)
}

func clonePaperConfirmationMap(in map[tss.PartyID]*KeygenConfirmation) map[tss.PartyID]*KeygenConfirmation {
	out := make(map[tss.PartyID]*KeygenConfirmation, len(in))
	for party, confirmation := range in {
		out[party] = confirmation.Clone()
	}
	return out
}

func destroyPaperConfirmationMap(in map[tss.PartyID]*KeygenConfirmation) {
	for party, confirmation := range in {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(in, party)
	}
}
