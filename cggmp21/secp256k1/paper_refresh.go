package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func startPaperRefresh(oldKey *KeyShare, plan *RefreshPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*RefreshSession, []tss.Envelope, error) {
	if oldKey == nil || oldKey.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil old key share"))
	}
	if plan == nil || plan.state == nil {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("nil refresh plan"))
	}
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, invalidRound, local.Self, err)
	}
	config.Parties = config.SortedParties()
	if local.Self != oldKey.state.Party {
		return nil, nil, invalidPlanConfig(local.Self, errors.New("local self must match the old key's party ID"))
	}
	if err := config.ValidateWithLimits(plan.limits.ThresholdLimits()); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := validateRefreshSourceKey(oldKey, plan); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(guard, tss.ProtocolCGGMP21Secp256k1, config.SessionID, config.Self); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	if err := requireLocalEnvelopeSigner(guard, local.EnvelopeSigner); err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	oldSecret, err := secpScalarFromSecret(oldKey.state.Secret)
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	lagrange, err := epochLagrangeCoefficient(oldKey.state.Epoch, oldKey.state.Party, oldKey.state.Parties)
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, fmt.Errorf("derive all-party additive refresh share: %w", err))
	}
	contribution, err := secpSecretScalarFromScalar(secp.ScalarMul(lagrange, oldSecret))
	if err != nil {
		return nil, nil, invalidPlanConfig(local.Self, err)
	}
	defer contribution.Destroy()
	auxInfo, out, err := startAuxInfo(auxInfoStartOption{
		Config:            config,
		StableSID:         oldKey.state.Epoch.SID,
		Limits:            plan.limits,
		SecurityParams:    plan.securityParams,
		EnvelopeVerifier:  guard.EnvelopeVerifier,
		PaillierBits:      plan.state.paillierBits,
		PlanHash:          planHash,
		SourceEpochID:     oldKey.state.Epoch.EpochID,
		ExpectedPublicKey: oldKey.state.PublicKey,
		Contribution:      contribution,
		Schedule: auxInfoSchedule{
			CommitmentRound: refreshAuxInfoCommitmentRound,
			RevealRound:     refreshAuxInfoRevealRound,
			ProofRound:      refreshAuxInfoProofRound,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	partyData := make(map[tss.PartyID]*refreshPartyData, len(config.Parties))
	for _, party := range config.Parties {
		partyData[party] = new(refreshPartyData)
	}
	session := &RefreshSession{
		oldKey:         oldKey,
		cfg:            config,
		log:            config.Logger(),
		limits:         plan.limits,
		securityParams: plan.securityParams,
		planHash:       bytes.Clone(planHash),
		partyData:      partyData,
		guard:          guard,
		auxInfo:        auxInfo,
		accepted:       make(map[paperKeygenMessageKey]struct{}, 4*len(config.Parties)),
	}
	return session, out, nil
}

func validateRefreshSourceKey(oldKey *KeyShare, plan *RefreshPlan) error {
	if oldKey == nil || oldKey.state == nil || plan == nil || plan.state == nil {
		return errors.New("nil refresh source key or plan")
	}
	if err := oldKey.requireMPCMaterial(plan.limits); err != nil {
		return err
	}
	if oldKey.state.Epoch == nil || !bytes.Equal(plan.state.sourceEpochID, oldKey.state.Epoch.EpochID) {
		return errors.New("refresh source epoch mismatch")
	}
	commitmentsHash, err := keygenCommitmentsHash(oldKey.state.GroupCommitments)
	if err != nil {
		return fmt.Errorf("hash refresh source commitments: %w", err)
	}
	if oldKey.state.Threshold != plan.state.threshold || !sameParties(oldKey.state.Parties, plan.state.parties) ||
		!bytes.Equal(oldKey.state.PublicKey, plan.state.publicKey) ||
		!bytes.Equal(oldKey.state.ChainCode, plan.state.chainCode) ||
		oldKey.state.PaillierProofSessionID != plan.state.oldPaillierProofSession ||
		!bytes.Equal(oldKey.state.KeygenTranscriptHash, plan.state.oldKeygenTranscriptHash) ||
		!bytes.Equal(oldKey.state.PlanHash, plan.state.oldPlanHash) ||
		!bytes.Equal(commitmentsHash, plan.state.oldCommitmentsHash) ||
		oldKey.state.SecurityParams != plan.securityParams {
		return errors.New("refresh source key does not exactly match plan")
	}
	return nil
}

type preparedPaperRefreshOutput struct {
	share                *KeyShare
	confirmation         *KeygenConfirmation
	confirmationEnvelope tss.Envelope
	final                *preparedPaperFinalKeyShare
	committed            bool
}

func (p *preparedPaperRefreshOutput) destroy() {
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

func (s *RefreshSession) preparePaperRefreshOutput(result *auxInfoResult) (*preparedPaperRefreshOutput, error) {
	if result == nil || result.epoch == nil {
		return nil, errors.New("auxinfo refresh result is incomplete")
	}
	shareProof, proofPublic, err := schnorr.Prove(result.transcriptHash, result.secret)
	if err != nil {
		return nil, err
	}
	localPublic, ok := result.epoch.PublicShare(s.cfg.Self)
	if !ok || !bytes.Equal(proofPublic, localPublic.PublicKey) {
		return nil, errors.New("refreshed local share proof public key mismatch")
	}
	snapshot := result.clone()
	defer snapshot.destroy()
	share := &KeyShare{state: &keyShareState{
		SecurityParams:         s.securityParams,
		Party:                  s.cfg.Self,
		Threshold:              s.cfg.Threshold,
		Parties:                s.cfg.Parties.Clone(),
		PublicKey:              bytes.Clone(snapshot.publicKey),
		ChainCode:              bytes.Clone(s.oldKey.state.ChainCode),
		Secret:                 snapshot.secret,
		GroupCommitments:       snapshot.commitments,
		PartyData:              snapshot.partyData,
		PaillierPrivateKey:     snapshot.paillier,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelRefreshPaillier,
		ShareProof:             shareProof.Clone(),
		PlanHash:               bytes.Clone(s.planHash),
		KeygenTranscriptHash:   bytes.Clone(result.transcriptHash),
		Epoch:                  snapshot.epoch,
	}}
	snapshot.secret = nil
	snapshot.commitments = nil
	snapshot.partyData = nil
	snapshot.paillier = nil
	snapshot.epoch = nil
	prepared := &preparedPaperRefreshOutput{share: share}
	cleanup := true
	defer func() {
		if cleanup {
			prepared.destroy()
		}
	}()
	if err := finalizeSignReadyKeyShareProofs(s.cfg.Reader(), share, s.limits); err != nil {
		return nil, err
	}
	if err := share.validateWithoutConfirmations(s.limits); err != nil {
		return nil, fmt.Errorf("validate Figure 7 refresh output: %w", err)
	}
	confirmation, err := share.NewConfirmationWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	prepared.confirmation = confirmation
	encoded, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	prepared.confirmationEnvelope, err = newEnvelope(s.cfg, refreshConfirmationRound, s.cfg.Self, tss.BroadcastPartyId, payloadKeygenConfirmation, encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	confirmations := s.refreshConfirmationCandidates(tss.BroadcastPartyId, nil)
	defer destroyPaperConfirmationMap(confirmations)
	confirmations[s.cfg.Self] = confirmation.Clone()
	for party, candidate := range confirmations {
		if err := verifyKeygenConfirmationForPreservedChainCode(share, candidate); err != nil {
			return nil, fmt.Errorf("buffered refresh confirmation from party %d: %w", party, err)
		}
	}
	if len(confirmations) == len(s.cfg.Parties) {
		prepared.final, err = s.buildPaperRefreshFinalKeyShare(share, confirmations)
		if err != nil {
			return nil, err
		}
	}
	cleanup = false
	return prepared, nil
}

func (s *RefreshSession) commitPaperRefreshOutput(prepared *preparedPaperRefreshOutput) error {
	s.newShare = prepared.share
	s.partyData[s.cfg.Self].confirmation = prepared.confirmation
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	prepared.committed = true
	if prepared.final != nil {
		s.lifecycleOutbox = []tss.Envelope{prepared.confirmationEnvelope.Clone()}
		if err := s.commitPaperRefreshFinalKeyShare(prepared.final); err != nil {
			return err
		}
		clearLifecycleEnvelopes(s.lifecycleOutbox)
		s.lifecycleOutbox = nil
	}
	return nil
}

func (s *RefreshSession) refreshConfirmationCandidates(overrideParty tss.PartyID, override *KeygenConfirmation) map[tss.PartyID]*KeygenConfirmation {
	out := make(map[tss.PartyID]*KeygenConfirmation, len(s.partyData))
	for party, pd := range s.partyData {
		if party == overrideParty {
			if override != nil {
				out[party] = override.Clone()
			}
			continue
		}
		if pd != nil && pd.confirmation != nil {
			out[party] = pd.confirmation.Clone()
		}
	}
	return out
}

func (s *RefreshSession) buildPaperRefreshFinalKeyShare(pending *KeyShare, confirmations map[tss.PartyID]*KeygenConfirmation) (*preparedPaperFinalKeyShare, error) {
	if pending == nil || len(confirmations) != len(s.cfg.Parties) {
		return nil, errors.New("incomplete refresh confirmation set")
	}
	ordered := make([]*KeygenConfirmation, len(s.cfg.Parties))
	for i, party := range s.cfg.Parties {
		confirmation := confirmations[party]
		if confirmation == nil {
			return nil, fmt.Errorf("missing refresh confirmation from party %d", party)
		}
		ordered[i] = confirmation.Clone()
	}
	defer func() {
		for _, confirmation := range ordered {
			clear(confirmation.ChainCode)
		}
	}()
	if err := verifyKeygenConfirmationSetPreservedChainCodeStruct(pending, ordered); err != nil {
		return nil, err
	}
	finalShare := cloneKeyShareValue(pending)
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

func (s *RefreshSession) commitPaperRefreshFinalKeyShare(prepared *preparedPaperFinalKeyShare) error {
	if prepared == nil {
		return errors.New("nil refreshed final key share")
	}
	return s.stageAndCommitRefreshFinal(s.cfg.Ctx(), prepared)
}
