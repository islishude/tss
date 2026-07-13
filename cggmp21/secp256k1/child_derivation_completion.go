package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/zk/schnorr"
	"github.com/islishude/tss/tssrun"
)

type preparedChildDerivationOutput struct {
	share                *KeyShare
	confirmation         *KeygenConfirmation
	confirmationEnvelope tss.Envelope
	final                *KeyShare
	committed            bool
}

func (p *preparedChildDerivationOutput) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
	}
	if p.confirmation != nil {
		clear(p.confirmation.ChainCode)
	}
	clearEnvelope(&p.confirmationEnvelope)
	if p.final != nil {
		p.final.Destroy()
	}
}

func (s *ChildDerivationSession) prepareChildDerivationOutput(result *auxInfoResult) (*preparedChildDerivationOutput, error) {
	if s == nil || result == nil || result.epoch == nil || result.secret == nil {
		return nil, errors.New("child Figure 7 result is incomplete")
	}
	if result.epoch.SID != s.plan.ChildSID ||
		result.epoch.Threshold != s.plan.Threshold ||
		!bytes.Equal(result.publicKey, s.plan.Derivation.ChildPublicKey) {
		return nil, errors.New("child Figure 7 result does not match plan")
	}
	sourceEpochID, ok := result.epoch.SourceEpochIDBytes()
	if !ok || !bytes.Equal(sourceEpochID, s.plan.ParentBinding.EpochID[:]) {
		clear(sourceEpochID)
		return nil, errors.New("child Figure 7 result has wrong source epoch")
	}
	clear(sourceEpochID)
	shareProof, proofPublic, err := schnorr.Prove(result.transcriptHash, result.secret)
	if err != nil {
		return nil, err
	}
	localPublic, ok := result.epoch.PublicShare(s.cfg.Self)
	if !ok || !bytes.Equal(proofPublic, localPublic.PublicKey) {
		return nil, errors.New("child local share proof public key mismatch")
	}
	snapshot := result.clone()
	defer snapshot.destroy()
	share := &KeyShare{state: &keyShareState{
		SecurityParams:         s.securityParams,
		Party:                  s.cfg.Self,
		Threshold:              s.cfg.Threshold,
		Parties:                s.cfg.Parties.Clone(),
		PublicKey:              bytes.Clone(snapshot.publicKey),
		ChainCode:              bytes.Clone(s.plan.Derivation.ChildChainCode),
		Secret:                 snapshot.secret,
		GroupCommitments:       snapshot.commitments,
		PartyData:              snapshot.partyData,
		PaillierPrivateKey:     snapshot.paillier,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelChildPaillier,
		ShareProof:             shareProof.Clone(),
		PlanHash:               bytes.Clone(s.planHash),
		KeygenTranscriptHash:   bytes.Clone(snapshot.transcriptHash),
		Epoch:                  snapshot.epoch,
	}}
	snapshot.secret = nil
	snapshot.commitments = nil
	snapshot.partyData = nil
	snapshot.paillier = nil
	snapshot.epoch = nil
	prepared := &preparedChildDerivationOutput{share: share}
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
		return nil, fmt.Errorf("validate child Figure 7 output: %w", err)
	}
	confirmation, err := share.NewConfirmationWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	prepared.confirmation = confirmation
	encoded, err := confirmation.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	prepared.confirmationEnvelope, err = newEnvelope(
		s.cfg,
		childConfirmationRound,
		s.cfg.Self,
		tss.BroadcastPartyId,
		payloadChildConfirmation,
		encoded,
	)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	candidates := s.childConfirmationCandidates(tss.BroadcastPartyId, nil)
	defer destroyPaperConfirmationMap(candidates)
	candidates[s.cfg.Self] = confirmation.Clone()
	for party, candidate := range candidates {
		if err := verifyKeygenConfirmationForPreservedChainCode(share, candidate); err != nil {
			return nil, fmt.Errorf("buffered child confirmation from party %d: %w", party, err)
		}
	}
	if len(candidates) == len(s.cfg.Parties) {
		prepared.final, err = s.buildChildFinalKeyShare(share, candidates)
		if err != nil {
			return nil, err
		}
	}
	cleanup = false
	return prepared, nil
}

func (s *ChildDerivationSession) commitChildDerivationOutputLocked(prepared *preparedChildDerivationOutput) {
	if s == nil || prepared == nil {
		return
	}
	s.pending = prepared.share
	s.confirmations[s.cfg.Self] = prepared.confirmation
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	prepared.committed = true
}

func (s *ChildDerivationSession) childConfirmationCandidates(overrideParty tss.PartyID, override *KeygenConfirmation) map[tss.PartyID]*KeygenConfirmation {
	out := make(map[tss.PartyID]*KeygenConfirmation, len(s.confirmations))
	for party, confirmation := range s.confirmations {
		if party == overrideParty {
			continue
		}
		if confirmation != nil {
			out[party] = confirmation.Clone()
		}
	}
	// A newly received confirmation has no pre-existing map slot. Insert the
	// override after cloning committed candidates so the transition can prepare
	// and validate the complete set before mutating accepted state.
	if override != nil {
		out[overrideParty] = override.Clone()
	}
	return out
}

func (s *ChildDerivationSession) buildChildFinalKeyShare(pending *KeyShare, confirmations map[tss.PartyID]*KeygenConfirmation) (*KeyShare, error) {
	if pending == nil || len(confirmations) != len(s.cfg.Parties) {
		return nil, errors.New("incomplete child confirmation set")
	}
	ordered := make([]*KeygenConfirmation, len(s.cfg.Parties))
	for i, party := range s.cfg.Parties {
		confirmation := confirmations[party]
		if confirmation == nil {
			return nil, fmt.Errorf("missing child confirmation from party %d", party)
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
	final := cloneKeyShareValue(pending)
	if err := attachKeygenConfirmations(final, ordered); err != nil {
		final.Destroy()
		return nil, err
	}
	if err := final.ValidateWithLimits(s.limits); err != nil {
		final.Destroy()
		return nil, err
	}
	return final, nil
}

func (s *ChildDerivationSession) persistChildGenerationLocked(final *KeyShare) error {
	if s == nil || final == nil || final.state == nil || final.state.Epoch == nil {
		return errors.New("invalid child generation persistence input")
	}
	defer final.Destroy()
	epochID, err := tssrun.NewEpochID(final.state.Epoch.EpochID)
	if err != nil {
		return err
	}
	binding := tssrun.GenerationBinding{
		KeyID:         s.plan.TargetKeyID,
		KeyGeneration: s.plan.TargetKeyGeneration,
		EpochID:       epochID,
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	if binding.KeyID == s.plan.ParentBinding.KeyID || binding.EpochID == s.plan.ParentBinding.EpochID {
		return errors.New("child generation must be distinct from parent")
	}
	blob, err := final.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return err
	}
	defer clear(blob)
	metadata := bytes.Clone(s.planHash)
	defer clear(metadata)
	storeCtx, cancel := durableStoreContext(s.cfg.Ctx(), s.storeTimeout)
	record, err := s.store.CommitInitialGenerationFromLease(storeCtx, s.lease, binding, blob, metadata)
	cancel()
	if err != nil {
		return err
	}
	defer clear(record.Blob)
	defer clear(record.Metadata)
	if record.Status != tssrun.GenerationCurrent || record.Binding != binding ||
		!bytes.Equal(record.Blob, blob) || !bytes.Equal(record.Metadata, metadata) {
		return fmt.Errorf("%w: child generation commit returned mismatched record", tssrun.ErrLifecycleCorrupt)
	}
	s.leaseFinished = true
	s.completed = true
	s.aborted = false
	s.installed = new(tssrun.GenerationBinding)
	*s.installed = binding
	if s.pending != nil {
		s.pending.Destroy()
		s.pending = nil
	}
	for party, confirmation := range s.confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(s.confirmations, party)
	}
	return nil
}
