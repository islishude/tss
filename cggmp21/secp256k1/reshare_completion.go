package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/zk/schnorr"
)

// tryComplete advances the public handoff boundary. Receiver parties do not
// create a KeyShare here: the verified handoff is converted to one additive
// contribution and passed into a complete Figure 7/F.1 execution first.
func (s *ReshareSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if !s.isReceiver {
		return nil, s.tryCompleteDealerOnly()
	}
	if s.newShare != nil {
		if s.allReshareConfirmationsReceived() {
			return nil, s.finalizeConfirmedShare()
		}
		return nil, nil
	}
	if s.auxInfo != nil {
		return nil, nil
	}
	if !s.allReshareDealerDataReceived() || !s.allReshareReceiverMaterialReceived() || !s.allReshareFactorProofsReceived() {
		return nil, nil
	}
	return s.startReshareAuxInfo()
}

func (s *ReshareSession) tryCompleteDealerOnly() error {
	if !s.allDealerCommitmentsReceived() {
		return nil
	}
	commitments, err := s.aggregateCommitments()
	if err != nil {
		return err
	}
	publicKey, err := secp.PointBytes(commitments[0])
	if err != nil {
		return err
	}
	if !bytes.Equal(publicKey, s.oldPublicKey) {
		return errors.New("reshared dealer handoff changed the group public key")
	}
	if !s.allReshareConfirmationsReceived() {
		return nil
	}
	var reference *KeygenConfirmation
	for _, party := range s.newParties {
		confirmation := s.newPartyData[party].confirmation
		if err := s.verifyReshareConfirmationPublicBinding(confirmation); err != nil {
			return tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, party, err)
		}
		if reference == nil {
			reference = confirmation
			continue
		}
		if err := compareKeygenConfirmationBindingFields(reference, confirmation); err != nil {
			return tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, party, err)
		}
		if !bytes.Equal(reference.ChainCode, confirmation.ChainCode) {
			return tss.NewProtocolError(tss.ErrCodeVerification, reshareConfirmationRound, party, errors.New("reshare confirmations disagree on preserved chain code"))
		}
	}
	s.cleanupTemporaryReshareHandoff()
	return s.stageReshareRetirement(reference)
}

func (s *ReshareSession) startReshareAuxInfo() ([]tss.Envelope, error) {
	expected, err := s.expectedReshareContributions()
	if err != nil {
		return nil, err
	}
	for _, dealer := range s.dealerParties {
		share, err := secpScalarFromSecretAllowZero(s.dealerData[dealer].share)
		if err != nil {
			return nil, err
		}
		dealerExpected, err := s.expectedDealerContribution(dealer, s.selfID)
		if err != nil {
			return nil, err
		}
		if !secp.Equal(secp.ScalarBaseMult(share), dealerExpected) {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, dealer, errors.New("verified temporary reshare contribution no longer matches dealer commitments"))
		}
	}
	additive := secp.ScalarZero()
	for _, dealer := range s.dealerParties {
		share, err := secpScalarFromSecretAllowZero(s.dealerData[dealer].share)
		if err != nil {
			return nil, err
		}
		additive = secp.ScalarAdd(additive, share)
	}
	contribution, err := secpSecretScalarFromScalar(additive)
	if err != nil {
		return nil, errors.New("reshare additive handoff contribution is zero")
	}
	defer contribution.Destroy()
	localExpected, ok := expected[s.selfID]
	if !ok {
		return nil, errors.New("missing local expected reshare contribution")
	}
	localExpectedPoint, err := secp.PointFromBytes(localExpected)
	if err != nil {
		return nil, err
	}
	if !secp.Equal(secp.ScalarBaseMult(additive), localExpectedPoint) {
		return nil, errors.New("aggregated reshare contribution does not match public dealer handoff")
	}
	auxInfo, out, err := startAuxInfo(auxInfoStartOption{
		Config:                s.receiverConfig(),
		StableSID:             s.plan.state.SourceEpoch.SID,
		Limits:                s.limits,
		SecurityParams:        s.securityParams,
		EnvelopeVerifier:      s.guard.EnvelopeVerifier,
		PaillierBits:          s.plan.state.PaillierBits,
		PlanHash:              s.planHash,
		SourceEpochID:         s.plan.state.SourceEpochID,
		ExpectedPublicKey:     s.oldPublicKey,
		ExpectedContributions: expected,
		Contribution:          contribution,
		Schedule: auxInfoSchedule{
			CommitmentRound: reshareAuxInfoCommitmentRound,
			RevealRound:     reshareAuxInfoRevealRound,
			ProofRound:      reshareAuxInfoProofRound,
		},
	})
	if err != nil {
		return nil, err
	}
	s.auxInfo = auxInfo
	s.cleanupTemporaryReshareHandoff()
	return out, nil
}

// expectedReshareContributions calculates each target party's public additive
// input λ_j F(id_j), where F is the aggregate dealer handoff polynomial.
func (s *ReshareSession) expectedReshareContributions() (map[tss.PartyID][]byte, error) {
	if !s.allDealerCommitmentsReceived() {
		return nil, errors.New("reshare dealer commitments are incomplete")
	}
	out := make(map[tss.PartyID][]byte, len(s.newParties))
	points := make([]*secp.Point, 0, len(s.newParties))
	for _, party := range s.newParties {
		perDealer := make([]*secp.Point, 0, len(s.dealerParties))
		for _, dealer := range s.dealerParties {
			point, err := s.expectedDealerContribution(dealer, party)
			if err != nil {
				return nil, err
			}
			perDealer = append(perDealer, point)
		}
		aggregate := secp.AddPoints(perDealer...)
		encoded, err := secp.PointBytes(aggregate)
		if err != nil {
			return nil, fmt.Errorf("encode expected additive contribution for party %d: %w", party, err)
		}
		out[party] = encoded
		points = append(points, aggregate)
	}
	publicKey, err := secp.PointBytes(secp.AddPoints(points...))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(publicKey, s.oldPublicKey) {
		return nil, errors.New("target additive contributions do not reconstruct the source public key")
	}
	return out, nil
}

func (s *ReshareSession) expectedDealerContribution(dealer, target tss.PartyID) (*secp.Point, error) {
	data := s.dealerData[dealer]
	if data == nil || data.commitments == nil {
		return nil, fmt.Errorf("missing commitments for dealer %d", dealer)
	}
	identifier, ok := s.provisionalIDs[target]
	if !ok {
		return nil, fmt.Errorf("missing provisional identifier for party %d", target)
	}
	evaluation, err := evaluateEncodedCommitmentsAtIdentifier(data.commitments, identifier)
	if err != nil {
		return nil, err
	}
	lambda, err := provisionalLagrangeCoefficient(s.provisionalIDs, target, s.newParties)
	if err != nil {
		return nil, err
	}
	return secp.ScalarMult(evaluation, lambda), nil
}

type preparedReshareOutput struct {
	share                *KeyShare
	confirmation         *KeygenConfirmation
	confirmationEnvelope tss.Envelope
	final                *preparedPaperFinalKeyShare
	committed            bool
}

func (p *preparedReshareOutput) destroy() {
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

func (s *ReshareSession) prepareReshareOutput(result *auxInfoResult) (*preparedReshareOutput, error) {
	if result == nil || result.epoch == nil {
		return nil, errors.New("reshare Figure 7 result is incomplete")
	}
	resultSourceEpochID, ok := result.epoch.SourceEpochIDBytes()
	if !ok || !bytes.Equal(resultSourceEpochID, s.plan.state.SourceEpochID) {
		return nil, errors.New("reshare Figure 7 output source epoch mismatch")
	}
	shareProof, proofPublic, err := schnorr.Prove(result.transcriptHash, result.secret)
	if err != nil {
		return nil, err
	}
	localPublic, ok := result.epoch.PublicShare(s.selfID)
	if !ok || !bytes.Equal(proofPublic, localPublic.PublicKey) {
		return nil, errors.New("reshared local share proof public key mismatch")
	}
	snapshot := result.clone()
	defer snapshot.destroy()
	share := &KeyShare{state: &keyShareState{
		SecurityParams:         s.securityParams,
		Party:                  s.selfID,
		Threshold:              s.newThreshold,
		Parties:                s.newParties.Clone(),
		PublicKey:              bytes.Clone(snapshot.publicKey),
		ChainCode:              bytes.Clone(s.oldChainCode),
		Secret:                 snapshot.secret,
		GroupCommitments:       snapshot.commitments,
		PartyData:              snapshot.partyData,
		PaillierPrivateKey:     snapshot.paillier,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
		ResharePlanHash:        bytes.Clone(s.planHash),
		PlanHash:               bytes.Clone(s.planHash),
		ShareProof:             shareProof.Clone(),
		KeygenTranscriptHash:   bytes.Clone(result.transcriptHash),
		Epoch:                  snapshot.epoch,
	}}
	snapshot.secret = nil
	snapshot.commitments = nil
	snapshot.partyData = nil
	snapshot.paillier = nil
	snapshot.epoch = nil
	prepared := &preparedReshareOutput{share: share}
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
		return nil, fmt.Errorf("validate reshared Figure 7 output: %w", err)
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
	prepared.confirmationEnvelope, err = newEnvelope(s.receiverConfig(), reshareConfirmationRound, s.selfID, tss.BroadcastPartyId, payloadKeygenConfirmation, encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	confirmations := s.reshareConfirmationCandidates(tss.BroadcastPartyId, nil)
	defer destroyPaperConfirmationMap(confirmations)
	confirmations[s.selfID] = confirmation.Clone()
	for party, candidate := range confirmations {
		if err := verifyKeygenConfirmationForPreservedChainCode(share, candidate); err != nil {
			return nil, fmt.Errorf("buffered reshare confirmation from party %d: %w", party, err)
		}
	}
	if len(confirmations) == len(s.newParties) {
		prepared.final, err = s.buildReshareFinalKeyShare(share, confirmations)
		if err != nil {
			return nil, err
		}
	}
	cleanup = false
	return prepared, nil
}

func (s *ReshareSession) commitReshareOutput(prepared *preparedReshareOutput) error {
	s.newShare = prepared.share
	s.newPartyData[s.selfID].confirmation = prepared.confirmation
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	prepared.committed = true
	if prepared.final != nil {
		if err := s.commitReshareFinalKeyShare(prepared.final); err != nil {
			return err
		}
	}
	return nil
}

func (s *ReshareSession) reshareConfirmationCandidates(overrideParty tss.PartyID, override *KeygenConfirmation) map[tss.PartyID]*KeygenConfirmation {
	out := make(map[tss.PartyID]*KeygenConfirmation, len(s.newPartyData))
	for party, data := range s.newPartyData {
		if party == overrideParty {
			if override != nil {
				out[party] = override.Clone()
			}
			continue
		}
		if data != nil && data.confirmation != nil {
			out[party] = data.confirmation.Clone()
		}
	}
	return out
}

func (s *ReshareSession) buildReshareFinalKeyShare(pending *KeyShare, confirmations map[tss.PartyID]*KeygenConfirmation) (*preparedPaperFinalKeyShare, error) {
	if pending == nil || len(confirmations) != len(s.newParties) {
		return nil, errors.New("incomplete reshare confirmation set")
	}
	ordered := make([]*KeygenConfirmation, len(s.newParties))
	for i, party := range s.newParties {
		confirmation := confirmations[party]
		if confirmation == nil {
			return nil, fmt.Errorf("missing reshare confirmation from party %d", party)
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

func (s *ReshareSession) commitReshareFinalKeyShare(prepared *preparedPaperFinalKeyShare) error {
	if prepared == nil {
		return errors.New("nil reshared final key share")
	}
	return s.stageReshareFinal(prepared)
}

func (s *ReshareSession) aggregateCommitments() ([]*secp.Point, error) {
	newCommitments := make([]*secp.Point, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*secp.Point, 0, len(s.dealerParties))
		for _, dealer := range s.dealerParties {
			data := s.dealerData[dealer]
			if data == nil || len(data.commitments) != s.newThreshold {
				return nil, fmt.Errorf("missing reshare commitments for dealer %d", dealer)
			}
			point, err := secp.PointFromBytes(data.commitments[degree])
			if err != nil {
				return nil, fmt.Errorf("invalid reshare commitment: dealer=%d degree=%d: %w", dealer, degree, err)
			}
			points = append(points, point)
		}
		newCommitments[degree] = secp.AddPoints(points...)
	}
	if newCommitments[0] == nil {
		return nil, errors.New("reshare produced empty group public key commitment")
	}
	return newCommitments, nil
}

// allDealerCommitmentsReceived returns true when every dealer has submitted commitments.
func (s *ReshareSession) allDealerCommitmentsReceived() bool {
	for _, id := range s.dealerParties {
		data := s.dealerData[id]
		if data == nil || data.commitments == nil {
			return false
		}
	}
	return true
}

func (s *ReshareSession) allReshareFactorProofsReceived() bool {
	for _, party := range s.newParties {
		if party == s.selfID {
			continue
		}
		data := s.newPartyData[party]
		if data == nil || data.factorProof == nil || data.factorKey == nil {
			return false
		}
	}
	return true
}

func (s *ReshareSession) cleanupTemporaryReshareHandoff() {
	for _, data := range s.dealerData {
		if data != nil && data.share != nil {
			data.share.Destroy()
			data.share = nil
		}
	}
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	for _, data := range s.newPartyData {
		if data == nil {
			continue
		}
		data.paillierPub = paillierPublicMaterial{}
		data.ringPedersen = ringPedersenPublicMaterial{}
		data.factorProof = nil
		data.factorKey = nil
	}
}
