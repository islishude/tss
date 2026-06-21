package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func (s *ReshareSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.newShare != nil {
		if s.allReshareConfirmationsReceived() {
			return nil, s.finalizeConfirmedShare()
		}
		return nil, nil
	}
	if !s.allDealerCommitmentsReceived() {
		return nil, nil
	}
	if !s.isReceiver {
		newCommitments, err := s.aggregateCommitments()
		if err != nil {
			return nil, err
		}
		publicKey, err := secp.PointBytes(newCommitments[0])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(publicKey, s.oldPublicKey) {
			return nil, errors.New("reshared group public key does not match original")
		}
		if !s.allReshareConfirmationsReceived() {
			return nil, nil
		}
		for _, id := range s.newParties {
			c := s.newPartyData[id].confirmation
			if err := s.verifyReshareConfirmationForPublicTranscript(c, newCommitments); err != nil {
				return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, err)
			}
		}
		s.completed = true
		return nil, nil
	}
	if !s.allReshareDealerDataReceived() || !s.allReshareReceiverMaterialReceived() {
		return nil, nil
	}
	for _, dealer := range s.dealerParties {
		dd := s.dealerData[dealer]
		share, err := secpScalarFromSecret(dd.share)
		if err != nil {
			return nil, err
		}
		if err := secp.VerifyShare(dd.commitments, s.selfID, share); err != nil {
			verifyErr := err
			evidenceEnv, evErr := newEnvelope(s.dealerConfig(), reshareStartRound, dealer, s.selfID, payloadReshareShare, nil)
			if evErr != nil {
				return nil, evErr
			}
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: reshareStartRound,
				Party: dealer,
				Blame: newBlame(
					evidenceEnv,
					tss.EvidenceKindReshareShare,
					"invalid reshare share",
					tss.NewPartySet(dealer),
					rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.dealerParties, partySetHashLabel)),
					rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, dd.commitments)),
				),
				Err: verifyErr,
			}
		}
	}
	newSecret := secp.ScalarZero()
	for _, dealer := range s.dealerParties {
		share, err := secpScalarFromSecret(s.dealerData[dealer].share)
		if err != nil {
			return nil, err
		}
		newSecret = secp.ScalarAdd(newSecret, share)
	}
	newSecretScalar, err := secpSecretScalarFromScalar(newSecret)
	if err != nil {
		return nil, err
	}
	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		newSecretScalar.Destroy()
		return nil, err
	}
	publicKey, err := secp.PointBytes(newCommitments[0])
	if err != nil {
		newSecretScalar.Destroy()
		return nil, err
	}
	if !bytes.Equal(publicKey, s.oldPublicKey) {
		newSecretScalar.Destroy()
		return nil, errors.New("reshared group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := secp.EvalCommitmentPoints(newCommitments, id)
		if err != nil {
			return nil, err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash, err := s.reshareTranscriptHash(newCommitments)
	if err != nil {
		return nil, err
	}
	localVerificationShare, ok := verificationShareFor(verificationShares, s.selfID)
	if !ok {
		return nil, errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, newSecretScalar)
	if err != nil {
		newSecretScalar.Destroy()
		return nil, err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		newSecretScalar.Destroy()
		return nil, errors.New("local share proof public key mismatch")
	}
	selfNPD := s.newPartyData[s.selfID]
	localProofShare := &KeyShare{state: &keyShareState{
		securityParams: s.securityParams,
		party:          s.selfID,
		threshold:      s.newThreshold,
		parties:        s.newParties,
		publicKey:      publicKey,
		partyData: map[tss.PartyID]keySharePartyData{
			s.selfID: {paillierPublicKey: selfNPD.paillierPub.PublicKey.Clone()},
		},
		keygenTranscriptHash:   transcriptHash,
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelResharePaillier,
		resharePlanHash:        s.planHash,
		planHash:               bytes.Clone(s.planHash),
	}}
	paillierDomain, err := keySharePaillierProofDomain(localProofShare, s.limits)
	if err != nil {
		return nil, err
	}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), paillierDomain, s.newPaillier, s.selfID)
	if err != nil {
		return nil, err
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.newParties))
	for _, id := range s.newParties {
		verificationShare, ok := verificationShareFor(verificationShares, id)
		if !ok {
			return nil, fmt.Errorf("missing verification share for party %d", id)
		}
		sessionData := s.newPartyData[id]
		partyProof := sessionData.paillierPub.Proof
		if id == s.selfID {
			partyProof = paillierProof
		}
		partyData[id] = keySharePartyData{
			verificationShare:  bytes.Clone(verificationShare),
			paillierPublicKey:  sessionData.paillierPub.PublicKey.Clone(),
			paillierProof:      partyProof.Clone(),
			ringPedersenParams: sessionData.ringPedersen.Params.Clone(),
			ringPedersenProof:  sessionData.ringPedersen.Proof.Clone(),
		}
	}
	s.newShare = &KeyShare{state: &keyShareState{
		securityParams:         s.securityParams,
		party:                  s.selfID,
		threshold:              s.newThreshold,
		parties:                s.newParties.Clone(),
		publicKey:              bytes.Clone(publicKey),
		chainCode:              bytes.Clone(s.oldChainCode),
		secret:                 newSecretScalar,
		groupCommitments:       newCommitments,
		partyData:              partyData,
		paillierPrivateKey:     s.newPaillier.Clone(),
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelResharePaillier,
		resharePlanHash:        bytes.Clone(s.planHash),
		planHash:               bytes.Clone(s.planHash),
		shareProof:             shareProof.Clone(),
		keygenTranscriptHash:   transcriptHash,
	}}
	logCiphertext, logRandomness, err := s.newPaillier.EncryptSecret(s.cfg.Reader(), newSecretScalar)
	if err != nil {
		return nil, err
	}
	defer logRandomness.Destroy()
	localRP := selfNPD.ringPedersen.Params.Clone()
	logDomain, err := logProofDomain(localProofShare, &s.newPaillier.PublicKey, localVerificationShare, transcriptHash, s.limits)
	if err != nil {
		return nil, err
	}
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   &s.newPaillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarOne()),
		VerifierAux: *localRP,
	}
	logWitness := zkpai.LogStarWitness{X: newSecretScalar, Rho: logRandomness}
	logProof, err := zkpai.ProveLogStar(s.securityParams, logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	s.newShare.state.logCiphertext = cloneBigInt(logCiphertext)
	s.newShare.state.logProof = logProof.Clone()
	if err := s.newShare.validateWithoutConfirmations(s.limits); err != nil {
		return nil, err
	}
	confirmation, err := s.newShare.NewConfirmationWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	selfNPD.confirmation = confirmation
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	confirmationEnv, err := newEnvelope(s.receiverConfig(), keygenConfirmationRound, s.selfID, tss.BroadcastPartyId, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	s.log.Info(s.cfg.Ctx(), "reshare local material complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if s.allReshareConfirmationsReceived() {
		if err := s.finalizeConfirmedShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *ReshareSession) aggregateCommitments() ([]*secp.Point, error) {
	newCommitments := make([]*secp.Point, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*secp.Point, 0, len(s.dealerParties))
		for _, dealer := range s.dealerParties {
			commitment := s.dealerData[dealer].commitments[degree]
			p, err := secp.PointFromBytes(commitment)
			if err != nil {
				return nil, fmt.Errorf("invalid reshare commitment: dealer=%d degree=%d: %w", dealer, degree, err)
			}
			points = append(points, p)
		}
		newCommitments[degree] = secp.AddPoints(points...)
	}
	if newCommitments[0] == nil {
		return nil, errors.New("reshare produced empty group public key commitment")
	}
	return newCommitments, nil
}

func (s *ReshareSession) reshareTranscriptHash(newCommitments []*secp.Point) ([]byte, error) {
	newCommitmentBytes, err := secp.CommitmentPointsBytes(newCommitments)
	if err != nil {
		return nil, err
	}
	t := transcript.New(reshareTranscriptHashLabel)
	t.AppendString("curve", s.plan.state.curveID)
	t.AppendBytes("session_id", s.cfg.SessionID[:])
	t.AppendBytes("old_public_key", s.oldPublicKey)
	t.AppendBytesList("old_group_commitments", s.plan.state.oldGroupCommitments)
	sortedOldParties := tss.SortParties(s.oldParties)
	sortedDealerParties := tss.SortParties(s.dealerParties)
	sortedNewParties := tss.SortParties(s.newParties)
	t.AppendUint32List("old_parties", sortedOldParties)
	t.AppendUint32List("dealer_parties", sortedDealerParties)
	t.AppendUint32List("new_parties", sortedNewParties)
	t.AppendUint32("old_threshold", uint32(s.plan.state.oldThreshold))
	t.AppendUint32("new_threshold", uint32(s.newThreshold))
	t.AppendBytes("chain_code", s.plan.state.chainCode)
	t.AppendUint32("paillier_bits", uint32(s.plan.state.paillierBits))
	t.AppendBytes("plan_hash", s.planHash)
	for _, dealer := range sortedOldParties {
		t.AppendUint32("old_party", dealer)
		t.AppendBytes("old_verification_share", s.plan.state.oldVerificationShares[dealer])
	}
	for _, dealer := range sortedDealerParties {
		t.AppendUint32("dealer", dealer)
		t.AppendBytesList("dealer_commitments", s.dealerData[dealer].commitments)
	}
	for _, id := range sortedNewParties {
		t.AppendUint32("new_party", id)
		npd := s.newPartyData[id]
		paillierSnapshot, err := npd.paillierPub.snapshot(s.limits)
		if err != nil {
			return nil, err
		}
		ringPedersenSnapshot, err := npd.ringPedersen.snapshot(s.limits)
		if err != nil {
			return nil, err
		}
		t.AppendBytes("paillier_public_key", paillierSnapshot.PublicKey)
		t.AppendBytes("paillier_proof", paillierSnapshot.Proof)
		t.AppendBytes("ring_pedersen_params", ringPedersenSnapshot.Params)
		t.AppendBytes("ring_pedersen_proof", ringPedersenSnapshot.Proof)
	}
	t.AppendBytesList("new_commitments", newCommitmentBytes)
	return t.Sum(), nil
}

// allDealerCommitmentsReceived returns true when every dealer has submitted commitments.
func (s *ReshareSession) allDealerCommitmentsReceived() bool {
	for _, id := range s.dealerParties {
		dd := s.dealerData[id]
		if dd == nil || dd.commitments == nil {
			return false
		}
	}
	return true
}
