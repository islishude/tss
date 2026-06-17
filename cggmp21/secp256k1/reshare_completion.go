package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

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
		if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
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
		if err := secp.VerifyShare(dd.commitments, s.selfID, secp.ScalarFromBigInt(dd.share)); err != nil {
			verifyErr := err
			evidenceEnv, evErr := newEnvelope(s.dealerConfig(), 1, dealer, s.selfID, payloadReshareShare, nil)
			if evErr != nil {
				return nil, evErr
			}
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
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
	order := secp.Order()
	newSecret := new(big.Int)
	for _, dealer := range s.dealerParties {
		newSecret.Add(newSecret, s.dealerData[dealer].share)
		newSecret.Mod(newSecret, order)
	}
	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
		return nil, errors.New("reshared group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := secp.EvalCommitments(newCommitments, id)
		if err != nil {
			return nil, err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.reshareTranscriptHash(newCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.selfID)
	if !ok {
		return nil, errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, newSecret)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		return nil, errors.New("local share proof public key mismatch")
	}
	shareProofBytes, err := shareProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	selfNPD := s.newPartyData[s.selfID]
	localProofShare := &KeyShare{state: &keyShareState{
		securityParams:         s.securityParams,
		party:                  s.selfID,
		threshold:              s.newThreshold,
		parties:                s.newParties,
		publicKey:              newCommitments[0],
		paillierPublicKey:      selfNPD.paillierPub.PublicKey,
		keygenTranscriptHash:   transcriptHash,
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelResharePaillier,
		resharePlanHash:        s.planHash,
		planHash:               append([]byte(nil), s.planHash...),
	}}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.newPaillier, s.selfID)
	if err != nil {
		return nil, err
	}
	paillierProofBytes, err := zkpai.Marshal(paillierProof)
	if err != nil {
		return nil, err
	}
	newSecretScalar, err := secpSecretScalarFromBig(newSecret)
	if err != nil {
		return nil, err
	}
	newPaillierPriv, err := s.newPaillier.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.newShare = &KeyShare{state: &keyShareState{
		securityParams:         s.securityParams,
		party:                  s.selfID,
		threshold:              s.newThreshold,
		parties:                s.newParties.Clone(),
		publicKey:              append([]byte(nil), newCommitments[0]...),
		chainCode:              append([]byte(nil), s.oldChainCode...),
		secret:                 newSecretScalar,
		groupCommitments:       newCommitments,
		verificationShares:     verificationShares,
		paillierPublicKey:      append([]byte(nil), selfNPD.paillierPub.PublicKey...),
		paillierPrivateKey:     newPaillierPriv,
		paillierProof:          paillierProofBytes,
		paillierPublicKeys:     s.sortedNewPaillierPublicKeys(),
		ringPedersenParams:     append([]byte(nil), selfNPD.ringPedersen.Params...),
		ringPedersenProof:      append([]byte(nil), selfNPD.ringPedersen.Proof...),
		ringPedersenPublic:     s.sortedNewRingPedersenPublic(),
		paillierProofSessionID: s.cfg.SessionID,
		paillierProofDomain:    domainLabelResharePaillier,
		resharePlanHash:        append([]byte(nil), s.planHash...),
		planHash:               append([]byte(nil), s.planHash...),
		shareProof:             shareProofBytes,
		keygenTranscriptHash:   transcriptHash,
	}}
	logCiphertext, logRandomness, err := s.newPaillier.Encrypt(s.cfg.Reader(), newSecret)
	if err != nil {
		return nil, err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(selfNPD.ringPedersen.Params, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return nil, fmt.Errorf("unmarshal local RP params: %w", err)
	}
	logDomain := logProofDomain(localProofShare, &s.newPaillier.PublicKey, localVerificationShare, transcriptHash)
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   &s.newPaillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: *localRP,
	}
	logWitness := zkpai.LogStarWitness{
		X:   new(big.Int).Set(newSecret),
		Rho: new(big.Int).Set(logRandomness),
	}
	logProof, err := zkpai.ProveLogStar(s.securityParams, logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	logProofBytes, err := logProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.newShare.state.logCiphertext = logCiphertext.Bytes()
	s.newShare.state.logProof = logProofBytes
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

func (s *ReshareSession) aggregateCommitments() ([][]byte, error) {
	newCommitments := make([][]byte, s.newThreshold)
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
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return nil, err
		}
		newCommitments[degree] = enc
	}
	if len(newCommitments[0]) == 0 {
		return nil, errors.New("reshare produced empty group public key commitment")
	}
	return newCommitments, nil
}

func (s *ReshareSession) reshareTranscriptHash(newCommitments [][]byte) []byte {
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
		t.AppendBytes("paillier_public_key", npd.paillierPub.PublicKey)
		t.AppendBytes("paillier_proof", npd.paillierPub.Proof)
		t.AppendBytes("ring_pedersen_params", npd.ringPedersen.Params)
		t.AppendBytes("ring_pedersen_proof", npd.ringPedersen.Proof)
	}
	t.AppendBytesList("new_commitments", newCommitments)
	return t.Sum()
}

func (s *ReshareSession) sortedNewPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		npd := s.newPartyData[id]
		out = append(out, PaillierPublicShare{
			Party:     npd.paillierPub.Party,
			PublicKey: append([]byte(nil), npd.paillierPub.PublicKey...),
			Proof:     append([]byte(nil), npd.paillierPub.Proof...),
		})
	}
	return out
}

func (s *ReshareSession) sortedNewRingPedersenPublic() []RingPedersenPublicShare {
	out := make([]RingPedersenPublicShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		npd := s.newPartyData[id]
		out = append(out, RingPedersenPublicShare{
			Party:  npd.ringPedersen.Party,
			Params: append([]byte(nil), npd.ringPedersen.Params...),
			Proof:  append([]byte(nil), npd.ringPedersen.Proof...),
		})
	}
	return out
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
