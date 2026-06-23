package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

func (s *RefreshSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.newShare != nil {
		if s.allRefreshConfirmationsReceived() {
			return nil, s.finalizeConfirmedShare()
		}
		return nil, nil
	}
	if !s.allRefreshRound1Complete() {
		return nil, nil
	}
	for _, dealer := range s.oldKey.state.Parties {
		pd := s.partyData[dealer]
		share, err := secpScalarFromSecretAllowZero(pd.share)
		if err != nil {
			return nil, err
		}
		if err := secp.VerifyShare(pd.commitments, s.oldKey.state.Party, share); err != nil {
			verifyErr := err
			evidenceEnv, evErr := newEnvelope(s.cfg, refreshStartRound, dealer, s.oldKey.state.Party, payloadRefreshShare, nil)
			if evErr != nil {
				return nil, evErr
			}
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: refreshStartRound,
				Party: dealer,
				Blame: newBlame(
					evidenceEnv,
					tss.EvidenceKindRefreshShare,
					"invalid refresh share",
					tss.NewPartySet(dealer),
					rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.oldKey.state.Parties, partySetHashLabel)),
					rawEvidenceField(evidenceFieldCommitmentsHash, transcript.ByteSlicesHash(refreshCommitmentsHashLabel, pd.commitments)),
				),
				Err: verifyErr,
			}
		}
	}
	newSecret, err := secpScalarFromSecret(s.oldKey.state.Secret)
	if err != nil {
		return nil, err
	}
	for _, dealer := range s.oldKey.state.Parties {
		share, err := secpScalarFromSecretAllowZero(s.partyData[dealer].share)
		if err != nil {
			return nil, err
		}
		newSecret = secp.ScalarAdd(newSecret, share)
	}
	newSecretScalar, err := secpSecretScalarFromScalar(newSecret)
	if err != nil {
		return nil, err
	}
	newCommitments := make([]*secp.Point, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*secp.Point, 0, len(s.oldKey.state.Parties))
		for _, dealer := range s.oldKey.state.Parties {
			if len(s.partyData[dealer].commitments[degree]) == 0 {
				continue
			}
			p, err := secp.PointFromBytes(s.partyData[dealer].commitments[degree])
			if err != nil {
				return nil, err
			}
			points = append(points, p)
		}
		if degree < len(s.oldKey.state.GroupCommitments) {
			if oldCommitment := s.oldKey.state.GroupCommitments[degree]; oldCommitment != nil {
				points = append(points, oldCommitment)
			}
		}
		if len(points) == 0 {
			newCommitments[degree] = nil
			continue
		}
		newCommitments[degree] = secp.AddPoints(points...)
	}
	publicKey, err := secp.PointBytes(newCommitments[0])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(publicKey, s.oldKey.state.PublicKey) {
		return nil, errors.New("refreshed group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.oldKey.state.Parties))
	for _, id := range s.oldKey.state.Parties {
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
	transcriptHash, err := s.refreshTranscriptHash(newCommitments)
	if err != nil {
		return nil, err
	}
	localVerificationShare, ok := verificationShareFor(verificationShares, s.oldKey.state.Party)
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
	selfPD := s.partyData[s.oldKey.state.Party]
	// Construct a temporary share for domain-separated Paillier proof binding.
	localProofShare := &KeyShare{state: &keyShareState{
		SecurityParams: s.securityParams,
		Party:          s.oldKey.state.Party,
		Threshold:      s.cfg.Threshold,
		Parties:        s.oldKey.state.Parties,
		PublicKey:      publicKey,
		PartyData: map[tss.PartyID]keySharePartyData{
			s.oldKey.state.Party: {PaillierPublicKey: selfPD.paillierPub.PublicKey.Clone()},
		},
		PlanHash:               append([]byte(nil), s.planHash...),
		KeygenTranscriptHash:   transcriptHash,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelRefreshPaillier,
	}}
	paillierDomain, err := keySharePaillierProofDomain(localProofShare, s.limits)
	if err != nil {
		return nil, err
	}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), paillierDomain, s.newPaillier, s.oldKey.state.Party)
	if err != nil {
		return nil, err
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.oldKey.state.Parties))
	for _, id := range s.oldKey.state.Parties {
		verificationShare, ok := verificationShareFor(verificationShares, id)
		if !ok {
			return nil, fmt.Errorf("missing verification share for party %d", id)
		}
		sessionData := s.partyData[id]
		partyProof := sessionData.paillierPub.Proof
		if id == s.oldKey.state.Party {
			partyProof = paillierProof
		}
		partyData[id] = keySharePartyData{
			VerificationShare:  bytes.Clone(verificationShare),
			PaillierPublicKey:  sessionData.paillierPub.PublicKey.Clone(),
			PaillierProof:      partyProof.Clone(),
			RingPedersenParams: sessionData.ringPedersen.Params.Clone(),
			RingPedersenProof:  sessionData.ringPedersen.Proof.Clone(),
		}
	}
	s.newShare = &KeyShare{state: &keyShareState{
		SecurityParams:         s.securityParams,
		Party:                  s.oldKey.state.Party,
		Threshold:              s.cfg.Threshold,
		Parties:                s.oldKey.state.Parties.Clone(),
		PublicKey:              append([]byte(nil), publicKey...),
		ChainCode:              append([]byte(nil), s.oldKey.state.ChainCode...),
		Secret:                 newSecretScalar,
		GroupCommitments:       newCommitments,
		PartyData:              partyData,
		PaillierPrivateKey:     s.newPaillier.Clone(),
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelRefreshPaillier,
		ShareProof:             shareProof.Clone(),
		PlanHash:               append([]byte(nil), s.planHash...),
		KeygenTranscriptHash:   transcriptHash,
	}}
	// Π^log*: prove that Enc_new(x'_i) and V'_i = x'_i·G share the same secret,
	// using the prover's own Ring-Pedersen parameters for the commitment.
	logCiphertext, logRandomness, err := s.newPaillier.EncryptSecret(s.cfg.Reader(), newSecretScalar)
	if err != nil {
		return nil, err
	}
	defer logRandomness.Destroy()
	localRP := selfPD.ringPedersen.Params.Clone()
	logDomain, err := logProofDomain(localProofShare, s.newPaillier.PublicKey, localVerificationShare, transcriptHash, s.limits)
	if err != nil {
		return nil, err
	}
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   s.newPaillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarOne()),
		VerifierAux: localRP,
	}
	logWitness := zkpai.LogStarWitness{X: newSecretScalar, Rho: logRandomness}
	logProof, err := zkpai.ProveLogStar(s.securityParams, logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	s.newShare.state.LogCiphertext = tss.CloneBigInt(logCiphertext)
	s.newShare.state.LogProof = logProof.Clone()
	if err := s.newShare.validateWithoutConfirmations(s.limits); err != nil {
		return nil, err
	}
	confirmation, err := s.newShare.NewConfirmationWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	selfPD.confirmation = confirmation
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	confirmationEnv, err := newEnvelope(s.cfg, keygenConfirmationRound, s.oldKey.state.Party, tss.BroadcastPartyId, payloadKeygenConfirmation, encodedConfirmation)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{confirmationEnv}
	s.log.Info(s.cfg.Ctx(), "refresh local material complete",
		"party_id", s.oldKey.state.Party,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if s.allRefreshConfirmationsReceived() {
		if err := s.finalizeConfirmedShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *RefreshSession) refreshTranscriptHash(newCommitments []*secp.Point) ([]byte, error) {
	newCommitmentBytes, err := secp.CommitmentPointsBytes(newCommitments)
	if err != nil {
		return nil, err
	}
	t := transcript.New(refreshTranscriptHashLabel)
	t.AppendBytes("session_id", s.cfg.SessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("old_keygen_transcript_hash", s.oldKey.state.KeygenTranscriptHash)
	sortedParties := tss.SortParties(s.oldKey.state.Parties)
	t.AppendUint32List("parties", sortedParties)
	t.AppendUint32("threshold", uint32(s.cfg.Threshold))
	t.AppendBytes("public_key", s.oldKey.state.PublicKey)
	t.AppendBytes("chain_code", s.oldKey.state.ChainCode)
	for _, id := range sortedParties {
		t.AppendUint32("party", id)
		pd := s.partyData[id]
		paillierSnapshot, err := pd.paillierPub.snapshot(s.limits)
		if err != nil {
			return nil, err
		}
		ringPedersenSnapshot, err := pd.ringPedersen.snapshot(s.limits)
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

func validateRefreshCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) == 0 {
		return errors.New("empty refresh commitments")
	}
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	if len(commitments[0]) != 0 {
		return errors.New("refresh constant commitment must be empty")
	}
	for i, commitment := range commitments {
		if len(commitment) == 0 {
			continue
		}
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return fmt.Errorf("invalid refresh commitment %d: %w", i, err)
		}
	}
	return nil
}
