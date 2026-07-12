package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/sessiontx"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func (s *ReshareSession) maybeSendDealerMessages() ([]tss.Envelope, error) {
	if !s.isDealer || s.dealerSent {
		return nil, nil
	}
	if !s.allReshareReceiverMaterialReceived() {
		return nil, nil
	}
	out, err := s.dealerMessages()
	if err != nil {
		return nil, err
	}
	s.dealerSent = true
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, err
	}
	out = append(out, completionOut...)
	return out, nil
}

func (s *ReshareSession) dealerMessages() ([]tss.Envelope, error) {
	lambda, err := shamir.LagrangeCoefficient(s.selfID, s.dealerParties)
	if err != nil {
		return nil, err
	}
	oldSecret, err := secpScalarFromSecret(s.oldKey.state.Secret)
	if err != nil {
		return nil, err
	}
	constant := secp.ScalarMul(oldSecret, lambda)
	// The wire format has no SEC 1 encoding for infinity, so every dealer
	// contribution commitment must be representable as a finite point.
	if constant.IsZero() {
		return nil, errors.New("reshare dealer constant is zero")
	}
	poly, err := shamir.RandomPolynomial(s.cfg.Reader(), s.newThreshold, &constant)
	if err != nil {
		return nil, err
	}
	defer clearSecpPolynomial(poly)
	commitments, err := polynomialCommitments(poly)
	if err != nil {
		return nil, err
	}
	if err := s.validateDealerCommitments(s.selfID, commitments); err != nil {
		return nil, err
	}
	cleanup := sessiontx.NewCleanupStack()
	defer cleanup.Run()
	var selfShare *secret.Scalar
	if s.isReceiver {
		selfShare, err = secpSecretScalarFromScalarAllowZero(shamir.Eval(poly, s.selfID))
		if err != nil {
			return nil, err
		}
		cleanup.Add(selfShare.Destroy)
	}
	payload, err := (reshareDealerCommitmentsPayload{
		Commitments: commitments,
		PlanHash:    s.planHash,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	dealerConfig := s.dealerConfig()
	dealerEnv, err := newEnvelope(dealerConfig, reshareStartRound, s.selfID, tss.BroadcastPartyId, payloadReshareDealerCommitments, payload)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{dealerEnv}
	commitmentsHash := transcript.ByteSlicesHash(reshareCommitmentsHashLabel, commitments)
	for _, id := range s.newParties {
		if id == s.selfID {
			continue
		}
		receiverData := s.newPartyData[id]
		if receiverData == nil || receiverData.paillierPub.PublicKey == nil || receiverData.ringPedersen.Params == nil {
			return nil, fmt.Errorf("missing reshare receiver material for party %d", id)
		}
		share, err := secpSecretScalarFromScalarAllowZero(shamir.Eval(poly, id))
		if err != nil {
			return nil, err
		}
		ciphertext, randomness, err := receiverData.paillierPub.PublicKey.EncryptSecret(s.cfg.Reader(), share)
		if err != nil {
			share.Destroy()
			return nil, err
		}
		evaluation, err := secp.EvalCommitments(commitments, id)
		if err != nil {
			share.Destroy()
			randomness.Destroy()
			return nil, err
		}
		domain, err := reshareEncryptedShareDomain(s.cfg.SessionID, s.newThreshold, s.dealerParties, s.newParties, s.selfID, id, receiverData.paillierPub.PublicKey, s.planHash, s.limits)
		if err != nil {
			share.Destroy()
			randomness.Destroy()
			return nil, err
		}
		proof, err := zkpai.ProveLogStar(s.securityParams, domain, zkpai.LogStarStatement{
			PaillierN:   receiverData.paillierPub.PublicKey,
			C:           ciphertext,
			X:           evaluation,
			B:           secp.ScalarBaseMult(secp.ScalarOne()),
			VerifierAux: receiverData.ringPedersen.Params,
		}, zkpai.LogStarWitness{X: share, Rho: randomness}, s.cfg.Reader())
		share.Destroy()
		randomness.Destroy()
		if err != nil {
			return nil, err
		}
		sharePayload, err := (reshareSharePayload{
			Dealer:               s.selfID,
			Receiver:             id,
			Ciphertext:           ciphertext.Bytes(),
			Proof:                *proof,
			DealerCommitmentHash: commitmentsHash,
			PlanHash:             s.planHash,
		}).MarshalBinaryWithLimits(s.limits)
		proof.Destroy()
		if err != nil {
			return nil, err
		}
		shareEnv, err := newEnvelope(dealerConfig, reshareShareRound, s.selfID, id, payloadReshareShare, sharePayload)
		if err != nil {
			return nil, err
		}
		out = append(out, shareEnv)
	}
	dd := s.dealerData[s.selfID]
	if dd == nil {
		dd = &reshareDealerPartyData{}
		s.dealerData[s.selfID] = dd
	}
	if dd.commitments != nil {
		return nil, errors.New("duplicate local reshare dealer commitments")
	}
	if selfShare != nil && dd.share != nil {
		return nil, errors.New("duplicate local reshare share")
	}
	dd.commitments = tss.CloneByteSlices(commitments)
	if selfShare != nil {
		dd.share = selfShare
	}
	cleanup.Disarm()
	return out, nil
}

func (s *ReshareSession) initReceiverMaterial() error {
	newPaillierKey, err := generatePaillierKey(s.cfg.Ctx(), s.cfg.Reader(), s.plan.state.PaillierBits)
	if err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			newPaillierKey.Destroy()
		}
	}()
	proofConfig := s.receiverConfig()
	modDomain, err := resharePaillierDomain(proofConfig, s.selfID, newPaillierKey.PublicKey, s.planHash, s.limits)
	if err != nil {
		return err
	}
	modProof, err := zkpai.ProveModulus(s.cfg.Reader(), modDomain, newPaillierKey, s.selfID)
	if err != nil {
		return err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(s.cfg.Reader(), newPaillierKey)
	if err != nil {
		return err
	}
	defer ringPedersenLambda.Destroy()
	ringDomain, err := reshareRingPedersenDomain(proofConfig, s.selfID, ringPedersenParams, s.planHash, s.limits)
	if err != nil {
		return err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(s.cfg.Reader(), ringDomain, newPaillierKey, ringPedersenParams, ringPedersenLambda, s.selfID)
	if err != nil {
		return err
	}
	s.newPaillier = newPaillierKey
	owned = false
	s.newPartyData[s.selfID] = &reshareNewPartyData{
		paillierPub: paillierPublicMaterial{
			Party:     s.selfID,
			PublicKey: newPaillierKey.PublicKey.Clone(),
			Proof:     modProof.Clone(),
		},
		ringPedersen: ringPedersenPublicMaterial{
			Party:  s.selfID,
			Params: ringPedersenParams.Clone(),
			Proof:  ringPedersenProof.Clone(),
		},
	}
	return nil
}

func (s *ReshareSession) verifyAndStoreReceiverMaterial(env tss.Envelope, p reshareReceiverMaterialPayload) error {
	existing := s.newPartyData[env.From]
	if existing != nil && existing.factorKey != nil && existing.factorKey.N.Cmp(p.PaillierPublicKey.N) != 0 {
		return verificationErrorWithEvidence(env, tss.EvidenceKindPaillierAux, "reshare receiver material conflicts with factor proof", tss.NewPartySet(env.From), errors.New("receiver Paillier key equivocation"))
	}
	observedPaillierKeyHash, err := hashWireEvidenceField(evidenceFieldObservedPaillierKeyHash, &p.PaillierPublicKey, s.limits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	pk := &p.PaillierPublicKey
	proof := &p.PaillierProof
	if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPaillierAux,
			"reshare Paillier modulus does not meet security requirements",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.newParties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	modDomain, err := resharePaillierDomain(s.receiverConfig(), env.From, pk, s.planHash, s.limits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	if !zkpai.VerifyModulus(modDomain, pk, env.From, proof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPaillierAux,
			"invalid reshare Paillier modulus proof",
			tss.NewPartySet(env.From),
			errors.New("invalid reshare Paillier modulus proof"),
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.newParties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	ringParams := &p.RingPedersenParams
	if ringParams.N.Cmp(pk.N) != 0 {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPaillierAux,
			"reshare Ring-Pedersen modulus mismatch",
			tss.NewPartySet(env.From),
			errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.newParties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	ringProof := &p.RingPedersenProof
	ringDomain, err := reshareRingPedersenDomain(s.receiverConfig(), env.From, ringParams, s.planHash, s.limits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	if !zkpai.VerifyRingPedersen(s.securityParams, ringDomain, ringParams, env.From, ringProof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPaillierAux,
			"invalid reshare Ring-Pedersen proof",
			tss.NewPartySet(env.From),
			errors.New("invalid reshare Ring-Pedersen proof"),
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.newParties, partySetHashLabel)),
		)
	}
	s.newPartyData[env.From] = &reshareNewPartyData{
		paillierPub: paillierPublicMaterial{
			Party:     env.From,
			PublicKey: p.PaillierPublicKey.Clone(),
			Proof:     p.PaillierProof.Clone(),
		},
		ringPedersen: ringPedersenPublicMaterial{
			Party:  env.From,
			Params: p.RingPedersenParams.Clone(),
			Proof:  p.RingPedersenProof.Clone(),
		},
		factorProof: existing.factorProof.Clone(),
		factorKey:   existing.factorKey.Clone(),
	}
	return nil
}

func (s *ReshareSession) maybeSendReceiverFactorProofs() ([]tss.Envelope, error) {
	if !s.isReceiver || s.factorProofsSent || !s.allReshareReceiverMaterialReceived() {
		return nil, nil
	}
	selfData := s.newPartyData[s.selfID]
	out := make([]tss.Envelope, 0, len(s.newParties)-1)
	for _, verifier := range s.newParties {
		if verifier == s.selfID {
			continue
		}
		verifierRP := s.newPartyData[verifier].ringPedersen.Params
		domain, err := reshareFactorProofDomain(s.receiverConfig(), s.selfID, verifier, selfData.paillierPub.PublicKey, verifierRP, s.planHash, s.limits)
		if err != nil {
			return nil, err
		}
		proof, err := zkpai.ProveFactor(s.securityParams, domain, s.newPaillier, verifierRP, s.cfg.Reader())
		if err != nil {
			return nil, err
		}
		payload, err := (reshareFactorProofPayload{Prover: s.selfID, Verifier: verifier, PaillierPublicKey: *selfData.paillierPub.PublicKey.Clone(), Proof: *proof, PlanHash: s.planHash}).MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, err
		}
		env, err := newEnvelope(s.receiverConfig(), reshareShareRound, s.selfID, verifier, payloadReshareFactorProof, payload)
		clear(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	s.factorProofsSent = true
	return out, nil
}

func (s *ReshareSession) applyReshareShare(env tss.Envelope, p reshareSharePayload) error {
	from := env.From
	if p.Dealer != from {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, reshareShareRound, from, errors.New("dealer share payload sender mismatch"))
	}
	if p.Receiver != s.selfID {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, reshareShareRound, from, errors.New("dealer share payload receiver mismatch"))
	}
	dd, ok := s.dealerData[from]
	if !ok || dd.commitments == nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, reshareShareRound, from, errors.New("dealer share has no dealer commitments"))
	}
	if !bytes.Equal(p.DealerCommitmentHash, transcript.ByteSlicesHash(reshareCommitmentsHashLabel, dd.commitments)) {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, reshareShareRound, from, errors.New("dealer share commitment hash mismatch"))
	}
	selfData := s.newPartyData[s.selfID]
	if selfData == nil || selfData.paillierPub.PublicKey == nil || selfData.ringPedersen.Params == nil || s.newPaillier == nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, 0, errors.New("missing local reshare receiver material"))
	}
	evaluation, err := secp.EvalCommitments(dd.commitments, s.selfID)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, 0, err)
	}
	domain, err := reshareEncryptedShareDomain(s.cfg.SessionID, s.newThreshold, s.dealerParties, s.newParties, from, s.selfID, selfData.paillierPub.PublicKey, s.planHash, s.limits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, 0, err)
	}
	ciphertext := new(big.Int).SetBytes(p.Ciphertext)
	if err := zkpai.VerifyLogStar(s.securityParams, domain, zkpai.LogStarStatement{
		PaillierN:   selfData.paillierPub.PublicKey,
		C:           ciphertext,
		X:           evaluation,
		B:           secp.ScalarBaseMult(secp.ScalarOne()),
		VerifierAux: selfData.ringPedersen.Params,
	}, &p.Proof); err != nil {
		p.Proof.Destroy()
		return verificationErrorWithEvidence(env, tss.EvidenceKindReshareShare, "invalid encrypted reshare share proof", tss.NewPartySet(from), err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(s.dealerParties, partySetHashLabel)),
			rawEvidenceField(evidenceFieldCommitmentsHash, transcript.ByteSlicesHash(reshareCommitmentsHashLabel, dd.commitments)),
			hashEvidenceField("encrypted_share_ciphertext_hash", p.Ciphertext))
	}
	p.Proof.Destroy()
	plaintext, err := s.newPaillier.Decrypt(ciphertext)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, 0, fmt.Errorf("verified reshare share decryption failed: %w", err))
	}
	defer secret.ClearBigInt(plaintext)
	if plaintext.Sign() < 0 || plaintext.Cmp(secp.Order()) >= 0 {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, 0, errors.New("verified reshare share plaintext is out of range"))
	}
	encoded := plaintext.FillBytes(make([]byte, secp.ScalarSize))
	share, err := newSecpSecretScalarAllowZero(encoded)
	clear(encoded)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, reshareShareRound, 0, err)
	}
	dd.share = share
	return nil
}

func validateReshareCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for i, commitment := range commitments {
		if len(commitment) == 0 {
			return fmt.Errorf("commitment %d is empty", i)
		}
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return err
		}
	}
	return nil
}

func (s *ReshareSession) validateDealerCommitments(dealer tss.PartyID, commitments [][]byte) error {
	if err := validateReshareCommitments(commitments, s.newThreshold); err != nil {
		return err
	}
	if !tss.ContainsParty(s.dealerParties, dealer) {
		return fmt.Errorf("sender %d is not a dealer", dealer)
	}
	verificationShare, ok := s.plan.state.OldVerificationShares[dealer]
	if !ok {
		return fmt.Errorf("missing old verification share for dealer %d", dealer)
	}
	oldPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return fmt.Errorf("invalid old verification share for dealer %d: %w", dealer, err)
	}
	lambda, err := shamir.LagrangeCoefficient(dealer, s.dealerParties)
	if err != nil {
		return err
	}
	// The dealer contribution preserves the old secret only if its constant
	// commitment is the old verification share weighted for this dealer set.
	expected, err := secp.PointBytes(secp.ScalarMult(oldPoint, lambda))
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, commitments[0]) {
		return errors.New("dealer constant commitment does not match weighted old verification share")
	}
	return nil
}

func polynomialCommitments(poly shamir.Polynomial) ([][]byte, error) {
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.IsZero() {
			return nil, fmt.Errorf("polynomial coefficient %d is zero", i)
		}
		enc, err := secp.PointBytes(secp.ScalarBaseMult(coeff))
		if err != nil {
			return nil, err
		}
		commitments[i] = enc
	}
	return commitments, nil
}
