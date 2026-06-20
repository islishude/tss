package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
	"github.com/islishude/tss/internal/wire/wireutil"
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
	lambda, err := shamirsecp.LagrangeCoefficient(s.selfID, s.dealerParties)
	if err != nil {
		return nil, err
	}
	oldSecret, err := secpScalarFromSecret(s.oldKey.state.secret)
	if err != nil {
		return nil, err
	}
	constant := secp.ScalarMul(oldSecret, lambda)
	// The wire format has no SEC 1 encoding for infinity, so every dealer
	// contribution commitment must be representable as a finite point.
	if constant.IsZero() {
		return nil, errors.New("reshare dealer constant is zero")
	}
	poly, err := shamirsecp.RandomPolynomial(s.cfg.Reader(), s.newThreshold, &constant)
	if err != nil {
		return nil, err
	}
	commitments, err := polynomialCommitments(poly)
	if err != nil {
		return nil, err
	}
	if err := s.validateDealerCommitments(s.selfID, commitments); err != nil {
		return nil, err
	}
	dd := s.dealerData[s.selfID]
	if dd == nil {
		dd = &reshareDealerPartyData{}
		s.dealerData[s.selfID] = dd
	}
	dd.commitments = commitments
	if s.isReceiver {
		dd.share, err = secpSecretScalarFromScalar(shamirsecp.Eval(poly, s.selfID))
		if err != nil {
			return nil, err
		}
	}
	payload, err := (reshareDealerCommitmentsPayload{
		Commitments: commitments,
		PlanHash:    s.planHash,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	dealerConfig := s.dealerConfig()
	dealerEnv, err := newEnvelope(dealerConfig, 1, s.selfID, tss.BroadcastPartyId, payloadReshareDealerCommitments, payload)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{dealerEnv}
	commitmentsHash := wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, commitments)
	for _, id := range s.newParties {
		if id == s.selfID {
			continue
		}
		share, err := secpSecretScalarFromScalar(shamirsecp.Eval(poly, id))
		if err != nil {
			return nil, err
		}
		sharePayload, err := (reshareSharePayload{
			Dealer:               s.selfID,
			Receiver:             id,
			Share:                share,
			DealerCommitmentHash: commitmentsHash,
			PlanHash:             s.planHash,
		}).MarshalBinaryWithLimits(s.limits)
		share.Destroy()
		if err != nil {
			return nil, err
		}
		shareEnv, err := newEnvelope(dealerConfig, 1, s.selfID, id, payloadReshareShare, sharePayload)
		if err != nil {
			return nil, err
		}
		out = append(out, shareEnv)
	}
	return out, nil
}

func (s *ReshareSession) initReceiverMaterial() error {
	newPaillierKey, err := generatePaillierKey(s.cfg.Ctx(), s.cfg.Reader(), s.plan.state.paillierBits)
	if err != nil {
		return err
	}
	proofConfig := s.receiverConfig()
	modDomain, err := resharePaillierDomain(proofConfig, s.selfID, &newPaillierKey.PublicKey, s.planHash, s.limits)
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
	observedPaillierKeyHash, err := hashWireEvidenceField(evidenceFieldObservedPaillierKeyHash, &p.PaillierPublicKey, s.limits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	pk := &p.PaillierPublicKey
	proof := &p.PaillierProof
	if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"reshare Paillier modulus does not meet security requirements",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
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
			tss.EvidenceKindKeygenPaillier,
			"invalid reshare Paillier modulus proof",
			tss.NewPartySet(env.From),
			errors.New("invalid reshare Paillier modulus proof"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	ringParams := &p.RingPedersenParams
	if ringParams.N.Cmp(pk.N) != 0 {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"reshare Ring-Pedersen modulus mismatch",
			tss.NewPartySet(env.From),
			errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
			observedPaillierKeyHash,
		)
	}
	ringProof := &p.RingPedersenProof
	ringDomain, err := reshareRingPedersenDomain(s.receiverConfig(), env.From, ringParams, s.planHash, s.limits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	}
	if !zkpai.VerifyRingPedersen(ringDomain, ringParams, env.From, ringProof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid reshare Ring-Pedersen proof",
			tss.NewPartySet(env.From),
			errors.New("invalid reshare Ring-Pedersen proof"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
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
	}
	return nil
}

func (s *ReshareSession) applyReshareShare(from tss.PartyID, p reshareSharePayload, rawPayload []byte) error {
	if p.Dealer != from {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share payload sender mismatch"))
	}
	if p.Receiver != s.selfID {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share payload receiver mismatch"))
	}
	dd, ok := s.dealerData[from]
	if !ok || dd.commitments == nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share has no dealer commitments"))
	}
	if !bytes.Equal(p.DealerCommitmentHash, wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, dd.commitments)) {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share commitment hash mismatch"))
	}
	share, err := secpScalarFromSecret(p.Share)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, err)
	}
	if err := secp.VerifyShare(dd.commitments, s.selfID, share); err != nil {
		verifyErr := err
		evidenceEnv, evErr := newEnvelope(s.dealerConfig(), 1, from, s.selfID, payloadReshareShare, rawPayload)
		if evErr != nil {
			return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, evErr)
		}
		return &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: 1,
			Party: from,
			Blame: newBlame(
				evidenceEnv,
				tss.EvidenceKindReshareShare,
				"invalid reshare share",
				tss.NewPartySet(from),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.dealerParties, partySetHashLabel)),
				rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, dd.commitments)),
				hashEvidenceField("dealer_share_payload_hash", rawPayload),
			),
			Err: verifyErr,
		}
	}
	dd.share = p.Share.Clone()
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
	verificationShare, ok := s.plan.state.oldVerificationShares[dealer]
	if !ok {
		return fmt.Errorf("missing old verification share for dealer %d", dealer)
	}
	oldPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return fmt.Errorf("invalid old verification share for dealer %d: %w", dealer, err)
	}
	lambda, err := shamirsecp.LagrangeCoefficient(dealer, s.dealerParties)
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

func polynomialCommitments(poly shamirsecp.Polynomial) ([][]byte, error) {
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
