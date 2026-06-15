package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func (s *ReshareSession) maybeSendDealerMessages() ([]tss.Envelope, error) {
	if !s.isDealer || s.dealerSent {
		return nil, nil
	}
	if len(s.newPaillierPubs) != len(s.newParties) || len(s.newRingPedersen) != len(s.newParties) {
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
	order := secp.Order()
	lambda, err := shamir.LagrangeCoefficient(s.selfID, s.dealerParties, order)
	if err != nil {
		return nil, err
	}
	oldSecret, err := s.oldKey.secretBig()
	if err != nil {
		return nil, err
	}
	constant := new(big.Int).Mul(oldSecret, lambda)
	constant.Mod(constant, order)
	// The wire format has no SEC 1 encoding for infinity, so every dealer
	// contribution commitment must be representable as a finite point.
	if constant.Sign() == 0 {
		return nil, errors.New("reshare dealer constant is zero")
	}
	poly, err := shamir.RandomPolynomial(s.cfg.Reader(), order, s.newThreshold, constant)
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
	s.ownPoly = poly
	s.commits[s.selfID] = commitments
	if s.isReceiver {
		s.shares[s.selfID] = shamir.Eval(poly, s.selfID, order)
	}
	payload, err := marshalReshareDealerCommitmentsPayloadWithLimits(reshareDealerCommitmentsPayload{
		Commitments: commitments,
		PlanHash:    s.planHash,
	}, s.limits)
	if err != nil {
		return nil, err
	}
	dealerConfig := s.dealerConfig()
	dealerEnv, err := envelope(dealerConfig, 1, s.selfID, 0, payloadReshareDealerCommitments, payload)
	if err != nil {
		return nil, err
	}
	out := []tss.Envelope{dealerEnv}
	commitmentsHash := wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, commitments)
	for _, id := range s.newParties {
		if id == s.selfID {
			continue
		}
		share := shamir.Eval(s.ownPoly, id, order)
		sharePayload, err := marshalReshareSharePayloadWithLimits(reshareSharePayload{
			Dealer:               s.selfID,
			Receiver:             id,
			Share:                share,
			DealerCommitmentHash: commitmentsHash,
			PlanHash:             s.planHash,
		}, s.limits)
		if err != nil {
			return nil, err
		}
		shareEnv, err := envelope(dealerConfig, 1, s.selfID, id, payloadReshareShare, sharePayload)
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
	newPaillierPubBytes, err := newPaillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	newPaillierPriv, err := newPaillierKey.MarshalBinary()
	if err != nil {
		return err
	}
	proofConfig := s.receiverConfig()
	modProof, err := zkpai.ProveModulus(s.cfg.Reader(), resharePaillierDomain(proofConfig, s.selfID, newPaillierPubBytes, s.planHash), newPaillierKey, s.selfID)
	if err != nil {
		return err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(s.cfg.Reader(), newPaillierKey)
	if err != nil {
		return err
	}
	ringPedersenParamsBytes, err := zkpai.MarshalRingPedersenParams(ringPedersenParams)
	if err != nil {
		return err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(s.cfg.Reader(), reshareRingPedersenDomain(proofConfig, s.selfID, ringPedersenParamsBytes, s.planHash), newPaillierKey, ringPedersenParams, ringPedersenLambda, s.selfID)
	if err != nil {
		return err
	}
	ringPedersenProofBytes, err := zkpai.Marshal(ringPedersenProof)
	if err != nil {
		return err
	}
	s.newPaillier = newPaillierKey
	s.newPaillierPriv = newPaillierPriv
	s.newPaillierPubs[s.selfID] = PaillierPublicShare{Party: s.selfID, PublicKey: newPaillierPubBytes, Proof: modProofBytes}
	s.newRingPedersen[s.selfID] = RingPedersenPublicShare{Party: s.selfID, Params: ringPedersenParamsBytes, Proof: ringPedersenProofBytes}
	return nil
}

func (s *ReshareSession) verifyAndStoreReceiverMaterial(env tss.Envelope, p reshareReceiverMaterialPayload) error {
	pk, err := pai.UnmarshalPublicKeyWithMaxModulusBits(p.PaillierPublicKey, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	proof, err := zkpai.UnmarshalModulusProof(p.PaillierProof)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := checkPaillierModulusBounds(pk, s.limits, s.securityParams); err != nil {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"reshare Paillier modulus does not meet security requirements",
			[]tss.PartyID{env.From},
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if !zkpai.VerifyModulus(resharePaillierDomain(s.receiverConfig(), env.From, p.PaillierPublicKey, s.planHash), pk, env.From, proof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid reshare Paillier modulus proof",
			[]tss.PartyID{env.From},
			errors.New("invalid reshare Paillier modulus proof"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	ringParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(p.RingPedersenParams, s.limits.Paillier.MaxModulusBits)
	if err != nil {
		return protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed reshare Ring-Pedersen parameters",
			[]tss.PartyID{env.From},
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if ringParams.N.Cmp(pk.N) != 0 {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"reshare Ring-Pedersen modulus mismatch",
			[]tss.PartyID{env.From},
			errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	ringProof, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof)
	if err != nil {
		return protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed reshare Ring-Pedersen proof",
			[]tss.PartyID{env.From},
			err,
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
		)
	}
	if !zkpai.VerifyRingPedersen(reshareRingPedersenDomain(s.receiverConfig(), env.From, p.RingPedersenParams, s.planHash), ringParams, env.From, ringProof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid reshare Ring-Pedersen proof",
			[]tss.PartyID{env.From},
			errors.New("invalid reshare Ring-Pedersen proof"),
			rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.newParties, partySetHashLabel)),
		)
	}
	s.newPaillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
	s.newRingPedersen[env.From] = RingPedersenPublicShare{Party: env.From, Params: p.RingPedersenParams, Proof: p.RingPedersenProof}
	return nil
}

func (s *ReshareSession) applyReshareShare(from tss.PartyID, p reshareSharePayload, rawPayload []byte) error {
	if p.Dealer != from {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share payload sender mismatch"))
	}
	if p.Receiver != s.selfID {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share payload receiver mismatch"))
	}
	commitments, ok := s.commits[from]
	if !ok {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share has no dealer commitments"))
	}
	if !bytes.Equal(p.DealerCommitmentHash, wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, commitments)) {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, from, errors.New("dealer share commitment hash mismatch"))
	}
	share := secp.ScalarFromBigInt(p.Share)
	if err := secp.VerifyShare(commitments, s.selfID, share); err != nil {
		verifyErr := err
		evidenceEnv, evErr := envelope(s.dealerConfig(), 1, from, s.selfID, payloadReshareShare, rawPayload)
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
				[]tss.PartyID{from},
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.dealerParties, partySetHashLabel)),
				rawEvidenceField(evidenceFieldCommitmentsHash, wireutil.ByteSlicesHash(reshareCommitmentsHashLabel, commitments)),
				hashEvidenceField("dealer_share_payload_hash", rawPayload),
			),
			Err: verifyErr,
		}
	}
	s.shares[from] = share.BigInt()
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
	lambda, err := shamir.LagrangeCoefficient(dealer, s.dealerParties, secp.Order())
	if err != nil {
		return err
	}
	// The dealer contribution preserves the old secret only if its constant
	// commitment is the old verification share weighted for this dealer set.
	expected, err := secp.PointBytes(secp.ScalarMult(oldPoint, secp.ScalarFromBigInt(lambda)))
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, commitments[0]) {
		return errors.New("dealer constant commitment does not match weighted old verification share")
	}
	return nil
}

func polynomialCommitments(poly []*big.Int) ([][]byte, error) {
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.Sign() == 0 {
			return nil, fmt.Errorf("polynomial coefficient %d is zero", i)
		}
		enc, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff)))
		if err != nil {
			return nil, err
		}
		commitments[i] = enc
	}
	return commitments, nil
}
