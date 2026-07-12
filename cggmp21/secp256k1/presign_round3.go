package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/zk/signprep"
)

type mtaContributionViewMismatchError struct {
	left  tss.PartyID
	right tss.PartyID
}

// Error describes a non-attributable mismatch between two remote MtA views.
func (e *mtaContributionViewMismatchError) Error() string {
	return fmt.Sprintf("inconsistent MTA contribution views between parties %d and %d", e.left, e.right)
}

func (s *PresignSession) buildAcceptPresignRound3Tx(env tss.Envelope) (*acceptPresignRound3Tx, error) {
	// ---- 1. PARSE ----
	p, err := tss.DecodeBinaryValueWithLimits[presignRound3Payload](env.Payload, s.limits)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound3,
			"malformed presign round3 payload",
			tss.NewPartySet(env.From),
			err,
			fields...,
		)
	}
	if p.Delta == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("missing presign delta"))
	}
	owned := true
	defer func() {
		if owned {
			p.Delta.Destroy()
		}
	}()

	// ---- 2. POLICY VALIDATE ----
	// (round and duplicate checks done in dispatcher)
	if err := requirePlanHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if _, err := secpScalarFromSecret(p.Delta); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}

	material, err := s.verifyRemoteSignprepProof(env.From, p)
	if err != nil {
		var viewMismatch *mtaContributionViewMismatchError
		if errors.As(err, &viewMismatch) {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, 0, err)
		}
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeVerification,
			env,
			tss.EvidenceKindPresignRound3,
			"invalid presign sign verification material",
			tss.NewPartySet(env.From),
			err,
			s.presignRound3EvidenceFields(p)...,
		)
	}

	if _, ok := s.partyState(env.From); !ok {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errPresignSignerMissing)
	}
	owned = false
	return &acceptPresignRound3Tx{
		from:        env.From,
		delta:       p.Delta,
		verifyShare: material,
	}, nil
}

func (s *PresignSession) verifyRemoteSignprepProof(from tss.PartyID, p presignRound3Payload) (signVerifyShare, error) {
	if p.KPoint == nil {
		return signVerifyShare{}, errors.New("missing KPoint")
	}
	if p.ChiPoint == nil {
		return signVerifyShare{}, errors.New("missing ChiPoint")
	}
	if err := p.Proof.Validate(); err != nil {
		return signVerifyShare{}, fmt.Errorf("invalid signprep proof: %w", err)
	}
	round2CommitmentsHash, err := s.verifyRound2Commitments(from, p.Round2Commitments)
	if err != nil {
		return signVerifyShare{}, err
	}
	mtaContributionsHash, mtaBasePoint, mtaOffsetPoint, deltaBasePoint, deltaOffsetPoint, err := s.verifyMTAContributions(from, p.MTAContributions)
	if err != nil {
		return signVerifyShare{}, err
	}
	kPointBytes, err := secp.PointBytes(p.KPoint)
	if err != nil {
		return signVerifyShare{}, err
	}
	chiPointBytes, err := secp.PointBytes(p.ChiPoint)
	if err != nil {
		return signVerifyShare{}, err
	}
	lambda, err := shamir.LagrangeCoefficient(from, s.signers)
	if err != nil {
		return signVerifyShare{}, err
	}
	verificationShare, ok := s.key.verificationShare(from)
	if !ok {
		return signVerifyShare{}, fmt.Errorf("missing verification share for party %d", from)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return signVerifyShare{}, err
	}
	xBarPoint, err := secp.PointBytes(secp.ScalarMult(verificationPoint, lambda))
	if err != nil {
		return signVerifyShare{}, err
	}
	fromState, ok := s.partyState(from)
	if !ok || !fromState.round1.havePayload {
		return signVerifyShare{}, fmt.Errorf("missing presign round1 state for party %d", from)
	}
	round1From := fromState.round1.payload
	if !bytes.Equal(kPointBytes, round1From.KPoint) {
		return signVerifyShare{}, errors.New("round3 KPoint does not match round1 encrypted nonce relation")
	}
	paillierPublicKeyBytes, err := canonicalWireMessageBytes(round1From.PaillierPublicKey, s.limits)
	if err != nil {
		return signVerifyShare{}, err
	}
	deltaBytes := p.Delta.FixedBytes()
	defer clear(deltaBytes)
	stmt := signprep.Statement{
		Protocol:              tss.ProtocolCGGMP21Secp256k1,
		SessionID:             s.sessionID,
		Party:                 from,
		Signers:               slices.Clone(s.signers),
		PlanHash:              slices.Clone(s.planHash),
		ContextHash:           slices.Clone(s.contextHash),
		AdditiveShift:         slices.Clone(s.derivation.AdditiveShift),
		PublicKey:             slices.Clone(s.key.state.PublicKey),
		KeygenTranscriptHash:  slices.Clone(s.key.state.KeygenTranscriptHash),
		PartiesHash:           tss.PartySetHash(s.key.state.Parties, partySetHashLabel),
		KPoint:                kPointBytes,
		ChiPoint:              chiPointBytes,
		XBarPoint:             xBarPoint,
		Gamma:                 slices.Clone(round1From.Gamma),
		EncK:                  slices.Clone(round1From.EncK),
		PaillierPublicKey:     paillierPublicKeyBytes,
		Round1Echo:            s.round1Echo(),
		Round2CommitmentsHash: round2CommitmentsHash,
		MTAContributionsHash:  mtaContributionsHash,
		MTABasePoint:          mtaBasePoint,
		MTAOffsetPoint:        mtaOffsetPoint,
		DeltaBasePoint:        deltaBasePoint,
		DeltaOffsetPoint:      deltaOffsetPoint,
		Delta:                 deltaBytes,
	}
	if err := signprep.Verify(stmt, p.Proof); err != nil {
		return signVerifyShare{}, err
	}
	return signVerifyShare{
		Party:                 from,
		KPoint:                secp.Clone(p.KPoint),
		ChiPoint:              secp.Clone(p.ChiPoint),
		Proof:                 p.Proof.Clone(),
		Round2CommitmentsHash: bytes.Clone(round2CommitmentsHash),
		MTAContributionsHash:  bytes.Clone(mtaContributionsHash),
		MTABasePoint:          bytes.Clone(mtaBasePoint),
		MTAOffsetPoint:        bytes.Clone(mtaOffsetPoint),
		DeltaBasePoint:        bytes.Clone(deltaBasePoint),
		DeltaOffsetPoint:      bytes.Clone(deltaOffsetPoint),
		mtaContributions:      cloneMTAContributions(p.MTAContributions),
	}, nil
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	kPointBytes, _ := secp.PointBytes(p.KPoint)
	chiPointBytes, _ := secp.PointBytes(p.ChiPoint)
	proofBytes, _ := p.Proof.MarshalBinary()
	deltaBytes := p.Delta.FixedBytes()
	defer clear(deltaBytes)
	return append(fields,
		hashEvidenceField("delta_hash", deltaBytes),
		hashEvidenceField(evidenceFieldSignVerifyKPointHash, kPointBytes),
		hashEvidenceField(evidenceFieldSignVerifyChiPointHash, chiPointBytes),
		hashEvidenceField(evidenceFieldSignPrepProofHash, proofBytes),
	)
}

func (s *PresignSession) tryEmitRound3() ([]tss.Envelope, error) {
	prepared, ok, err := s.preparePresignRound3Output()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer prepared.destroy()
	effects, err := s.commitPresignRound3Output(prepared)
	if err != nil {
		return nil, err
	}
	return effects.envelopes, nil
}

type preparedPresignRound3Output struct {
	delta       *secret.Scalar
	verifyShare signVerifyShare
	presign     *Presign
	env         tss.Envelope
	committed   bool
}

func (p *preparedPresignRound3Output) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.delta != nil {
		p.delta.Destroy()
		p.delta = nil
	}
	if p.presign != nil {
		p.presign.Destroy()
		p.presign = nil
	}
	p.verifyShare.destroy()
	clear(p.env.Payload)
}

func (s *PresignSession) preparePresignRound3Output() (*preparedPresignRound3Output, bool, error) {
	if s.round3Sent || !s.allRound2Accepted() {
		return nil, false, nil
	}
	kShare, err := secpScalarFromSecret(s.kShare)
	if err != nil {
		return nil, false, err
	}
	gamma, err := secpScalarFromSecret(s.gamma)
	if err != nil {
		return nil, false, err
	}
	xBar, err := secpScalarFromSecret(s.xBar)
	if err != nil {
		return nil, false, err
	}
	deltaShare := secp.ScalarMul(kShare, gamma)
	chiShare := secp.ScalarMul(kShare, xBar)
	for _, peer := range s.signers {
		if peer == s.key.state.Party {
			continue
		}
		peerState, ok := s.partyState(peer)
		if !ok {
			return nil, false, fmt.Errorf("missing presign state for party %d", peer)
		}
		alphaDelta, err := secpScalarFromSecret(peerState.mta.alphaDelta)
		if err != nil {
			return nil, false, err
		}
		betaDelta, err := secpScalarFromSecret(peerState.mta.betaDelta)
		if err != nil {
			return nil, false, err
		}
		alphaSigma, err := secpScalarFromSecret(peerState.mta.alphaSigma)
		if err != nil {
			return nil, false, err
		}
		betaSigma, err := secpScalarFromSecret(peerState.mta.betaSigma)
		if err != nil {
			return nil, false, err
		}
		deltaShare = secp.ScalarAdd(deltaShare, alphaDelta)
		deltaShare = secp.ScalarAdd(deltaShare, betaDelta)
		chiShare = secp.ScalarAdd(chiShare, alphaSigma)
		chiShare = secp.ScalarAdd(chiShare, betaSigma)
	}
	baseChi := secp.ScalarMul(kShare, xBar)
	mtaSum := secp.ScalarSub(chiShare, baseChi)
	if len(s.derivation.AdditiveShift) > 0 {
		shift, err := secp.ScalarFromBytesAllowZero(s.derivation.AdditiveShift)
		if err != nil {
			return nil, false, err
		}
		if !shift.IsZero() {
			chiShare = secp.ScalarAdd(chiShare, secp.ScalarMul(kShare, shift))
		}
	}
	deltaSecret, err := secpSecretScalarFromScalar(deltaShare)
	if err != nil {
		return nil, false, err
	}
	deltaOwned := false
	defer func() {
		if !deltaOwned {
			deltaSecret.Destroy()
		}
	}()
	selfState, ok := s.partyState(s.key.state.Party)
	if !ok {
		return nil, false, errors.New("missing local presign party state")
	}
	round2Commitments, round2CommitmentsHash, err := s.localRound2Commitments()
	if err != nil {
		return nil, false, err
	}
	mtaContributions, mtaContributionsHash, mtaBasePoint, mtaOffsetPoint, deltaBasePoint, deltaOffsetPoint, err := s.localMTAContributions()
	if err != nil {
		return nil, false, err
	}
	defer destroyMTAContributions(mtaContributions)

	// Compute KPoint and ChiPoint.
	kPoint := secp.ScalarBaseMult(kShare)
	kPointBytes, err := secp.PointBytes(kPoint)
	if err != nil {
		return nil, false, err
	}
	chiPoint := secp.ScalarBaseMult(chiShare)
	chiPointBytes, err := secp.PointBytes(chiPoint)
	if err != nil {
		return nil, false, err
	}

	// Compute XBarPoint.
	lambda, err := shamir.LagrangeCoefficient(s.key.state.Party, s.signers)
	if err != nil {
		return nil, false, err
	}
	verificationShare, ok := s.key.verificationShare(s.key.state.Party)
	if !ok {
		return nil, false, fmt.Errorf("missing local verification share for party %d", s.key.state.Party)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return nil, false, err
	}
	xBarPoint, err := secp.PointBytes(secp.ScalarMult(verificationPoint, lambda))
	if err != nil {
		return nil, false, err
	}

	// Build signprep proof.
	localPaillierPublicKey, err := s.key.paillierPublicFor(s.key.state.Party, s.limits)
	if err != nil {
		return nil, false, err
	}
	paillierPublicKey, err := canonicalWireMessageBytes(localPaillierPublicKey, s.limits)
	if err != nil {
		return nil, false, err
	}
	stmt := signprep.Statement{
		Protocol:              tss.ProtocolCGGMP21Secp256k1,
		SessionID:             s.sessionID,
		Party:                 s.key.state.Party,
		Signers:               slices.Clone(s.signers),
		PlanHash:              slices.Clone(s.planHash),
		ContextHash:           slices.Clone(s.contextHash),
		AdditiveShift:         slices.Clone(s.derivation.AdditiveShift),
		PublicKey:             slices.Clone(s.key.state.PublicKey),
		KeygenTranscriptHash:  slices.Clone(s.key.state.KeygenTranscriptHash),
		PartiesHash:           tss.PartySetHash(s.key.state.Parties, partySetHashLabel),
		KPoint:                kPointBytes,
		ChiPoint:              chiPointBytes,
		XBarPoint:             xBarPoint,
		Gamma:                 slices.Clone(selfState.round1.payload.Gamma),
		EncK:                  slices.Clone(selfState.round1.payload.EncK),
		PaillierPublicKey:     paillierPublicKey,
		Round1Echo:            s.round1Echo(),
		Round2CommitmentsHash: round2CommitmentsHash,
		MTAContributionsHash:  mtaContributionsHash,
		MTABasePoint:          mtaBasePoint,
		MTAOffsetPoint:        mtaOffsetPoint,
		DeltaBasePoint:        deltaBasePoint,
		DeltaOffsetPoint:      deltaOffsetPoint,
		Delta:                 deltaShare.Bytes(),
	}
	mtaSumSecret, err := secpSecretScalarFromScalarAllowZero(mtaSum)
	if err != nil {
		return nil, false, err
	}
	defer mtaSumSecret.Destroy()
	chiSecret, err := secpSecretScalarFromScalar(chiShare)
	if err != nil {
		return nil, false, err
	}
	chiOwned := false
	defer func() {
		if !chiOwned {
			chiSecret.Destroy()
		}
	}()
	wit := signprep.Witness{
		KShare:   s.kShare,
		MTASum:   mtaSumSecret,
		ChiShare: chiSecret,
	}
	proof, err := signprep.Prove(s.config.Reader(), stmt, wit)
	if err != nil {
		return nil, false, fmt.Errorf("signprep proof generation: %w", err)
	}

	payload, err := (presignRound3Payload{
		Delta:             deltaSecret,
		KPoint:            kPoint,
		ChiPoint:          chiPoint,
		Proof:             proof,
		PlanHash:          s.planHash,
		Round2Commitments: round2Commitments,
		MTAContributions:  mtaContributions,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, false, err
	}
	verifyShare := signVerifyShare{
		Party:                 s.key.state.Party,
		KPoint:                secp.Clone(kPoint),
		ChiPoint:              secp.Clone(chiPoint),
		Proof:                 proof.Clone(),
		Round2CommitmentsHash: bytes.Clone(round2CommitmentsHash),
		MTAContributionsHash:  bytes.Clone(mtaContributionsHash),
		MTABasePoint:          bytes.Clone(mtaBasePoint),
		MTAOffsetPoint:        bytes.Clone(mtaOffsetPoint),
		DeltaBasePoint:        bytes.Clone(deltaBasePoint),
		DeltaOffsetPoint:      bytes.Clone(deltaOffsetPoint),
		mtaContributions:      cloneMTAContributions(mtaContributions),
	}
	context := s.context.Clone()
	publicKeyPoint, err := secp.PointFromBytes(s.key.state.PublicKey)
	if err != nil {
		clear(payload)
		return nil, false, err
	}
	stagedPresign := &Presign{state: &presignState{
		Consumed:             NewAtomicBoolWire(false),
		attempt:              newPresignAttemptBinding(false),
		SecurityParams:       s.securityParams,
		Party:                s.key.state.Party,
		Threshold:            s.key.state.Threshold,
		Signers:              s.signers.Clone(),
		Context:              context,
		ContextHash:          append([]byte(nil), s.contextHash...),
		Derivation:           s.derivation.Clone(),
		PlanHash:             append([]byte(nil), s.planHash...),
		PublicKey:            publicKeyPoint,
		KeygenTranscriptHash: append([]byte(nil), s.key.state.KeygenTranscriptHash...),
		PartiesHash:          tss.PartySetHash(s.key.state.Parties, partySetHashLabel),
		KShare:               s.kShare.Clone(),
	}}
	stagedPresign.state.ChiShare = chiSecret
	chiOwned = true
	env, err := newEnvelope(s.config, presignRound3, s.key.state.Party, tss.BroadcastPartyId, payloadPresignRound3, payload)
	clear(payload)
	if err != nil {
		stagedPresign.Destroy()
		return nil, false, err
	}
	deltaOwned = true
	return &preparedPresignRound3Output{
		delta:       deltaSecret,
		verifyShare: verifyShare,
		presign:     stagedPresign,
		env:         env,
	}, true, nil
}

func (s *PresignSession) localRound2Commitments() ([]presignRound2Commitment, []byte, error) {
	commitments := make([]presignRound2Commitment, 0, len(s.signers)-1)
	for _, recipient := range s.signers {
		if recipient == s.key.state.Party {
			continue
		}
		state, ok := s.partyState(recipient)
		if !ok || len(state.round2.outboundHash) != sha256.Size {
			return nil, nil, fmt.Errorf("missing round2 commitment for recipient %d", recipient)
		}
		commitments = append(commitments, presignRound2Commitment{
			Recipient: recipient,
			Hash:      bytes.Clone(state.round2.outboundHash),
		})
	}
	return commitments, round2CommitmentsDigest(commitments), nil
}

func (s *PresignSession) verifyRound2Commitments(from tss.PartyID, commitments []presignRound2Commitment) ([]byte, error) {
	if len(commitments) != len(s.signers)-1 {
		return nil, errors.New("round2 commitment set has wrong size")
	}
	index := 0
	for _, recipient := range s.signers {
		if recipient == from {
			continue
		}
		if commitments[index].Recipient != recipient {
			return nil, errors.New("round2 commitment recipients do not match signer set")
		}
		index++
	}
	fromState, ok := s.partyState(from)
	if !ok || !fromState.round2.havePayload {
		return nil, errors.New("missing verified round2 payload for commitment check")
	}
	raw, err := fromState.round2.payload.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	want := sha256.Sum256(raw)
	for _, commitment := range commitments {
		if commitment.Recipient == s.key.state.Party {
			if !bytes.Equal(commitment.Hash, want[:]) {
				return nil, errors.New("round2 commitment does not match verified payload")
			}
			return round2CommitmentsDigest(commitments), nil
		}
	}
	return nil, errors.New("round2 commitment set omits local recipient")
}

func round2CommitmentsDigest(commitments []presignRound2Commitment) []byte {
	t := transcript.New("cggmp21-secp256k1-presign-round2-commitments")
	for _, commitment := range commitments {
		t.AppendUint32("recipient", commitment.Recipient)
		t.AppendBytes("payload_hash", commitment.Hash)
	}
	return t.Sum()
}

func (s *PresignSession) localMTAContributions() ([]presignMTAContribution, []byte, []byte, []byte, []byte, []byte, error) {
	contributions := make([]presignMTAContribution, 0, len(s.signers)-1)
	base := secp.NewInfinity()
	offset := secp.NewInfinity()
	deltaBase := secp.NewInfinity()
	deltaOffset := secp.NewInfinity()
	for _, signer := range s.signers {
		state, ok := s.partyState(signer)
		if !ok || !state.round1.havePayload {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("missing round1 gamma for signer %d", signer)
		}
		gamma, err := secp.PointFromBytes(state.round1.payload.Gamma)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		deltaBase = secp.Add(deltaBase, gamma)
	}
	for _, peer := range s.signers {
		if peer == s.key.state.Party {
			continue
		}
		state, ok := s.partyState(peer)
		if !ok || !state.round2.havePayload || !state.round2.haveOutboundSigma || !state.round2.haveOutboundDelta {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("missing MtA contribution for peer %d", peer)
		}
		contributions = append(contributions, presignMTAContribution{
			Peer:          peer,
			Inbound:       state.round2.payload.Sigma.Clone(),
			Outbound:      state.round2.outboundSigma.Clone(),
			InboundDelta:  state.round2.payload.Delta.Clone(),
			OutboundDelta: state.round2.outboundDelta.Clone(),
		})
		xBar, err := s.xBarCommitment(peer)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		xBarPoint, err := secp.PointFromBytes(xBar)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		base = secp.Add(base, xBarPoint)
		inboundY, err := mtaMaskPoint(state.round2.payload.Sigma)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		outboundY, err := mtaMaskPoint(state.round2.outboundSigma)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		offset = secp.Add(offset, inboundY)
		negOutbound := secp.Clone(outboundY)
		negOutbound.Y = secp.FieldNeg(negOutbound.Y)
		offset = secp.Add(offset, negOutbound)
		inboundDeltaY, err := mtaMaskPoint(state.round2.payload.Delta)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		outboundDeltaY, err := mtaMaskPoint(state.round2.outboundDelta)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		deltaOffset = secp.Add(deltaOffset, inboundDeltaY)
		negOutboundDelta := secp.Clone(outboundDeltaY)
		negOutboundDelta.Y = secp.FieldNeg(negOutboundDelta.Y)
		deltaOffset = secp.Add(deltaOffset, negOutboundDelta)
	}
	baseBytes, err := optionalSecpPointBytes(base)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	offsetBytes, err := optionalSecpPointBytes(offset)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	deltaBaseBytes, err := optionalSecpPointBytes(deltaBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	deltaOffsetBytes, err := optionalSecpPointBytes(deltaOffset)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	digest, err := mtaContributionsDigest(contributions)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	return contributions, digest, baseBytes, offsetBytes, deltaBaseBytes, deltaOffsetBytes, nil
}

func optionalSecpPointBytes(point *secp.Point) ([]byte, error) {
	if point == nil || point.Inf != 0 {
		return nil, nil
	}
	return secp.PointBytes(point)
}

func mtaMaskPoint(response mta.ResponseMessage) (*secp.Point, error) {
	if len(response.Proof.YPoint) == 0 {
		return secp.NewInfinity(), nil
	}
	return secp.PointFromBytes(response.Proof.YPoint)
}

func mtaContributionsDigest(contributions []presignMTAContribution) ([]byte, error) {
	t := transcript.New("cggmp21-secp256k1-presign-mta-contributions")
	for i := range contributions {
		inbound, err := contributions[i].Inbound.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode inbound sigma contribution: %w", err)
		}
		outbound, err := contributions[i].Outbound.MarshalBinary()
		if err != nil {
			clear(inbound)
			return nil, fmt.Errorf("encode outbound sigma contribution: %w", err)
		}
		inboundDelta, err := contributions[i].InboundDelta.MarshalBinary()
		if err != nil {
			clear(inbound)
			clear(outbound)
			return nil, fmt.Errorf("encode inbound delta contribution: %w", err)
		}
		outboundDelta, err := contributions[i].OutboundDelta.MarshalBinary()
		if err != nil {
			clear(inbound)
			clear(outbound)
			clear(inboundDelta)
			return nil, fmt.Errorf("encode outbound delta contribution: %w", err)
		}
		t.AppendUint32("peer", contributions[i].Peer)
		inboundHash := sha256.Sum256(inbound)
		outboundHash := sha256.Sum256(outbound)
		inboundDeltaHash := sha256.Sum256(inboundDelta)
		outboundDeltaHash := sha256.Sum256(outboundDelta)
		t.AppendBytes("inbound_hash", inboundHash[:])
		t.AppendBytes("outbound_hash", outboundHash[:])
		t.AppendBytes("inbound_delta_hash", inboundDeltaHash[:])
		t.AppendBytes("outbound_delta_hash", outboundDeltaHash[:])
		clear(inbound)
		clear(outbound)
		clear(inboundDelta)
		clear(outboundDelta)
	}
	return t.Sum(), nil
}

func (s *PresignSession) verifyMTAContributions(from tss.PartyID, contributions []presignMTAContribution) ([]byte, []byte, []byte, []byte, []byte, error) {
	if len(contributions) != len(s.signers)-1 {
		return nil, nil, nil, nil, nil, errors.New("MtA contribution set has wrong size")
	}
	base := secp.NewInfinity()
	offset := secp.NewInfinity()
	deltaBase := secp.NewInfinity()
	deltaOffset := secp.NewInfinity()
	for _, signer := range s.signers {
		state, ok := s.partyState(signer)
		if !ok || !state.round1.havePayload {
			return nil, nil, nil, nil, nil, fmt.Errorf("missing round1 gamma for signer %d", signer)
		}
		gamma, err := secp.PointFromBytes(state.round1.payload.Gamma)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		deltaBase = secp.Add(deltaBase, gamma)
	}
	index := 0
	for _, peer := range s.signers {
		if peer == from {
			continue
		}
		contribution := contributions[index]
		index++
		if contribution.Peer != peer {
			return nil, nil, nil, nil, nil, errors.New("MtA contribution peers do not match signer set")
		}
		if err := s.verifyPublicSigmaResponse(from, peer, contribution.Inbound); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid inbound sigma contribution from %d: %w", peer, err)
		}
		if err := s.verifyPublicSigmaResponse(peer, from, contribution.Outbound); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid outbound sigma contribution to %d: %w", peer, err)
		}
		if err := s.verifyPublicDeltaResponse(from, peer, contribution.InboundDelta); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid inbound delta contribution from %d: %w", peer, err)
		}
		if err := s.verifyPublicDeltaResponse(peer, from, contribution.OutboundDelta); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid outbound delta contribution to %d: %w", peer, err)
		}
		xBar, err := s.xBarCommitment(peer)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		xBarPoint, err := secp.PointFromBytes(xBar)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		base = secp.Add(base, xBarPoint)
		inboundY, err := mtaMaskPoint(contribution.Inbound)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		outboundY, err := mtaMaskPoint(contribution.Outbound)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		offset = secp.Add(offset, inboundY)
		negOutbound := secp.Clone(outboundY)
		negOutbound.Y = secp.FieldNeg(negOutbound.Y)
		offset = secp.Add(offset, negOutbound)
		inboundDeltaY, err := mtaMaskPoint(contribution.InboundDelta)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		outboundDeltaY, err := mtaMaskPoint(contribution.OutboundDelta)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		deltaOffset = secp.Add(deltaOffset, inboundDeltaY)
		negOutboundDelta := secp.Clone(outboundDeltaY)
		negOutboundDelta.Y = secp.FieldNeg(negOutboundDelta.Y)
		deltaOffset = secp.Add(deltaOffset, negOutboundDelta)
		if err := s.verifyMTAContributionConsistency(from, peer, contribution); err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}
	baseBytes, err := optionalSecpPointBytes(base)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	offsetBytes, err := optionalSecpPointBytes(offset)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	deltaBaseBytes, err := optionalSecpPointBytes(deltaBase)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	deltaOffsetBytes, err := optionalSecpPointBytes(deltaOffset)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	digest, err := mtaContributionsDigest(contributions)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return digest, baseBytes, offsetBytes, deltaBaseBytes, deltaOffsetBytes, nil
}

func (s *PresignSession) verifyPublicSigmaResponse(initiator, responder tss.PartyID, response mta.ResponseMessage) error {
	initiatorState, ok := s.partyState(initiator)
	if !ok || !initiatorState.round1.havePayload {
		return fmt.Errorf("missing round1 state for initiator %d", initiator)
	}
	initiatorPK, err := s.key.paillierPublicFor(initiator, s.limits)
	if err != nil {
		return err
	}
	responderPK, err := s.key.paillierPublicFor(responder, s.limits)
	if err != nil {
		return err
	}
	initiatorRP, err := s.key.ringPedersenPublicFor(initiator, s.limits)
	if err != nil {
		return err
	}
	responderXBar, err := s.xBarCommitment(responder)
	if err != nil {
		return err
	}
	domain, err := mtaSigmaResponseDomain(s.key, s.sessionID, s.signers, initiator, responder, initiatorPK, s.contextHash, s.planHash, s.limits)
	if err != nil {
		return err
	}
	return mta.VerifyResponse(s.securityParams, domain,
		mta.StartMessage{Ciphertext: initiatorState.round1.payload.EncK}, response,
		initiatorState.round1.payload.KPoint, responderXBar, initiatorPK, responderPK, initiatorRP)
}

func (s *PresignSession) verifyPublicDeltaResponse(initiator, responder tss.PartyID, response mta.ResponseMessage) error {
	initiatorState, ok := s.partyState(initiator)
	if !ok || !initiatorState.round1.havePayload {
		return fmt.Errorf("missing round1 state for initiator %d", initiator)
	}
	responderState, ok := s.partyState(responder)
	if !ok || !responderState.round1.havePayload {
		return fmt.Errorf("missing round1 state for responder %d", responder)
	}
	initiatorPK, err := s.key.paillierPublicFor(initiator, s.limits)
	if err != nil {
		return err
	}
	responderPK, err := s.key.paillierPublicFor(responder, s.limits)
	if err != nil {
		return err
	}
	initiatorRP, err := s.key.ringPedersenPublicFor(initiator, s.limits)
	if err != nil {
		return err
	}
	domain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, initiator, responder, initiatorPK, s.contextHash, s.planHash, s.limits)
	if err != nil {
		return err
	}
	return mta.VerifyResponse(s.securityParams, domain,
		mta.StartMessage{Ciphertext: initiatorState.round1.payload.EncK}, response,
		initiatorState.round1.payload.KPoint, responderState.round1.payload.Gamma,
		initiatorPK, responderPK, initiatorRP)
}

func (s *PresignSession) verifyMTAContributionConsistency(from, peer tss.PartyID, contribution presignMTAContribution) error {
	if peer == s.key.state.Party {
		state, ok := s.partyState(from)
		if !ok || !state.round2.havePayload || !state.round2.haveOutboundSigma || !state.round2.haveOutboundDelta {
			return errors.New("missing local MTA contribution state")
		}
		if !sameSigmaResponse(contribution.Inbound, state.round2.outboundSigma) ||
			!sameSigmaResponse(contribution.Outbound, state.round2.payload.Sigma) ||
			!sameSigmaResponse(contribution.InboundDelta, state.round2.outboundDelta) ||
			!sameSigmaResponse(contribution.OutboundDelta, state.round2.payload.Delta) {
			return errors.New("MTA contribution does not match verified round2 exchange")
		}
	}
	peerState, ok := s.partyState(peer)
	if !ok || !peerState.round3.haveVerifyShare {
		return nil
	}
	other, ok := mtaContributionFor(peerState.round3.verifyShare.mtaContributions, from)
	if !ok {
		return errors.New("stored peer MTA contribution is incomplete")
	}
	if !sameSigmaResponse(contribution.Outbound, other.Inbound) ||
		!sameSigmaResponse(contribution.Inbound, other.Outbound) ||
		!sameSigmaResponse(contribution.OutboundDelta, other.InboundDelta) ||
		!sameSigmaResponse(contribution.InboundDelta, other.OutboundDelta) {
		return &mtaContributionViewMismatchError{left: from, right: peer}
	}
	return nil
}

func sameSigmaResponse(left, right mta.ResponseMessage) bool {
	leftBytes, leftErr := left.MarshalBinary()
	rightBytes, rightErr := right.MarshalBinary()
	defer clear(leftBytes)
	defer clear(rightBytes)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func mtaContributionFor(contributions []presignMTAContribution, peer tss.PartyID) (presignMTAContribution, bool) {
	for i := range contributions {
		if contributions[i].Peer == peer {
			return contributions[i], true
		}
	}
	return presignMTAContribution{}, false
}

func cloneMTAContributions(in []presignMTAContribution) []presignMTAContribution {
	out := make([]presignMTAContribution, len(in))
	for i := range in {
		out[i] = presignMTAContribution{
			Peer:          in[i].Peer,
			Inbound:       in[i].Inbound.Clone(),
			Outbound:      in[i].Outbound.Clone(),
			InboundDelta:  in[i].InboundDelta.Clone(),
			OutboundDelta: in[i].OutboundDelta.Clone(),
		}
	}
	return out
}

func destroyMTAContributions(in []presignMTAContribution) {
	for i := range in {
		in[i].Inbound.Destroy()
		in[i].Outbound.Destroy()
		in[i].InboundDelta.Destroy()
		in[i].OutboundDelta.Destroy()
	}
}

func (s *PresignSession) commitPresignRound3Output(p *preparedPresignRound3Output) (sessionEffects, error) {
	if p == nil {
		return sessionEffects{}, nil
	}
	selfState, ok := s.partyState(s.key.state.Party)
	if !ok {
		return sessionEffects{}, errors.New("missing local presign party state")
	}
	selfState.round3.delta = p.delta
	selfState.round3.verifyShare = p.verifyShare
	selfState.round3.haveDelta = true
	selfState.round3.haveVerifyShare = true
	s.round3Sent = true
	s.presign = p.presign
	p.committed = true
	if err := s.tryComplete(); err != nil {
		return sessionEffects{}, err
	}
	return sessionEffects{envelopes: []tss.Envelope{p.env}}, nil
}

func (s *PresignSession) tryComplete() error {
	prepared, ok, err := s.maybePreparePresignCompletion()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer prepared.destroy()
	s.commitPresignCompletion(prepared)
	return nil
}

type preparedPresignCompletion struct {
	presign   *Presign
	committed bool
}

func (p *preparedPresignCompletion) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.presign != nil {
		p.presign.Destroy()
		p.presign = nil
	}
}

func (s *PresignSession) maybePreparePresignCompletion() (*preparedPresignCompletion, bool, error) {
	if s.completed || !s.allRound3Accepted() {
		return nil, false, nil
	}
	delta := secp.ScalarZero()
	gammaPoints := make([]*secp.Point, 0, len(s.parties))
	for i := range s.parties {
		st := &s.parties[i]
		if !st.round3.haveDelta || !st.round3.haveVerifyShare {
			return nil, false, nil
		}
		deltaShare, err := secpScalarFromSecret(st.round3.delta)
		if err != nil {
			return nil, false, err
		}
		delta = secp.ScalarAdd(delta, deltaShare)
		gammaPoint, err := secp.PointFromBytes(st.round1.payload.Gamma)
		if err != nil {
			return nil, false, err
		}
		gammaPoints = append(gammaPoints, gammaPoint)
	}
	if delta.IsZero() {
		return nil, false, errors.New("zero presign delta")
	}
	deltaInv, err := secp.ScalarInvert(delta)
	if err != nil {
		return nil, false, errors.New("non-invertible presign delta")
	}
	gamma := secp.AddPoints(gammaPoints...)
	RPoint := secp.ScalarMult(gamma, deltaInv)
	littleR := secp.ScalarFromFieldElement(RPoint.X)
	if littleR.IsZero() {
		return nil, false, errors.New("zero ECDSA r")
	}
	if s.presign == nil {
		return nil, false, errors.New("local presign shares not computed")
	}
	verifyShares := make([]signVerifyShare, 0, len(s.signers))
	for _, id := range s.signers {
		st, ok := s.partyState(id)
		if !ok {
			return nil, false, fmt.Errorf("missing presign state for party %d", id)
		}
		share := st.round3.verifyShare.Clone()
		destroyMTAContributions(share.mtaContributions)
		share.mtaContributions = nil
		verifyShares = append(verifyShares, share)
	}
	verification, err := s.buildPresignVerificationContext()
	if err != nil {
		return nil, false, err
	}
	deltaSecret, err := secpSecretScalarFromScalar(delta)
	if err != nil {
		return nil, false, err
	}
	base := s.presign.state
	completed := &Presign{state: &presignState{
		SecurityParams:       base.SecurityParams,
		Party:                base.Party,
		Threshold:            base.Threshold,
		Signers:              base.Signers.Clone(),
		R:                    secp.Clone(RPoint),
		LittleR:              littleR,
		TranscriptHash:       s.presignTranscriptHash(RPoint, littleR, delta),
		Context:              base.Context.Clone(),
		ContextHash:          bytes.Clone(base.ContextHash),
		Derivation:           base.Derivation.Clone(),
		PlanHash:             bytes.Clone(base.PlanHash),
		PublicKey:            secp.Clone(base.PublicKey),
		KeygenTranscriptHash: bytes.Clone(base.KeygenTranscriptHash),
		PartiesHash:          bytes.Clone(base.PartiesHash),
		VerifyShares:         verifyShares,
		Verification:         verification,
		KShare:               base.KShare.Clone(),
		ChiShare:             base.ChiShare.Clone(),
		DeltaAggregate:       deltaSecret,
		Consumed:             NewAtomicBoolWire(false),
		attempt:              newPresignAttemptBinding(false),
	}}
	return &preparedPresignCompletion{presign: completed}, true, nil
}

func (s *PresignSession) buildPresignVerificationContext() (presignVerificationContext, error) {
	context := presignVerificationContext{
		SessionID:  s.sessionID,
		Round1Echo: s.round1Echo(),
		Entries:    make([]presignVerificationEntry, 0, len(s.signers)),
	}
	for _, id := range s.signers {
		state, ok := s.partyState(id)
		if !ok || !state.round1.havePayload || !state.round3.haveDelta {
			context.destroy()
			return presignVerificationContext{}, fmt.Errorf("missing persisted verification material for party %d", id)
		}
		lambda, err := shamir.LagrangeCoefficient(id, s.signers)
		if err != nil {
			context.destroy()
			return presignVerificationContext{}, err
		}
		verificationShare, ok := s.key.verificationShare(id)
		if !ok {
			context.destroy()
			return presignVerificationContext{}, fmt.Errorf("missing verification share for party %d", id)
		}
		verificationPoint, err := secp.PointFromBytes(verificationShare)
		if err != nil {
			context.destroy()
			return presignVerificationContext{}, err
		}
		delta, err := secpScalarFromSecret(state.round3.delta)
		if err != nil {
			context.destroy()
			return presignVerificationContext{}, err
		}
		context.Entries = append(context.Entries, presignVerificationEntry{
			Party:             id,
			Gamma:             bytes.Clone(state.round1.payload.Gamma),
			EncK:              bytes.Clone(state.round1.payload.EncK),
			PaillierPublicKey: state.round1.payload.PaillierPublicKey.Clone(),
			XBarPoint:         secp.ScalarMult(verificationPoint, lambda),
			Delta:             &delta,
			KPoint:            bytes.Clone(state.round1.payload.KPoint),
		})
	}
	return context, nil
}

func (s *PresignSession) commitPresignCompletion(p *preparedPresignCompletion) {
	if p == nil {
		return
	}
	if s.presign != nil {
		s.presign.Destroy()
	}
	s.presign = p.presign
	s.completed = true
	s.log.Info(s.config.Ctx(), "presign complete",
		"party_id", s.key.state.Party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	p.committed = true
}

func (s *PresignSession) presignTranscriptHash(R *secp.Point, littleR, delta secp.Scalar) []byte {
	t := transcript.New(presignTranscriptHashLabel)
	rBytes, _ := secp.PointBytes(R)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendBytes("additive_shift", s.derivation.AdditiveShift)
	t.AppendBytes("public_key", s.key.state.PublicKey)
	t.AppendBytes("keygen_transcript_hash", s.key.state.KeygenTranscriptHash)
	t.AppendBytes("parties_hash", tss.PartySetHash(s.key.state.Parties, partySetHashLabel))
	for _, id := range s.signers {
		st, ok := s.partyState(id)
		if !ok {
			continue
		}
		t.AppendUint32("signer", id)
		t.AppendBytes("gamma", st.round1.payload.Gamma)
		t.AppendBytes("enc_k", st.round1.payload.EncK)
		t.AppendBytes("delta_share", st.round3.delta.FixedBytes())
		vs := st.round3.verifyShare
		kPointBytes, _ := vs.kPointBytes()
		chiPointBytes, _ := vs.chiPointBytes()
		proofBytes, _ := vs.proofBytes()
		t.AppendBytes("k_point", kPointBytes)
		t.AppendBytes("chi_point", chiPointBytes)
		proofHash := sha256.Sum256(proofBytes)
		t.AppendBytes("proof_hash", proofHash[:])
	}
	t.AppendBytes("r_point", rBytes)
	t.AppendBytes("little_r", littleR.Bytes())
	t.AppendBytes("delta", delta.Bytes())
	return t.Sum()
}

func (s *PresignSession) round1Echo() []byte {
	t := transcript.New(presignRound1EchoLabel)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendBytes("additive_shift", s.derivation.AdditiveShift)
	for _, id := range s.signers {
		st, ok := s.partyState(id)
		if !ok {
			continue
		}
		p := st.round1.payload
		t.AppendUint32("signer", id)
		t.AppendBytes("gamma", p.Gamma)
		t.AppendBytes("enc_k", p.EncK)
		t.AppendBytes("k_point", p.KPoint)
		paillierPublicKeyBytes, _ := canonicalWireMessageBytes(p.PaillierPublicKey, s.limits)
		t.AppendBytes("paillier_public_key", paillierPublicKeyBytes)
	}
	return t.Sum()
}
