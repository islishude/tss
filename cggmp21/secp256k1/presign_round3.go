package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
	"github.com/islishude/tss/internal/zk/signprep"
)

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
	kPointBytes, err := secp.PointBytes(p.KPoint)
	if err != nil {
		return signVerifyShare{}, err
	}
	chiPointBytes, err := secp.PointBytes(p.ChiPoint)
	if err != nil {
		return signVerifyShare{}, err
	}
	lambda, err := shamirsecp.LagrangeCoefficient(from, s.signers)
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
	paillierPublicKeyBytes, err := canonicalWireMessageBytes(&round1From.PaillierPublicKey, s.limits)
	if err != nil {
		return signVerifyShare{}, err
	}
	deltaBytes := p.Delta.FixedBytes()
	defer clear(deltaBytes)
	stmt := signprep.Statement{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		SessionID:            s.sessionID,
		Party:                from,
		Signers:              slices.Clone(s.signers),
		PlanHash:             slices.Clone(s.planHash),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.derivation.AdditiveShift),
		PublicKey:            slices.Clone(s.key.state.PublicKey),
		KeygenTranscriptHash: slices.Clone(s.key.state.KeygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.state.Parties, partySetHashLabel),
		KPoint:               kPointBytes,
		ChiPoint:             chiPointBytes,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(round1From.Gamma),
		EncK:                 slices.Clone(round1From.EncK),
		PaillierPublicKey:    paillierPublicKeyBytes,
		Round1Echo:           s.round1Echo(),
		Delta:                deltaBytes,
	}
	if err := signprep.Verify(stmt, p.Proof); err != nil {
		return signVerifyShare{}, err
	}
	return signVerifyShare{
		Party:    from,
		KPoint:   secp.Clone(p.KPoint),
		ChiPoint: secp.Clone(p.ChiPoint),
		Proof:    p.Proof.Clone(),
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
	lambda, err := shamirsecp.LagrangeCoefficient(s.key.state.Party, s.signers)
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
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		SessionID:            s.sessionID,
		Party:                s.key.state.Party,
		Signers:              slices.Clone(s.signers),
		PlanHash:             slices.Clone(s.planHash),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.derivation.AdditiveShift),
		PublicKey:            slices.Clone(s.key.state.PublicKey),
		KeygenTranscriptHash: slices.Clone(s.key.state.KeygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.state.Parties, partySetHashLabel),
		KPoint:               kPointBytes,
		ChiPoint:             chiPointBytes,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(selfState.round1.payload.Gamma),
		EncK:                 slices.Clone(selfState.round1.payload.EncK),
		PaillierPublicKey:    paillierPublicKey,
		Round1Echo:           s.round1Echo(),
		Delta:                deltaShare.Bytes(),
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
		Delta:    deltaSecret,
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proof,
		PlanHash: s.planHash,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, false, err
	}
	verifyShare := signVerifyShare{
		Party:    s.key.state.Party,
		KPoint:   secp.Clone(kPoint),
		ChiPoint: secp.Clone(chiPoint),
		Proof:    proof.Clone(),
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
		PartiesHash:          wireutil.PartySetHash(s.key.state.Parties, partySetHashLabel),
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
		verifyShares = append(verifyShares, st.round3.verifyShare.Clone())
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
		KShare:               base.KShare.Clone(),
		ChiShare:             base.ChiShare.Clone(),
		Delta:                deltaSecret,
		Consumed:             NewAtomicBoolWire(false),
		attempt:              newPresignAttemptBinding(false),
	}}
	return &preparedPresignCompletion{presign: completed}, true, nil
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
	t.AppendBytes("parties_hash", wireutil.PartySetHash(s.key.state.Parties, partySetHashLabel))
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
		paillierPublicKeyBytes, _ := canonicalWireMessageBytes(&p.PaillierPublicKey, s.limits)
		t.AppendBytes("paillier_public_key", paillierPublicKeyBytes)
	}
	return t.Sum()
}
