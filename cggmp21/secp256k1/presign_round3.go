package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync/atomic"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
	"github.com/islishude/tss/internal/zk/signprep"
)

// handlePresignRound3 validates and applies a presign round 3 delta share.
//
// Follows the handler template (see doc.go).
func (s *PresignSession) handlePresignRound3(env tss.Envelope) ([]tss.Envelope, error) {
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

	// ---- 2. POLICY VALIDATE ----
	// (round and duplicate checks done in dispatcher)
	if err := requirePlanHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	delta := secp.ScalarFromBigInt(p.Delta)

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

	// ---- 4. MUTATE STATE ----
	deltaSecret, err := secpSecretScalarFromScalar(delta)
	if err != nil {
		return nil, err
	}
	st, ok := s.partyState(env.From)
	if !ok {
		deltaSecret.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	st.round3.delta = deltaSecret
	st.round3.verifyShare = material
	st.round3.haveDelta = true
	st.round3.haveVerifyShare = true
	s.round3Count++

	// ---- 5. EMIT ----
	return nil, s.tryComplete()
}

func (s *PresignSession) verifyRemoteSignprepProof(from tss.PartyID, p presignRound3Payload) (signVerifyShare, error) {
	if p.KPoint.P == nil {
		return signVerifyShare{}, errors.New("missing KPoint")
	}
	if p.ChiPoint.P == nil {
		return signVerifyShare{}, errors.New("missing ChiPoint")
	}
	if err := p.Proof.Validate(); err != nil {
		return signVerifyShare{}, fmt.Errorf("invalid signprep proof: %w", err)
	}
	kPointBytes, err := secp.PointBytes(p.KPoint.P)
	if err != nil {
		return signVerifyShare{}, err
	}
	chiPointBytes, err := secp.PointBytes(p.ChiPoint.P)
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
	stmt := signprep.Statement{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		SessionID:            s.sessionID,
		Party:                from,
		Signers:              slices.Clone(s.signers),
		PlanHash:             slices.Clone(s.planHash),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.derivation.AdditiveShift),
		PublicKey:            slices.Clone(s.key.state.publicKey),
		KeygenTranscriptHash: slices.Clone(s.key.state.keygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.state.parties, partySetHashLabel),
		KPoint:               kPointBytes,
		ChiPoint:             chiPointBytes,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(round1From.Gamma),
		EncK:                 slices.Clone(round1From.EncK),
		PaillierPublicKey:    paillierPublicKeyBytes,
		Round1Echo:           s.round1Echo(),
		Delta:                scalarBytes(p.Delta),
	}
	if err := signprep.Verify(stmt, &p.Proof); err != nil {
		return signVerifyShare{}, err
	}
	return signVerifyShare{
		party:    from,
		kPoint:   secp.Clone(p.KPoint.P),
		chiPoint: secp.Clone(p.ChiPoint.P),
		proof:    cloneSignPrepProof(p.Proof),
	}, nil
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	kPointBytes, _ := secp.PointBytes(p.KPoint.P)
	chiPointBytes, _ := secp.PointBytes(p.ChiPoint.P)
	proofBytes, _ := p.Proof.MarshalBinary()
	return append(fields,
		hashEvidenceField("delta_hash", scalarBytes(p.Delta)),
		hashEvidenceField(evidenceFieldSignVerifyKPointHash, kPointBytes),
		hashEvidenceField(evidenceFieldSignVerifyChiPointHash, chiPointBytes),
		hashEvidenceField(evidenceFieldSignPrepProofHash, proofBytes),
	)
}

func (s *PresignSession) tryEmitRound3() ([]tss.Envelope, error) {
	if s.round3Sent || s.round2Count != len(s.parties)-1 {
		return nil, nil
	}
	kShare, err := secpScalarFromSecret(s.kShare)
	if err != nil {
		return nil, err
	}
	gamma, err := secpScalarFromSecret(s.gamma)
	if err != nil {
		return nil, err
	}
	xBar, err := secpScalarFromSecret(s.xBar)
	if err != nil {
		return nil, err
	}
	deltaShare := secp.ScalarMul(kShare, gamma)
	chiShare := secp.ScalarMul(kShare, xBar)
	for _, peer := range s.signers {
		if peer == s.key.state.party {
			continue
		}
		peerState, ok := s.partyState(peer)
		if !ok {
			return nil, fmt.Errorf("missing presign state for party %d", peer)
		}
		alphaDelta, err := secpScalarFromSecret(peerState.mta.alphaDelta)
		if err != nil {
			return nil, err
		}
		betaDelta, err := secpScalarFromSecret(peerState.mta.betaDelta)
		if err != nil {
			return nil, err
		}
		alphaSigma, err := secpScalarFromSecret(peerState.mta.alphaSigma)
		if err != nil {
			return nil, err
		}
		betaSigma, err := secpScalarFromSecret(peerState.mta.betaSigma)
		if err != nil {
			return nil, err
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
			return nil, err
		}
		if !shift.IsZero() {
			chiShare = secp.ScalarAdd(chiShare, secp.ScalarMul(kShare, shift))
		}
	}
	deltaSecret, err := secpSecretScalarFromScalar(deltaShare)
	if err != nil {
		return nil, err
	}
	selfState, ok := s.partyState(s.key.state.party)
	if !ok {
		deltaSecret.Destroy()
		return nil, errors.New("missing local presign party state")
	}

	// Compute KPoint and ChiPoint.
	kPoint := secp.ScalarBaseMult(kShare)
	kPointBytes, err := secp.PointBytes(kPoint)
	if err != nil {
		return nil, err
	}
	chiPoint := secp.ScalarBaseMult(chiShare)
	chiPointBytes, err := secp.PointBytes(chiPoint)
	if err != nil {
		return nil, err
	}

	// Compute XBarPoint.
	lambda, err := shamirsecp.LagrangeCoefficient(s.key.state.party, s.signers)
	if err != nil {
		return nil, err
	}
	verificationShare, ok := s.key.verificationShare(s.key.state.party)
	if !ok {
		return nil, fmt.Errorf("missing local verification share for party %d", s.key.state.party)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return nil, err
	}
	xBarPoint, err := secp.PointBytes(secp.ScalarMult(verificationPoint, lambda))
	if err != nil {
		return nil, err
	}

	// Build signprep proof.
	localPaillierPublicKey, err := s.key.paillierPublicFor(s.key.state.party, s.limits)
	if err != nil {
		return nil, err
	}
	paillierPublicKey, err := canonicalWireMessageBytes(localPaillierPublicKey, s.limits)
	if err != nil {
		return nil, err
	}
	stmt := signprep.Statement{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		SessionID:            s.sessionID,
		Party:                s.key.state.party,
		Signers:              slices.Clone(s.signers),
		PlanHash:             slices.Clone(s.planHash),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.derivation.AdditiveShift),
		PublicKey:            slices.Clone(s.key.state.publicKey),
		KeygenTranscriptHash: slices.Clone(s.key.state.keygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.state.parties, partySetHashLabel),
		KPoint:               kPointBytes,
		ChiPoint:             chiPointBytes,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(selfState.round1.payload.Gamma),
		EncK:                 slices.Clone(selfState.round1.payload.EncK),
		PaillierPublicKey:    paillierPublicKey,
		Round1Echo:           s.round1Echo(),
		Delta:                deltaShare.Bytes(),
	}
	kShareBig := kShare.BigInt()
	defer secret.ClearBigInt(kShareBig)
	mtaSumBig := mtaSum.BigInt()
	defer secret.ClearBigInt(mtaSumBig)
	chiShareBig := chiShare.BigInt()
	defer secret.ClearBigInt(chiShareBig)
	wit := signprep.Witness{
		KShare:   kShareBig,
		MTASum:   mtaSumBig,
		ChiShare: chiShareBig,
	}
	proof, err := signprep.Prove(s.config.Reader(), stmt, wit)
	if err != nil {
		return nil, fmt.Errorf("signprep proof generation: %w", err)
	}

	deltaShareBig := deltaShare.BigInt()
	defer secret.ClearBigInt(deltaShareBig)
	payload, err := (presignRound3Payload{
		Delta:    deltaShareBig,
		KPoint:   secp.WirePoint{P: kPoint},
		ChiPoint: secp.WirePoint{P: chiPoint},
		Proof:    *proof,
		PlanHash: s.planHash,
	}).MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, err
	}
	s.round3Sent = true
	selfState.round3.delta = deltaSecret
	selfState.round3.verifyShare = signVerifyShare{
		party:    s.key.state.party,
		kPoint:   secp.Clone(kPoint),
		chiPoint: secp.Clone(chiPoint),
		proof:    cloneSignPrepProof(*proof),
	}
	selfState.round3.haveDelta = true
	selfState.round3.haveVerifyShare = true
	s.round3Count++
	context := s.context.Clone()
	publicKeyPoint, err := secp.PointFromBytes(s.key.state.publicKey)
	if err != nil {
		return nil, err
	}
	s.presign = &Presign{state: &presignState{
		consumed:             new(atomic.Bool),
		attempt:              newPresignAttemptBinding(false),
		securityParams:       s.securityParams,
		party:                s.key.state.party,
		threshold:            s.key.state.threshold,
		signers:              s.signers.Clone(),
		context:              context,
		contextHash:          append([]byte(nil), s.contextHash...),
		derivation:           s.derivation.Clone(),
		planHash:             append([]byte(nil), s.planHash...),
		publicKey:            publicKeyPoint,
		keygenTranscriptHash: append([]byte(nil), s.key.state.keygenTranscriptHash...),
		partiesHash:          wireutil.PartySetHash(s.key.state.parties, partySetHashLabel),
		kShare:               s.kShare.Clone(),
	}}
	s.presign.state.chiShare, err = secpSecretScalarFromScalar(chiShare)
	if err != nil {
		return nil, err
	}
	if err := s.tryComplete(); err != nil {
		return nil, err
	}
	env, err := newEnvelope(s.config, 3, s.key.state.party, tss.BroadcastPartyId, payloadPresignRound3, payload)
	if err != nil {
		return nil, err
	}
	return []tss.Envelope{env}, nil
}

func (s *PresignSession) tryComplete() error {
	if s.completed || s.round3Count != len(s.parties) {
		return nil
	}
	delta := secp.ScalarZero()
	gammaPoints := make([]*secp.Point, 0, len(s.parties))
	for i := range s.parties {
		st := &s.parties[i]
		if !st.round3.haveDelta || !st.round3.haveVerifyShare {
			return nil
		}
		deltaShare, err := secpScalarFromSecret(st.round3.delta)
		if err != nil {
			return err
		}
		delta = secp.ScalarAdd(delta, deltaShare)
		gammaPoint, err := secp.PointFromBytes(st.round1.payload.Gamma)
		if err != nil {
			return err
		}
		gammaPoints = append(gammaPoints, gammaPoint)
	}
	if delta.IsZero() {
		return errors.New("zero presign delta")
	}
	deltaInv, err := secp.ScalarInvert(delta)
	if err != nil {
		return errors.New("non-invertible presign delta")
	}
	gamma := secp.AddPoints(gammaPoints...)
	RPoint := secp.ScalarMult(gamma, deltaInv)
	littleRBig := new(big.Int).Mod(RPoint.X.BigInt(), secp.Order())
	defer secret.ClearBigInt(littleRBig)
	littleR := secp.ScalarFromBigInt(littleRBig)
	if littleR.IsZero() {
		return errors.New("zero ECDSA r")
	}
	if s.presign == nil {
		return errors.New("local presign shares not computed")
	}
	// R = delta^{-1} * Gamma, with Gamma=sum_i Gamma_i. LittleR is the ECDSA r.
	// Populate VerifyShares from the session's collected verification material.
	s.presign.state.verifyShares = make([]signVerifyShare, 0, len(s.signers))
	for _, id := range s.signers {
		st, ok := s.partyState(id)
		if !ok {
			return fmt.Errorf("missing presign state for party %d", id)
		}
		s.presign.state.verifyShares = append(s.presign.state.verifyShares, st.round3.verifyShare.clone())
	}
	s.presign.state.r = secp.Clone(RPoint)
	s.presign.state.littleR = littleR
	s.presign.state.delta, err = secpSecretScalarFromScalar(delta)
	if err != nil {
		return err
	}
	s.presign.state.transcriptHash = s.presignTranscriptHash(RPoint, littleR, delta)
	s.completed = true
	s.log.Info(s.config.Ctx(), "presign complete",
		"party_id", s.key.state.party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	return nil
}

func (s *PresignSession) presignTranscriptHash(R *secp.Point, littleR, delta secp.Scalar) []byte {
	t := transcript.New(presignTranscriptHashLabel)
	rBytes, _ := secp.PointBytes(R)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendBytes("additive_shift", s.derivation.AdditiveShift)
	t.AppendBytes("public_key", s.key.state.publicKey)
	t.AppendBytes("keygen_transcript_hash", s.key.state.keygenTranscriptHash)
	t.AppendBytes("parties_hash", wireutil.PartySetHash(s.key.state.parties, partySetHashLabel))
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
