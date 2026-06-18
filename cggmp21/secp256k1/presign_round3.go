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

	if err := s.verifyRemoteSignprepProof(env.From, p); err != nil {
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
	s.deltas[env.From] = deltaSecret
	s.verifyShares[env.From] = SignVerifyShare{
		Party:    env.From,
		KPoint:   p.KPoint,
		ChiPoint: p.ChiPoint,
		Proof:    p.Proof,
	}

	// ---- 5. EMIT ----
	return nil, s.tryComplete()
}

func (s *PresignSession) verifyRemoteSignprepProof(from tss.PartyID, p presignRound3Payload) error {
	proof, err := signprep.UnmarshalProof(p.Proof)
	if err != nil {
		return fmt.Errorf("invalid signprep proof: %w", err)
	}
	lambda, err := shamirsecp.LagrangeCoefficient(from, s.signers)
	if err != nil {
		return err
	}
	verificationShare, ok := s.key.verificationShare(from)
	if !ok {
		return fmt.Errorf("missing verification share for party %d", from)
	}
	verificationPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return err
	}
	xBarPoint, err := secp.PointBytes(secp.ScalarMult(verificationPoint, lambda))
	if err != nil {
		return err
	}
	round1From := s.round1[from]
	paillierPublicKeyBytes, err := canonicalWireMessageBytes(&round1From.PaillierPublicKey, s.limits)
	if err != nil {
		return err
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
		KPoint:               slices.Clone(p.KPoint),
		ChiPoint:             slices.Clone(p.ChiPoint),
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(s.round1[from].Gamma),
		EncK:                 slices.Clone(s.round1[from].EncK),
		PaillierPublicKey:    paillierPublicKeyBytes,
		Round1Echo:           s.round1Echo(),
		Delta:                scalarBytes(p.Delta),
	}
	return signprep.Verify(stmt, proof)
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields,
		hashEvidenceField("delta_hash", scalarBytes(p.Delta)),
		hashEvidenceField(evidenceFieldSignVerifyKPointHash, p.KPoint),
		hashEvidenceField(evidenceFieldSignVerifyChiPointHash, p.ChiPoint),
		hashEvidenceField(evidenceFieldSignPrepProofHash, p.Proof),
	)
}

func (s *PresignSession) tryEmitRound3() ([]tss.Envelope, error) {
	if s.round3Sent || len(s.round2) != len(s.signers)-1 {
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
		alphaDelta, err := secpScalarFromSecret(s.alphaDelta[peer])
		if err != nil {
			return nil, err
		}
		betaDelta, err := secpScalarFromSecret(s.betaDelta[peer])
		if err != nil {
			return nil, err
		}
		alphaSigma, err := secpScalarFromSecret(s.alphaSigma[peer])
		if err != nil {
			return nil, err
		}
		betaSigma, err := secpScalarFromSecret(s.betaSigma[peer])
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
	s.deltas[s.key.state.party] = deltaSecret

	// Compute KPoint and ChiPoint.
	kPoint, err := secp.PointBytes(secp.ScalarBaseMult(kShare))
	if err != nil {
		return nil, err
	}
	chiPoint, err := secp.PointBytes(secp.ScalarBaseMult(chiShare))
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
	paillierPublicKey, err := canonicalWireMessageBytes(s.key.state.paillierPublicKey, s.limits)
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
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(s.round1[s.key.state.party].Gamma),
		EncK:                 slices.Clone(s.round1[s.key.state.party].EncK),
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
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return nil, err
	}

	deltaShareBig := deltaShare.BigInt()
	defer secret.ClearBigInt(deltaShareBig)
	payload, err := marshalPresignRound3PayloadWithLimits(presignRound3Payload{
		Delta:    deltaShareBig,
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proofBytes,
		PlanHash: s.planHash,
	}, s.limits)
	if err != nil {
		return nil, err
	}
	s.round3Sent = true
	s.verifyShares[s.key.state.party] = SignVerifyShare{
		Party:    s.key.state.party,
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proofBytes,
	}
	context := s.context.Clone()
	s.presign = &Presign{state: &presignState{
		version:              tss.Version,
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
		publicKey:            append([]byte(nil), s.key.state.publicKey...),
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
	if s.completed || len(s.deltas) != len(s.signers) || len(s.verifyShares) != len(s.signers) {
		return nil
	}
	delta := secp.ScalarZero()
	gammaPoints := make([]*secp.Point, 0, len(s.signers))
	for _, id := range s.signers {
		deltaShare, err := secpScalarFromSecret(s.deltas[id])
		if err != nil {
			return err
		}
		delta = secp.ScalarAdd(delta, deltaShare)
		gammaPoint, err := secp.PointFromBytes(s.round1[id].Gamma)
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
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		return err
	}
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
	s.presign.state.verifyShares = make([]SignVerifyShare, 0, len(s.signers))
	for _, id := range s.signers {
		s.presign.state.verifyShares = append(s.presign.state.verifyShares, s.verifyShares[id].Clone())
	}
	s.presign.state.r = R
	s.presign.state.littleR = littleR.Bytes()
	s.presign.state.delta, err = secpSecretScalarFromScalar(delta)
	if err != nil {
		return err
	}
	s.presign.state.transcriptHash = s.presignTranscriptHash(R, littleR, delta)
	s.completed = true
	s.log.Info(s.config.Ctx(), "presign complete",
		"party_id", s.key.state.party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	return nil
}

func (s *PresignSession) presignTranscriptHash(R []byte, littleR, delta secp.Scalar) []byte {
	t := transcript.New(presignTranscriptHashLabel)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendBytes("additive_shift", s.derivation.AdditiveShift)
	t.AppendBytes("public_key", s.key.state.publicKey)
	t.AppendBytes("keygen_transcript_hash", s.key.state.keygenTranscriptHash)
	t.AppendBytes("parties_hash", wireutil.PartySetHash(s.key.state.parties, partySetHashLabel))
	for _, id := range s.signers {
		t.AppendUint32("signer", id)
		t.AppendBytes("gamma", s.round1[id].Gamma)
		t.AppendBytes("enc_k", s.round1[id].EncK)
		t.AppendBytes("delta_share", s.deltas[id].FixedBytes())
		vs := s.verifyShares[id]
		t.AppendBytes("k_point", vs.KPoint)
		t.AppendBytes("chi_point", vs.ChiPoint)
		proofHash := sha256.Sum256(vs.Proof)
		t.AppendBytes("proof_hash", proofHash[:])
	}
	t.AppendBytes("r_point", R)
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
		p := s.round1[id]
		t.AppendUint32("signer", id)
		t.AppendBytes("gamma", p.Gamma)
		t.AppendBytes("enc_k", p.EncK)
		paillierPublicKeyBytes, _ := canonicalWireMessageBytes(&p.PaillierPublicKey, s.limits)
		t.AppendBytes("paillier_public_key", paillierPublicKeyBytes)
	}
	return t.Sum()
}
