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
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire/wireutil"
	"github.com/islishude/tss/internal/zk/signprep"
)

// handlePresignRound3 validates and applies a presign round 3 delta share.
//
// Follows the handler template (see doc.go).
func (s *PresignSession) handlePresignRound3(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	p, err := unmarshalPresignRound3Payload(env.Payload)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound3,
			"malformed presign round3 payload",
			[]tss.PartyID{env.From},
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
			[]tss.PartyID{env.From},
			err,
			s.presignRound3EvidenceFields(p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	s.deltas[env.From] = delta.BigInt()
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
	order := secp.Order()
	lambda, err := shamir.LagrangeCoefficient(from, s.signers, order)
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
	xBarPoint, err := secp.PointBytes(secp.ScalarMult(verificationPoint, secp.ScalarFromBigInt(lambda)))
	if err != nil {
		return err
	}
	stmt := signprep.Statement{
		Protocol:             protocol,
		SessionID:            s.sessionID,
		Party:                from,
		Signers:              slices.Clone(s.signers),
		PlanHash:             slices.Clone(s.planHash),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.additiveShift),
		PublicKey:            slices.Clone(s.key.state.publicKey),
		KeygenTranscriptHash: slices.Clone(s.key.state.keygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.state.parties, partySetHashLabel),
		KPoint:               slices.Clone(p.KPoint),
		ChiPoint:             slices.Clone(p.ChiPoint),
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(s.round1[from].Gamma),
		EncK:                 slices.Clone(s.round1[from].EncK),
		PaillierPublicKey:    slices.Clone(s.round1[from].PaillierPublicKey),
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
	kShare, err := secpSecretBig(s.kShare)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(kShare)
	gamma, err := secpSecretBig(s.gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gamma)
	xBar, err := secpSecretBig(s.xBar)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(xBar)
	deltaShare := new(big.Int).Mul(kShare, gamma)
	chiShare := new(big.Int).Mul(kShare, xBar)
	order := secp.Order()
	for _, peer := range s.signers {
		if peer == s.key.state.party {
			continue
		}
		deltaShare.Add(deltaShare, s.alphaDelta[peer])
		deltaShare.Add(deltaShare, s.betaDelta[peer])
		chiShare.Add(chiShare, s.alphaSigma[peer])
		chiShare.Add(chiShare, s.betaSigma[peer])
	}
	deltaShare.Mod(deltaShare, order)
	chiShare.Mod(chiShare, order)
	mtaSum := new(big.Int).Sub(chiShare, new(big.Int).Mul(kShare, xBar))
	mtaSum.Mod(mtaSum, order)
	if len(s.additiveShift) > 0 {
		shift, err := secp.ScalarFromBytes(s.additiveShift)
		if err != nil {
			return nil, err
		}
		shiftTerm := new(big.Int).Mul(kShare, shift.BigInt())
		chiShare.Add(chiShare, shiftTerm)
		chiShare.Mod(chiShare, order)
	}
	s.deltas[s.key.state.party] = deltaShare

	// Compute KPoint and ChiPoint.
	kScalar, err := secp.ScalarFromBytes(scalarBytes(kShare))
	if err != nil {
		return nil, err
	}
	kPoint, err := secp.PointBytes(secp.ScalarBaseMult(kScalar))
	if err != nil {
		return nil, err
	}
	chiScalar, err := secp.ScalarFromBytes(scalarBytes(chiShare))
	if err != nil {
		return nil, err
	}
	chiPoint, err := secp.PointBytes(secp.ScalarBaseMult(chiScalar))
	if err != nil {
		return nil, err
	}

	// Compute XBarPoint.
	lambda, err := shamir.LagrangeCoefficient(s.key.state.party, s.signers, order)
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
	xBarPoint, err := secp.PointBytes(secp.ScalarMult(verificationPoint, secp.ScalarFromBigInt(lambda)))
	if err != nil {
		return nil, err
	}

	// Build signprep proof.
	stmt := signprep.Statement{
		Protocol:             protocol,
		SessionID:            s.sessionID,
		Party:                s.key.state.party,
		Signers:              slices.Clone(s.signers),
		PlanHash:             slices.Clone(s.planHash),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.additiveShift),
		PublicKey:            slices.Clone(s.key.state.publicKey),
		KeygenTranscriptHash: slices.Clone(s.key.state.keygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.state.parties, partySetHashLabel),
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(s.round1[s.key.state.party].Gamma),
		EncK:                 slices.Clone(s.round1[s.key.state.party].EncK),
		PaillierPublicKey:    slices.Clone(s.key.state.paillierPublicKey),
		Round1Echo:           s.round1Echo(),
		Delta:                scalarBytes(deltaShare),
	}
	wit := signprep.Witness{
		KShare:   new(big.Int).Set(kShare),
		MTASum:   mtaSum,
		ChiShare: new(big.Int).Set(chiShare),
	}
	proof, err := signprep.Prove(s.config.Reader(), stmt, wit)
	if err != nil {
		return nil, fmt.Errorf("signprep proof generation: %w", err)
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return nil, err
	}

	payload, err := marshalPresignRound3Payload(presignRound3Payload{
		Delta:    deltaShare,
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proofBytes,
		PlanHash: s.planHash,
	})
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
	context := s.context
	context.DerivationPath = slices.Clone(context.DerivationPath)
	s.presign = &Presign{state: &presignState{
		consumed:             new(atomic.Bool),
		attempt:              newPresignAttemptBinding(false),
		version:              tss.Version,
		party:                s.key.state.party,
		threshold:            s.key.state.threshold,
		signers:              append([]tss.PartyID(nil), s.signers...),
		context:              context,
		contextHash:          append([]byte(nil), s.contextHash...),
		additiveShift:        append([]byte(nil), s.additiveShift...),
		planHash:             append([]byte(nil), s.planHash...),
		publicKey:            append([]byte(nil), s.key.state.publicKey...),
		keygenTranscriptHash: append([]byte(nil), s.key.state.keygenTranscriptHash...),
		partiesHash:          wireutil.PartySetHash(s.key.state.parties, partySetHashLabel),
		kShare:               s.kShare.Clone(),
	}}
	s.presign.state.chiShare, err = secpSecretScalarFromBig(chiShare)
	if err != nil {
		return nil, err
	}
	if err := s.tryComplete(); err != nil {
		return nil, err
	}
	env, err := envelope(s.config, 3, s.key.state.party, 0, payloadPresignRound3, payload, false)
	if err != nil {
		return nil, err
	}
	return []tss.Envelope{env}, nil
}

func (s *PresignSession) tryComplete() error {
	if s.completed || len(s.deltas) != len(s.signers) || len(s.verifyShares) != len(s.signers) {
		return nil
	}
	order := secp.Order()
	delta := new(big.Int)
	gammaPoints := make([]*secp.Point, 0, len(s.signers))
	for _, id := range s.signers {
		delta.Add(delta, s.deltas[id])
		delta.Mod(delta, order)
		gammaPoint, err := secp.PointFromBytes(s.round1[id].Gamma)
		if err != nil {
			return err
		}
		gammaPoints = append(gammaPoints, gammaPoint)
	}
	if delta.Sign() == 0 {
		return errors.New("zero presign delta")
	}
	deltaInv := new(big.Int).ModInverse(delta, order)
	if deltaInv == nil {
		return errors.New("non-invertible presign delta")
	}
	gamma := secp.AddPoints(gammaPoints...)
	RPoint := secp.ScalarMult(gamma, secp.ScalarFromBigInt(deltaInv))
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		return err
	}
	littleR := new(big.Int).Mod(RPoint.X.BigInt(), order)
	if littleR.Sign() == 0 {
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
	s.presign.state.littleR = scalarBytes(littleR)
	s.presign.state.delta, err = secpSecretScalarFromBig(delta)
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

func (s *PresignSession) presignTranscriptHash(R []byte, littleR, delta *big.Int) []byte {
	t := transcript.New(presignTranscriptHashLabel)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendBytes("additive_shift", s.additiveShift)
	t.AppendBytes("public_key", s.key.state.publicKey)
	t.AppendBytes("keygen_transcript_hash", s.key.state.keygenTranscriptHash)
	t.AppendBytes("parties_hash", wireutil.PartySetHash(s.key.state.parties, partySetHashLabel))
	for _, id := range s.signers {
		t.AppendUint32("signer", uint32(id))
		t.AppendBytes("gamma", s.round1[id].Gamma)
		t.AppendBytes("enc_k", s.round1[id].EncK)
		t.AppendBytes("delta_share", scalarBytes(s.deltas[id]))
		vs := s.verifyShares[id]
		t.AppendBytes("k_point", vs.KPoint)
		t.AppendBytes("chi_point", vs.ChiPoint)
		proofHash := sha256.Sum256(vs.Proof)
		t.AppendBytes("proof_hash", proofHash[:])
	}
	t.AppendBytes("r_point", R)
	t.AppendBytes("little_r", scalarBytes(littleR))
	t.AppendBytes("delta", scalarBytes(delta))
	return t.Sum()
}

func (s *PresignSession) round1Echo() []byte {
	t := transcript.New(presignRound1EchoLabel)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendBytes("additive_shift", s.additiveShift)
	for _, id := range s.signers {
		p := s.round1[id]
		t.AppendUint32("signer", uint32(id))
		t.AppendBytes("gamma", p.Gamma)
		t.AppendBytes("enc_k", p.EncK)
		t.AppendBytes("paillier_public_key", p.PaillierPublicKey)
	}
	return t.Sum()
}
