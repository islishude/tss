package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire"
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
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.additiveShift),
		PublicKey:            slices.Clone(s.key.PublicKey),
		KeygenTranscriptHash: slices.Clone(s.key.KeygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.Parties, partySetHashLabel),
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
		if peer == s.key.Party {
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
	s.deltas[s.key.Party] = deltaShare

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
	lambda, err := shamir.LagrangeCoefficient(s.key.Party, s.signers, order)
	if err != nil {
		return nil, err
	}
	verificationShare, ok := s.key.verificationShare(s.key.Party)
	if !ok {
		return nil, fmt.Errorf("missing local verification share for party %d", s.key.Party)
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
		Party:                s.key.Party,
		Signers:              slices.Clone(s.signers),
		ContextHash:          slices.Clone(s.contextHash),
		AdditiveShift:        slices.Clone(s.additiveShift),
		PublicKey:            slices.Clone(s.key.PublicKey),
		KeygenTranscriptHash: slices.Clone(s.key.KeygenTranscriptHash),
		PartiesHash:          wireutil.PartySetHash(s.key.Parties, partySetHashLabel),
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
		Gamma:                slices.Clone(s.round1[s.key.Party].Gamma),
		EncK:                 slices.Clone(s.round1[s.key.Party].EncK),
		PaillierPublicKey:    slices.Clone(s.key.PaillierPublicKey),
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
	})
	if err != nil {
		return nil, err
	}
	s.round3Sent = true
	s.verifyShares[s.key.Party] = SignVerifyShare{
		Party:    s.key.Party,
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proofBytes,
	}
	s.presign = &Presign{
		consumed:             newPresignConsumedState(false),
		Version:              tss.Version,
		Party:                s.key.Party,
		Threshold:            s.key.Threshold,
		Signers:              append([]tss.PartyID(nil), s.signers...),
		Context:              s.context,
		ContextHash:          append([]byte(nil), s.contextHash...),
		AdditiveShift:        append([]byte(nil), s.additiveShift...),
		PublicKey:            append([]byte(nil), s.key.PublicKey...),
		KeygenTranscriptHash: append([]byte(nil), s.key.KeygenTranscriptHash...),
		PartiesHash:          wireutil.PartySetHash(s.key.Parties, partySetHashLabel),
		kShare:               s.kShare.Clone(),
	}
	s.presign.chiShare, err = secpSecretScalarFromBig(chiShare)
	if err != nil {
		return nil, err
	}
	if err := s.tryComplete(); err != nil {
		return nil, err
	}
	env, err := envelope(s.config, 3, s.key.Party, 0, payloadPresignRound3, payload, false)
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
	s.presign.VerifyShares = make([]SignVerifyShare, 0, len(s.signers))
	for _, id := range s.signers {
		s.presign.VerifyShares = append(s.presign.VerifyShares, s.verifyShares[id].Clone())
	}
	s.presign.R = R
	s.presign.LittleR = scalarBytes(littleR)
	s.presign.delta, err = secpSecretScalarFromBig(delta)
	if err != nil {
		return err
	}
	s.presign.TranscriptHash = s.presignTranscriptHash(R, littleR, delta)
	s.completed = true
	s.log.Info(s.config.Ctx(), "presign complete",
		"party_id", s.key.Party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	return nil
}

func (s *PresignSession) presignTranscriptHash(R []byte, littleR, delta *big.Int) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignTranscriptHashLabel))
	wire.WriteHashPart(h, s.sessionID[:])
	wire.WriteHashPart(h, s.contextHash)
	wire.WriteHashPart(h, s.additiveShift)
	wire.WriteHashPart(h, s.key.PublicKey)
	wire.WriteHashPart(h, s.key.KeygenTranscriptHash)
	wire.WriteHashPart(h, wireutil.PartySetHash(s.key.Parties, partySetHashLabel))
	for _, id := range s.signers {
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		wire.WriteHashPart(h, s.round1[id].Gamma)
		wire.WriteHashPart(h, s.round1[id].EncK)
		wire.WriteHashPart(h, scalarBytes(s.deltas[id]))
		vs := s.verifyShares[id]
		wire.WriteHashPart(h, vs.KPoint)
		wire.WriteHashPart(h, vs.ChiPoint)
		proofHash := sha256.Sum256(vs.Proof)
		wire.WriteHashPart(h, proofHash[:])
	}
	wire.WriteHashPart(h, R)
	wire.WriteHashPart(h, scalarBytes(littleR))
	wire.WriteHashPart(h, scalarBytes(delta))
	return h.Sum(nil)
}

func (s *PresignSession) round1Echo() []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignRound1EchoLabel))
	wire.WriteHashPart(h, s.sessionID[:])
	wire.WriteHashPart(h, s.contextHash)
	wire.WriteHashPart(h, s.additiveShift)
	for _, id := range s.signers {
		p := s.round1[id]
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		wire.WriteHashPart(h, p.Gamma)
		wire.WriteHashPart(h, p.EncK)
		wire.WriteHashPart(h, p.PaillierPublicKey)
	}
	return h.Sum(nil)
}
