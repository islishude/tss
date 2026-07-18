package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/planvalidation"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/tssrun"
)

type presignRedAlertKind string

const (
	presignRedAlertNonce presignRedAlertKind = "nonce"
	presignRedAlertChi   presignRedAlertKind = "chi"
)

type presignRedAlertError struct{ kind presignRedAlertKind }

// errUnattributedPresignFailure marks a mathematically valid Figure 8
// transcript whose aggregate cannot produce a usable ECDSA presign. No party
// can be blamed for cancellation to zero, but the one-use PresignID and every
// retained witness must still be destroyed immediately.
var errUnattributedPresignFailure = errors.New("unattributed Figure 8 presign failure")

// Error reports which Figure 8 aggregate equation triggered the red alert.
func (e *presignRedAlertError) Error() string {
	return "Figure 8 " + string(e.kind) + " aggregate equation failed"
}

func (s *PresignSession) buildAcceptPresignRound3Tx(env tss.Envelope) (*acceptPresignRound3Tx, error) {
	p, err := tss.DecodeBinaryValueWithLimits[presignRound3Payload](env.Payload, s.limits)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindPresignRound3,
			"malformed Figure 8 round3 payload", tss.NewPartySet(env.From), err, fields...)
	}
	if p.Delta == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("missing presign delta"))
	}
	owned := true
	defer func() {
		if owned {
			p.Delta.Destroy()
			p.Proof.Destroy()
			clear(p.S)
			clear(p.DeltaPoint)
		}
	}()
	if err := planvalidation.RequireHash("presign", p.PlanHash, s.planHash); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if err := requireFigure8Binding(p.EpochID, p.PresignID, s.epochID, s.presignID); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
	}
	if _, err := secpScalarFromSecretAllowZero(p.Delta); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := s.verifyFigure8Round3(env.From, p); err != nil {
		return nil, verificationErrorWithEvidence(env, tss.EvidenceKindPresignRound3,
			"invalid Figure 8 round3 proof", tss.NewPartySet(env.From), err, s.presignRound3EvidenceFields(p)...)
	}
	tx := &acceptPresignRound3Tx{from: env.From, payload: p}
	owned = false
	if err := tx.prepare(s); err != nil {
		tx.cleanupOnReject()
		return nil, err
	}
	return tx, nil
}

func (s *PresignSession) verifyFigure8Round3(from tss.PartyID, p presignRound3Payload) error {
	gamma, err := s.aggregateGamma()
	if err != nil {
		return err
	}
	deltaPoint, err := secp.PointFromBytes(p.DeltaPoint)
	if err != nil {
		return err
	}
	if _, err := decodePresignGroupElement(p.S); err != nil {
		return err
	}
	state, ok := s.partyState(from)
	if !ok || !state.round1.havePayload {
		return fmt.Errorf("missing Figure 8 round1 state for party %d", from)
	}
	round1 := state.round1.payload
	yPoint, err := secp.PointFromBytes(round1.Y)
	if err != nil {
		return err
	}
	a1Point, err := secp.PointFromBytes(round1.A1)
	if err != nil {
		return err
	}
	a2Point, err := secp.PointFromBytes(round1.A2)
	if err != nil {
		return err
	}
	domain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash,
		s.signers, presignRound3, from, tss.BroadcastPartyId, "elog-delta")
	if err != nil {
		return err
	}
	return zkpai.VerifyElog(domain, zkpai.ElogStatement{
		Generator:         secp.G,
		LambdaCommitment:  a1Point,
		ElGamalCommitment: a2Point,
		ElGamalBase:       yPoint,
		ResultCommitment:  deltaPoint,
		ResultBase:        gamma,
	}, &p.Proof)
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	delta := p.Delta.FixedBytes()
	defer clear(delta)
	proof, _ := p.Proof.MarshalBinary()
	return append(fields,
		hashEvidenceField("delta_hash", delta),
		hashEvidenceField("delta_point_hash", p.DeltaPoint),
		hashEvidenceField("s_point_hash", p.S),
		hashEvidenceField("elog_proof_hash", proof),
		rawEvidenceField("epoch_id", p.EpochID),
		rawEvidenceField("presign_id", p.PresignID),
	)
}

func (s *PresignSession) tryEmitRound3() ([]tss.Envelope, error) {
	prepared, ok, err := s.preparePresignRound3Output()
	if err != nil || !ok {
		return nil, err
	}
	defer prepared.destroy()
	terminal, ready, err := s.preparePresignCompletionWithStagedLocalRound3(prepared)
	if err != nil {
		return nil, err
	}
	if ready {
		defer terminal.destroy()
	}
	effects, err := s.commitPresignRound3Output(prepared)
	if err != nil {
		return nil, err
	}
	if ready {
		terminalEffects, err := s.commitPresignCompletionEffects(terminal)
		if err != nil {
			for i := range effects.envelopes {
				clearEnvelope(&effects.envelopes[i])
			}
			return nil, err
		}
		effects.envelopes = append(effects.envelopes, terminalEffects.envelopes...)
	}
	return effects.envelopes, nil
}

type preparedPresignRound3Output struct {
	payload   presignRound3Payload
	chi       *secret.Scalar
	env       tss.Envelope
	committed bool
}

func (p *preparedPresignRound3Output) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.payload.Delta != nil {
		p.payload.Delta.Destroy()
	}
	if p.chi != nil {
		p.chi.Destroy()
	}
	p.payload.Proof.Destroy()
	clear(p.payload.S)
	clear(p.payload.DeltaPoint)
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
	gammaShare, err := secpScalarFromSecret(s.gamma)
	if err != nil {
		return nil, false, err
	}
	xBar, err := secpScalarFromSecret(s.xBar)
	if err != nil {
		return nil, false, err
	}
	deltaShare := secp.ScalarMul(kShare, gammaShare)
	chiShare := secp.ScalarMul(kShare, xBar)
	for _, peer := range s.signers {
		if peer == s.key.state.Party {
			continue
		}
		state, ok := s.partyState(peer)
		if !ok {
			return nil, false, fmt.Errorf("missing presign state for party %d", peer)
		}
		for _, item := range []struct {
			name string
			ptr  *secret.Scalar
			add  func(secp.Scalar)
		}{
			{"alpha delta", state.mta.alphaDelta, func(v secp.Scalar) { deltaShare = secp.ScalarAdd(deltaShare, v) }},
			{"beta delta", state.mta.betaDelta, func(v secp.Scalar) { deltaShare = secp.ScalarAdd(deltaShare, v) }},
			{"alpha chi", state.mta.alphaSigma, func(v secp.Scalar) { chiShare = secp.ScalarAdd(chiShare, v) }},
			{"beta chi", state.mta.betaSigma, func(v secp.Scalar) { chiShare = secp.ScalarAdd(chiShare, v) }},
		} {
			value, err := secpScalarFromSecretAllowZero(item.ptr)
			if err != nil {
				return nil, false, fmt.Errorf("party %d %s: %w", peer, item.name, err)
			}
			item.add(value)
		}
	}
	deltaSecret, err := secpSecretScalarFromScalarAllowZero(deltaShare)
	if err != nil {
		return nil, false, err
	}
	chiSecret, err := secpSecretScalarFromScalarAllowZero(chiShare)
	if err != nil {
		deltaSecret.Destroy()
		return nil, false, err
	}
	prepared := &preparedPresignRound3Output{
		payload: presignRound3Payload{Delta: deltaSecret},
		chi:     chiSecret,
	}
	success := false
	defer func() {
		if !success {
			prepared.destroy()
		}
	}()
	gamma, err := s.aggregateGamma()
	if err != nil {
		return nil, false, err
	}
	deltaPoint := secp.ScalarMult(gamma, kShare)
	deltaPointBytes, err := secp.PointBytes(deltaPoint)
	if err != nil {
		return nil, false, err
	}
	sPointBytes, err := encodePresignGroupElement(secp.ScalarMult(gamma, chiShare))
	if err != nil {
		return nil, false, err
	}
	self, ok := s.partyState(s.key.state.Party)
	if !ok || !self.round1.havePayload {
		return nil, false, errors.New("missing local Figure 8 round1 state")
	}
	yPoint, err := secp.PointFromBytes(self.round1.payload.Y)
	if err != nil {
		return nil, false, err
	}
	a1Point, err := secp.PointFromBytes(self.round1.payload.A1)
	if err != nil {
		return nil, false, err
	}
	a2Point, err := secp.PointFromBytes(self.round1.payload.A2)
	if err != nil {
		return nil, false, err
	}
	domain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash,
		s.signers, presignRound3, s.key.state.Party, tss.BroadcastPartyId, "elog-delta")
	if err != nil {
		return nil, false, err
	}
	proof, err := zkpai.ProveElog(domain, zkpai.ElogStatement{
		Generator:         secp.G,
		LambdaCommitment:  a1Point,
		ElGamalCommitment: a2Point,
		ElGamalBase:       yPoint,
		ResultCommitment:  deltaPoint,
		ResultBase:        gamma,
	}, zkpai.ElogWitness{Y: s.kShare, Lambda: s.a}, s.config.Reader())
	if err != nil {
		return nil, false, err
	}
	prepared.payload.S = sPointBytes
	prepared.payload.DeltaPoint = deltaPointBytes
	prepared.payload.Proof = *proof
	prepared.payload.PlanHash = bytes.Clone(s.planHash)
	prepared.payload.EpochID = bytes.Clone(s.epochID)
	prepared.payload.PresignID = bytes.Clone(s.presignID)
	payload, err := prepared.payload.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		return nil, false, err
	}
	prepared.env, err = newEnvelope(s.config, presignRound3, s.key.state.Party, tss.BroadcastPartyId, payloadPresignRound3, payload)
	clear(payload)
	if err != nil {
		return nil, false, err
	}
	success = true
	return prepared, true, nil
}

func (s *PresignSession) aggregateGamma() (*secp.Point, error) {
	points := make([]*secp.Point, 0, len(s.signers))
	for _, signer := range s.signers {
		var encoded []byte
		if signer == s.key.state.Party {
			encoded = s.gammaComm
		} else {
			state, ok := s.partyState(signer)
			if !ok || !state.round2.havePayload {
				return nil, fmt.Errorf("missing Figure 8 Gamma for party %d", signer)
			}
			encoded = state.round2.payload.Gamma
		}
		point, err := secp.PointFromBytes(encoded)
		if err != nil {
			return nil, fmt.Errorf("invalid Figure 8 Gamma for party %d: %w", signer, err)
		}
		points = append(points, point)
	}
	gamma := secp.AddPoints(points...)
	if gamma == nil || gamma.Inf != 0 {
		return nil, fmt.Errorf("%w: aggregate Gamma is the identity; retry with a new PresignID", errUnattributedPresignFailure)
	}
	return gamma, nil
}

func (s *PresignSession) commitPresignRound3Output(p *preparedPresignRound3Output) (sessionEffects, error) {
	if p == nil || p.payload.Delta == nil || p.chi == nil {
		return sessionEffects{}, errors.New("invalid prepared Figure 8 round3 output")
	}
	self, ok := s.partyState(s.key.state.Party)
	if !ok {
		return sessionEffects{}, errors.New("missing local presign state")
	}
	self.round3 = presignRound3State{
		delta: p.payload.Delta, chi: p.chi, deltaPoint: bytes.Clone(p.payload.DeltaPoint),
		sPoint: bytes.Clone(p.payload.S), proof: *p.payload.Proof.Clone(), havePayload: true,
	}
	s.round3Sent = true
	p.committed = true
	return sessionEffects{envelopes: []tss.Envelope{p.env}}, nil
}

type preparedPresignCompletionEffects struct {
	completion *preparedPresignCompletion
	redAlert   *preparedPresignRedAlert
}

func (p *preparedPresignCompletionEffects) destroy() {
	if p != nil && p.completion != nil {
		p.completion.destroy()
	}
	if p != nil && p.redAlert != nil {
		p.redAlert.destroy()
	}
}

func (s *PresignSession) preparePresignCompletionEffects() (*preparedPresignCompletionEffects, bool, error) {
	completion, ready, err := s.maybePreparePresignCompletion()
	if err != nil {
		var redAlert *presignRedAlertError
		if !errors.As(err, &redAlert) {
			return nil, false, err
		}
		preparedRedAlert, prepareErr := s.preparePresignRedAlert(redAlert.kind)
		if prepareErr != nil {
			return nil, false, prepareErr
		}
		return &preparedPresignCompletionEffects{redAlert: preparedRedAlert}, true, nil
	}
	if !ready {
		return nil, false, nil
	}
	return &preparedPresignCompletionEffects{completion: completion}, true, nil
}

func (s *PresignSession) commitPresignCompletionEffects(p *preparedPresignCompletionEffects) (sessionEffects, error) {
	if p != nil && p.completion != nil {
		if err := s.commitPresignCompletion(p.completion); err != nil {
			return sessionEffects{}, err
		}
	}
	if p != nil && p.redAlert != nil {
		return s.commitPresignRedAlert(p.redAlert), nil
	}
	return sessionEffects{}, nil
}

func (s *PresignSession) preparePresignCompletionWithStagedLocalRound3(p *preparedPresignRound3Output) (*preparedPresignCompletionEffects, bool, error) {
	self, ok := s.partyState(s.key.state.Party)
	if !ok {
		return nil, false, errors.New("missing local presign state")
	}
	previous := self.round3
	self.round3 = presignRound3State{
		delta: p.payload.Delta, chi: p.chi, deltaPoint: p.payload.DeltaPoint,
		sPoint: p.payload.S, proof: p.payload.Proof, havePayload: true,
	}
	completion, ready, err := s.preparePresignCompletionEffects()
	self.round3 = previous
	return completion, ready, err
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
	}
}

func (s *PresignSession) maybePreparePresignCompletion() (*preparedPresignCompletion, bool, error) {
	if s.completed || !s.allRound3Accepted() {
		return nil, false, nil
	}
	gamma, err := s.aggregateGamma()
	if err != nil {
		return nil, false, err
	}
	delta := secp.ScalarZero()
	deltaPoints := make([]*secp.Point, 0, len(s.signers))
	sPoints := make([]*secp.Point, 0, len(s.signers))
	for _, signer := range s.signers {
		state, _ := s.partyState(signer)
		value, err := secpScalarFromSecretAllowZero(state.round3.delta)
		if err != nil {
			return nil, false, err
		}
		delta = secp.ScalarAdd(delta, value)
		deltaPoint, err := secp.PointFromBytes(state.round3.deltaPoint)
		if err != nil {
			return nil, false, err
		}
		sPoint, err := decodePresignGroupElement(state.round3.sPoint)
		if err != nil {
			return nil, false, err
		}
		deltaPoints = append(deltaPoints, deltaPoint)
		sPoints = append(sPoints, sPoint)
	}
	if delta.IsZero() {
		return nil, false, fmt.Errorf("%w: aggregate delta is zero; retry with a new PresignID", errUnattributedPresignFailure)
	}
	if !secp.Equal(secp.ScalarBaseMult(delta), secp.AddPoints(deltaPoints...)) {
		return nil, false, &presignRedAlertError{kind: presignRedAlertNonce}
	}
	publicKey, err := secp.PointFromBytes(s.key.state.PublicKey)
	if err != nil {
		return nil, false, err
	}
	if !secp.Equal(secp.ScalarMult(publicKey, delta), secp.AddPoints(sPoints...)) {
		return nil, false, &presignRedAlertError{kind: presignRedAlertChi}
	}
	deltaInverse, err := secp.ScalarInvert(delta)
	if err != nil {
		return nil, false, fmt.Errorf("%w: aggregate delta is not invertible; retry with a new PresignID", errUnattributedPresignFailure)
	}
	self, _ := s.partyState(s.key.state.Party)
	k, err := secpScalarFromSecret(s.kShare)
	if err != nil {
		return nil, false, err
	}
	chi, err := secpScalarFromSecretAllowZero(self.round3.chi)
	if err != nil {
		return nil, false, err
	}
	kTilde := secp.ScalarMul(k, deltaInverse)
	chiTilde := secp.ScalarMul(chi, deltaInverse)
	kSecret, err := secpSecretScalarFromScalar(kTilde)
	if err != nil {
		return nil, false, err
	}
	chiSecret, err := secpSecretScalarFromScalarAllowZero(chiTilde)
	if err != nil {
		kSecret.Destroy()
		return nil, false, err
	}
	commitments := make([]normalizedPresignCommitment, 0, len(s.signers))
	for i, signer := range s.signers {
		deltaTilde := secp.ScalarMult(deltaPoints[i], deltaInverse)
		sTilde := secp.ScalarMult(sPoints[i], deltaInverse)
		deltaEncoded, err := encodePresignGroupElement(deltaTilde)
		if err != nil {
			kSecret.Destroy()
			chiSecret.Destroy()
			return nil, false, err
		}
		sEncoded, err := encodePresignGroupElement(sTilde)
		if err != nil {
			kSecret.Destroy()
			chiSecret.Destroy()
			return nil, false, err
		}
		commitments = append(commitments, normalizedPresignCommitment{Party: signer, DeltaTilde: deltaEncoded, STilde: sEncoded})
	}
	littleR := secp.ScalarFromFieldElement(gamma.X)
	if littleR.IsZero() {
		kSecret.Destroy()
		chiSecret.Destroy()
		return nil, false, fmt.Errorf("%w: aggregate Gamma yields zero ECDSA r; retry with a new PresignID", errUnattributedPresignFailure)
	}
	if err := validateNormalizedPresignArtifact(s.signers, commitments, s.key.state.Party, gamma, publicKey, kTilde, chiTilde); err != nil {
		kSecret.Destroy()
		chiSecret.Destroy()
		return nil, false, err
	}
	completed := &Presign{state: &presignState{
		Party: s.key.state.Party, Threshold: s.key.state.Threshold, Signers: s.signers.Clone(),
		PresignID: bytes.Clone(s.presignID), EpochID: bytes.Clone(s.epochID), Gamma: secp.Clone(gamma), LittleR: littleR,
		KShare: kSecret, ChiShare: chiSecret, Commitments: commitments,
		TranscriptHash: s.presignTranscriptHash(gamma, littleR, commitments), Context: s.context.Clone(),
		ContextHash: bytes.Clone(s.contextHash), PublicKey: publicKey,
		KeygenTranscriptHash: bytes.Clone(s.key.state.KeygenTranscriptHash),
		PartiesHash:          tss.PartySetHash(s.key.state.Parties, partySetHashLabel), PlanHash: bytes.Clone(s.planHash),
		SecurityParams: s.securityParams, Derivation: s.derivation.Clone(), Epoch: s.key.state.Epoch.Clone(),
		Consumed: newAtomicBool(), attempt: newPresignAttemptBinding(false),
	}}
	if err := completed.ValidateWithLimits(s.limits); err != nil {
		completed.Destroy()
		return nil, false, err
	}
	return &preparedPresignCompletion{presign: completed}, true, nil
}

func (s *PresignSession) commitPresignCompletion(p *preparedPresignCompletion) error {
	if p == nil || p.presign == nil {
		return errors.New("missing prepared presign completion")
	}
	metadata, ok := p.presign.PublicMetadata()
	if !ok {
		p.presign.Destroy()
		p.presign = nil
		p.committed = true
		return s.abortPresignRun(errors.New("prepared presign has no valid public metadata"))
	}
	expectedSlot, err := PresignSlotID(metadata.PresignID)
	if err != nil {
		p.presign.Destroy()
		p.presign = nil
		p.committed = true
		return s.abortPresignRun(err)
	}
	storeCtx, cancel := durableStoreContext(s.config.Ctx(), s.lifecycleTimeout)
	slot, err := PersistPresignFromLeaseWithLimits(storeCtx, s.lifecycleStore, s.lifecycleLease, p.presign, s.limits)
	cancel()
	if err != nil {
		p.presign.Destroy()
		p.presign = nil
		p.committed = true
		return s.abortPresignRun(fmt.Errorf("persist completed presign: %w", err))
	}
	if slot != expectedSlot {
		// PersistPresignFromLease validates this before the atomic store call, so
		// reaching this branch means the local lifecycle integration is corrupt.
		p.presign.Destroy()
		p.presign = nil
		p.committed = true
		return s.abortPresignRun(fmt.Errorf("%w: persisted presign slot mismatch", tssrun.ErrLifecycleCorrupt))
	}
	s.leaseFinished = true
	s.persistedPresign = func() *PersistedPresign {
		descriptor := newPersistedPresign(slot, metadata)
		return &descriptor
	}()
	p.presign.Destroy()
	p.presign = nil
	p.committed = true
	s.completed = true
	s.clearCompletedWitnesses()
	return nil
}

func (s *PresignSession) clearCompletedWitnesses() {
	for _, value := range []**secret.Scalar{&s.kShare, &s.gamma, &s.a, &s.b, &s.xBar} {
		if *value != nil {
			(*value).Destroy()
			*value = nil
		}
	}
	if s.paillier != nil {
		s.paillier.Destroy()
		s.paillier = nil
	}
	if s.startOpening != nil {
		s.startOpening.Destroy()
		s.startOpening = nil
	}
	if s.gammaOpening != nil {
		s.gammaOpening.Destroy()
		s.gammaOpening = nil
	}
	for i := range s.parties {
		s.parties[i].destroy()
	}
	if s.ownsKey && s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
}

func (s *PresignSession) presignTranscriptHash(gamma *secp.Point, littleR secp.Scalar, commitments []normalizedPresignCommitment) []byte {
	t := transcript.New(presignTranscriptHashLabel)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("epoch_id", s.epochID)
	t.AppendBytes("presign_id", s.presignID)
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendUint32List("signers", s.signers)
	gammaBytes, _ := secp.PointBytes(gamma)
	t.AppendBytes("gamma", gammaBytes)
	t.AppendBytes("little_r", littleR.Bytes())
	for i := range commitments {
		t.AppendUint32("party", commitments[i].Party)
		t.AppendBytes("delta_tilde", commitments[i].DeltaTilde)
		t.AppendBytes("s_tilde", commitments[i].STilde)
	}
	return t.Sum()
}

func (s *PresignSession) round1Echo() []byte {
	t := transcript.New(presignRound1EchoLabel)
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("epoch_id", s.epochID)
	t.AppendBytes("presign_id", s.presignID)
	t.AppendBytes("plan_hash", s.planHash)
	for _, signer := range s.signers {
		state, ok := s.partyState(signer)
		if !ok || !state.round1.havePayload {
			return nil
		}
		encoded, err := state.round1.payload.MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil
		}
		t.AppendUint32("party", signer)
		t.AppendBytes("round1_payload", encoded)
	}
	return t.Sum()
}

func defaultEnvelopeLimitsForEvidence() tss.EnvelopeLimits { return tss.DefaultEnvelopeLimits() }
