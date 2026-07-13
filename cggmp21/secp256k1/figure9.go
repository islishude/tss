package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	figure9AlertDigestLabel       = "cggmp21-secp256k1-figure9-alert-v1"
	figure9ProofDomainLabel       = "cggmp21-secp256k1-figure9-proof-domain-v1"
	figure9AlertDigestEvidenceKey = "presign_red_alert_digest"
)

type preparedPresignRedAlert struct {
	kind      presignRedAlertKind
	alert     []byte
	payload   presignRedAlertPayload
	envelope  tss.Envelope
	committed bool
}

func (p *preparedPresignRedAlert) destroy() {
	if p == nil || p.committed {
		return
	}
	clear(p.alert)
	p.payload.Destroy()
	clearEnvelope(&p.envelope)
}

func (s *PresignSession) preparePresignRedAlert(kind presignRedAlertKind) (*preparedPresignRedAlert, error) {
	if s.identifying {
		return nil, errors.New("figure 9 red-alert phase is already active")
	}
	alert, err := s.figure9AlertDigest(kind)
	if err != nil {
		return nil, err
	}
	prepared := &preparedPresignRedAlert{kind: kind, alert: alert}
	success := false
	defer func() {
		if !success {
			prepared.destroy()
		}
	}()

	self := s.key.state.Party
	selfPK, err := s.key.paillierPublicFor(self, s.limits)
	if err != nil {
		return nil, err
	}
	x, xCommitment, err := s.figure9Multiplier(self, kind)
	if err != nil {
		return nil, err
	}
	prepared.payload.Pairs = make([]presignRedAlertPair, 0, len(s.signers)-1)
	for _, peer := range s.signers {
		if peer == self {
			continue
		}
		state, ok := s.partyState(peer)
		if !ok || !state.round2.havePayload {
			return nil, fmt.Errorf("missing Figure 9 MtA state for party %d", peer)
		}
		inbound, outbound, opening, err := figure9MTARecords(state, kind)
		if err != nil {
			return nil, fmt.Errorf("party %d: %w", peer, err)
		}
		peerState, _ := s.partyState(peer)
		peerPK, err := s.key.paillierPublicFor(peer, s.limits)
		if err != nil {
			return nil, err
		}
		domain, err := s.figure9ProofDomain(kind, self, peer, "aff-g-star", alert)
		if err != nil {
			return nil, err
		}
		proof, err := opening.ProveAffGStar(
			s.securityParams, s.config.Reader(), domain,
			mta.StartMessage{Ciphertext: peerState.round1.payload.EncK}, outbound,
			xCommitment, peerPK, selfPK,
		)
		if err != nil {
			return nil, fmt.Errorf("prove Figure 9 affine relation for party %d: %w", peer, err)
		}
		prepared.payload.Pairs = append(prepared.payload.Pairs, presignRedAlertPair{
			Peer: peer, Inbound: inbound.Clone(), Outbound: outbound.Clone(), Proof: *proof,
		})
	}

	d, err := aggregateFigure9MaskCiphertext(prepared.payload.Pairs, selfPK)
	if err != nil {
		return nil, err
	}
	decStatement, err := s.figure9DecStatement(self, kind, d)
	if err != nil {
		return nil, err
	}
	xBytes := x.FixedBytes()
	xSigned, err := secret.NewSignedInt(false, xBytes, len(xBytes))
	clear(xBytes)
	if err != nil {
		return nil, err
	}
	defer xSigned.Destroy()
	kX, err := zkpai.OMulCT(decStatement.PaillierN, xSigned, decStatement.K, xSigned.FixedLen())
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(kX)
	openedCiphertext, err := zkpai.OAdd(decStatement.PaillierN, kX, decStatement.D)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(openedCiphertext)
	y, rho, err := s.paillier.RecoverOpening(openedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("recover Figure 9 decryption opening: %w", err)
	}
	defer y.Destroy()
	defer rho.Destroy()
	decDomain, err := s.figure9ProofDomain(kind, self, tss.BroadcastPartyId, "dec", alert)
	if err != nil {
		return nil, err
	}
	decProof, err := zkpai.ProveDec(s.securityParams, decDomain, decStatement, zkpai.DecWitness{
		X: x, Y: y, Rho: rho,
	}, s.config.Reader())
	if err != nil {
		return nil, fmt.Errorf("prove Figure 9 decryption relation: %w", err)
	}
	prepared.payload.Kind = string(kind)
	prepared.payload.AlertDigest = bytes.Clone(alert)
	prepared.payload.DecProof = *decProof
	prepared.payload.PlanHash = bytes.Clone(s.planHash)
	prepared.payload.EpochID = bytes.Clone(s.epochID)
	prepared.payload.PresignID = bytes.Clone(s.presignID)
	payloadBytes, err := prepared.payload.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer clear(payloadBytes)
	prepared.envelope, err = newFigure9Envelope(s.config, self, payloadBytes)
	if err != nil {
		return nil, err
	}
	success = true
	return prepared, nil
}

func newFigure9Envelope(config tss.ThresholdConfig, from tss.PartyID, payload []byte) (tss.Envelope, error) {
	env, err := tss.NewEnvelopeWithLimits(tss.EnvelopeInput{
		Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: config.SessionID,
		Round: presignRedAlertRound, From: from, To: tss.BroadcastPartyId,
		PayloadType: payloadPresignRedAlert, Payload: payload,
	}, Figure9EnvelopeLimits())
	if err != nil {
		return tss.Envelope{}, err
	}
	if config.EnvelopeSigner == nil {
		return env, nil
	}
	return tss.SignEnvelope(env, config.EnvelopeSigner)
}

func (s *PresignSession) commitPresignRedAlert(p *preparedPresignRedAlert) sessionEffects {
	if p == nil {
		return sessionEffects{}
	}
	s.identifying = true
	s.redAlertKind = p.kind
	s.redAlertDigest = bytes.Clone(p.alert)
	s.redAlertPayloads = map[tss.PartyID]presignRedAlertPayload{
		s.key.state.Party: p.payload,
	}
	p.committed = true
	return sessionEffects{envelopes: []tss.Envelope{p.envelope}}
}

func (s *PresignSession) figure9AlertDigest(kind presignRedAlertKind) ([]byte, error) {
	if kind != presignRedAlertNonce && kind != presignRedAlertChi {
		return nil, errors.New("invalid Figure 9 alert kind")
	}
	if !s.allRound3Accepted() {
		return nil, errors.New("figure 9 alert requires every round3 broadcast")
	}
	t := transcript.New(figure9AlertDigestLabel)
	t.AppendString("protocol", string(tss.ProtocolCGGMP21Secp256k1))
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("epoch_id", s.epochID)
	t.AppendBytes("presign_id", s.presignID)
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendUint32("threshold", uint32(s.key.state.Threshold))
	t.AppendUint32List("parties", s.key.state.Parties)
	t.AppendUint32List("signers", s.signers)
	t.AppendBytes("public_key", s.key.state.PublicKey)
	t.AppendBytes("keygen_transcript_hash", s.key.state.KeygenTranscriptHash)
	t.AppendUint32("round", uint32(presignRedAlertRound))
	t.AppendString("kind", string(kind))
	t.AppendBytes("round1_echo", s.round1Echo())
	for _, signer := range s.signers {
		state, _ := s.partyState(signer)
		delta := state.round3.delta.FixedBytes()
		proof, err := state.round3.proof.MarshalBinary()
		if err != nil {
			clear(delta)
			return nil, err
		}
		t.AppendUint32("party", signer)
		t.AppendBytes("delta", delta)
		t.AppendBytes("delta_point", state.round3.deltaPoint)
		t.AppendBytes("s", state.round3.sPoint)
		t.AppendBytes("elog_proof", proof)
		clear(delta)
		clear(proof)
	}
	return t.Sum(), nil
}

func (s *PresignSession) figure9ProofDomain(kind presignRedAlertKind, prover, peer tss.PartyID, relation string, alert []byte) ([]byte, error) {
	if kind != presignRedAlertNonce && kind != presignRedAlertChi {
		return nil, errors.New("invalid Figure 9 proof kind")
	}
	if !tss.ContainsParty(s.signers, prover) || (peer != tss.BroadcastPartyId && !tss.ContainsParty(s.signers, peer)) {
		return nil, errors.New("figure 9 proof party is outside signer set")
	}
	if relation == "" || len(alert) != 32 {
		return nil, errors.New("invalid Figure 9 proof binding")
	}
	t := transcript.New(figure9ProofDomainLabel)
	t.AppendString("protocol", string(tss.ProtocolCGGMP21Secp256k1))
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("epoch_id", s.epochID)
	t.AppendBytes("presign_id", s.presignID)
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("context_hash", s.contextHash)
	t.AppendUint32("threshold", uint32(s.key.state.Threshold))
	t.AppendUint32List("parties", s.key.state.Parties)
	t.AppendUint32List("signers", s.signers)
	t.AppendBytes("public_key", s.key.state.PublicKey)
	t.AppendBytes("keygen_transcript_hash", s.key.state.KeygenTranscriptHash)
	t.AppendUint32("round", uint32(presignRedAlertRound))
	t.AppendString("kind", string(kind))
	t.AppendBytes("alert_digest", alert)
	t.AppendUint32("prover", prover)
	t.AppendUint32("peer", peer)
	t.AppendString("relation", relation)
	return t.Sum(), nil
}

func (s *PresignSession) figure9Multiplier(party tss.PartyID, kind presignRedAlertKind) (*secret.Scalar, []byte, error) {
	state, ok := s.partyState(party)
	if !ok {
		return nil, nil, errors.New("missing Figure 9 party state")
	}
	switch kind {
	case presignRedAlertNonce:
		if party == s.key.state.Party {
			return s.gamma, bytes.Clone(s.gammaComm), nil
		}
		if !state.round2.havePayload {
			return nil, nil, errors.New("missing Figure 9 gamma commitment")
		}
		return nil, bytes.Clone(state.round2.payload.Gamma), nil
	case presignRedAlertChi:
		commitment, err := s.xBarCommitment(party)
		if err != nil {
			return nil, nil, err
		}
		if party == s.key.state.Party {
			return s.xBar, commitment, nil
		}
		return nil, commitment, nil
	default:
		return nil, nil, errors.New("invalid Figure 9 multiplier kind")
	}
}

func figure9MTARecords(state *presignPartyState, kind presignRedAlertKind) (mta.ResponseMessage, mta.ResponseMessage, *mta.ResponseOpening, error) {
	if state == nil || !state.round2.havePayload {
		return mta.ResponseMessage{}, mta.ResponseMessage{}, nil, errors.New("missing Figure 9 round2 state")
	}
	switch kind {
	case presignRedAlertNonce:
		if !state.round2.haveOutboundDelta || state.mta.deltaOpening == nil {
			return mta.ResponseMessage{}, mta.ResponseMessage{}, nil, errors.New("missing Figure 9 delta opening")
		}
		return state.round2.payload.Delta, state.round2.outboundDelta, state.mta.deltaOpening, nil
	case presignRedAlertChi:
		if !state.round2.haveOutboundSigma || state.mta.sigmaOpening == nil {
			return mta.ResponseMessage{}, mta.ResponseMessage{}, nil, errors.New("missing Figure 9 sigma opening")
		}
		return state.round2.payload.Sigma, state.round2.outboundSigma, state.mta.sigmaOpening, nil
	default:
		return mta.ResponseMessage{}, mta.ResponseMessage{}, nil, errors.New("invalid Figure 9 MtA kind")
	}
}

func aggregateFigure9MaskCiphertext(pairs []presignRedAlertPair, publicKey *pai.PublicKey) (*big.Int, error) {
	if publicKey == nil {
		return nil, errors.New("nil Figure 9 Paillier public key")
	}
	var aggregate *big.Int
	for i := range pairs {
		inbound := new(big.Int).SetBytes(pairs[i].Inbound.Ciphertext)
		outboundMask := new(big.Int).SetBytes(pairs[i].Outbound.F)
		if err := publicKey.ValidateCiphertext(inbound); err != nil {
			return nil, fmt.Errorf("invalid Figure 9 inbound ciphertext for peer %d: %w", pairs[i].Peer, err)
		}
		if err := publicKey.ValidateCiphertext(outboundMask); err != nil {
			return nil, fmt.Errorf("invalid Figure 9 outbound mask for peer %d: %w", pairs[i].Peer, err)
		}
		// The responder retains -beta as its additive share while F encrypts
		// +beta. Figure 9 therefore multiplies each incoming D by F^{-1}.
		outboundInverse := new(big.Int).ModInverse(outboundMask, publicKey.NSquared)
		if outboundInverse == nil {
			return nil, fmt.Errorf("figure 9 outbound mask for peer %d is not invertible", pairs[i].Peer)
		}
		for _, ciphertext := range []*big.Int{inbound, outboundInverse} {
			if aggregate == nil {
				aggregate = new(big.Int).Set(ciphertext)
				continue
			}
			var err error
			aggregate, err = publicKey.AddCiphertexts(aggregate, ciphertext)
			if err != nil {
				return nil, fmt.Errorf("aggregate Figure 9 mask ciphertext: %w", err)
			}
		}
	}
	if aggregate == nil {
		return nil, errors.New("empty Figure 9 mask ciphertext aggregate")
	}
	return aggregate, nil
}

func (s *PresignSession) figure9DecStatement(accused tss.PartyID, kind presignRedAlertKind, d *big.Int) (zkpai.DecStatement, error) {
	state, ok := s.partyState(accused)
	if !ok || !state.round1.havePayload || !state.round3.havePayload {
		return zkpai.DecStatement{}, errors.New("missing Figure 9 public party state")
	}
	publicKey, err := s.key.paillierPublicFor(accused, s.limits)
	if err != nil {
		return zkpai.DecStatement{}, err
	}
	_, xCommitment, err := s.figure9Multiplier(accused, kind)
	if err != nil {
		return zkpai.DecStatement{}, err
	}
	xPoint, err := secp.PointFromBytes(xCommitment)
	if err != nil {
		return zkpai.DecStatement{}, err
	}
	var result, base *secp.Point
	switch kind {
	case presignRedAlertNonce:
		delta, err := secpScalarFromSecretAllowZero(state.round3.delta)
		if err != nil {
			return zkpai.DecStatement{}, err
		}
		result = secp.ScalarBaseMult(delta)
		base = secp.G
	case presignRedAlertChi:
		result, err = decodePresignGroupElement(state.round3.sPoint)
		if err != nil {
			return zkpai.DecStatement{}, err
		}
		base, err = s.aggregateGamma()
		if err != nil {
			return zkpai.DecStatement{}, err
		}
	default:
		return zkpai.DecStatement{}, errors.New("invalid Figure 9 decryption kind")
	}
	return zkpai.DecStatement{
		PaillierN: publicKey, K: new(big.Int).SetBytes(state.round1.payload.EncK), D: d,
		X: xPoint, S: result, PlaintextBase: base,
	}, nil
}

func (s *PresignSession) buildAcceptPresignRedAlertTx(env tss.Envelope) (*acceptPresignRedAlertTx, error) {
	if !s.identifying {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("figure 9 red-alert phase is not active"))
	}
	if len(env.Payload) > maxFigure9PayloadBytes {
		return nil, tss.NewProtocolError(tss.ErrCodePayloadTooLarge, env.Round, env.From,
			fmt.Errorf("figure 9 payload too large: %d > %d", len(env.Payload), maxFigure9PayloadBytes))
	}
	var payload presignRedAlertPayload
	if err := payload.UnmarshalBinaryWithLimits(env.Payload, s.limits); err != nil {
		return nil, s.figure9VerificationError(env, "malformed Figure 9 payload", err)
	}
	owned := true
	defer func() {
		if owned {
			payload.Destroy()
		}
	}()
	if payload.Kind != string(s.redAlertKind) ||
		!bytes.Equal(payload.AlertDigest, s.redAlertDigest) ||
		!bytes.Equal(payload.PlanHash, s.planHash) ||
		!bytes.Equal(payload.EpochID, s.epochID) ||
		!bytes.Equal(payload.PresignID, s.presignID) {
		return nil, s.figure9VerificationError(env, "invalid Figure 9 transcript binding", errors.New("figure 9 binding mismatch"))
	}
	if err := s.verifyFigure9Payload(env.From, payload); err != nil {
		return nil, s.figure9VerificationError(env, "invalid Figure 9 proof", err)
	}
	if len(s.redAlertPayloads)+1 == len(s.signers) {
		// Every authenticated party supplied a valid proof, so the original red
		// alert cannot be attributed. This is terminal, but it must not blame the
		// sender of the last valid proof.
		terminalErr := tss.NewProtocolError(tss.ErrCodeInvariant, presignRedAlertRound, 0,
			errors.New("all Figure 9 proofs verified but the aggregate failure persists"))
		return nil, s.abortPresignRun(terminalErr)
	}
	tx := &acceptPresignRedAlertTx{from: env.From, payload: payload}
	owned = false
	return tx, nil
}

func (s *PresignSession) verifyFigure9Payload(accused tss.PartyID, payload presignRedAlertPayload) error {
	if accused == s.key.state.Party {
		return errors.New("unexpected local Figure 9 payload")
	}
	expectedPeers := make([]tss.PartyID, 0, len(s.signers)-1)
	for _, party := range s.signers {
		if party != accused {
			expectedPeers = append(expectedPeers, party)
		}
	}
	if len(payload.Pairs) != len(expectedPeers) {
		return fmt.Errorf("figure 9 peer count %d, want %d", len(payload.Pairs), len(expectedPeers))
	}
	for i := range expectedPeers {
		if payload.Pairs[i].Peer != expectedPeers[i] {
			return fmt.Errorf("figure 9 peer %d at index %d, want %d", payload.Pairs[i].Peer, i, expectedPeers[i])
		}
		if err := s.verifyFigure9Pair(accused, payload.Pairs[i], presignRedAlertKind(payload.Kind), payload.AlertDigest); err != nil {
			return err
		}
	}
	accusedPK, err := s.key.paillierPublicFor(accused, s.limits)
	if err != nil {
		return err
	}
	d, err := aggregateFigure9MaskCiphertext(payload.Pairs, accusedPK)
	if err != nil {
		return err
	}
	stmt, err := s.figure9DecStatement(accused, presignRedAlertKind(payload.Kind), d)
	if err != nil {
		return err
	}
	domain, err := s.figure9ProofDomain(presignRedAlertKind(payload.Kind), accused, tss.BroadcastPartyId, "dec", payload.AlertDigest)
	if err != nil {
		return err
	}
	if err := zkpai.VerifyDec(s.securityParams, domain, stmt, &payload.DecProof); err != nil {
		return fmt.Errorf("verify Figure 9 decryption proof: %w", err)
	}
	return nil
}

func (s *PresignSession) verifyFigure9Pair(accused tss.PartyID, pair presignRedAlertPair, kind presignRedAlertKind, alert []byte) error {
	peer := pair.Peer
	accusedState, ok := s.partyState(accused)
	if !ok || !accusedState.round1.havePayload || !accusedState.round3.havePayload {
		return errors.New("missing accused Figure 9 state")
	}
	peerState, ok := s.partyState(peer)
	if !ok || !peerState.round1.havePayload || !peerState.round3.havePayload {
		return fmt.Errorf("missing Figure 9 state for peer %d", peer)
	}
	if peer == s.key.state.Party {
		expectedInbound, expectedOutbound, err := s.figure9LocalPairView(accusedState, kind)
		if err != nil {
			return err
		}
		if !equalFigure9Response(pair.Inbound, expectedInbound) || !equalFigure9Response(pair.Outbound, expectedOutbound) {
			return errors.New("figure 9 payload conflicts with the authenticated local MtA transcript")
		}
	}

	accusedPK, err := s.key.paillierPublicFor(accused, s.limits)
	if err != nil {
		return err
	}
	peerPK, err := s.key.paillierPublicFor(peer, s.limits)
	if err != nil {
		return err
	}
	accusedAux, err := s.key.ringPedersenPublicFor(accused, s.limits)
	if err != nil {
		return err
	}
	peerAux, err := s.key.ringPedersenPublicFor(peer, s.limits)
	if err != nil {
		return err
	}
	_, accusedCommitment, err := s.figure9Multiplier(accused, kind)
	if err != nil {
		return err
	}
	_, peerCommitment, err := s.figure9Multiplier(peer, kind)
	if err != nil {
		return err
	}
	figure8Relation, err := figure9ResponseRelation(kind)
	if err != nil {
		return err
	}
	inboundDomain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash,
		s.signers, presignRound2, peer, accused, figure8Relation)
	if err != nil {
		return err
	}
	if err := mta.VerifyResponse(s.securityParams, inboundDomain,
		mta.StartMessage{Ciphertext: accusedState.round1.payload.EncK}, pair.Inbound, peerCommitment,
		accusedPK, peerPK, accusedAux,
	); err != nil {
		return fmt.Errorf("verify Figure 9 inbound MtA record for peer %d: %w", peer, err)
	}
	outboundDomain, err := figure8ProofDomain(s.sessionID, s.epochID, s.presignID, s.planHash, s.contextHash,
		s.signers, presignRound2, accused, peer, figure8Relation)
	if err != nil {
		return err
	}
	if err := mta.VerifyResponse(s.securityParams, outboundDomain,
		mta.StartMessage{Ciphertext: peerState.round1.payload.EncK}, pair.Outbound, accusedCommitment,
		peerPK, accusedPK, peerAux,
	); err != nil {
		return fmt.Errorf("verify Figure 9 outbound MtA record for peer %d: %w", peer, err)
	}
	proofDomain, err := s.figure9ProofDomain(kind, accused, peer, "aff-g-star", alert)
	if err != nil {
		return err
	}
	if err := mta.VerifyFigure9AffGStar(s.securityParams, proofDomain,
		mta.StartMessage{Ciphertext: peerState.round1.payload.EncK}, pair.Outbound, accusedCommitment,
		peerPK, accusedPK, &pair.Proof,
	); err != nil {
		return fmt.Errorf("verify Figure 9 affine proof for peer %d: %w", peer, err)
	}
	return nil
}

func (s *PresignSession) figure9LocalPairView(accusedState *presignPartyState, kind presignRedAlertKind) (mta.ResponseMessage, mta.ResponseMessage, error) {
	if accusedState == nil || !accusedState.round2.havePayload {
		return mta.ResponseMessage{}, mta.ResponseMessage{}, errors.New("missing local Figure 9 MtA view")
	}
	switch kind {
	case presignRedAlertNonce:
		if !accusedState.round2.haveOutboundDelta {
			return mta.ResponseMessage{}, mta.ResponseMessage{}, errors.New("missing local Figure 9 delta response")
		}
		return accusedState.round2.outboundDelta, accusedState.round2.payload.Delta, nil
	case presignRedAlertChi:
		if !accusedState.round2.haveOutboundSigma {
			return mta.ResponseMessage{}, mta.ResponseMessage{}, errors.New("missing local Figure 9 sigma response")
		}
		return accusedState.round2.outboundSigma, accusedState.round2.payload.Sigma, nil
	default:
		return mta.ResponseMessage{}, mta.ResponseMessage{}, errors.New("invalid Figure 9 local view kind")
	}
}

func figure9ResponseRelation(kind presignRedAlertKind) (string, error) {
	switch kind {
	case presignRedAlertNonce:
		return "aff-g-delta", nil
	case presignRedAlertChi:
		return "aff-g-chi", nil
	default:
		return "", errors.New("invalid Figure 9 response kind")
	}
}

func equalFigure9Response(left, right mta.ResponseMessage) bool {
	leftBytes, leftErr := left.MarshalBinary()
	rightBytes, rightErr := right.MarshalBinary()
	defer clear(leftBytes)
	defer clear(rightBytes)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func (s *PresignSession) figure9VerificationError(env tss.Envelope, reason string, cause error) *tss.ProtocolError {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	fields = append(fields, rawEvidenceField(figure9AlertDigestEvidenceKey, s.redAlertDigest))
	record := &tss.IdentificationRecord{
		FailureClass: "presign_figure9_" + string(s.redAlertKind),
		Accused:      env.From, Statement: bytes.Clone(s.redAlertDigest), Proof: bytes.Clone(env.Payload),
		TranscriptHashes: []tss.EvidenceField{
			rawEvidenceField(figure9AlertDigestEvidenceKey, s.redAlertDigest),
		},
	}
	for _, field := range fields {
		if len(field.Value) == 32 && field.Key != figure9AlertDigestEvidenceKey {
			record.TranscriptHashes = append(record.TranscriptHashes, field.Clone())
		}
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	recordField, err := tss.IdentificationEvidenceFieldWithLimits(record, figure9IdentificationRecordLimits())
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From,
			fmt.Errorf("marshal Figure 9 red-alert phase record: %w", errors.Join(err, cause)))
	}
	fields = append(fields, recordField)
	return verificationErrorWithEvidence(env, tss.EvidenceKindPresignRedAlert, reason,
		tss.NewPartySet(env.From), cause, fields...)
}

type acceptPresignRedAlertTx struct {
	from      tss.PartyID
	payload   presignRedAlertPayload
	committed bool
}

func (tx *acceptPresignRedAlertTx) apply(s *PresignSession) (sessionEffects, error) {
	if !s.identifying || s.redAlertPayloads == nil {
		return sessionEffects{}, errors.New("figure 9 red-alert phase state disappeared before commit")
	}
	s.redAlertPayloads[tx.from] = tx.payload
	return sessionEffects{}, nil
}

func (tx *acceptPresignRedAlertTx) cleanupOnReject() {
	if tx != nil && !tx.committed {
		tx.payload.Destroy()
	}
}

func (tx *acceptPresignRedAlertTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}
