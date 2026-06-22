package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
)

func (s *PresignSession) buildAcceptPresignRound2Tx(env tss.Envelope) (*acceptPresignRound2Tx, error) {
	// ---- 1. PARSE ----
	p, err := tss.DecodeBinaryValueWithLimits[presignRound2Payload](env.Payload, s.limits)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound2,
			"malformed presign round2 payload",
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
	material, err := s.verifyPresignRound2(env.From, p)
	if err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPresignRound2,
			"invalid presign round2 proof",
			tss.NewPartySet(env.From),
			err,
			s.presignRound2EvidenceFields(p)...,
		)
	}

	return &acceptPresignRound2Tx{
		from:     env.From,
		payload:  p,
		material: material,
	}, nil
}

func (s *PresignSession) presignRound2EvidenceFields(p presignRound2Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields,
		rawEvidenceField(evidenceFieldDeltaResponseHash, mtaResponseHash("delta", p.Delta)),
		rawEvidenceField(evidenceFieldSigmaResponseHash, mtaResponseHash("sigma", p.Sigma)),
		hashEvidenceField("round1_echo_hash", p.Round1Echo),
	)
}

func (s *PresignSession) tryEmitRound2() ([]tss.Envelope, error) {
	prepared, ok, err := s.preparePresignRound2Outputs()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer prepared.destroy()
	effects := s.commitPresignRound2Outputs(prepared)
	return effects.envelopes, nil
}

type preparedPresignRound2Peer struct {
	party     tss.PartyID
	betaDelta *secret.Scalar
	betaSigma *secret.Scalar
}

type preparedPresignRound2Outputs struct {
	peers     []preparedPresignRound2Peer
	envelopes []tss.Envelope
	committed bool
}

func (p *preparedPresignRound2Outputs) destroy() {
	if p == nil || p.committed {
		return
	}
	for i := range p.peers {
		if p.peers[i].betaDelta != nil {
			p.peers[i].betaDelta.Destroy()
		}
		if p.peers[i].betaSigma != nil {
			p.peers[i].betaSigma.Destroy()
		}
	}
	for i := range p.envelopes {
		clear(p.envelopes[i].Payload)
	}
}

func (s *PresignSession) preparePresignRound2Outputs() (*preparedPresignRound2Outputs, bool, error) {
	if s.round2Sent || !s.allRound1PayloadsAccepted() || !s.allRound1Verified() {
		return nil, false, nil
	}
	prepared := &preparedPresignRound2Outputs{
		peers:     make([]preparedPresignRound2Peer, 0, len(s.signers)-1),
		envelopes: make([]tss.Envelope, 0, len(s.signers)-1),
	}
	success := false
	defer func() {
		if !success {
			prepared.destroy()
		}
	}()
	selfPK, err := s.key.paillierPublic(s.limits)
	if err != nil {
		return nil, false, err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.state.Party, s.limits)
	if err != nil {
		return nil, false, err
	}
	for _, peer := range s.signers {
		if peer == s.key.state.Party {
			continue
		}
		peerPK, err := s.key.paillierPublicFor(peer, s.limits)
		if err != nil {
			return nil, false, err
		}
		peerRP, err := s.key.ringPedersenPublicFor(peer, s.limits)
		if err != nil {
			return nil, false, err
		}
		peerState, ok := s.partyState(peer)
		if !ok || !peerState.round1.havePayload || !peerState.round1.haveProof {
			return nil, false, fmt.Errorf("missing presign round1 state for party %d", peer)
		}
		peerRound1 := peerState.round1.payload
		start := mta.StartMessage{Ciphertext: peerRound1.EncK}
		startProofDomain, err := mtaStartProofDomain(s.key, s.sessionID, s.signers, peer, s.key.state.Party, peerRound1.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return nil, false, err
		}
		deltaDomain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.state.Party, peerRound1.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return nil, false, err
		}
		sigmaDomain, err := mtaSigmaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.state.Party, peerRound1.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return nil, false, err
		}
		startProofPayload := peerState.round1.proof
		startProof := &startProofPayload.EncKProof
		// The delta MtA instance creates additive shares of k_i*gamma_j.
		deltaResp, betaDelta, err := mta.Respond(
			s.securityParams,
			nil,
			startProofDomain,
			deltaDomain,
			start,
			startProof,
			s.gamma,
			s.gammaComm,
			peerPK,
			selfPK,
			localRP,
			peerRP,
		)
		if err != nil {
			return nil, false, err
		}
		// The sigma MtA instance creates additive shares of k_i*x_j, where x_j
		// is already adjusted by the signer-set Lagrange coefficient.
		sigmaResp, betaSigma, err := mta.Respond(
			s.securityParams,
			nil,
			startProofDomain,
			sigmaDomain,
			start,
			startProof,
			s.xBar,
			s.xBarComm,
			peerPK,
			selfPK,
			localRP,
			peerRP,
		)
		if err != nil {
			betaDelta.Destroy()
			return nil, false, err
		}
		prepared.peers = append(prepared.peers, preparedPresignRound2Peer{
			party:     peer,
			betaDelta: betaDelta,
			betaSigma: betaSigma,
		})
		payload, err := (presignRound2Payload{
			Delta:      *deltaResp,
			Sigma:      *sigmaResp,
			Round1Echo: s.round1Echo(),
			PlanHash:   s.planHash,
		}).MarshalBinaryWithLimits(s.limits)
		if err != nil {
			return nil, false, err
		}
		round2Env, err := newEnvelope(s.config, presignRound2, s.key.state.Party, peer, payloadPresignRound2, payload)
		clear(payload)
		if err != nil {
			return nil, false, err
		}
		prepared.envelopes = append(prepared.envelopes, round2Env)
	}
	success = true
	return prepared, true, nil
}

func (s *PresignSession) commitPresignRound2Outputs(p *preparedPresignRound2Outputs) sessionEffects {
	if p == nil {
		return sessionEffects{}
	}
	for i := range p.peers {
		st, ok := s.partyState(p.peers[i].party)
		if !ok {
			continue
		}
		st.mta.betaDelta = p.peers[i].betaDelta
		st.mta.betaSigma = p.peers[i].betaSigma
	}
	s.round2Sent = true
	p.committed = true
	return sessionEffects{envelopes: p.envelopes}
}

func (s *PresignSession) verifyPresignRound2(from tss.PartyID, p presignRound2Payload) (*round2VerifiedMaterial, error) {
	if !bytes.Equal(p.Round1Echo, s.round1Echo()) {
		return nil, errors.New("presign round1 echo mismatch")
	}
	selfState, ok := s.partyState(s.key.state.Party)
	if !ok || !selfState.round1.havePayload {
		return nil, errors.New("missing local presign round1 state")
	}
	fromState, ok := s.partyState(from)
	if !ok || !fromState.round1.havePayload {
		return nil, fmt.Errorf("missing presign round1 state for party %d", from)
	}
	start := mta.StartMessage{Ciphertext: selfState.round1.payload.EncK}
	gammaCommit := fromState.round1.payload.Gamma

	// Responder's Paillier public key (for verifying the Y commitment in Πaff-g).
	responderPK, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return nil, err
	}
	// Initiator's own Ring-Pedersen params (the verifier's auxiliary input).
	selfRP, err := s.key.ringPedersenPublicFor(s.key.state.Party, s.limits)
	if err != nil {
		return nil, err
	}

	deltaDomain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, s.key.state.Party, from, &s.paillier.PublicKey, s.contextHash, s.planHash, s.limits)
	if err != nil {
		return nil, err
	}
	alphaDelta, err := mta.Finish(
		s.securityParams,
		deltaDomain,
		start,
		p.Delta,
		gammaCommit,
		s.paillier,
		responderPK,
		selfRP,
	)
	if err != nil {
		return nil, err
	}
	xBarCommit, err := s.xBarCommitment(from)
	if err != nil {
		alphaDelta.Destroy()
		return nil, err
	}
	sigmaDomain, err := mtaSigmaResponseDomain(s.key, s.sessionID, s.signers, s.key.state.Party, from, &s.paillier.PublicKey, s.contextHash, s.planHash, s.limits)
	if err != nil {
		alphaDelta.Destroy()
		return nil, err
	}
	alphaSigma, err := mta.Finish(
		s.securityParams,
		sigmaDomain,
		start,
		p.Sigma,
		xBarCommit,
		s.paillier,
		responderPK,
		selfRP,
	)
	if err != nil {
		alphaDelta.Destroy()
		return nil, err
	}
	return &round2VerifiedMaterial{
		alphaDelta: alphaDelta,
		alphaSigma: alphaSigma,
	}, nil
}

func (s *PresignSession) xBarCommitment(id tss.PartyID) ([]byte, error) {
	verificationShare, ok := s.key.verificationShare(id)
	if !ok {
		return nil, fmt.Errorf("missing verification share for %d", id)
	}
	point, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return nil, err
	}
	lambda, err := shamir.LagrangeCoefficient(id, s.signers)
	if err != nil {
		return nil, err
	}
	return secp.PointBytes(secp.ScalarMult(point, lambda))
}
