package secp256k1

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	shamirsecp "github.com/islishude/tss/internal/shamir/secp256k1"
)

// handlePresignRound2 validates and applies a presign round 2 payload.
//
// Follows the handler template (see doc.go).
func (s *PresignSession) handlePresignRound2(env tss.Envelope) ([]tss.Envelope, error) {
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
	if err := s.finishRound2(env.From, p); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPresignRound2,
			"invalid presign round2 proof",
			tss.NewPartySet(env.From),
			err,
			s.presignRound2EvidenceFields(p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	st, ok := s.partyState(env.From)
	if !ok {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	st.round2.payload = p
	st.round2.havePayload = true
	s.round2Count++

	// ---- 5. EMIT ----
	return s.tryEmitRound3()
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
	if s.round2Sent ||
		s.round1Count != len(s.parties) ||
		s.round1VerifiedCount != len(s.parties) {
		return nil, nil
	}
	out := make([]tss.Envelope, 0, len(s.signers)-1)
	selfPK, err := s.key.paillierPublic(s.limits)
	if err != nil {
		return nil, err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.state.party, s.limits)
	if err != nil {
		return nil, err
	}
	for _, peer := range s.signers {
		if peer == s.key.state.party {
			continue
		}
		peerPK, err := s.key.paillierPublicFor(peer, s.limits)
		if err != nil {
			return nil, err
		}
		peerRP, err := s.key.ringPedersenPublicFor(peer, s.limits)
		if err != nil {
			return nil, err
		}
		peerState, ok := s.partyState(peer)
		if !ok || !peerState.round1.havePayload || !peerState.round1.haveProof {
			return nil, fmt.Errorf("missing presign round1 state for party %d", peer)
		}
		peerRound1 := peerState.round1.payload
		start := mta.StartMessage{Ciphertext: peerRound1.EncK}
		startProofDomain, err := mtaStartProofDomain(s.key, s.sessionID, s.signers, peer, s.key.state.party, &peerRound1.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return nil, err
		}
		deltaDomain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.state.party, &peerRound1.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return nil, err
		}
		sigmaDomain, err := mtaSigmaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.state.party, &peerRound1.PaillierPublicKey, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return nil, err
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
			return nil, err
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
			return nil, err
		}
		peerState.mta.betaDelta = betaDelta
		peerState.mta.betaSigma = betaSigma
		payload, err := marshalPresignRound2PayloadWithLimits(presignRound2Payload{
			Delta:      *deltaResp,
			Sigma:      *sigmaResp,
			Round1Echo: s.round1Echo(),
			PlanHash:   s.planHash,
		}, s.limits)
		if err != nil {
			return nil, err
		}
		round2Env, err := newEnvelope(s.config, 2, s.key.state.party, peer, payloadPresignRound2, payload)
		if err != nil {
			return nil, err
		}
		out = append(out, round2Env)
	}
	s.round2Sent = true
	return out, nil
}

func (s *PresignSession) finishRound2(from tss.PartyID, p presignRound2Payload) error {
	if !bytes.Equal(p.Round1Echo, s.round1Echo()) {
		return errors.New("presign round1 echo mismatch")
	}
	selfState, ok := s.partyState(s.key.state.party)
	if !ok || !selfState.round1.havePayload {
		return errors.New("missing local presign round1 state")
	}
	fromState, ok := s.partyState(from)
	if !ok || !fromState.round1.havePayload {
		return fmt.Errorf("missing presign round1 state for party %d", from)
	}
	start := mta.StartMessage{Ciphertext: selfState.round1.payload.EncK}
	gammaCommit := fromState.round1.payload.Gamma

	// Responder's Paillier public key (for verifying the Y commitment in Πaff-g).
	responderPK, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	// Initiator's own Ring-Pedersen params (the verifier's auxiliary input).
	selfRP, err := s.key.ringPedersenPublicFor(s.key.state.party, s.limits)
	if err != nil {
		return err
	}

	deltaDomain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, s.key.state.party, from, &s.paillier.PublicKey, s.contextHash, s.planHash, s.limits)
	if err != nil {
		return err
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
		return err
	}
	xBarCommit, err := s.xBarCommitment(from)
	if err != nil {
		return err
	}
	sigmaDomain, err := mtaSigmaResponseDomain(s.key, s.sessionID, s.signers, s.key.state.party, from, &s.paillier.PublicKey, s.contextHash, s.planHash, s.limits)
	if err != nil {
		return err
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
		return err
	}
	fromState.mta.alphaDelta = alphaDelta
	fromState.mta.alphaSigma = alphaSigma
	return nil
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
	lambda, err := shamirsecp.LagrangeCoefficient(id, s.signers)
	if err != nil {
		return nil, err
	}
	return secp.PointBytes(secp.ScalarMult(point, lambda))
}
