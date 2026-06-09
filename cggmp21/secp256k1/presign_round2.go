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

// handlePresignRound2 validates and applies a presign round 2 payload.
//
// Follows the handler template (see doc.go).
func (s *PresignSession) handlePresignRound2(env tss.Envelope) ([]tss.Envelope, error) {
	// ---- 1. PARSE ----
	p, err := unmarshalPresignRound2Payload(env.Payload)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindPresignRound2,
			"malformed presign round2 payload",
			[]tss.PartyID{env.From},
			err,
			fields...,
		)
	}

	// ---- 2. POLICY VALIDATE ----
	// (round and duplicate checks done in dispatcher)

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if err := s.finishRound2(env.From, p); err != nil {
		return nil, verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPresignRound2,
			"invalid presign round2 proof",
			[]tss.PartyID{env.From},
			err,
			s.presignRound2EvidenceFields(p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	s.round2[env.From] = p

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
	if s.round2Sent || len(s.round1) != len(s.signers) {
		return nil, nil
	}
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		if !s.round1Verified[peer] {
			return nil, nil
		}
	}
	out := make([]tss.Envelope, 0, len(s.signers)-1)
	selfPK, err := s.key.paillierPublic()
	if err != nil {
		return nil, err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.Party)
	if err != nil {
		return nil, err
	}
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
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		peerPK, err := s.key.paillierPublicFor(peer)
		if err != nil {
			return nil, err
		}
		peerRP, err := s.key.ringPedersenPublicFor(peer)
		if err != nil {
			return nil, err
		}
		start := mta.StartMessage{Ciphertext: s.round1[peer].EncK}
		startProofDomain := mtaStartProofDomain(s.key, s.sessionID, s.signers, peer, s.key.Party, s.round1[peer].PaillierPublicKey, s.contextHash)
		startProof := s.round1Proofs[peer].EncKProof
		// The delta MtA instance creates additive shares of k_i*gamma_j.
		deltaResp, betaDelta, err := mta.Respond(
			nil,
			startProofDomain,
			mtaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.Party, "delta", s.round1[peer].PaillierPublicKey, s.contextHash),
			start,
			startProof,
			gamma,
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
			nil,
			startProofDomain,
			mtaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.Party, "sigma", s.round1[peer].PaillierPublicKey, s.contextHash),
			start,
			startProof,
			xBar,
			s.xBarComm,
			peerPK,
			selfPK,
			localRP,
			peerRP,
		)
		if err != nil {
			return nil, err
		}
		s.betaDelta[peer] = betaDelta
		s.betaSigma[peer] = betaSigma
		payload, err := marshalPresignRound2Payload(presignRound2Payload{Delta: *deltaResp, Sigma: *sigmaResp, Round1Echo: s.round1Echo()})
		if err != nil {
			return nil, err
		}
		round2Env, err := envelope(s.config, 2, s.key.Party, peer, payloadPresignRound2, payload, true)
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
	start := mta.StartMessage{Ciphertext: s.round1[s.key.Party].EncK}
	gammaCommit := s.round1[from].Gamma

	// Responder's Paillier public key (for verifying the Y commitment in Πaff-g).
	responderPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	// Initiator's own Ring-Pedersen params (the verifier's auxiliary input).
	selfRP, err := s.key.ringPedersenPublicFor(s.key.Party)
	if err != nil {
		return err
	}

	alphaDelta, err := mta.Finish(
		mtaResponseDomain(s.key, s.sessionID, s.signers, s.key.Party, from, "delta", s.key.PaillierPublicKey, s.contextHash),
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
	alphaSigma, err := mta.Finish(
		mtaResponseDomain(s.key, s.sessionID, s.signers, s.key.Party, from, "sigma", s.key.PaillierPublicKey, s.contextHash),
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
	s.alphaDelta[from] = alphaDelta
	s.alphaSigma[from] = alphaSigma
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
	lambda, err := shamir.LagrangeCoefficient(id, s.signers, secp.Order())
	if err != nil {
		return nil, err
	}
	return secp.PointBytes(secp.ScalarMult(point, secp.ScalarFromBigInt(lambda)))
}
