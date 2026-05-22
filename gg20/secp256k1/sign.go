package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/shamir"
)

type Presign struct {
	Version        uint16        `json:"version"`
	Party          tss.PartyID   `json:"party"`
	Threshold      int           `json:"threshold"`
	Signers        []tss.PartyID `json:"signers"`
	R              []byte        `json:"r"`
	LittleR        []byte        `json:"little_r"`
	KShare         []byte        `json:"k_share"`
	SigmaShare     []byte        `json:"sigma_share"`
	Delta          []byte        `json:"delta"`
	TranscriptHash []byte        `json:"transcript_hash"`
	Consumed       bool          `json:"consumed"`
	SecurityNotice string        `json:"security_notice"`
}

type PresignSession struct {
	key       *KeyShare
	sessionID tss.SessionID
	config    tss.ThresholdConfig
	signers   []tss.PartyID
	paillier  *pai.PrivateKey

	kShare    *big.Int
	gamma     *big.Int
	xBar      *big.Int
	gammaComm []byte
	xBarComm  []byte

	round1 map[tss.PartyID]presignRound1Payload
	round2 map[tss.PartyID]presignRound2Payload
	deltas map[tss.PartyID]*big.Int

	alphaDelta map[tss.PartyID]*big.Int
	betaDelta  map[tss.PartyID]*big.Int
	alphaSigma map[tss.PartyID]*big.Int
	betaSigma  map[tss.PartyID]*big.Int

	round2Sent bool
	round3Sent bool
	completed  bool
	presign    *Presign
}

type SignSession struct {
	key       *KeyShare
	presign   *Presign
	sessionID tss.SessionID
	digest    []byte
	lowS      bool
	partials  map[tss.PartyID]*big.Int
	completed bool
	signature *Signature
}

type presignRound1Payload struct {
	Gamma             []byte `json:"gamma"`
	EncK              []byte `json:"enc_k"`
	EncKProof         []byte `json:"enc_k_proof"`
	EncKRangeProof    []byte `json:"enc_k_range_proof"`
	PaillierPublicKey []byte `json:"paillier_public_key"`
}

type presignRound2Payload struct {
	Delta mta.ResponseMessage `json:"delta"`
	Sigma mta.ResponseMessage `json:"sigma"`
}

type presignRound3Payload struct {
	Delta []byte `json:"delta"`
}

type signPartialPayload struct {
	S                 []byte `json:"s"`
	PresignTranscript []byte `json:"presign_transcript"`
}

func StartPresign(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID) (*PresignSession, []tss.Envelope, error) {
	if err := key.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	signers = tss.SortParties(signers)
	if len(signers) < key.Threshold {
		return nil, nil, errors.New("not enough signers")
	}
	if !tss.ContainsParty(signers, key.Party) {
		return nil, nil, errors.New("local party is not in signer set")
	}
	if err := validateSignerSet(key, signers); err != nil {
		return nil, nil, err
	}
	paillierKey, err := key.paillierPrivate()
	if err != nil {
		return nil, nil, err
	}
	kShare, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	gamma, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	gammaComm, err := secp.PointBytes(secp.ScalarBaseMult(gamma))
	if err != nil {
		return nil, nil, err
	}
	lambda, err := shamir.LagrangeCoefficient(key.Party, signers, secp.Order())
	if err != nil {
		return nil, nil, err
	}
	secret, err := key.secretBig()
	if err != nil {
		return nil, nil, err
	}
	xBar := new(big.Int).Mul(lambda, secret)
	xBar.Mod(xBar, secp.Order())
	localVerificationShare, ok := key.verificationShare(key.Party)
	if !ok {
		return nil, nil, errors.New("missing local verification share")
	}
	localVerificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, nil, err
	}
	xBarComm, err := secp.PointBytes(secp.ScalarMult(localVerificationPoint, lambda))
	if err != nil {
		return nil, nil, err
	}
	startMsg, err := mta.Start(nil, mtaStartDomain(sessionID, signers, key.Party), kShare, &paillierKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	config := tss.ThresholdConfig{Threshold: key.Threshold, Parties: signers, Self: key.Party, SessionID: sessionID}
	payload, err := json.Marshal(presignRound1Payload{
		Gamma:             gammaComm,
		EncK:              startMsg.Ciphertext,
		EncKProof:         startMsg.EncProof,
		EncKRangeProof:    startMsg.RangeProof,
		PaillierPublicKey: append([]byte(nil), key.PaillierPublicKey...),
	})
	if err != nil {
		return nil, nil, err
	}
	env := envelope(config, 1, key.Party, 0, payloadPresignRound1, payload, false)
	s := &PresignSession{
		key:        key,
		sessionID:  sessionID,
		config:     config,
		signers:    signers,
		paillier:   paillierKey,
		kShare:     kShare,
		gamma:      gamma,
		xBar:       xBar,
		gammaComm:  gammaComm,
		xBarComm:   xBarComm,
		round1:     map[tss.PartyID]presignRound1Payload{key.Party: mustRound1(payload)},
		round2:     make(map[tss.PartyID]presignRound2Payload),
		deltas:     make(map[tss.PartyID]*big.Int),
		alphaDelta: make(map[tss.PartyID]*big.Int),
		betaDelta:  make(map[tss.PartyID]*big.Int),
		alphaSigma: make(map[tss.PartyID]*big.Int),
		betaSigma:  make(map[tss.PartyID]*big.Int),
	}
	out := []tss.Envelope{env}
	round2, err := s.tryEmitRound2()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round2...)
	round3, err := s.tryEmitRound3()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round3...)
	return s, out, nil
}

func (s *PresignSession) HandlePresignMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil presign session")
	}
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	switch env.PayloadType {
	case payloadPresignRound1:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round1 payload in wrong round"))
		}
		if _, ok := s.round1[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round1"))
		}
		var p presignRound1Payload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound1,
				"malformed presign round1 payload",
				[]tss.PartyID{env.From},
				err,
				fields...,
			)
		}
		if err := s.validateRound1(env.From, p); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPresignRound1,
				"invalid presign round1 proof",
				[]tss.PartyID{env.From},
				err,
				s.presignRound1EvidenceFields(env.From, p)...,
			)
		}
		s.round1[env.From] = p
		return s.tryEmitRound2()
	case payloadPresignRound2:
		if env.Round != 2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round2 payload in wrong round"))
		}
		if _, ok := s.round2[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round2"))
		}
		var p presignRound2Payload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
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
		s.round2[env.From] = p
		return s.tryEmitRound3()
	case payloadPresignRound3:
		if env.Round != 3 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round3 payload in wrong round"))
		}
		if _, ok := s.deltas[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate delta share"))
		}
		var p presignRound3Payload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
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
		delta, err := secp.ParseScalar(p.Delta)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound3,
				"malformed presign delta",
				[]tss.PartyID{env.From},
				err,
				s.presignRound3EvidenceFields(p)...,
			)
		}
		s.deltas[env.From] = delta
		return nil, s.tryComplete()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
}

func (s *PresignSession) Presign() (*Presign, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.presign, true
}

func (s *PresignSession) presignRound1EvidenceFields(from tss.PartyID, p presignRound1Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	fields = append(fields,
		hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		hashEvidenceField("gamma_hash", p.Gamma),
		hashEvidenceField("enc_k_hash", p.EncK),
	)
	if expected, err := s.key.paillierPublicFor(from); err == nil {
		if encoded, err := expected.MarshalBinary(); err == nil {
			fields = append(fields, hashEvidenceField(evidenceFieldExpectedPaillierKeyHash, encoded))
		}
	}
	return fields
}

func (s *PresignSession) presignRound2EvidenceFields(p presignRound2Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields,
		rawEvidenceField(evidenceFieldDeltaResponseHash, mtaResponseHash("delta", p.Delta)),
		rawEvidenceField(evidenceFieldSigmaResponseHash, mtaResponseHash("sigma", p.Sigma)),
	)
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields, hashEvidenceField("delta_hash", p.Delta))
}

func (s *PresignSession) validateRound1(from tss.PartyID, p presignRound1Payload) error {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return fmt.Errorf("invalid gamma: %w", err)
	}
	expectedPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	expectedPKBytes, err := expectedPK.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedPKBytes, p.PaillierPublicKey) {
		return errors.New("round1 Paillier public key does not match keygen")
	}
	start := mta.StartMessage{Ciphertext: p.EncK, EncProof: p.EncKProof, RangeProof: p.EncKRangeProof}
	if !mta.VerifyStart(mtaStartDomain(s.sessionID, s.signers, from), start, expectedPK) {
		return errors.New("invalid encrypted nonce proof")
	}
	return nil
}

func (s *PresignSession) tryEmitRound2() ([]tss.Envelope, error) {
	if s.round2Sent || len(s.round1) != len(s.signers) {
		return nil, nil
	}
	out := make([]tss.Envelope, 0, len(s.signers)-1)
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		peerPK, err := s.key.paillierPublicFor(peer)
		if err != nil {
			return nil, err
		}
		start := mta.StartMessage{Ciphertext: s.round1[peer].EncK, EncProof: s.round1[peer].EncKProof, RangeProof: s.round1[peer].EncKRangeProof}
		deltaResp, betaDelta, err := mta.Respond(nil, mtaStartDomain(s.sessionID, s.signers, peer), mtaResponseDomain(s.sessionID, s.signers, peer, s.key.Party, "delta"), start, s.gamma, s.gammaComm, peerPK)
		if err != nil {
			return nil, err
		}
		sigmaResp, betaSigma, err := mta.Respond(nil, mtaStartDomain(s.sessionID, s.signers, peer), mtaResponseDomain(s.sessionID, s.signers, peer, s.key.Party, "sigma"), start, s.xBar, s.xBarComm, peerPK)
		if err != nil {
			return nil, err
		}
		s.betaDelta[peer] = betaDelta
		s.betaSigma[peer] = betaSigma
		payload, err := json.Marshal(presignRound2Payload{Delta: *deltaResp, Sigma: *sigmaResp})
		if err != nil {
			return nil, err
		}
		out = append(out, envelope(s.config, 2, s.key.Party, peer, payloadPresignRound2, payload, true))
	}
	s.round2Sent = true
	return out, nil
}

func (s *PresignSession) finishRound2(from tss.PartyID, p presignRound2Payload) error {
	start := mta.StartMessage{Ciphertext: s.round1[s.key.Party].EncK, EncProof: s.round1[s.key.Party].EncKProof, RangeProof: s.round1[s.key.Party].EncKRangeProof}
	gammaCommit := s.round1[from].Gamma
	alphaDelta, err := mta.Finish(mtaStartDomain(s.sessionID, s.signers, s.key.Party), mtaResponseDomain(s.sessionID, s.signers, s.key.Party, from, "delta"), start, p.Delta, gammaCommit, s.paillier)
	if err != nil {
		return err
	}
	xBarCommit, err := s.xBarCommitment(from)
	if err != nil {
		return err
	}
	alphaSigma, err := mta.Finish(mtaStartDomain(s.sessionID, s.signers, s.key.Party), mtaResponseDomain(s.sessionID, s.signers, s.key.Party, from, "sigma"), start, p.Sigma, xBarCommit, s.paillier)
	if err != nil {
		return err
	}
	s.alphaDelta[from] = alphaDelta
	s.alphaSigma[from] = alphaSigma
	return nil
}

func (s *PresignSession) tryEmitRound3() ([]tss.Envelope, error) {
	if s.round3Sent || len(s.round2) != len(s.signers)-1 {
		return nil, nil
	}
	deltaShare := new(big.Int).Mul(s.kShare, s.gamma)
	sigmaShare := new(big.Int).Mul(s.kShare, s.xBar)
	order := secp.Order()
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		deltaShare.Add(deltaShare, s.alphaDelta[peer])
		deltaShare.Add(deltaShare, s.betaDelta[peer])
		sigmaShare.Add(sigmaShare, s.alphaSigma[peer])
		sigmaShare.Add(sigmaShare, s.betaSigma[peer])
	}
	deltaShare.Mod(deltaShare, order)
	sigmaShare.Mod(sigmaShare, order)
	s.deltas[s.key.Party] = deltaShare
	payload, err := json.Marshal(presignRound3Payload{Delta: scalarBytes(deltaShare)})
	if err != nil {
		return nil, err
	}
	s.round3Sent = true
	s.presign = &Presign{
		Version:        tss.Version,
		Party:          s.key.Party,
		Threshold:      s.key.Threshold,
		Signers:        append([]tss.PartyID(nil), s.signers...),
		KShare:         scalarBytes(s.kShare),
		SigmaShare:     scalarBytes(sigmaShare),
		SecurityNotice: ExperimentalSecurityNotice,
	}
	if err := s.tryComplete(); err != nil {
		return nil, err
	}
	return []tss.Envelope{envelope(s.config, 3, s.key.Party, 0, payloadPresignRound3, payload, false)}, nil
}

func (s *PresignSession) tryComplete() error {
	if s.completed || len(s.deltas) != len(s.signers) {
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
	RPoint := secp.ScalarMult(gamma, deltaInv)
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		return err
	}
	littleR := new(big.Int).Mod(RPoint.X, order)
	if littleR.Sign() == 0 {
		return errors.New("zero ECDSA r")
	}
	if s.presign == nil {
		return errors.New("local presign shares not computed")
	}
	s.presign.R = R
	s.presign.LittleR = scalarBytes(littleR)
	s.presign.Delta = scalarBytes(delta)
	s.presign.TranscriptHash = s.presignTranscriptHash(R, littleR, delta)
	s.completed = true
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
	return secp.PointBytes(secp.ScalarMult(point, lambda))
}

func (s *PresignSession) presignTranscriptHash(R []byte, littleR, delta *big.Int) []byte {
	h := sha256.New()
	writeHashPart(h, []byte("gg20-secp256k1-presign-transcript-v1"))
	writeHashPart(h, s.sessionID[:])
	for _, id := range s.signers {
		writeHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		writeHashPart(h, s.round1[id].Gamma)
		writeHashPart(h, s.round1[id].EncK)
		writeHashPart(h, s.round1[id].EncKProof)
		writeHashPart(h, s.round1[id].EncKRangeProof)
		writeHashPart(h, scalarBytes(s.deltas[id]))
	}
	writeHashPart(h, R)
	writeHashPart(h, scalarBytes(littleR))
	writeHashPart(h, scalarBytes(delta))
	return h.Sum(nil)
}

func StartSignDigest(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte) (*SignSession, []tss.Envelope, error) {
	if err := key.Validate(); err != nil {
		return nil, nil, err
	}
	return StartSignDigestWithOptions(key, presign, sessionID, digest32, true)
}

func StartSignDigestWithOptions(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte, lowS bool) (*SignSession, []tss.Envelope, error) {
	if err := key.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	if err := validatePresign(key, presign); err != nil {
		return nil, nil, err
	}
	if len(digest32) != 32 {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	if presign.Consumed {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.Party, errors.New("presign already consumed"))
	}
	presign.Consumed = true
	kShare, err := secp.ParseScalar(presign.KShare)
	if err != nil {
		return nil, nil, err
	}
	sigmaShare, err := secp.ParseScalar(presign.SigmaShare)
	if err != nil {
		return nil, nil, err
	}
	littleR, err := secp.ParseScalar(presign.LittleR)
	if err != nil {
		return nil, nil, err
	}
	z := new(big.Int).SetBytes(digest32)
	partial := new(big.Int).Mul(z, kShare)
	rs := new(big.Int).Mul(littleR, sigmaShare)
	partial.Add(partial, rs)
	partial.Mod(partial, secp.Order())
	payload, err := json.Marshal(signPartialPayload{S: scalarBytes(partial), PresignTranscript: append([]byte(nil), presign.TranscriptHash...)})
	if err != nil {
		return nil, nil, err
	}
	env := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        key.Party,
		PayloadType: payloadSignPartial,
		Payload:     payload,
	}.WithTranscriptHash()
	s := &SignSession{
		key:       key,
		presign:   presign,
		sessionID: sessionID,
		digest:    append([]byte(nil), digest32...),
		lowS:      lowS,
		partials:  map[tss.PartyID]*big.Int{key.Party: partial},
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, []tss.Envelope{env}, nil
}

func (s *SignSession) HandleSignMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.presign.Signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.Round != 1 || env.PayloadType != payloadSignPartial {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("expected round 1 sign partial"))
	}
	if _, ok := s.partials[env.From]; ok {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate sign partial"))
	}
	var p signPartialPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"malformed sign partial payload",
			[]tss.PartyID{env.From},
			err,
			fields...,
		)
	}
	if !bytes.Equal(p.PresignTranscript, s.presign.TranscriptHash) {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"presign transcript mismatch",
			[]tss.PartyID{env.From},
			errors.New("presign transcript mismatch"),
			s.signPartialEvidenceFields(p)...,
		)
	}
	partial, err := secp.ParseScalar(p.S)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"malformed sign partial",
			[]tss.PartyID{env.From},
			err,
			s.signPartialEvidenceFields(p)...,
		)
	}
	s.partials[env.From] = partial
	return nil, s.tryComplete()
}

func (s *SignSession) Signature() (*Signature, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return &Signature{R: append([]byte(nil), s.signature.R...), S: append([]byte(nil), s.signature.S...)}, true
}

func (s *SignSession) signPartialEvidenceFields(p signPartialPayload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
	return append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.TranscriptHash),
		hashEvidenceField("observed_presign_transcript_hash", p.PresignTranscript),
		hashEvidenceField("sign_partial_hash", p.S),
	)
}

func (s *SignSession) aggregateEvidenceFields(r, sigS *big.Int) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
	return append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.TranscriptHash),
		hashEvidenceField(evidenceFieldDigestHash, s.digest),
		hashEvidenceField(evidenceFieldRHash, scalarBytes(r)),
		hashEvidenceField(evidenceFieldSHash, scalarBytes(sigS)),
	)
}

func (s *SignSession) tryComplete() error {
	if s.completed || len(s.partials) != len(s.presign.Signers) {
		return nil
	}
	sigS := new(big.Int)
	for _, id := range s.presign.Signers {
		sigS.Add(sigS, s.partials[id])
		sigS.Mod(sigS, secp.Order())
	}
	if sigS.Sign() == 0 {
		return errors.New("zero ECDSA s")
	}
	if s.lowS && sigS.Cmp(new(big.Int).Rsh(new(big.Int).Set(secp.N), 1)) > 0 {
		sigS.Sub(secp.N, sigS)
	}
	r, err := secp.ParseScalar(s.presign.LittleR)
	if err != nil {
		return err
	}
	public, err := secp.PointFromBytes(s.key.PublicKey)
	if err != nil {
		return err
	}
	if !secp.VerifyECDSA(public, s.digest, r, sigS) {
		env := tss.Envelope{
			Protocol:    protocol,
			Version:     tss.Version,
			SessionID:   s.sessionID,
			Round:       1,
			PayloadType: payloadSignPartial,
			Payload:     aggregateEvidencePayload(s.digest, scalarBytes(r), scalarBytes(sigS), s.presign.TranscriptHash),
		}.WithTranscriptHash()
		return &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: 1,
			Blame: &tss.Blame{
				Reason:  "aggregated ECDSA signature failed verification",
				Parties: append([]tss.PartyID(nil), s.presign.Signers...),
				Evidence: marshalEvidence(
					env,
					tss.EvidenceKindAggregateSign,
					"aggregated ECDSA signature failed verification",
					s.aggregateEvidenceFields(r, sigS)...,
				),
			},
			Err: errors.New("ECDSA signature failed verification"),
		}
	}
	s.signature = &Signature{R: scalarBytes(r), S: scalarBytes(sigS)}
	s.completed = true
	return nil
}

func VerifyDigest(publicKey, digest32 []byte, sig *Signature) bool {
	public, err := secp.PointFromBytes(publicKey)
	if err != nil {
		return false
	}
	if sig == nil {
		return false
	}
	r, err := secp.ParseScalar(sig.R)
	if err != nil {
		return false
	}
	s, err := secp.ParseScalar(sig.S)
	if err != nil {
		return false
	}
	return secp.VerifyECDSA(public, digest32, r, s)
}

func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.requireMPCMaterial(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.Party
		shares[share.Party] = share
	}
	ids = tss.SortParties(ids)
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	presignSessions := make(map[tss.PartyID]*PresignSession, len(ids))
	presignQueue := make([]tss.Envelope, 0)
	for _, id := range ids {
		session, out, err := StartPresign(shares[id], presignID, ids)
		if err != nil {
			return nil, nil, err
		}
		presignSessions[id] = session
		presignQueue = append(presignQueue, out...)
	}
	for len(presignQueue) > 0 {
		env := presignQueue[0]
		presignQueue = presignQueue[1:]
		for _, id := range ids {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].HandlePresignMessage(env)
			if err != nil {
				return nil, nil, err
			}
			presignQueue = append(presignQueue, out...)
		}
	}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	signSessions := make(map[tss.PartyID]*SignSession, len(ids))
	signMessages := make([]tss.Envelope, 0, len(ids))
	for _, id := range ids {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			return nil, nil, fmt.Errorf("presign not completed for %d", id)
		}
		session, out, err := StartSignDigest(shares[id], presign, signID, digest32)
		if err != nil {
			return nil, nil, err
		}
		signSessions[id] = session
		signMessages = append(signMessages, out...)
	}
	for _, env := range signMessages {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if _, err := signSessions[id].HandleSignMessage(env); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, id := range ids {
		if sig, ok := signSessions[id].Signature(); ok {
			return signers[0].PublicKeyBytes(), sig, nil
		}
	}
	return nil, nil, errors.New("signature not completed")
}

func validatePresign(key *KeyShare, presign *Presign) error {
	if presign == nil {
		return errors.New("nil presign")
	}
	if presign.Version != tss.Version {
		return fmt.Errorf("unexpected presign version %d", presign.Version)
	}
	if presign.Party != key.Party {
		return errors.New("presign party mismatch")
	}
	if presign.Threshold != key.Threshold {
		return errors.New("presign threshold mismatch")
	}
	if len(presign.Signers) < key.Threshold || !tss.ContainsParty(presign.Signers, key.Party) {
		return errors.New("invalid presign signer set")
	}
	if _, err := secp.PointFromBytes(presign.R); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	if _, err := secp.ParseScalar(presign.LittleR); err != nil {
		return fmt.Errorf("invalid little r: %w", err)
	}
	if _, err := secp.ParseScalar(presign.KShare); err != nil {
		return fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secp.ParseScalar(presign.SigmaShare); err != nil {
		return fmt.Errorf("invalid sigma share: %w", err)
	}
	if _, err := secp.ParseScalar(presign.Delta); err != nil {
		return fmt.Errorf("invalid delta: %w", err)
	}
	if len(presign.TranscriptHash) != sha256.Size {
		return errors.New("invalid presign transcript hash")
	}
	return nil
}

func validateSignerSet(key *KeyShare, signers []tss.PartyID) error {
	seen := make(map[tss.PartyID]struct{}, len(signers))
	for _, id := range signers {
		if !tss.ContainsParty(key.Parties, id) {
			return fmt.Errorf("signer %d is not a participant", id)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate signer %d", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func mtaStartDomain(sessionID tss.SessionID, signers []tss.PartyID, owner tss.PartyID) []byte {
	return domainBytes("mta-start", sessionID, signers, owner, 0, "")
}

func mtaResponseDomain(sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, kind string) []byte {
	return domainBytes("mta-response", sessionID, signers, initiator, responder, kind)
}

func domainBytes(label string, sessionID tss.SessionID, signers []tss.PartyID, a, b tss.PartyID, kind string) []byte {
	h := sha256.New()
	writeHashPart(h, []byte("gg20-secp256k1"))
	writeHashPart(h, []byte(label))
	writeHashPart(h, sessionID[:])
	for _, id := range signers {
		writeHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
	}
	writeHashPart(h, []byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
	writeHashPart(h, []byte{byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b)})
	writeHashPart(h, []byte(kind))
	return h.Sum(nil)
}

func mtaResponseHash(label string, response mta.ResponseMessage) []byte {
	h := sha256.New()
	writeHashPart(h, []byte("gg20-secp256k1-mta-response-evidence-v1"))
	writeHashPart(h, []byte(label))
	writeHashPart(h, response.Ciphertext)
	writeHashPart(h, response.Proof)
	return h.Sum(nil)
}

func aggregateEvidencePayload(digest, r, sValue, transcript []byte) []byte {
	h := sha256.New()
	writeHashPart(h, []byte("gg20-secp256k1-aggregate-sign-evidence-v1"))
	writeHashPart(h, digest)
	writeHashPart(h, r)
	writeHashPart(h, sValue)
	writeHashPart(h, transcript)
	return h.Sum(nil)
}

func mustRound1(payload []byte) presignRound1Payload {
	var p presignRound1Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		panic(err)
	}
	return p
}
