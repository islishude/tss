package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
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
	delta, err := secp.ScalarFromBytes(p.Delta)
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

	// ---- 4. MUTATE STATE ----
	s.deltas[env.From] = delta.BigInt()

	// ---- 5. EMIT ----
	return nil, s.tryComplete()
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields, hashEvidenceField("delta_hash", p.Delta))
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
		// delta_i = k_i*gamma_i + sum_j alpha_ij + sum_j beta_ji.
		deltaShare.Add(deltaShare, s.alphaDelta[peer])
		deltaShare.Add(deltaShare, s.betaDelta[peer])
		// chi_i = k_i*x_i + sum_j alphaHat_ij + sum_j betaHat_ji.
		chiShare.Add(chiShare, s.alphaSigma[peer])
		chiShare.Add(chiShare, s.betaSigma[peer])
	}
	deltaShare.Mod(deltaShare, order)
	chiShare.Mod(chiShare, order)
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
	payload, err := marshalPresignRound3Payload(presignRound3Payload{Delta: scalarBytes(deltaShare)})
	if err != nil {
		return nil, err
	}
	s.round3Sent = true
	s.presign = &Presign{
		mu:                   &sync.Mutex{},
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
		// Binding every signer id, nonce commitment, encrypted nonce, and delta
		// share prevents replaying presign material across signer sets.
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		wire.WriteHashPart(h, s.round1[id].Gamma)
		wire.WriteHashPart(h, s.round1[id].EncK)
		wire.WriteHashPart(h, scalarBytes(s.deltas[id]))
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
