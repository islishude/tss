package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type acceptPresignRound1PayloadTx struct {
	from     tss.PartyID
	payload  presignRound1Payload
	verified bool
}

func (tx *acceptPresignRound1PayloadTx) apply(s *PresignSession) (sessionEffects, error) {
	st, ok := s.partyState(tx.from)
	if !ok {
		return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, tx.from, errPresignSignerMissing)
	}
	st.round1.payload = tx.payload
	st.round1.havePayload = true
	if tx.verified && !st.round1.verified {
		st.round1.verified = true
	}
	out, err := s.tryEmitRound2()
	return sessionEffects{envelopes: out}, err
}

func (*acceptPresignRound1PayloadTx) cleanupOnReject() {}

func (*acceptPresignRound1PayloadTx) markCommitted() {}

type acceptPresignRound1ProofTx struct {
	from          tss.PartyID
	proof         presignRound1ProofPayload
	proofEnvelope tss.Envelope
	verified      bool
}

func (tx *acceptPresignRound1ProofTx) apply(s *PresignSession) (sessionEffects, error) {
	st, ok := s.partyState(tx.from)
	if !ok {
		return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeInvalidMessage, 1, tx.from, errPresignSignerMissing)
	}
	st.round1.proof = tx.proof
	st.round1.proofEnvelope = tx.proofEnvelope.Clone()
	st.round1.haveProof = true
	if tx.verified && !st.round1.verified {
		st.round1.verified = true
	}
	out, err := s.tryEmitRound2()
	return sessionEffects{envelopes: out}, err
}

func (*acceptPresignRound1ProofTx) cleanupOnReject() {}

func (*acceptPresignRound1ProofTx) markCommitted() {}

type round2VerifiedMaterial struct {
	alphaDelta *secret.Scalar
	alphaSigma *secret.Scalar
	committed  bool
}

func (m *round2VerifiedMaterial) destroy() {
	if m == nil || m.committed {
		return
	}
	if m.alphaDelta != nil {
		m.alphaDelta.Destroy()
		m.alphaDelta = nil
	}
	if m.alphaSigma != nil {
		m.alphaSigma.Destroy()
		m.alphaSigma = nil
	}
}

type acceptPresignRound2Tx struct {
	from     tss.PartyID
	payload  presignRound2Payload
	material *round2VerifiedMaterial
}

func (tx *acceptPresignRound2Tx) apply(s *PresignSession) (sessionEffects, error) {
	st, ok := s.partyState(tx.from)
	if !ok {
		return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeInvalidMessage, 2, tx.from, errPresignSignerMissing)
	}
	st.round2.payload = tx.payload
	st.round2.havePayload = true
	st.mta.alphaDelta = tx.material.alphaDelta
	st.mta.alphaSigma = tx.material.alphaSigma
	out, err := s.tryEmitRound3()
	return sessionEffects{envelopes: out}, err
}

func (tx *acceptPresignRound2Tx) cleanupOnReject() {
	if tx != nil && tx.material != nil {
		tx.material.destroy()
	}
}

func (tx *acceptPresignRound2Tx) markCommitted() {
	if tx != nil && tx.material != nil {
		tx.material.committed = true
	}
}

type acceptPresignRound3Tx struct {
	from        tss.PartyID
	delta       *secret.Scalar
	verifyShare signVerifyShare
	committed   bool
}

func (tx *acceptPresignRound3Tx) apply(s *PresignSession) (sessionEffects, error) {
	st, ok := s.partyState(tx.from)
	if !ok {
		return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeInvalidMessage, 3, tx.from, errPresignSignerMissing)
	}
	st.round3.delta = tx.delta
	st.round3.verifyShare = tx.verifyShare
	st.round3.haveDelta = true
	st.round3.haveVerifyShare = true
	return sessionEffects{}, s.tryComplete()
}

func (tx *acceptPresignRound3Tx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.delta == nil {
		return
	}
	tx.delta.Destroy()
	tx.delta = nil
}

func (tx *acceptPresignRound3Tx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}
