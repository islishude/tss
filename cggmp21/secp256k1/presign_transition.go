package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type acceptPresignRound1PayloadTx struct {
	from     tss.PartyID
	payload  presignRound1Payload
	verified bool
	prepared preparedPresignTransitionEffects
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
	return tx.prepared.commit(s)
}

func (tx *acceptPresignRound1PayloadTx) cleanupOnReject() { tx.prepared.destroy() }

func (*acceptPresignRound1PayloadTx) markCommitted() {}

type acceptPresignRound1ProofTx struct {
	from          tss.PartyID
	proof         presignRound1ProofPayload
	proofEnvelope tss.Envelope
	verified      bool
	prepared      preparedPresignTransitionEffects
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
	return tx.prepared.commit(s)
}

func (tx *acceptPresignRound1ProofTx) cleanupOnReject() { tx.prepared.destroy() }

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
	envelope tss.Envelope
	material *round2VerifiedMaterial
	prepared preparedPresignTransitionEffects
}

func (tx *acceptPresignRound2Tx) apply(s *PresignSession) (sessionEffects, error) {
	st, ok := s.partyState(tx.from)
	if !ok {
		return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeInvalidMessage, 2, tx.from, errPresignSignerMissing)
	}
	st.round2.payload = tx.payload
	st.round2.payloadEnvelope = tx.envelope.Clone()
	st.round2.havePayload = true
	st.mta.alphaDelta = tx.material.alphaDelta
	st.mta.alphaSigma = tx.material.alphaSigma
	return tx.prepared.commit(s)
}

func (tx *acceptPresignRound2Tx) cleanupOnReject() {
	if tx != nil {
		tx.prepared.destroy()
	}
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
	from      tss.PartyID
	payload   presignRound3Payload
	committed bool
	prepared  preparedPresignTransitionEffects
}

func (tx *acceptPresignRound3Tx) apply(s *PresignSession) (sessionEffects, error) {
	st, ok := s.partyState(tx.from)
	if !ok {
		return sessionEffects{}, tss.NewProtocolError(tss.ErrCodeInvalidMessage, 3, tx.from, errPresignSignerMissing)
	}
	st.round3 = presignRound3State{
		delta:       tx.payload.Delta,
		deltaPoint:  tx.payload.DeltaPoint,
		sPoint:      tx.payload.S,
		proof:       tx.payload.Proof,
		havePayload: true,
	}
	return tx.prepared.commit(s)
}

func (tx *acceptPresignRound3Tx) cleanupOnReject() {
	if tx == nil {
		return
	}
	tx.prepared.destroy()
	if tx.committed || tx.payload.Delta == nil {
		return
	}
	tx.payload.Delta.Destroy()
	tx.payload.Delta = nil
	tx.payload.Proof.Destroy()
	clear(tx.payload.DeltaPoint)
	clear(tx.payload.S)
	clear(tx.payload.PlanHash)
	clear(tx.payload.EpochID)
	clear(tx.payload.PresignID)
}

func (tx *acceptPresignRound3Tx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

type preparedPresignTransitionEffects struct {
	round2     *preparedPresignRound2Outputs
	round3     *preparedPresignRound3Output
	completion *preparedPresignCompletionEffects
}

func (p *preparedPresignTransitionEffects) destroy() {
	if p == nil {
		return
	}
	if p.round2 != nil {
		p.round2.destroy()
	}
	if p.round3 != nil {
		p.round3.destroy()
	}
	if p.completion != nil {
		p.completion.destroy()
	}
}

func (p *preparedPresignTransitionEffects) commit(s *PresignSession) (sessionEffects, error) {
	if p == nil {
		return sessionEffects{}, nil
	}
	var effects sessionEffects
	if p.round2 != nil {
		round2Effects := s.commitPresignRound2Outputs(p.round2)
		effects.envelopes = append(effects.envelopes, round2Effects.envelopes...)
	}
	if p.round3 != nil {
		round3Effects, err := s.commitPresignRound3Output(p.round3)
		if err != nil {
			return sessionEffects{}, err
		}
		effects.envelopes = append(effects.envelopes, round3Effects.envelopes...)
	}
	if p.completion != nil {
		completionEffects, err := s.commitPresignCompletionEffects(p.completion)
		if err != nil {
			for i := range effects.envelopes {
				clearEnvelope(&effects.envelopes[i])
			}
			return sessionEffects{}, err
		}
		effects.envelopes = append(effects.envelopes, completionEffects.envelopes...)
	}
	return effects, nil
}

func (tx *acceptPresignRound1PayloadTx) prepare(s *PresignSession) error {
	st, ok := s.partyState(tx.from)
	if !ok {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, presignStartRound, tx.from, errPresignSignerMissing)
	}
	previous := st.round1
	st.round1.payload = tx.payload
	st.round1.havePayload = true
	if tx.verified {
		st.round1.verified = true
	}
	prepared, ready, err := s.preparePresignRound2Outputs()
	st.round1 = previous
	if err != nil {
		return err
	}
	if ready {
		tx.prepared.round2 = prepared
	}
	return nil
}

func (tx *acceptPresignRound1ProofTx) prepare(s *PresignSession) error {
	st, ok := s.partyState(tx.from)
	if !ok {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, presignStartRound, tx.from, errPresignSignerMissing)
	}
	previous := st.round1
	st.round1.proof = tx.proof
	st.round1.proofEnvelope = tx.proofEnvelope
	st.round1.haveProof = true
	if tx.verified {
		st.round1.verified = true
	}
	prepared, ready, err := s.preparePresignRound2Outputs()
	st.round1 = previous
	if err != nil {
		return err
	}
	if ready {
		tx.prepared.round2 = prepared
	}
	return nil
}

func (tx *acceptPresignRound2Tx) prepare(s *PresignSession) error {
	st, ok := s.partyState(tx.from)
	if !ok {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, presignRound2, tx.from, errPresignSignerMissing)
	}
	previousRound2 := st.round2
	previousMTA := st.mta
	st.round2.payload = tx.payload
	st.round2.payloadEnvelope = tx.envelope
	st.round2.havePayload = true
	st.mta.alphaDelta = tx.material.alphaDelta
	st.mta.alphaSigma = tx.material.alphaSigma
	prepared, ready, err := s.preparePresignRound3Output()
	if err == nil && ready {
		tx.prepared.round3 = prepared
		var completionReady bool
		tx.prepared.completion, completionReady, err = s.preparePresignCompletionWithStagedLocalRound3(prepared)
		if !completionReady {
			tx.prepared.completion = nil
		}
	}
	st.round2 = previousRound2
	st.mta = previousMTA
	if err != nil {
		tx.prepared.destroy()
		tx.prepared = preparedPresignTransitionEffects{}
		return err
	}
	return nil
}

func (tx *acceptPresignRound3Tx) prepare(s *PresignSession) error {
	st, ok := s.partyState(tx.from)
	if !ok {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, presignRound3, tx.from, errPresignSignerMissing)
	}
	previous := st.round3
	st.round3 = presignRound3State{
		delta:       tx.payload.Delta,
		deltaPoint:  tx.payload.DeltaPoint,
		sPoint:      tx.payload.S,
		proof:       tx.payload.Proof,
		havePayload: true,
	}
	prepared, ready, err := s.preparePresignCompletionEffects()
	st.round3 = previous
	if err != nil {
		return err
	}
	if ready {
		tx.prepared.completion = prepared
	}
	return nil
}
