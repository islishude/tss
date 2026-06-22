package secp256k1

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
)

type acceptCGGMPKeygenCommitmentsTx struct {
	from            tss.PartyID
	commitments     [][]byte
	chainCodeCommit []byte
	paillierPub     paillierPublicMaterial
	ringPedersen    ringPedersenPublicMaterial
}

func (tx *acceptCGGMPKeygenCommitmentsTx) apply(s *KeygenSession) (sessionEffects, error) {
	if err := s.round1.recordCommitments(
		tx.from,
		tx.commitments,
		tx.chainCodeCommit,
		tx.paillierPub,
		tx.ringPedersen,
	); err != nil {
		return sessionEffects{}, err
	}
	out, err := s.tryAdvance()
	return sessionEffects{envelopes: out}, err
}

func (*acceptCGGMPKeygenCommitmentsTx) cleanupOnReject() {}

func (*acceptCGGMPKeygenCommitmentsTx) markCommitted() {}

type acceptCGGMPKeygenShareTx struct {
	from      tss.PartyID
	share     *secret.Scalar
	committed bool
}

func (tx *acceptCGGMPKeygenShareTx) apply(s *KeygenSession) (sessionEffects, error) {
	if err := s.round1.recordShare(tx.from, tx.share); err != nil {
		return sessionEffects{}, err
	}
	out, err := s.tryAdvance()
	return sessionEffects{envelopes: out}, err
}

func (tx *acceptCGGMPKeygenShareTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.share == nil {
		return
	}
	tx.share.Destroy()
	tx.share = nil
}

func (tx *acceptCGGMPKeygenShareTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

type acceptCGGMPKeygenConfirmationTx struct {
	from         tss.PartyID
	confirmation *KeygenConfirmation
	committed    bool
}

func (tx *acceptCGGMPKeygenConfirmationTx) apply(s *KeygenSession) (sessionEffects, error) {
	if err := s.confirmations.record(tx.from, tx.confirmation); err != nil {
		return sessionEffects{}, err
	}
	out, err := s.tryAdvance()
	return sessionEffects{envelopes: out}, err
}

func (tx *acceptCGGMPKeygenConfirmationTx) cleanupOnReject() {
	if tx == nil || tx.committed || tx.confirmation == nil {
		return
	}
	clear(tx.confirmation.ChainCode)
	tx.confirmation = nil
}

func (tx *acceptCGGMPKeygenConfirmationTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}
