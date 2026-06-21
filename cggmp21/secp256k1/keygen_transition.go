package secp256k1

import (
	"bytes"

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
	pd, err := s.partyEntry(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	pd.commitments = tx.commitments
	pd.chainCodeCommit = tx.chainCodeCommit
	pd.paillierPub = tx.paillierPub
	pd.ringPedersen = tx.ringPedersen
	out, err := s.tryComplete()
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
	pd, err := s.partyEntry(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	pd.share = tx.share
	out, err := s.tryComplete()
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
	pd, err := s.partyEntry(tx.from)
	if err != nil {
		return sessionEffects{}, err
	}
	pd.chainCode = bytes.Clone(tx.confirmation.ChainCode)
	pd.confirmation = tx.confirmation
	if s.pending != nil && allConfirmationsReceived(s.partyData, s.cfg.Parties) {
		return sessionEffects{}, s.finalizeConfirmedKeyShare()
	}
	return sessionEffects{}, nil
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
