package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
)

func (s *KeygenSession) completeConfirmationRound(snap *keygenConfirmationSnapshot) error {
	prepared, err := s.buildFinalKeyShare(snap)
	if err != nil {
		return err
	}
	defer prepared.destroy()
	s.commitCGGMPFinalKeyShare(prepared)
	return nil
}

type preparedCGGMPFinalKeyShare struct {
	share               *KeyShare
	confirmationSetHash []byte
	committed           bool
}

func (p *preparedCGGMPFinalKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
		p.share = nil
	}
	clear(p.confirmationSetHash)
}

func (s *KeygenSession) maybePrepareCGGMPFinalKeyShare() (*preparedCGGMPFinalKeyShare, bool, error) {
	snap, ok, err := s.confirmations.snapshot()
	if err != nil || !ok {
		return nil, ok, err
	}
	defer snap.Destroy()
	prepared, err := s.buildFinalKeyShare(snap)
	if err != nil {
		return nil, false, err
	}
	return prepared, true, nil
}

func (s *KeygenSession) buildFinalKeyShare(snap *keygenConfirmationSnapshot) (*preparedCGGMPFinalKeyShare, error) {
	if s.pending == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("missing pending key share"))
	}
	if snap == nil {
		return nil, errors.New("nil keygen confirmation snapshot")
	}
	if err := verifyKeygenConfirmationSetBinding(s.pending, snap.confirmations); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	for _, id := range s.cfg.Parties {
		slot, err := s.round1.slot(id)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, keygenConfirmationRound, id, err)
		}
		if err := verifyConfirmationCommitRevealChainCode(
			s.cfg.SessionID,
			id,
			snap.chainCodes[id],
			slot.chainCodeCommit,
		); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, err)
		}
	}
	chainCode, err := bip32util.AggregateChainCode(s.cfg.Parties, snap.chainCodes)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	if s.importPlan != nil && !bytes.Equal(chainCode, s.importPlan.state.ChainCode) {
		clear(chainCode)
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("trusted-dealer import chain code mismatch"))
	}
	finalShare := cloneKeyShareValue(s.pending)
	finalShare.state.ChainCode = chainCode
	round1Snap, ok, err := s.round1.snapshot()
	if err != nil {
		finalShare.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, keygenConfirmationRound, s.cfg.Self, err)
	}
	if !ok {
		finalShare.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, keygenConfirmationRound, s.cfg.Self, errors.New("incomplete round1 state during finalization"))
	}
	defer round1Snap.Destroy()
	finalTranscriptHash, err := s.keygenTranscriptHash(round1Snap, finalShare.state.GroupCommitments)
	if err != nil {
		finalShare.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, keygenConfirmationRound, s.cfg.Self, err)
	}
	finalShare.state.KeygenTranscriptHash = finalTranscriptHash
	if err := attachKeygenConfirmations(finalShare, snap.confirmations); err != nil {
		finalShare.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, keygenConfirmationRound, s.cfg.Self, err)
	}
	if err := finalShare.ValidateWithLimits(s.limits); err != nil {
		finalShare.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	return &preparedCGGMPFinalKeyShare{
		share:               finalShare,
		confirmationSetHash: keygenConfirmationSetHash(snap.confirmations),
	}, nil
}

func (s *KeygenSession) commitCGGMPFinalKeyShare(p *preparedCGGMPFinalKeyShare) {
	if p == nil {
		return
	}
	s.pending.Destroy()
	s.pending = nil
	if s.round1 != nil {
		s.round1.Destroy()
	}
	if s.confirmations != nil {
		s.confirmations.Destroy()
	}
	s.keyShare = p.share
	s.completed = true
	s.state = keygenConfirmed
	pubKeyHash := sha256.Sum256(p.share.state.PublicKey)
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", pubKeyHash[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", p.confirmationSetHash[:8]),
	)
	p.committed = true
}
