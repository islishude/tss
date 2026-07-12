package ed25519

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
)

func (s *KeygenSession) completeConfirmationRound(snap *frostKeygenConfirmationSnapshot) error {
	prepared, err := s.buildFinalKeyShare(snap)
	if err != nil {
		return err
	}
	defer prepared.destroy()
	s.commitFinalKeyShare(prepared)
	return nil
}

type preparedFinalKeyShare struct {
	share               *KeyShare
	confirmationSetHash []byte
	committed           bool
}

func (p *preparedFinalKeyShare) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.share != nil {
		p.share.Destroy()
		p.share = nil
	}
	clear(p.confirmationSetHash)
}

func (s *KeygenSession) buildFinalKeyShare(snap *frostKeygenConfirmationSnapshot) (*preparedFinalKeyShare, error) {
	if s.pending == nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, errors.New("missing pending key share"))
	}
	if err := verifyKeygenConfirmationSetForPending(s.pending, snap.confirmations); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	for _, id := range s.cfg.Parties {
		slot, err := s.round1.slot(id)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, err)
		}
		if err := verifyFROSTKeygenCommitRevealChainCode(s.cfg.SessionID, id, snap.chainCodes[id], slot.chainCodeCommit); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, err)
		}
	}
	chainCode, err := bip32util.AggregateChainCode(s.cfg.Parties, snap.chainCodes)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(s.pending.partyData))
	for id, data := range s.pending.partyData {
		partyData[id] = data.Clone()
	}
	final := &KeyShare{state: &keyShareState{
		Party:                s.pending.party,
		Threshold:            s.pending.threshold,
		Parties:              s.pending.parties.Clone(),
		PublicKey:            s.pending.publicKey.Clone(),
		ChainCode:            bytes.Clone(chainCode),
		Secret:               s.pending.secret.Clone(),
		GroupCommitments:     s.pending.groupCommitments.Clone(),
		PartyData:            partyData,
		KeygenSessionID:      s.pending.keygenSessionID,
		KeygenTranscriptHash: bytes.Clone(s.pending.keygenTranscriptHash),
		PlanHash:             bytes.Clone(s.pending.planHash),
		ConfirmationMode:     keyShareConfirmationModeKeygenContributions,
	}}
	if err := applyKeygenConfirmationSet(final, snap.confirmations); err != nil {
		final.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	if err := final.ValidateConsistency(); err != nil {
		final.Destroy()
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.cfg.Self, err)
	}
	return &preparedFinalKeyShare{
		share:               final,
		confirmationSetHash: keygenConfirmationSetHash(snap.confirmations),
	}, nil
}

func (s *KeygenSession) commitFinalKeyShare(p *preparedFinalKeyShare) {
	if p == nil {
		return
	}
	s.pending.Destroy()
	s.pending = nil
	s.confirmations.ClearReveals()
	s.keyShare = p.share
	s.completed = true
	s.state = keygenConfirmed
	s.cfg.Logger().Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", p.confirmationSetHash[:8]),
	)
	p.committed = true
}
