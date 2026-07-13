package secp256k1

import (
	"bytes"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/shamir"
)

// cloneForInboundTransition creates an independently owned keygen state on
// which all cryptographic work and outbound construction can run before the
// live guard replay slot and session state are committed.
func (s *KeygenSession) cloneForInboundTransition() *KeygenSession {
	if s == nil {
		return nil
	}
	out := &KeygenSession{
		cfg:                  s.cfg,
		limits:               s.limits,
		securityParams:       s.securityParams,
		planHash:             bytes.Clone(s.planHash),
		importPlan:           cloneCGGMPTrustedDealerPlan(s.importPlan),
		pendingConfirmations: make(map[tss.PartyID]*KeygenConfirmation, len(s.pendingConfirmations)),
		sharesSent:           s.sharesSent,
		completed:            s.completed,
		aborted:              s.aborted,
		state:                s.state,
		pending:              cloneKeyShareValue(s.pending),
		keyShare:             cloneKeyShareValue(s.keyShare),
		guard:                s.guard,
	}
	if s.local != nil {
		out.local = &keygenLocalMaterial{
			commitments:     tss.CloneByteSlices(s.local.commitments),
			localShare:      s.local.localShare.Clone(),
			chainCode:       bytes.Clone(s.local.chainCode),
			chainCodeCommit: bytes.Clone(s.local.chainCodeCommit),
			paillier:        s.local.paillier.Clone(),
			paillierPub: paillierPublicMaterial{
				Party:     s.local.paillierPub.Party,
				PublicKey: s.local.paillierPub.PublicKey.Clone(),
				Proof:     s.local.paillierPub.Proof.Clone(),
			},
			ringPedersen: ringPedersenPublicMaterial{
				Party:  s.local.ringPedersen.Party,
				Params: s.local.ringPedersen.Params.Clone(),
				Proof:  s.local.ringPedersen.Proof.Clone(),
			},
			polynomial: append(shamir.Polynomial(nil), s.local.polynomial...),
		}
	}
	out.round1 = newKeygenRound1Inbox(s.round1.parties)
	for id, source := range s.round1.slots {
		if source == nil {
			out.round1.slots[id] = nil
			continue
		}
		out.round1.slots[id] = &keygenRound1Slot{
			commitments:     tss.CloneByteSlices(source.commitments),
			share:           source.share.Clone(),
			chainCodeCommit: bytes.Clone(source.chainCodeCommit),
			paillierPub: paillierPublicMaterial{
				Party:     source.paillierPub.Party,
				PublicKey: source.paillierPub.PublicKey.Clone(),
				Proof:     source.paillierPub.Proof.Clone(),
			},
			ringPedersen: ringPedersenPublicMaterial{
				Party:  source.ringPedersen.Party,
				Params: source.ringPedersen.Params.Clone(),
				Proof:  source.ringPedersen.Proof.Clone(),
			},
			factorProof: source.factorProof.Clone(),
		}
	}
	out.confirmations = newKeygenConfirmationInbox(s.confirmations.parties)
	for id, confirmation := range s.confirmations.slots {
		out.confirmations.slots[id] = confirmation.Clone()
	}
	for id, reveal := range s.confirmations.reveals {
		out.confirmations.reveals[id] = bytes.Clone(reveal)
	}
	for id, confirmation := range s.pendingConfirmations {
		out.pendingConfirmations[id] = confirmation.Clone()
	}
	return out
}

func (s *KeygenSession) commitInboundTransition(staged *KeygenSession) {
	s.abort()
	s.cfg = staged.cfg
	s.limits = staged.limits
	s.securityParams = staged.securityParams
	s.planHash = staged.planHash
	s.importPlan = staged.importPlan
	s.local = staged.local
	s.round1 = staged.round1
	s.confirmations = staged.confirmations
	s.pendingConfirmations = staged.pendingConfirmations
	s.sharesSent = staged.sharesSent
	s.completed = staged.completed
	s.aborted = staged.aborted
	s.state = staged.state
	s.pending = staged.pending
	s.keyShare = staged.keyShare
	s.guard = staged.guard
}

func (s *RefreshSession) cloneForInboundTransition() *RefreshSession {
	if s == nil {
		return nil
	}
	out := &RefreshSession{
		oldKey:          s.oldKey,
		cfg:             s.cfg,
		log:             s.log,
		limits:          s.limits,
		securityParams:  s.securityParams,
		planHash:        bytes.Clone(s.planHash),
		partyData:       make(map[tss.PartyID]*refreshPartyData, len(s.partyData)),
		completed:       s.completed,
		aborted:         s.aborted,
		guard:           s.guard,
		newShare:        cloneKeyShareValue(s.newShare),
		newPaillier:     s.newPaillier.Clone(),
		localPolynomial: append(shamir.Polynomial(nil), s.localPolynomial...),
		sharesSent:      s.sharesSent,
	}
	for id, source := range s.partyData {
		if source == nil {
			continue
		}
		out.partyData[id] = &refreshPartyData{
			commitments: tss.CloneByteSlices(source.commitments),
			share:       source.share.Clone(),
			paillierPub: paillierPublicMaterial{
				Party:     source.paillierPub.Party,
				PublicKey: source.paillierPub.PublicKey.Clone(),
				Proof:     source.paillierPub.Proof.Clone(),
			},
			ringPedersen: ringPedersenPublicMaterial{
				Party:  source.ringPedersen.Party,
				Params: source.ringPedersen.Params.Clone(),
				Proof:  source.ringPedersen.Proof.Clone(),
			},
			factorProof:  source.factorProof.Clone(),
			confirmation: source.confirmation.Clone(),
		}
	}
	return out
}

func (s *RefreshSession) commitInboundTransition(staged *RefreshSession) {
	s.abort()
	s.oldKey = staged.oldKey
	s.cfg = staged.cfg
	s.log = staged.log
	s.limits = staged.limits
	s.securityParams = staged.securityParams
	s.planHash = staged.planHash
	s.partyData = staged.partyData
	s.completed = staged.completed
	s.aborted = staged.aborted
	s.guard = staged.guard
	s.newShare = staged.newShare
	s.newPaillier = staged.newPaillier
	s.localPolynomial = staged.localPolynomial
	s.sharesSent = staged.sharesSent
}

func (s *ReshareSession) cloneForInboundTransition() *ReshareSession {
	if s == nil {
		return nil
	}
	out := &ReshareSession{
		plan:             cloneResharePlan(s.plan),
		oldKey:           s.oldKey,
		oldPublicKey:     bytes.Clone(s.oldPublicKey),
		oldChainCode:     bytes.Clone(s.oldChainCode),
		oldParties:       s.oldParties.Clone(),
		dealerParties:    s.dealerParties.Clone(),
		newParties:       s.newParties.Clone(),
		newThreshold:     s.newThreshold,
		selfID:           s.selfID,
		isDealer:         s.isDealer,
		isReceiver:       s.isReceiver,
		cfg:              s.cfg,
		log:              s.log,
		limits:           s.limits,
		securityParams:   s.securityParams,
		planHash:         bytes.Clone(s.planHash),
		dealerData:       make(map[tss.PartyID]*reshareDealerPartyData, len(s.dealerData)),
		newPartyData:     make(map[tss.PartyID]*reshareNewPartyData, len(s.newPartyData)),
		completed:        s.completed,
		aborted:          s.aborted,
		newShare:         cloneKeyShareValue(s.newShare),
		newPaillier:      s.newPaillier.Clone(),
		dealerSent:       s.dealerSent,
		factorProofsSent: s.factorProofsSent,
		guard:            s.guard,
	}
	for id, source := range s.dealerData {
		if source == nil {
			continue
		}
		out.dealerData[id] = &reshareDealerPartyData{
			commitments: tss.CloneByteSlices(source.commitments),
			share:       source.share.Clone(),
		}
	}
	for id, source := range s.newPartyData {
		if source == nil {
			continue
		}
		out.newPartyData[id] = &reshareNewPartyData{
			paillierPub: paillierPublicMaterial{
				Party:     source.paillierPub.Party,
				PublicKey: source.paillierPub.PublicKey.Clone(),
				Proof:     source.paillierPub.Proof.Clone(),
			},
			ringPedersen: ringPedersenPublicMaterial{
				Party:  source.ringPedersen.Party,
				Params: source.ringPedersen.Params.Clone(),
				Proof:  source.ringPedersen.Proof.Clone(),
			},
			factorProof:  source.factorProof.Clone(),
			factorKey:    source.factorKey.Clone(),
			confirmation: source.confirmation.Clone(),
		}
	}
	return out
}

func (s *ReshareSession) commitInboundTransition(staged *ReshareSession) {
	s.abort()
	s.plan = staged.plan
	s.oldKey = staged.oldKey
	s.oldPublicKey = staged.oldPublicKey
	s.oldChainCode = staged.oldChainCode
	s.oldParties = staged.oldParties
	s.dealerParties = staged.dealerParties
	s.newParties = staged.newParties
	s.newThreshold = staged.newThreshold
	s.selfID = staged.selfID
	s.isDealer = staged.isDealer
	s.isReceiver = staged.isReceiver
	s.cfg = staged.cfg
	s.log = staged.log
	s.limits = staged.limits
	s.securityParams = staged.securityParams
	s.planHash = staged.planHash
	s.dealerData = staged.dealerData
	s.newPartyData = staged.newPartyData
	s.completed = staged.completed
	s.aborted = staged.aborted
	s.newShare = staged.newShare
	s.newPaillier = staged.newPaillier
	s.dealerSent = staged.dealerSent
	s.factorProofsSent = staged.factorProofsSent
	s.guard = staged.guard
}
