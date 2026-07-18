package secp256k1

import (
	"bytes"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/clone"
)

func (s *ReshareSession) cloneForInboundTransition() *ReshareSession {
	if s == nil {
		return nil
	}
	out := &ReshareSession{
		plan:                      cloneResharePlan(s.plan),
		oldKey:                    cloneKeyShareValue(s.oldKey),
		oldPublicKey:              bytes.Clone(s.oldPublicKey),
		oldChainCode:              bytes.Clone(s.oldChainCode),
		oldParties:                s.oldParties.Clone(),
		dealerParties:             s.dealerParties.Clone(),
		newParties:                s.newParties.Clone(),
		newThreshold:              s.newThreshold,
		selfID:                    s.selfID,
		isDealer:                  s.isDealer,
		isReceiver:                s.isReceiver,
		cfg:                       s.cfg,
		log:                       s.log,
		limits:                    s.limits,
		securityParams:            s.securityParams,
		planHash:                  bytes.Clone(s.planHash),
		provisionalIDs:            clonePublicByteMap(s.provisionalIDs),
		dealerData:                make(map[tss.PartyID]*reshareDealerPartyData, len(s.dealerData)),
		newPartyData:              make(map[tss.PartyID]*reshareNewPartyData, len(s.newPartyData)),
		completed:                 s.completed,
		aborted:                   s.aborted,
		newShare:                  cloneKeyShareValue(s.newShare),
		newPaillier:               s.newPaillier.Clone(),
		dealerSent:                s.dealerSent,
		factorProofsSent:          s.factorProofsSent,
		guard:                     s.guard,
		accepted:                  make(map[paperKeygenMessageKey]struct{}, len(s.accepted)),
		lifecycleStore:            s.lifecycleStore,
		lifecycleLease:            s.lifecycleLease,
		lifecycleSource:           s.lifecycleSource,
		lifecycleTargetGeneration: s.lifecycleTargetGeneration,
		lifecycleTimeout:          s.lifecycleTimeout,
		lifecycleFinished:         s.lifecycleFinished,
		lifecycleOutbox:           cloneLifecycleEnvelopes(s.lifecycleOutbox),
	}
	if s.lifecycleRetirement != nil {
		target := *s.lifecycleRetirement
		out.lifecycleRetirement = &target
	}
	for key := range s.accepted {
		out.accepted[key] = struct{}{}
	}
	for id, source := range s.dealerData {
		if source == nil {
			continue
		}
		out.dealerData[id] = &reshareDealerPartyData{
			commitments: clone.ByteSlices(source.commitments),
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
	s.provisionalIDs = staged.provisionalIDs
	s.dealerData = staged.dealerData
	s.newPartyData = staged.newPartyData
	s.completed = staged.completed
	s.aborted = staged.aborted
	s.newShare = staged.newShare
	s.newPaillier = staged.newPaillier
	s.dealerSent = staged.dealerSent
	s.factorProofsSent = staged.factorProofsSent
	s.guard = staged.guard
	s.auxInfo = staged.auxInfo
	s.figure7Failure = staged.figure7Failure
	s.accepted = staged.accepted
	s.lifecycleStore = staged.lifecycleStore
	s.lifecycleLease = staged.lifecycleLease
	s.lifecycleSource = staged.lifecycleSource
	s.lifecycleTargetGeneration = staged.lifecycleTargetGeneration
	s.lifecycleTimeout = staged.lifecycleTimeout
	s.lifecycleFinished = staged.lifecycleFinished
	s.lifecycleFinal = staged.lifecycleFinal
	s.lifecycleRetirement = staged.lifecycleRetirement
	s.lifecycleOutbox = staged.lifecycleOutbox
}
