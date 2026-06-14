package secp256k1

import (
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const resharePlanWireType = "cggmp21.secp256k1.reshare-plan"

// resharePlanWire is the private wire DTO for ResharePlan.
type resharePlanWire struct {
	SessionID             []byte                         `wire:"1,bytes,len=32"`
	CurveID               string                         `wire:"2,string,max_bytes=curve_id"`
	OldGroupPublicKey     []byte                         `wire:"3,bytes,max_bytes=point"`
	OldGroupCommitments   [][]byte                       `wire:"4,byteslist,max_bytes=point,max_items=threshold"`
	OldVerificationShares []wire.PartyBytes[tss.PartyID] `wire:"5,partybytes,max_bytes=point,max_items=parties"`
	OldParties            []tss.PartyID                  `wire:"6,u32list,max_items=parties"`
	OldThreshold          int                            `wire:"7,u32"`
	DealerParties         []tss.PartyID                  `wire:"8,u32list,max_items=parties"`
	NewParties            []tss.PartyID                  `wire:"9,u32list,max_items=parties"`
	NewThreshold          int                            `wire:"10,u32"`
	ChainCode             []byte                         `wire:"11,bytes,max_bytes=scalar"`
	PaillierBits          int                            `wire:"12,u32"`
}

// WireType returns the canonical wire type identifier for resharePlanWire.
func (resharePlanWire) WireType() string { return resharePlanWireType }

// WireVersion returns the wire format version for resharePlanWire.
func (resharePlanWire) WireVersion() uint16 { return tss.Version }

// MarshalBinary returns the canonical wire encoding of p.
func (p *ResharePlan) MarshalBinary() ([]byte, error) {
	limits := DefaultLimits()
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	verificationShares := make([]wire.PartyBytes[tss.PartyID], len(p.state.oldParties))
	for i, party := range p.state.oldParties {
		verificationShares[i] = wire.PartyBytes[tss.PartyID]{
			Party: party,
			Bytes: p.state.oldVerificationShares[party],
		}
	}
	raw, err := wire.Marshal(&resharePlanWire{
		SessionID:             p.state.sessionID[:],
		CurveID:               p.state.curveID,
		OldGroupPublicKey:     p.state.oldGroupPublicKey,
		OldGroupCommitments:   p.state.oldGroupCommitments,
		OldVerificationShares: verificationShares,
		OldParties:            p.state.oldParties,
		OldThreshold:          p.state.oldThreshold,
		DealerParties:         p.state.dealerParties,
		NewParties:            p.state.newParties,
		NewThreshold:          p.state.newThreshold,
		ChainCode:             p.state.chainCode,
		PaillierBits:          p.state.paillierBits,
	}, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	if len(raw) > limits.State.MaxSerializedResharePlanBytes {
		return nil, fmt.Errorf("reshare plan too large: %d > %d", len(raw), limits.State.MaxSerializedResharePlanBytes)
	}
	return raw, nil
}

// UnmarshalResharePlan decodes and validates a canonical reshare plan.
func UnmarshalResharePlan(in []byte) (*ResharePlan, error) {
	return unmarshalResharePlanWithLimits(in, DefaultLimits())
}

func unmarshalResharePlanWithLimits(in []byte, limits Limits) (*ResharePlan, error) {
	var w resharePlanWire
	if err := wire.Unmarshal(in, &w,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedResharePlanBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return nil, err
	}
	if w.OldThreshold > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("old threshold too large: %d > %d", w.OldThreshold, limits.Threshold.MaxThreshold)
	}
	if w.NewThreshold > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("new threshold too large: %d > %d", w.NewThreshold, limits.Threshold.MaxThreshold)
	}
	if w.PaillierBits > limits.Paillier.MaxModulusBits {
		return nil, fmt.Errorf("paillier key size %d exceeds max %d", w.PaillierBits, limits.Paillier.MaxModulusBits)
	}
	if len(w.OldVerificationShares) != len(w.OldParties) {
		return nil, fmt.Errorf("old verification share count must equal old party count")
	}
	verificationShares := make(map[tss.PartyID][]byte, len(w.OldVerificationShares))
	for i, share := range w.OldVerificationShares {
		if share.Party != w.OldParties[i] {
			return nil, fmt.Errorf("old verification share %d is for party %d, want party %d", i, share.Party, w.OldParties[i])
		}
		if _, exists := verificationShares[share.Party]; exists {
			return nil, fmt.Errorf("duplicate old verification share for party %d", share.Party)
		}
		verificationShares[share.Party] = share.Bytes
	}
	sessionID, err := tss.SessionIDFromBytes(w.SessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid reshare session id: %w", err)
	}
	plan := &ResharePlan{state: &resharePlanState{
		sessionID:             sessionID,
		curveID:               w.CurveID,
		oldGroupPublicKey:     w.OldGroupPublicKey,
		oldGroupCommitments:   w.OldGroupCommitments,
		oldVerificationShares: verificationShares,
		oldParties:            w.OldParties,
		oldThreshold:          w.OldThreshold,
		dealerParties:         w.DealerParties,
		newParties:            w.NewParties,
		newThreshold:          w.NewThreshold,
		chainCode:             w.ChainCode,
		paillierBits:          w.PaillierBits,
	}}
	if err := plan.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return plan, nil
}
