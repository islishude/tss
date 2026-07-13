package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const maxFigure9ProofBytes = 1 << 20

// presignRedAlertPair carries the two public MtA records used by Figure 9 for
// one peer and the setup-less proof for the accused party's outbound record.
// Inbound is peer -> accused; Outbound is accused -> peer.
type presignRedAlertPair struct {
	Peer     tss.PartyID         `wire:"1,u32"`
	Inbound  mta.ResponseMessage `wire:"2,nested,max_bytes=mta_response"`
	Outbound mta.ResponseMessage `wire:"3,nested,max_bytes=mta_response"`
	Proof    zkpai.AffGStarProof `wire:"4,nested,max_bytes=figure9_affg_star_proof"`
}

type presignRedAlertPayload struct {
	Kind        string                `wire:"1,string,max_bytes=red_alert_kind"`
	AlertDigest []byte                `wire:"2,bytes,len=32"`
	Pairs       []presignRedAlertPair `wire:"3,recordlist,max_items=figure9_pairs"`
	DecProof    zkpai.DecProof        `wire:"4,nested,max_bytes=figure9_dec_proof"`
	PlanHash    []byte                `wire:"5,bytes,len=32"`
	EpochID     []byte                `wire:"6,bytes,len=32"`
	PresignID   []byte                `wire:"7,bytes,len=32"`
}

// WireType returns the canonical wire type for a presign red-alert payload.
func (presignRedAlertPayload) WireType() string {
	return presignRedAlertPayloadWireType
}

// WireVersion returns the canonical wire version for a presign red-alert payload.
func (presignRedAlertPayload) WireVersion() uint16 {
	return presignRedAlertPayloadWireVersion
}

// Clone returns a defensive deep copy of the presign red-alert payload.
func (p presignRedAlertPayload) Clone() presignRedAlertPayload {
	clone := presignRedAlertPayload{
		Kind:        p.Kind,
		AlertDigest: bytes.Clone(p.AlertDigest),
		Pairs:       make([]presignRedAlertPair, len(p.Pairs)),
		PlanHash:    bytes.Clone(p.PlanHash),
		EpochID:     bytes.Clone(p.EpochID),
		PresignID:   bytes.Clone(p.PresignID),
	}
	if proof := p.DecProof.Clone(); proof != nil {
		clone.DecProof = *proof
	}
	for i := range p.Pairs {
		clone.Pairs[i] = presignRedAlertPair{
			Peer: p.Pairs[i].Peer, Inbound: p.Pairs[i].Inbound.Clone(), Outbound: p.Pairs[i].Outbound.Clone(),
		}
		if proof := p.Pairs[i].Proof.Clone(); proof != nil {
			clone.Pairs[i].Proof = *proof
		}
	}
	return clone
}

// Destroy clears the payload's owned buffers and proof state.
func (p *presignRedAlertPayload) Destroy() {
	if p == nil {
		return
	}
	clear(p.AlertDigest)
	clear(p.PlanHash)
	clear(p.EpochID)
	clear(p.PresignID)
	for i := range p.Pairs {
		p.Pairs[i].Inbound.Destroy()
		p.Pairs[i].Outbound.Destroy()
		p.Pairs[i].Proof.Destroy()
	}
	p.DecProof.Destroy()
	*p = presignRedAlertPayload{}
}

// Validate checks the payload's canonical shape and nested proof records.
func (p presignRedAlertPayload) Validate() error {
	if p.Kind != string(presignRedAlertNonce) && p.Kind != string(presignRedAlertChi) {
		return errors.New("invalid Figure 9 alert kind")
	}
	for name, value := range map[string][]byte{
		"alert digest": p.AlertDigest, "plan hash": p.PlanHash,
		"epoch id": p.EpochID, "presign id": p.PresignID,
	} {
		if len(value) != sha256.Size {
			return fmt.Errorf("figure 9 %s must be 32 bytes", name)
		}
	}
	if len(p.Pairs) == 0 || len(p.Pairs) >= maxCGGMPSigners {
		return errors.New("invalid Figure 9 peer proof count")
	}
	for i := range p.Pairs {
		pair := &p.Pairs[i]
		if pair.Peer == tss.BroadcastPartyId {
			return errors.New("figure 9 peer is zero")
		}
		if i > 0 && p.Pairs[i-1].Peer >= pair.Peer {
			return errors.New("figure 9 peers are not strictly sorted")
		}
		if err := pair.Inbound.Validate(); err != nil {
			return fmt.Errorf("figure 9 peer %d inbound response: %w", pair.Peer, err)
		}
		if err := pair.Outbound.Validate(); err != nil {
			return fmt.Errorf("figure 9 peer %d outbound response: %w", pair.Peer, err)
		}
		if err := pair.Proof.Validate(); err != nil {
			return fmt.Errorf("figure 9 peer %d affine proof: %w", pair.Peer, err)
		}
	}
	if !slices.IsSortedFunc(p.Pairs, func(a, b presignRedAlertPair) int {
		if a.Peer < b.Peer {
			return -1
		}
		if a.Peer > b.Peer {
			return 1
		}
		return 0
	}) {
		return errors.New("figure 9 peers are not canonical")
	}
	return p.DecProof.Validate()
}

func figure9PayloadFieldLimits(limits Limits) wire.FieldLimits {
	fields := limits.fieldLimits()
	fields["red_alert_kind"] = 16
	fields["figure9_pairs"] = limits.Threshold.MaxSigners - 1
	fields["figure9_affg_star_proof"] = maxFigure9ProofBytes
	fields["figure9_dec_proof"] = maxFigure9ProofBytes
	return fields
}

// MarshalBinary returns the canonical bounded wire encoding of the payload.
func (p presignRedAlertPayload) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := wire.Marshal(p, wire.WithFieldLimitsForMarshal(figure9PayloadFieldLimits(DefaultLimits())))
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxFigure9PayloadBytes {
		return nil, fmt.Errorf("figure 9 payload too large: %d > %d", len(encoded), maxFigure9PayloadBytes)
	}
	return encoded, nil
}

// UnmarshalBinary decodes a canonical payload using the default protocol limits.
func (p *presignRedAlertPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical payload under explicit protocol limits.
func (p *presignRedAlertPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if len(in) == 0 || len(in) > maxFigure9PayloadBytes {
		return fmt.Errorf("invalid Figure 9 payload size: %d", len(in))
	}
	var decoded presignRedAlertPayload
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(wire.FrameLimits{
			MaxTotalBytes: maxFigure9PayloadBytes,
			MaxFields:     limits.TLV.MaxFields,
			MaxFieldBytes: maxFigure9PayloadBytes,
		}),
		wire.WithFieldLimits(figure9PayloadFieldLimits(limits)),
	); err != nil {
		return err
	}
	if err := decoded.Validate(); err != nil {
		decoded.Destroy()
		return err
	}
	p.Destroy()
	*p = decoded
	return nil
}
