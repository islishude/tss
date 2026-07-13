package secp256k1

import (
	"errors"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	presignContentIDLabel           = "cggmp21-secp256k1-presign-content"
	presignContentIDPayloadWireType = "cggmp21.secp256k1.presign-content-id"
	presignContentIDPayloadVersion  = uint16(1)
)

// presignContentIDPayload is the canonical identity of the exact normalized
// Figure 8 artifact. It deliberately excludes mutable lifecycle state.
type presignContentIDPayload struct {
	ArtifactVersion      uint16                        `wire:"1,u16"`
	SecurityParams       SecurityParams                `wire:"2,record"`
	Party                tss.PartyID                   `wire:"3,u32"`
	Threshold            int                           `wire:"4,u32"`
	Signers              tss.PartySet                  `wire:"5,u32list,max_items=signers"`
	PresignID            []byte                        `wire:"6,bytes,len=32"`
	EpochID              []byte                        `wire:"7,bytes,len=32"`
	Gamma                *secp.Point                   `wire:"8,custom,len=33"`
	LittleR              secp.Scalar                   `wire:"9,custom,len=32"`
	KShare               *secret.Scalar                `wire:"10,custom,len=32"`
	ChiShare             *secret.Scalar                `wire:"11,custom,len=32"`
	Commitments          []normalizedPresignCommitment `wire:"12,recordlist,max_items=signers"`
	TranscriptHash       []byte                        `wire:"13,bytes,len=32"`
	Context              tss.SigningContext            `wire:"14,nested"`
	ContextHash          []byte                        `wire:"15,bytes,len=32"`
	PublicKey            *secp.Point                   `wire:"16,custom,len=33"`
	KeygenTranscriptHash []byte                        `wire:"17,bytes,len=32"`
	PartiesHash          []byte                        `wire:"18,bytes,len=32"`
	PlanHash             []byte                        `wire:"19,bytes,len=32"`
	Derivation           *tss.DerivationResult         `wire:"20,record"`
	Epoch                *EpochContext                 `wire:"21,record"`
}

// WireType returns the canonical wire type for a presign content-identity payload.
func (presignContentIDPayload) WireType() string { return presignContentIDPayloadWireType }

// WireVersion returns the canonical wire version for a presign content-identity payload.
func (presignContentIDPayload) WireVersion() uint16 { return presignContentIDPayloadVersion }

// contentID returns a secret-derived content commitment for the exact
// normalized presign. It is secret-tainted and must never be logged or used as
// plaintext storage metadata.
func (p *Presign) contentID() ([]byte, error) { return p.contentIDWithLimits(DefaultLimits()) }

func (p *Presign) contentIDWithLimits(limits Limits) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil presign")
	}
	payload := presignContentIDPayload{
		ArtifactVersion:      presignWireVersion,
		SecurityParams:       p.state.SecurityParams,
		Party:                p.state.Party,
		Threshold:            p.state.Threshold,
		Signers:              p.state.Signers,
		PresignID:            p.state.PresignID,
		EpochID:              p.state.EpochID,
		Gamma:                p.state.Gamma,
		LittleR:              p.state.LittleR,
		KShare:               p.state.KShare,
		ChiShare:             p.state.ChiShare,
		Commitments:          p.state.Commitments,
		TranscriptHash:       p.state.TranscriptHash,
		Context:              p.state.Context,
		ContextHash:          p.state.ContextHash,
		PublicKey:            p.state.PublicKey,
		KeygenTranscriptHash: p.state.KeygenTranscriptHash,
		PartiesHash:          p.state.PartiesHash,
		PlanHash:             p.state.PlanHash,
		Derivation:           p.state.Derivation,
		Epoch:                p.state.Epoch,
	}
	raw, err := wire.Marshal(payload, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	t := transcript.New(presignContentIDLabel)
	t.AppendBytes("canonical_presign", raw)
	return t.Sum(), nil
}
