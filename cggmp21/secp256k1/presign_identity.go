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
	presignContentIDLabel           = "cggmp21-secp256k1-presign-content-v1"
	presignContentIDPayloadWireType = "cggmp21.secp256k1.presign-content-id"
	presignContentIDPayloadVersion  = uint16(1)
)

type presignContentIDPayload struct {
	ArtifactVersion           uint16                            `wire:"1,u16"`
	SecurityParams            SecurityParams                    `wire:"2,record"`
	Party                     tss.PartyID                       `wire:"3,u32"`
	Threshold                 int                               `wire:"4,u32"`
	Signers                   tss.PartySet                      `wire:"5,u32list,max_items=signers"`
	R                         *secp.Point                       `wire:"6,custom,len=33"`
	LittleR                   secp.Scalar                       `wire:"7,custom,len=32"`
	TranscriptHash            []byte                            `wire:"8,bytes,len=32"`
	Context                   tss.SigningContext                `wire:"9,nested"`
	ContextHash               []byte                            `wire:"10,bytes,len=32"`
	Derivation                *tss.DerivationResult             `wire:"11,record"`
	PlanHash                  []byte                            `wire:"12,bytes,len=32"`
	PublicKey                 *secp.Point                       `wire:"13,custom,len=33"`
	KeygenTranscriptHash      []byte                            `wire:"14,bytes,len=32"`
	PartiesHash               []byte                            `wire:"15,bytes,len=32"`
	VerifyShares              []signVerifyShare                 `wire:"16,recordlist,max_items=signers"`
	Verification              presignVerificationContext        `wire:"17,record"`
	KShare                    *secret.Scalar                    `wire:"18,custom,len=32"`
	ChiShare                  *secret.Scalar                    `wire:"19,custom,len=32"`
	DeltaAggregate            *secret.Scalar                    `wire:"20,custom,len=32"`
	IdentificationTranscripts []presignIdentificationTranscript `wire:"21,recordlist,max_items=signers"`
	SigmaOpeningRecords       []presignSigmaOpeningRecord       `wire:"22,recordlist,max_items=signers"`
}

// WireType returns the private canonical content-ID payload type.
func (presignContentIDPayload) WireType() string {
	return presignContentIDPayloadWireType
}

// WireVersion returns the private canonical content-ID payload version.
func (presignContentIDPayload) WireVersion() uint16 {
	return presignContentIDPayloadVersion
}

// contentID returns a secret-derived content commitment for the exact presign
// nonce material and persisted protocol bindings. The result is secret-tainted:
// it must not be logged, exposed, used as a filename, or stored as plaintext
// metadata. SignAttemptStore implementations must derive an opaque store key
// before using it as a durable storage key.
func (p *Presign) contentID() ([]byte, error) {
	return p.contentIDWithLimits(DefaultLimits())
}

func (p *Presign) contentIDWithLimits(limits Limits) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil presign")
	}
	payload := presignContentIDPayload{
		ArtifactVersion:           presignWireVersion,
		SecurityParams:            p.state.SecurityParams,
		Party:                     p.state.Party,
		Threshold:                 p.state.Threshold,
		Signers:                   p.state.Signers,
		R:                         p.state.R,
		LittleR:                   p.state.LittleR,
		TranscriptHash:            p.state.TranscriptHash,
		Context:                   p.state.Context,
		ContextHash:               p.state.ContextHash,
		Derivation:                p.state.Derivation,
		PlanHash:                  p.state.PlanHash,
		PublicKey:                 p.state.PublicKey,
		KeygenTranscriptHash:      p.state.KeygenTranscriptHash,
		PartiesHash:               p.state.PartiesHash,
		VerifyShares:              p.state.VerifyShares,
		Verification:              p.state.Verification,
		KShare:                    p.state.KShare,
		ChiShare:                  p.state.ChiShare,
		DeltaAggregate:            p.state.DeltaAggregate,
		IdentificationTranscripts: p.state.IdentificationTranscripts,
		SigmaOpeningRecords:       p.state.SigmaOpeningRecords,
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
