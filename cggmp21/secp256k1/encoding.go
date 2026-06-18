package secp256k1

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/islishude/tss"

	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType = "cggmp21.secp256k1.keyshare"
	presignWireType  = "cggmp21.secp256k1.presign"
)

// keyShareWire is the wire DTO for KeyShare.
type keyShareWire struct {
	Party                  tss.PartyID               `wire:"1,u32"`
	Threshold              int                       `wire:"2,u32"`
	Parties                tss.PartySet              `wire:"3,u32list"`
	PublicKey              []byte                    `wire:"4,bytes,max_bytes=point"`
	ChainCode              []byte                    `wire:"5,bytes"`
	Secret                 *secret.Scalar            `wire:"6,custom,len=32"`
	GroupCommitments       [][]byte                  `wire:"7,byteslist,max_bytes=point,max_items=threshold"`
	VerificationShares     []VerificationShare       `wire:"8,recordlist,max_items=parties"`
	PaillierPublicKey      []byte                    `wire:"9,bytes,max_bytes=paillier_public_key"`
	PaillierPrivateKey     []byte                    `wire:"10,bytes,max_bytes=paillier_private_key"`
	PaillierProof          []byte                    `wire:"11,bytes,max_bytes=zk_proof"`
	RingPedersenParams     []byte                    `wire:"12,bytes,max_bytes=ring_pedersen_params"`
	RingPedersenProof      []byte                    `wire:"13,bytes,max_bytes=paillier_proof"`
	RingPedersenPublic     []RingPedersenPublicShare `wire:"14,recordlist,max_items=parties"`
	PaillierPublicKeys     []PaillierPublicShare     `wire:"15,recordlist,max_items=parties"`
	ShareProof             []byte                    `wire:"16,bytes,max_bytes=zk_proof"`
	KeygenTranscriptHash   []byte                    `wire:"17,bytes"`
	PaillierProofSessionID []byte                    `wire:"18,bytes,len=32"`
	PaillierProofDomain    string                    `wire:"19,string"`
	LogCiphertext          []byte                    `wire:"20,bytes,max_bytes=paillier_ciphertext"`
	LogProof               []byte                    `wire:"21,bytes,max_bytes=zk_proof"`
	KeygenConfirmations    []*KeygenConfirmation     `wire:"22,recordlist,max_items=parties"`
	ResharePlanHash        []byte                    `wire:"23,bytes"`
	PlanHash               []byte                    `wire:"24,bytes,len=32"`
	SecurityParams         SecurityParams            `wire:"25,record"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return tss.Version }

func encodeKeyShareWire(k *KeyShare) (*keyShareWire, error) {
	return &keyShareWire{
		Party:                  k.state.party,
		Threshold:              k.state.threshold,
		Parties:                k.state.parties,
		PublicKey:              k.state.publicKey,
		ChainCode:              k.state.chainCode,
		Secret:                 k.state.secret,
		GroupCommitments:       k.state.groupCommitments,
		VerificationShares:     k.state.verificationShares,
		PaillierPublicKey:      k.state.paillierPublicKey,
		PaillierPrivateKey:     k.state.paillierPrivateKey,
		PaillierProof:          k.state.paillierProof,
		RingPedersenParams:     k.state.ringPedersenParams,
		RingPedersenProof:      k.state.ringPedersenProof,
		RingPedersenPublic:     k.state.ringPedersenPublic,
		PaillierPublicKeys:     k.state.paillierPublicKeys,
		ShareProof:             k.state.shareProof,
		KeygenTranscriptHash:   k.state.keygenTranscriptHash,
		PaillierProofSessionID: k.state.paillierProofSessionID[:],
		PaillierProofDomain:    k.state.paillierProofDomain,
		LogCiphertext:          k.state.logCiphertext,
		LogProof:               k.state.logProof,
		KeygenConfirmations:    k.state.keygenConfirmations,
		ResharePlanHash:        k.state.resharePlanHash,
		PlanHash:               k.state.planHash,
		SecurityParams:         k.state.securityParams,
	}, nil
}

func decodeKeyShareWire(w *keyShareWire) (*keyShareState, error) {
	if _, err := secpScalarFromSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	sid, err := tss.SessionIDFromBytes(w.PaillierProofSessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid paillier proof session id: %w", err)
	}
	return &keyShareState{
		securityParams:         w.SecurityParams,
		party:                  w.Party,
		threshold:              w.Threshold,
		parties:                w.Parties,
		publicKey:              w.PublicKey,
		chainCode:              w.ChainCode,
		secret:                 w.Secret,
		groupCommitments:       w.GroupCommitments,
		verificationShares:     w.VerificationShares,
		paillierPublicKey:      w.PaillierPublicKey,
		paillierPrivateKey:     w.PaillierPrivateKey,
		paillierProof:          w.PaillierProof,
		ringPedersenParams:     w.RingPedersenParams,
		ringPedersenProof:      w.RingPedersenProof,
		ringPedersenPublic:     w.RingPedersenPublic,
		paillierPublicKeys:     w.PaillierPublicKeys,
		shareProof:             w.ShareProof,
		keygenTranscriptHash:   w.KeygenTranscriptHash,
		paillierProofSessionID: sid,
		paillierProofDomain:    w.PaillierProofDomain,
		logCiphertext:          w.LogCiphertext,
		logProof:               w.LogProof,
		keygenConfirmations:    w.KeygenConfirmations,
		resharePlanHash:        w.ResharePlanHash,
		planHash:               w.PlanHash,
	}, nil
}

// WireType returns the canonical wire type identifier for KeyShare.
func (*KeyShare) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for KeyShare.
func (*KeyShare) WireVersion() uint16 { return tss.Version }

// MarshalWireMessage encodes KeyShare through its private wire DTO.
func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	w, err := encodeKeyShareWire(k)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(w, opts...)
}

// UnmarshalWireMessage decodes KeyShare through its private wire DTO.
func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var w keyShareWire
	if err := wire.Unmarshal(in, &w, opts...); err != nil {
		return err
	}
	state, err := decodeKeyShareWire(&w)
	if err != nil {
		return err
	}
	k.state = state
	return nil
}

// UnmarshalPresign decodes a canonical CGGMP21 presign record with size caps.
func UnmarshalPresign(in []byte) (*Presign, error) {
	return tss.DecodeBinary[Presign](in)
}

// UnmarshalPresignWithLimits decodes a canonical presign record using explicit
// local resource limits.
func UnmarshalPresignWithLimits(in []byte, limits Limits) (*Presign, error) {
	return tss.DecodeBinaryWithLimits[Presign](in, limits)
}

// presignWire is the wire DTO for Presign.
type presignWire struct {
	Party                tss.PartyID           `wire:"1,u32"`
	Threshold            int                   `wire:"2,u32"`
	Signers              tss.PartySet          `wire:"3,u32list"`
	R                    []byte                `wire:"4,bytes,max_bytes=point"`
	LittleR              []byte                `wire:"5,bytes,max_bytes=point"`
	KShare               *secret.Scalar        `wire:"6,custom,len=32"`
	ChiShare             *secret.Scalar        `wire:"7,custom,len=32"`
	Delta                *secret.Scalar        `wire:"8,custom,len=32"`
	TranscriptHash       []byte                `wire:"9,bytes"`
	Context              PresignContext        `wire:"10,nested"`
	ContextHash          []byte                `wire:"11,bytes"`
	Consumed             bool                  `wire:"12,bool"`
	PublicKey            []byte                `wire:"13,bytes,max_bytes=point"`
	KeygenTranscriptHash []byte                `wire:"14,bytes"`
	PartiesHash          []byte                `wire:"15,bytes"`
	VerifyShares         []SignVerifyShare     `wire:"16,recordlist,max_items=signers"`
	PlanHash             []byte                `wire:"17,bytes,len=32"`
	SecurityParams       SecurityParams        `wire:"18,record"`
	Derivation           *tss.DerivationResult `wire:"19,record"`
}

// WireType returns the canonical wire type identifier for presignWire.
func (presignWire) WireType() string { return presignWireType }

// WireVersion returns the wire format version for presignWire.
func (presignWire) WireVersion() uint16 { return tss.Version }

func decodePresignWire(w *presignWire) (*presignState, error) {
	if _, err := secpScalarFromSecret(w.KShare); err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secpScalarFromSecret(w.ChiShare); err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secpScalarFromSecret(w.Delta); err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	consumed := new(atomic.Bool)
	consumed.Store(w.Consumed)
	derivation := w.Derivation
	if derivation == nil {
		return nil, errors.New("missing presign derivation")
	}
	if err := validateDerivationResult(derivation, tss.DerivationSchemeBIP32Secp256k1); err != nil {
		return nil, fmt.Errorf("presign derivation result: %w", err)
	}
	return &presignState{
		version:              tss.Version,
		securityParams:       w.SecurityParams,
		party:                w.Party,
		threshold:            w.Threshold,
		signers:              w.Signers,
		r:                    w.R,
		littleR:              w.LittleR,
		transcriptHash:       w.TranscriptHash,
		context:              w.Context,
		contextHash:          w.ContextHash,
		derivation:           derivation,
		planHash:             w.PlanHash,
		publicKey:            w.PublicKey,
		keygenTranscriptHash: w.KeygenTranscriptHash,
		partiesHash:          w.PartiesHash,
		verifyShares:         w.VerifyShares,
		kShare:               w.KShare,
		chiShare:             w.ChiShare,
		delta:                w.Delta,
		consumed:             consumed,
		attempt:              newPresignAttemptBinding(w.Consumed),
	}, nil
}

// WireType returns the canonical wire type identifier for Presign.
func (*Presign) WireType() string { return presignWireType }

// WireVersion returns the wire format version for Presign.
func (*Presign) WireVersion() uint16 { return tss.Version }

// MarshalWireMessage encodes Presign through its private wire DTO.
func (p *Presign) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	return wire.Marshal(encodePresignWire(p), opts...)
}

// UnmarshalWireMessage decodes Presign through its private wire DTO.
func (p *Presign) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var w presignWire
	if err := wire.Unmarshal(in, &w, opts...); err != nil {
		return err
	}
	state, err := decodePresignWire(&w)
	if err != nil {
		return err
	}
	p.state = state
	return nil
}

func encodePresignWire(p *Presign) presignWire {
	return presignWire{
		Party:                p.state.party,
		Threshold:            p.state.threshold,
		Signers:              p.state.signers,
		R:                    p.state.r,
		LittleR:              p.state.littleR,
		KShare:               p.state.kShare,
		ChiShare:             p.state.chiShare,
		Delta:                p.state.delta,
		TranscriptHash:       p.state.transcriptHash,
		Context:              p.state.context,
		ContextHash:          p.state.contextHash,
		PlanHash:             p.state.planHash,
		Consumed:             IsPresignConsumed(p),
		PublicKey:            p.state.publicKey,
		KeygenTranscriptHash: p.state.keygenTranscriptHash,
		PartiesHash:          p.state.partiesHash,
		VerifyShares:         p.state.verifyShares,
		SecurityParams:       p.state.securityParams,
		Derivation:           p.state.derivation,
	}
}
