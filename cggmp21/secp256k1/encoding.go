package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	keyShareWireType           = "cggmp21.secp256k1.keyshare"
	presignWireType            = "cggmp21.secp256k1.presign"
	keyShareWireVersion uint16 = 1
	presignWireVersion  uint16 = 1
)

// keyShareWire is the wire DTO for KeyShare.
type keyShareWire struct {
	Party                  tss.PartyID                           `wire:"1,u32"`
	Threshold              int                                   `wire:"2,u32"`
	Parties                tss.PartySet                          `wire:"3,u32list"`
	PublicKey              []byte                                `wire:"4,bytes,max_bytes=point"`
	ChainCode              []byte                                `wire:"5,bytes"`
	Secret                 *secret.Scalar                        `wire:"6,custom,len=32"`
	GroupCommitments       [][]byte                              `wire:"7,byteslist,max_bytes=point,max_items=threshold"`
	PartyData              map[tss.PartyID]keySharePartyDataWire `wire:"8,map,max_items=parties"`
	PaillierPrivateKey     *pai.PrivateKey                       `wire:"9,custom,max_bytes=paillier_private_key"`
	PaillierProofSessionID tss.SessionID                         `wire:"12,bytes,len=32"`
	PaillierProofDomain    string                                `wire:"13,string"`
	ShareProof             []byte                                `wire:"10,bytes,max_bytes=zk_proof"`
	KeygenTranscriptHash   []byte                                `wire:"11,bytes"`
	PlanHash               []byte                                `wire:"17,bytes,len=32"`
	ResharePlanHash        []byte                                `wire:"16,bytes"`
	LogCiphertext          []byte                                `wire:"14,bytes,max_bytes=paillier_ciphertext"`
	LogProof               []byte                                `wire:"15,bytes,max_bytes=zk_proof"`
	SecurityParams         SecurityParams                        `wire:"18,record"`
}

type keySharePartyDataWire struct {
	VerificationShare []byte `wire:"1,bytes,max_bytes=point"`

	PaillierPublicKey []byte `wire:"2,bytes,max_bytes=paillier_public_key"`
	PaillierProof     []byte `wire:"3,bytes,max_bytes=zk_proof"`

	RingPedersenParams []byte `wire:"4,bytes,max_bytes=ring_pedersen_params"`
	RingPedersenProof  []byte `wire:"5,bytes,max_bytes=paillier_proof"`

	KeygenConfirmation *KeygenConfirmation `wire:"6,record"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return keyShareWireVersion }

func keySharePartyDataWireFromState(id tss.PartyID, data keySharePartyData, limits Limits) (keySharePartyDataWire, error) {
	paillierPublicKey, err := canonicalWireMessageBytes(data.paillierPublicKey, limits)
	if err != nil {
		return keySharePartyDataWire{}, fmt.Errorf("encode Paillier public key for party %d: %w", id, err)
	}
	paillierProof, err := canonicalWireMessageBytes(data.paillierProof, limits)
	if err != nil {
		return keySharePartyDataWire{}, fmt.Errorf("encode Paillier proof for party %d: %w", id, err)
	}
	ringPedersenParams, err := canonicalWireMessageBytes(data.ringPedersenParams, limits)
	if err != nil {
		return keySharePartyDataWire{}, fmt.Errorf("encode Ring-Pedersen parameters for party %d: %w", id, err)
	}
	ringPedersenProof, err := canonicalWireMessageBytes(data.ringPedersenProof, limits)
	if err != nil {
		return keySharePartyDataWire{}, fmt.Errorf("encode Ring-Pedersen proof for party %d: %w", id, err)
	}
	if data.keygenConfirmation != nil && data.keygenConfirmation.Sender != id {
		return keySharePartyDataWire{}, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.keygenConfirmation.Sender, id)
	}
	return keySharePartyDataWire{
		VerificationShare:  bytes.Clone(data.verificationShare),
		PaillierPublicKey:  paillierPublicKey,
		PaillierProof:      paillierProof,
		RingPedersenParams: ringPedersenParams,
		RingPedersenProof:  ringPedersenProof,
		KeygenConfirmation: data.keygenConfirmation.Clone(),
	}, nil
}

func keySharePartyDataFromWire(id tss.PartyID, w keySharePartyDataWire, limits Limits) (keySharePartyData, error) {
	paillierPublicKey, err := pai.UnmarshalPublicKeyWithMaxModulusBits(w.PaillierPublicKey, limits.Paillier.MaxModulusBits)
	if err != nil {
		return keySharePartyData{}, fmt.Errorf("invalid Paillier public key for party %d: %w", id, err)
	}
	paillierProof, err := zkpai.UnmarshalModulusProof(w.PaillierProof)
	if err != nil {
		return keySharePartyData{}, fmt.Errorf("invalid Paillier proof for party %d: %w", id, err)
	}
	ringPedersenParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(w.RingPedersenParams, limits.Paillier.MaxModulusBits)
	if err != nil {
		return keySharePartyData{}, fmt.Errorf("invalid Ring-Pedersen parameters for party %d: %w", id, err)
	}
	ringPedersenProof, err := zkpai.UnmarshalRingPedersenProof(w.RingPedersenProof)
	if err != nil {
		return keySharePartyData{}, fmt.Errorf("invalid Ring-Pedersen proof for party %d: %w", id, err)
	}
	if w.KeygenConfirmation != nil && w.KeygenConfirmation.Sender != id {
		return keySharePartyData{}, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", w.KeygenConfirmation.Sender, id)
	}
	return keySharePartyData{
		verificationShare:  bytes.Clone(w.VerificationShare),
		paillierPublicKey:  paillierPublicKey,
		paillierProof:      paillierProof,
		ringPedersenParams: ringPedersenParams,
		ringPedersenProof:  ringPedersenProof,
		keygenConfirmation: w.KeygenConfirmation.Clone(),
	}, nil
}

func encodeKeyShareWire(k *KeyShare) (*keyShareWire, error) {
	limits := DefaultLimits()
	partyData := make(map[tss.PartyID]keySharePartyDataWire, len(k.state.partyData))
	for id, data := range k.state.partyData {
		wireData, err := keySharePartyDataWireFromState(id, data, limits)
		if err != nil {
			return nil, err
		}
		partyData[id] = wireData
	}
	return &keyShareWire{
		Party:                  k.state.party,
		Threshold:              k.state.threshold,
		Parties:                k.state.parties,
		PublicKey:              k.state.publicKey,
		ChainCode:              k.state.chainCode,
		Secret:                 k.state.secret,
		GroupCommitments:       k.state.groupCommitments,
		PartyData:              partyData,
		PaillierPrivateKey:     k.state.paillierPrivateKey,
		PaillierProofSessionID: k.state.paillierProofSessionID,
		PaillierProofDomain:    k.state.paillierProofDomain,
		ShareProof:             k.state.shareProof,
		KeygenTranscriptHash:   k.state.keygenTranscriptHash,
		PlanHash:               k.state.planHash,
		ResharePlanHash:        k.state.resharePlanHash,
		LogCiphertext:          k.state.logCiphertext,
		LogProof:               k.state.logProof,
		SecurityParams:         k.state.securityParams,
	}, nil
}

func decodeKeyShareWire(w *keyShareWire) (*keyShareState, error) {
	limits := DefaultLimits()
	if _, err := secpScalarFromSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(w.PartyData) != len(w.Parties) {
		return nil, fmt.Errorf("party data count %d != party count %d", len(w.PartyData), len(w.Parties))
	}
	partyData := make(map[tss.PartyID]keySharePartyData, len(w.PartyData))
	for _, id := range w.Parties {
		if id == tss.BroadcastPartyId {
			return nil, errors.New("broadcast party cannot have key share party data")
		}
		wireData, ok := w.PartyData[id]
		if !ok {
			return nil, fmt.Errorf("missing party data for participant %d", id)
		}
		data, err := keySharePartyDataFromWire(id, wireData, limits)
		if err != nil {
			return nil, err
		}
		partyData[id] = data
	}
	for id := range w.PartyData {
		if id == tss.BroadcastPartyId {
			return nil, errors.New("broadcast party cannot have key share party data")
		}
		if !tss.ContainsParty(w.Parties, id) {
			return nil, fmt.Errorf("party data for non-participant %d", id)
		}
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
		partyData:              partyData,
		paillierPrivateKey:     w.PaillierPrivateKey,
		shareProof:             w.ShareProof,
		keygenTranscriptHash:   w.KeygenTranscriptHash,
		paillierProofSessionID: w.PaillierProofSessionID,
		paillierProofDomain:    w.PaillierProofDomain,
		logCiphertext:          w.LogCiphertext,
		logProof:               w.LogProof,
		resharePlanHash:        w.ResharePlanHash,
		planHash:               w.PlanHash,
	}, nil
}

// WireType returns the canonical wire type identifier for KeyShare.
func (*KeyShare) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for KeyShare.
func (*KeyShare) WireVersion() uint16 { return keyShareWireVersion }

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

// Clone returns an independently owned deep copy of the key share.
//
// The clone contains secret material and must be destroyed separately when it is
// no longer needed. Destroying the clone does not destroy the original, and
// destroying the original does not destroy the clone.
func (k *KeyShare) Clone() *KeyShare {
	return cloneKeyShareValue(k)
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
func (presignWire) WireVersion() uint16 { return presignWireVersion }

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
func (*Presign) WireVersion() uint16 { return presignWireVersion }

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
