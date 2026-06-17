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
	VerificationShares     []VerificationShare       `wire:"8,recordlist"`
	PaillierPublicKey      []byte                    `wire:"9,bytes,max_bytes=paillier_public_key"`
	PaillierPrivateKey     []byte                    `wire:"10,bytes,max_bytes=paillier_private_key"`
	PaillierProof          []byte                    `wire:"11,bytes,max_bytes=zk_proof"`
	RingPedersenParams     []byte                    `wire:"12,bytes,max_bytes=ring_pedersen_params"`
	RingPedersenProof      []byte                    `wire:"13,bytes,max_bytes=paillier_proof"`
	RingPedersenPublic     []RingPedersenPublicShare `wire:"14,recordlist"`
	PaillierPublicKeys     []PaillierPublicShare     `wire:"15,recordlist"`
	ShareProof             []byte                    `wire:"16,bytes,max_bytes=zk_proof"`
	KeygenTranscriptHash   []byte                    `wire:"17,bytes"`
	PaillierProofSessionID []byte                    `wire:"18,bytes,len=32"`
	PaillierProofDomain    string                    `wire:"19,string"`
	LogCiphertext          []byte                    `wire:"20,bytes,max_bytes=paillier_ciphertext"`
	LogProof               []byte                    `wire:"21,bytes,max_bytes=zk_proof"`
	KeygenConfirmations    []*KeygenConfirmation     `wire:"22,recordlist"`
	ResharePlanHash        []byte                    `wire:"23,bytes"`
	PlanHash               []byte                    `wire:"24,bytes,len=32"`
	SecurityParams         SecurityParams            `wire:"25,record"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return tss.Version }

func (k *KeyShare) toWire() (*keyShareWire, error) {
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

func marshalKeyShare(k *KeyShare, limits Limits) ([]byte, error) {
	if err := k.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	w, err := k.toWire()
	if err != nil {
		return nil, err
	}
	return wire.Marshal(w, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalKeyShareWithLimits(in []byte, limits Limits) (*KeyShare, error) {
	var w keyShareWire
	if err := wire.Unmarshal(in, &w,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return nil, err
	}
	if w.Threshold > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", w.Threshold, limits.Threshold.MaxThreshold)
	}
	if len(w.Parties) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("parties too large: %d > %d", len(w.Parties), limits.Threshold.MaxParties)
	}
	if len(w.GroupCommitments) > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("group commitments too large: %d > %d", len(w.GroupCommitments), limits.Threshold.MaxThreshold)
	}
	for i, c := range w.GroupCommitments {
		if len(c) > limits.Curve.MaxPointBytes {
			return nil, fmt.Errorf("group commitment %d too large: %d > %d", i, len(c), limits.Curve.MaxPointBytes)
		}
	}
	if len(w.VerificationShares) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("verification shares too large: %d > %d", len(w.VerificationShares), limits.Threshold.MaxParties)
	}
	for i, s := range w.VerificationShares {
		if len(s.PublicKey) > limits.Curve.MaxPointBytes {
			return nil, fmt.Errorf("verification share %d too large: %d > %d", i, len(s.PublicKey), limits.Curve.MaxPointBytes)
		}
	}
	if len(w.KeygenConfirmations) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("keygen confirmations too large: %d > %d", len(w.KeygenConfirmations), limits.Threshold.MaxParties)
	}
	if _, err := secpScalarFromSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	sid, err := tss.SessionIDFromBytes(w.PaillierProofSessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid paillier proof session id: %w", err)
	}
	k := &KeyShare{state: &keyShareState{
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
	}}
	if err := k.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return k, nil
}

// UnmarshalPresign decodes a canonical CGGMP21 presign record with size caps.
func UnmarshalPresign(in []byte) (*Presign, error) {
	return UnmarshalPresignWithLimits(in, DefaultLimits())
}

// UnmarshalPresignWithLimits decodes a canonical presign record using explicit
// local resource limits.
func UnmarshalPresignWithLimits(in []byte, limits Limits) (*Presign, error) {
	if len(in) == 0 {
		return nil, errors.New("empty presign")
	}
	if len(in) > limits.State.MaxSerializedPresignBytes {
		return nil, fmt.Errorf("presign too large: %d > %d", len(in), limits.State.MaxSerializedPresignBytes)
	}
	return unmarshalPresignWithLimits(in, limits)
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
	VerifyShares         []byte                `wire:"16,bytes,max_bytes=signprep_verify_shares"`
	PlanHash             []byte                `wire:"17,bytes,len=32"`
	SecurityParams       SecurityParams        `wire:"18,record"`
	Derivation           *tss.DerivationResult `wire:"19,record"`
}

// WireType returns the canonical wire type identifier for presignWire.
func (presignWire) WireType() string { return presignWireType }

// WireVersion returns the wire format version for presignWire.
func (presignWire) WireVersion() uint16 { return tss.Version }

func unmarshalPresignWithLimits(in []byte, limits Limits) (*Presign, error) {
	var w presignWire
	if err := wire.Unmarshal(in, &w,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedPresignBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return nil, err
	}
	if w.Threshold > limits.Threshold.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", w.Threshold, limits.Threshold.MaxThreshold)
	}
	if len(w.Signers) > limits.Threshold.MaxSigners {
		return nil, fmt.Errorf("signers too large: %d > %d", len(w.Signers), limits.Threshold.MaxSigners)
	}
	if _, err := secpScalarFromSecret(w.KShare); err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secpScalarFromSecret(w.ChiShare); err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secpScalarFromSecret(w.Delta); err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	verifyShares, err := decodeSignVerifySharesBytesWithLimit(w.VerifyShares, limits)
	if err != nil {
		return nil, fmt.Errorf("invalid verify shares: %w", err)
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
	p := &Presign{state: &presignState{
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
		verifyShares:         verifyShares,
		kShare:               w.KShare,
		chiShare:             w.ChiShare,
		delta:                w.Delta,
		consumed:             consumed,
		attempt:              newPresignAttemptBinding(w.Consumed),
	}}
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return p, nil
}

// encodeSignVerifyShares encodes a slice of SignVerifyShare into a deterministic
// TLV structure sorted by party ID.
func encodeSignVerifyShares(shares []SignVerifyShare) []byte {
	if len(shares) == 0 {
		return nil
	}
	records := make([]wire.PartyTriple[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyTriple[tss.PartyID]{
			Party:  share.Party,
			First:  share.KPoint,
			Second: share.ChiPoint,
			Third:  share.Proof,
		}
	}
	return wire.EncodePartyTriples(records)
}

// decodeSignVerifySharesBytesWithLimit decodes a SignVerifyShare slice with
// per-field size caps.
func decodeSignVerifySharesBytesWithLimit(raw []byte, limits Limits) ([]SignVerifyShare, error) {
	records, err := wire.DecodePartyTriplesWithLimit[tss.PartyID](raw,
		limits.Threshold.MaxSigners,
		limits.Curve.MaxPointBytes,
		limits.Curve.MaxPointBytes,
		limits.SignPrep.MaxProofBytes,
		"sign verify share",
	)
	if err != nil {
		return nil, err
	}
	out := make([]SignVerifyShare, 0, len(records))
	for _, record := range records {
		out = append(out, SignVerifyShare{
			Party:    record.Party,
			KPoint:   record.First,
			ChiPoint: record.Second,
			Proof:    record.Third,
		})
	}
	return out, nil
}
