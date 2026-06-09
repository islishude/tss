package secp256k1

import (
	"errors"
	"fmt"
	"sync"

	"github.com/islishude/tss"

	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType       = "cggmp21.secp256k1.keyshare"
	presignWireType        = "cggmp21.secp256k1.presign"
	presignContextWireType = "cggmp21.secp256k1.presign.context"
)

const (
	keyShareFieldParty uint16 = iota + 1
	keyShareFieldThreshold
	keyShareFieldParties
	keyShareFieldPublicKey
	keyShareFieldChainCode
	keyShareFieldSecret
	keyShareFieldGroupCommitments
	keyShareFieldVerificationShares
	keyShareFieldPaillierPublicKey
	keyShareFieldPaillierPrivateKey
	keyShareFieldPaillierProof
	keyShareFieldRingPedersenParams
	keyShareFieldRingPedersenProof
	keyShareFieldRingPedersenPublic
	keyShareFieldPaillierPublicKeys
	keyShareFieldShareProof
	keyShareFieldKeygenTranscriptHash
	keyShareFieldPaillierProofSessionID
	keyShareFieldPaillierProofDomain
	keyShareFieldLogCiphertext
	keyShareFieldLogProof
	keyShareFieldKeygenConfirmations
)

const (
	presignFieldParty uint16 = iota + 1
	presignFieldThreshold
	presignFieldSigners
	presignFieldR
	presignFieldLittleR
	presignFieldKShare
	presignFieldChiShare
	presignFieldDelta
	presignFieldTranscriptHash
	presignFieldContext
	presignFieldContextHash
	presignFieldAdditiveShift
	presignFieldConsumed
	presignFieldPublicKey
	presignFieldKeygenTranscriptHash
	presignFieldPartiesHash
	presignFieldVerifyShares
)

// keyShareWire is the wire DTO for KeyShare.
type keyShareWire struct {
	Party                  tss.PartyID                       `wire:"1,u32"`
	Threshold              int                               `wire:"2,u32"`
	Parties                []tss.PartyID                     `wire:"3,u32list"`
	PublicKey              []byte                            `wire:"4,bytes"`
	ChainCode              []byte                            `wire:"5,bytes"`
	Secret                 []byte                            `wire:"6,bytes"`
	GroupCommitments       [][]byte                          `wire:"7,byteslist"`
	VerificationShares     []wire.PartyBytes[tss.PartyID]    `wire:"8,partybytes"`
	PaillierPublicKey      []byte                            `wire:"9,bytes"`
	PaillierPrivateKey     []byte                            `wire:"10,bytes"`
	PaillierProof          []byte                            `wire:"11,bytes"`
	RingPedersenParams     []byte                            `wire:"12,bytes"`
	RingPedersenProof      []byte                            `wire:"13,bytes"`
	RingPedersenPublic     []wire.PartyBytePair[tss.PartyID] `wire:"14,partybytepairs"`
	PaillierPublicKeys     []wire.PartyBytePair[tss.PartyID] `wire:"15,partybytepairs"`
	ShareProof             []byte                            `wire:"16,bytes"`
	KeygenTranscriptHash   []byte                            `wire:"17,bytes"`
	PaillierProofSessionID []byte                            `wire:"18,bytes,len=32"`
	PaillierProofDomain    string                            `wire:"19,string"`
	LogCiphertext          []byte                            `wire:"20,bytes"`
	LogProof               []byte                            `wire:"21,bytes"`
	KeygenConfirmations    [][]byte                          `wire:"22,byteslist"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return tss.Version }

func (k *KeyShare) toWire() (*keyShareWire, error) {
	secretBytes, err := secpSecretScalarBytes(k.secret)
	if err != nil {
		return nil, err
	}
	verificationShares := make([]wire.PartyBytes[tss.PartyID], len(k.VerificationShares))
	for i, s := range k.VerificationShares {
		verificationShares[i] = wire.PartyBytes[tss.PartyID]{Party: s.Party, Bytes: s.PublicKey}
	}
	ringPedersenPublic := make([]wire.PartyBytePair[tss.PartyID], len(k.RingPedersenPublic))
	for i, s := range k.RingPedersenPublic {
		ringPedersenPublic[i] = wire.PartyBytePair[tss.PartyID]{Party: s.Party, First: s.Params, Second: s.Proof}
	}
	paillierPublicKeys := make([]wire.PartyBytePair[tss.PartyID], len(k.PaillierPublicKeys))
	for i, s := range k.PaillierPublicKeys {
		paillierPublicKeys[i] = wire.PartyBytePair[tss.PartyID]{Party: s.Party, First: s.PublicKey, Second: s.Proof}
	}
	return &keyShareWire{
		Party:                  k.Party,
		Threshold:              k.Threshold,
		Parties:                k.Parties,
		PublicKey:              k.PublicKey,
		ChainCode:              k.ChainCode,
		Secret:                 secretBytes,
		GroupCommitments:       k.GroupCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      k.PaillierPublicKey,
		PaillierPrivateKey:     k.paillierPrivateKey,
		PaillierProof:          k.PaillierProof,
		RingPedersenParams:     k.RingPedersenParams,
		RingPedersenProof:      k.RingPedersenProof,
		RingPedersenPublic:     ringPedersenPublic,
		PaillierPublicKeys:     paillierPublicKeys,
		ShareProof:             k.ShareProof,
		KeygenTranscriptHash:   k.KeygenTranscriptHash,
		PaillierProofSessionID: k.PaillierProofSessionID[:],
		PaillierProofDomain:    k.PaillierProofDomain,
		LogCiphertext:          k.LogCiphertext,
		LogProof:               k.LogProof,
		KeygenConfirmations:    k.KeygenConfirmations,
	}, nil
}

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	w, err := k.toWire()
	if err != nil {
		return nil, err
	}
	return wire.Marshal(w)
}

func unmarshalKeyShareWithLimits(in []byte, limits tss.Limits) (*KeyShare, error) {
	var w keyShareWire
	if err := wire.Unmarshal(in, &w, wire.WithLimits(wire.Limits{
		MaxTotalBytes: limits.MaxSerializedKeyShareBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})); err != nil {
		return nil, err
	}
	if w.Threshold > limits.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", w.Threshold, limits.MaxThreshold)
	}
	if len(w.Parties) > limits.MaxParties {
		return nil, fmt.Errorf("parties too large: %d > %d", len(w.Parties), limits.MaxParties)
	}
	if len(w.GroupCommitments) > limits.MaxThreshold {
		return nil, fmt.Errorf("group commitments too large: %d > %d", len(w.GroupCommitments), limits.MaxThreshold)
	}
	for i, c := range w.GroupCommitments {
		if len(c) > limits.MaxPointBytes {
			return nil, fmt.Errorf("group commitment %d too large: %d > %d", i, len(c), limits.MaxPointBytes)
		}
	}
	if len(w.VerificationShares) > limits.MaxParties {
		return nil, fmt.Errorf("verification shares too large: %d > %d", len(w.VerificationShares), limits.MaxParties)
	}
	for i, s := range w.VerificationShares {
		if len(s.Bytes) > limits.MaxPointBytes {
			return nil, fmt.Errorf("verification share %d too large: %d > %d", i, len(s.Bytes), limits.MaxPointBytes)
		}
	}
	if len(w.RingPedersenPublic) > limits.MaxParties {
		return nil, fmt.Errorf("ring pedersen public too large: %d > %d", len(w.RingPedersenPublic), limits.MaxParties)
	}
	for i, s := range w.RingPedersenPublic {
		if len(s.First) > limits.MaxPaillierProofBytes {
			return nil, fmt.Errorf("ring pedersen public %d params too large: %d > %d", i, len(s.First), limits.MaxPaillierProofBytes)
		}
		if len(s.Second) > limits.MaxPaillierProofBytes {
			return nil, fmt.Errorf("ring pedersen public %d proof too large: %d > %d", i, len(s.Second), limits.MaxPaillierProofBytes)
		}
	}
	if len(w.PaillierPublicKeys) > limits.MaxParties {
		return nil, fmt.Errorf("paillier public keys too large: %d > %d", len(w.PaillierPublicKeys), limits.MaxParties)
	}
	for i, s := range w.PaillierPublicKeys {
		if len(s.First) > limits.MaxPaillierProofBytes {
			return nil, fmt.Errorf("paillier public key %d too large: %d > %d", i, len(s.First), limits.MaxPaillierProofBytes)
		}
		if len(s.Second) > limits.MaxPaillierProofBytes {
			return nil, fmt.Errorf("paillier public key %d proof too large: %d > %d", i, len(s.Second), limits.MaxPaillierProofBytes)
		}
	}
	if len(w.KeygenConfirmations) > limits.MaxParties {
		return nil, fmt.Errorf("keygen confirmations too large: %d > %d", len(w.KeygenConfirmations), limits.MaxParties)
	}
	for i, c := range w.KeygenConfirmations {
		if len(c) > limits.MaxWireFieldBytes {
			return nil, fmt.Errorf("keygen confirmation %d too large: %d > %d", i, len(c), limits.MaxWireFieldBytes)
		}
	}
	secretScalar, err := newSecpSecretScalar(w.Secret)
	if err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	sid, err := tss.SessionIDFromBytes(w.PaillierProofSessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid paillier proof session id: %w", err)
	}
	verificationShares := make([]VerificationShare, len(w.VerificationShares))
	for i, s := range w.VerificationShares {
		verificationShares[i] = VerificationShare{Party: s.Party, PublicKey: s.Bytes}
	}
	ringPedersenPublic := make([]RingPedersenPublicShare, len(w.RingPedersenPublic))
	for i, s := range w.RingPedersenPublic {
		ringPedersenPublic[i] = RingPedersenPublicShare{Party: s.Party, Params: s.First, Proof: s.Second}
	}
	paillierPublicKeys := make([]PaillierPublicShare, len(w.PaillierPublicKeys))
	for i, s := range w.PaillierPublicKeys {
		paillierPublicKeys[i] = PaillierPublicShare{Party: s.Party, PublicKey: s.First, Proof: s.Second}
	}
	k := &KeyShare{
		Version:                tss.Version,
		Party:                  w.Party,
		Threshold:              w.Threshold,
		Parties:                w.Parties,
		PublicKey:              w.PublicKey,
		ChainCode:              w.ChainCode,
		secret:                 secretScalar,
		GroupCommitments:       w.GroupCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      w.PaillierPublicKey,
		paillierPrivateKey:     w.PaillierPrivateKey,
		PaillierProof:          w.PaillierProof,
		RingPedersenParams:     w.RingPedersenParams,
		RingPedersenProof:      w.RingPedersenProof,
		RingPedersenPublic:     ringPedersenPublic,
		PaillierPublicKeys:     paillierPublicKeys,
		ShareProof:             w.ShareProof,
		KeygenTranscriptHash:   w.KeygenTranscriptHash,
		PaillierProofSessionID: sid,
		PaillierProofDomain:    w.PaillierProofDomain,
		LogCiphertext:          w.LogCiphertext,
		LogProof:               w.LogProof,
		KeygenConfirmations:    w.KeygenConfirmations,
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

// UnmarshalPresign decodes a canonical CGGMP21 presign record with size caps.
func UnmarshalPresign(in []byte) (*Presign, error) {
	limits := DefaultLimits()
	if len(in) == 0 {
		return nil, errors.New("empty presign")
	}
	if len(in) > limits.MaxSerializedPresignBytes {
		return nil, fmt.Errorf("presign too large: %d > %d", len(in), limits.MaxSerializedPresignBytes)
	}
	return unmarshalPresignWithLimits(in, limits)
}

// presignWire is the wire DTO for Presign.
type presignWire struct {
	Party                tss.PartyID   `wire:"1,u32"`
	Threshold            int           `wire:"2,u32"`
	Signers              []tss.PartyID `wire:"3,u32list"`
	R                    []byte        `wire:"4,bytes"`
	LittleR              []byte        `wire:"5,bytes"`
	KShare               []byte        `wire:"6,bytes"`
	ChiShare             []byte        `wire:"7,bytes"`
	Delta                []byte        `wire:"8,bytes"`
	TranscriptHash       []byte        `wire:"9,bytes"`
	Context              []byte        `wire:"10,bytes"`
	ContextHash          []byte        `wire:"11,bytes"`
	AdditiveShift        []byte        `wire:"12,bytes"`
	Consumed             bool          `wire:"13,bool"`
	PublicKey            []byte        `wire:"14,bytes"`
	KeygenTranscriptHash []byte        `wire:"15,bytes"`
	PartiesHash          []byte        `wire:"16,bytes"`
	VerifyShares         []byte        `wire:"17,bytes"`
}

// WireType returns the canonical wire type identifier for presignWire.
func (presignWire) WireType() string { return presignWireType }

// WireVersion returns the wire format version for presignWire.
func (presignWire) WireVersion() uint16 { return tss.Version }

func unmarshalPresignWithLimits(in []byte, limits tss.Limits) (*Presign, error) {
	var w presignWire
	if err := wire.Unmarshal(in, &w, wire.WithLimits(wire.Limits{
		MaxTotalBytes: limits.MaxSerializedPresignBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})); err != nil {
		return nil, err
	}
	if w.Threshold > limits.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", w.Threshold, limits.MaxThreshold)
	}
	if len(w.Signers) > limits.MaxSigners {
		return nil, fmt.Errorf("signers too large: %d > %d", len(w.Signers), limits.MaxSigners)
	}
	ctx, err := decodePresignContext(w.Context)
	if err != nil {
		return nil, err
	}
	kShare, err := newSecpSecretScalar(w.KShare)
	if err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	chiShare, err := newSecpSecretScalar(w.ChiShare)
	if err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	delta, err := newSecpSecretScalar(w.Delta)
	if err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	verifyShares, err := decodeSignVerifySharesBytesWithLimit(w.VerifyShares, limits)
	if err != nil {
		return nil, fmt.Errorf("invalid verify shares: %w", err)
	}
	p := &Presign{
		mu:                   &sync.Mutex{},
		Version:              tss.Version,
		Party:                w.Party,
		Threshold:            w.Threshold,
		Signers:              w.Signers,
		R:                    w.R,
		LittleR:              w.LittleR,
		TranscriptHash:       w.TranscriptHash,
		Context:              ctx,
		ContextHash:          w.ContextHash,
		AdditiveShift:        w.AdditiveShift,
		PublicKey:            w.PublicKey,
		KeygenTranscriptHash: w.KeygenTranscriptHash,
		PartiesHash:          w.PartiesHash,
		Consumed:             w.Consumed,
		VerifyShares:         verifyShares,
		kShare:               kShare,
		chiShare:             chiShare,
		delta:                delta,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// presignContextWire is the wire DTO for PresignContext.
type presignContextWire struct {
	KeyID          string   `wire:"1,string"`
	ChainID        string   `wire:"2,string"`
	DerivationPath []uint32 `wire:"3,u32list"`
	PolicyDomain   string   `wire:"4,string"`
	MessageDomain  string   `wire:"5,string"`
}

// WireType returns the canonical wire type identifier for presignContextWire.
func (presignContextWire) WireType() string { return presignContextWireType }

// WireVersion returns the wire format version for presignContextWire.
func (presignContextWire) WireVersion() uint16 { return tss.Version }

func encodePresignContext(ctx PresignContext) []byte {
	raw, _ := wire.Marshal(presignContextWire(ctx))
	return raw
}

func decodePresignContext(in []byte) (PresignContext, error) {
	var w presignContextWire
	if err := wire.Unmarshal(in, &w); err != nil {
		return PresignContext{}, err
	}
	ctx := PresignContext(w)
	if err := validatePresignContext(ctx); err != nil {
		return PresignContext{}, err
	}
	return ctx, nil
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
func decodeSignVerifySharesBytesWithLimit(raw []byte, limits tss.Limits) ([]SignVerifyShare, error) {
	records, err := wire.DecodePartyTriplesWithLimit[tss.PartyID](raw,
		limits.MaxSigners,
		limits.MaxPointBytes,
		limits.MaxPointBytes,
		limits.MaxCGGMP21SignPrepProofBytes,
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
