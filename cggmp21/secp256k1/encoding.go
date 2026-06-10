package secp256k1

import (
	"errors"
	"fmt"
	"sync"

	"github.com/islishude/tss"

	"github.com/islishude/tss/internal/secret"
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
	PublicKey              []byte                            `wire:"4,bytes,max_bytes=point"`
	ChainCode              []byte                            `wire:"5,bytes"`
	Secret                 *secret.Scalar                    `wire:"6,custom,len=32"`
	GroupCommitments       [][]byte                          `wire:"7,byteslist,max_bytes=point,max_items=threshold"`
	VerificationShares     []wire.PartyBytes[tss.PartyID]    `wire:"8,partybytes,max_bytes=point"`
	PaillierPublicKey      []byte                            `wire:"9,bytes,max_bytes=paillier_public_key"`
	PaillierPrivateKey     []byte                            `wire:"10,bytes,max_bytes=paillier_private_key"`
	PaillierProof          []byte                            `wire:"11,bytes,max_bytes=zk_proof"`
	RingPedersenParams     []byte                            `wire:"12,bytes,max_bytes=ring_pedersen_params"`
	RingPedersenProof      []byte                            `wire:"13,bytes,max_bytes=paillier_proof"`
	RingPedersenPublic     []wire.PartyBytePair[tss.PartyID] `wire:"14,partybytepairs,max_bytes=paillier_proof"`
	PaillierPublicKeys     []wire.PartyBytePair[tss.PartyID] `wire:"15,partybytepairs,max_bytes=paillier_proof"`
	ShareProof             []byte                            `wire:"16,bytes,max_bytes=zk_proof"`
	KeygenTranscriptHash   []byte                            `wire:"17,bytes"`
	PaillierProofSessionID []byte                            `wire:"18,bytes,len=32"`
	PaillierProofDomain    string                            `wire:"19,string"`
	LogCiphertext          []byte                            `wire:"20,bytes,max_bytes=paillier_ciphertext"`
	LogProof               []byte                            `wire:"21,bytes,max_bytes=zk_proof"`
	KeygenConfirmations    [][]byte                          `wire:"22,byteslist,max_bytes=zk_proof"`
}

// WireType returns the canonical wire type identifier for keyShareWire.
func (keyShareWire) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareWire.
func (keyShareWire) WireVersion() uint16 { return tss.Version }

func (k *KeyShare) toWire() (*keyShareWire, error) {
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
		Secret:                 k.secret,
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
	return wire.Marshal(w, wire.WithFieldLimitsForMarshal(DefaultLimits().fieldLimits()))
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
		if len(s.Bytes) > limits.Curve.MaxPointBytes {
			return nil, fmt.Errorf("verification share %d too large: %d > %d", i, len(s.Bytes), limits.Curve.MaxPointBytes)
		}
	}
	if len(w.RingPedersenPublic) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("ring pedersen public too large: %d > %d", len(w.RingPedersenPublic), limits.Threshold.MaxParties)
	}
	for i, s := range w.RingPedersenPublic {
		if len(s.First) > limits.Paillier.MaxProofBytes {
			return nil, fmt.Errorf("ring pedersen public %d params too large: %d > %d", i, len(s.First), limits.Paillier.MaxProofBytes)
		}
		if len(s.Second) > limits.Paillier.MaxProofBytes {
			return nil, fmt.Errorf("ring pedersen public %d proof too large: %d > %d", i, len(s.Second), limits.Paillier.MaxProofBytes)
		}
	}
	if len(w.PaillierPublicKeys) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("paillier public keys too large: %d > %d", len(w.PaillierPublicKeys), limits.Threshold.MaxParties)
	}
	for i, s := range w.PaillierPublicKeys {
		if len(s.First) > limits.Paillier.MaxProofBytes {
			return nil, fmt.Errorf("paillier public key %d too large: %d > %d", i, len(s.First), limits.Paillier.MaxProofBytes)
		}
		if len(s.Second) > limits.Paillier.MaxProofBytes {
			return nil, fmt.Errorf("paillier public key %d proof too large: %d > %d", i, len(s.Second), limits.Paillier.MaxProofBytes)
		}
	}
	if len(w.KeygenConfirmations) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("keygen confirmations too large: %d > %d", len(w.KeygenConfirmations), limits.Threshold.MaxParties)
	}
	for i, c := range w.KeygenConfirmations {
		if len(c) > limits.TLV.MaxFieldBytes {
			return nil, fmt.Errorf("keygen confirmation %d too large: %d > %d", i, len(c), limits.TLV.MaxFieldBytes)
		}
	}
	if _, err := secpScalarFromSecret(w.Secret); err != nil {
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
		secret:                 w.Secret,
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
	if len(in) > limits.State.MaxSerializedPresignBytes {
		return nil, fmt.Errorf("presign too large: %d > %d", len(in), limits.State.MaxSerializedPresignBytes)
	}
	return unmarshalPresignWithLimits(in, limits)
}

// presignWire is the wire DTO for Presign.
type presignWire struct {
	Party                tss.PartyID    `wire:"1,u32"`
	Threshold            int            `wire:"2,u32"`
	Signers              []tss.PartyID  `wire:"3,u32list"`
	R                    []byte         `wire:"4,bytes,max_bytes=point"`
	LittleR              []byte         `wire:"5,bytes,max_bytes=point"`
	KShare               *secret.Scalar `wire:"6,custom,len=32"`
	ChiShare             *secret.Scalar `wire:"7,custom,len=32"`
	Delta                *secret.Scalar `wire:"8,custom,len=32"`
	TranscriptHash       []byte         `wire:"9,bytes"`
	Context              []byte         `wire:"10,bytes"`
	ContextHash          []byte         `wire:"11,bytes"`
	AdditiveShift        []byte         `wire:"12,bytes"`
	Consumed             bool           `wire:"13,bool"`
	PublicKey            []byte         `wire:"14,bytes,max_bytes=point"`
	KeygenTranscriptHash []byte         `wire:"15,bytes"`
	PartiesHash          []byte         `wire:"16,bytes"`
	VerifyShares         []byte         `wire:"17,bytes,max_bytes=signprep_verify_shares"`
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
	ctx, err := decodePresignContext(w.Context)
	if err != nil {
		return nil, err
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
		kShare:               w.KShare,
		chiShare:             w.ChiShare,
		delta:                w.Delta,
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
