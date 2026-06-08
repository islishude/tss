package secp256k1

import (
	"errors"
	"fmt"
	"math"
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
)

const (
	presignContextFieldKeyID uint16 = iota + 1
	presignContextFieldChainID
	presignContextFieldDerivationPath
	presignContextFieldPolicyDomain
	presignContextFieldMessageDomain
)

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	secretBytes, err := secpSecretScalarBytes(k.secret)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keyShareWireType, []wire.Field{
		{Tag: keyShareFieldParty, Value: wire.Uint32(uint32(k.Party))},
		{Tag: keyShareFieldThreshold, Value: wire.Uint32(uint32(k.Threshold))},
		{Tag: keyShareFieldParties, Value: wire.EncodeUint32List(k.Parties)},
		{Tag: keyShareFieldPublicKey, Value: wire.NonNilBytes(k.PublicKey)},
		{Tag: keyShareFieldChainCode, Value: wire.NonNilBytes(k.ChainCode)},
		{Tag: keyShareFieldSecret, Value: wire.NonNilBytes(secretBytes)},
		{Tag: keyShareFieldGroupCommitments, Value: wire.EncodeBytesList(k.GroupCommitments)},
		{Tag: keyShareFieldVerificationShares, Value: encodeVerificationShares(k.VerificationShares)},
		{Tag: keyShareFieldPaillierPublicKey, Value: wire.NonNilBytes(k.PaillierPublicKey)},
		{Tag: keyShareFieldPaillierPrivateKey, Value: wire.NonNilBytes(k.paillierPrivateKey)},
		{Tag: keyShareFieldPaillierProof, Value: wire.NonNilBytes(k.PaillierProof)},
		{Tag: keyShareFieldRingPedersenParams, Value: wire.NonNilBytes(k.RingPedersenParams)},
		{Tag: keyShareFieldRingPedersenProof, Value: wire.NonNilBytes(k.RingPedersenProof)},
		{Tag: keyShareFieldRingPedersenPublic, Value: encodeRingPedersenPublicShares(k.RingPedersenPublic)},
		{Tag: keyShareFieldPaillierPublicKeys, Value: encodePaillierPublicShares(k.PaillierPublicKeys)},
		{Tag: keyShareFieldShareProof, Value: wire.NonNilBytes(k.ShareProof)},
		{Tag: keyShareFieldKeygenTranscriptHash, Value: wire.NonNilBytes(k.KeygenTranscriptHash)},
		{Tag: keyShareFieldPaillierProofSessionID, Value: k.PaillierProofSessionID.Bytes()},
		{Tag: keyShareFieldPaillierProofDomain, Value: []byte(k.PaillierProofDomain)},
		{Tag: keyShareFieldLogCiphertext, Value: wire.NonNilBytes(k.LogCiphertext)},
		{Tag: keyShareFieldLogProof, Value: wire.NonNilBytes(k.LogProof)},
		{Tag: keyShareFieldKeygenConfirmations, Value: wire.EncodeBytesList(k.KeygenConfirmations)},
	})
}

func unmarshalKeyShareWithLimits(in []byte, limits tss.Limits) (*KeyShare, error) {
	version, fields, err := wire.UnmarshalWithLimits(in, keyShareWireType, wire.Limits{
		MaxTotalBytes: limits.MaxSerializedKeyShareBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})
	if err != nil {
		return nil, err
	}
	if version != tss.Version {
		return nil, fmt.Errorf("unexpected key share wire version %d", version)
	}
	if err := wire.RequireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldChainCode, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares, keyShareFieldPaillierPublicKey, keyShareFieldPaillierPrivateKey, keyShareFieldPaillierProof, keyShareFieldRingPedersenParams, keyShareFieldRingPedersenProof, keyShareFieldRingPedersenPublic, keyShareFieldPaillierPublicKeys, keyShareFieldShareProof, keyShareFieldKeygenTranscriptHash, keyShareFieldPaillierProofSessionID, keyShareFieldPaillierProofDomain, keyShareFieldLogCiphertext, keyShareFieldLogProof, keyShareFieldKeygenConfirmations); err != nil {
		return nil, err
	}
	party, err := wire.Uint32Field(fields, keyShareFieldParty)
	if err != nil {
		return nil, err
	}
	threshold, err := wire.Uint32Field(fields, keyShareFieldThreshold)
	if err != nil {
		return nil, err
	}
	// Guard int conversion: on 32-bit platforms int is int32, so any uint32
	// above MaxInt32 would overflow.
	if threshold > math.MaxInt32 {
		return nil, fmt.Errorf("threshold overflows platform int: %d", threshold)
	}
	if int(threshold) > limits.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", threshold, limits.MaxThreshold)
	}
	parties, err := wire.Uint32ListFieldWithLimit[tss.PartyID](fields, keyShareFieldParties, limits.MaxParties)
	if err != nil {
		return nil, err
	}
	groupCommitments, err := wire.BytesListFieldWithLimit(fields, keyShareFieldGroupCommitments, limits.MaxThreshold, limits.MaxPointBytes)
	if err != nil {
		return nil, err
	}
	verificationShares, err := decodeVerificationSharesFieldWithLimit(fields, keyShareFieldVerificationShares, limits)
	if err != nil {
		return nil, err
	}
	paillierPublicKeys, err := decodePaillierPublicSharesFieldWithLimit(fields, keyShareFieldPaillierPublicKeys, limits)
	if err != nil {
		return nil, err
	}
	ringPedersenPublic, err := decodeRingPedersenPublicSharesFieldWithLimit(fields, keyShareFieldRingPedersenPublic, limits)
	if err != nil {
		return nil, err
	}
	paillierProofSessionID, err := tss.SessionIDFromBytes(wire.MustField(fields, keyShareFieldPaillierProofSessionID))
	if err != nil {
		return nil, fmt.Errorf("invalid paillier proof session id: %w", err)
	}
	keygenConfirmations, err := wire.BytesListFieldWithLimit(fields, keyShareFieldKeygenConfirmations, limits.MaxParties, limits.MaxWireFieldBytes)
	if err != nil {
		return nil, fmt.Errorf("keygen confirmations: %w", err)
	}
	secretScalar, err := newSecpSecretScalar(wire.MustField(fields, keyShareFieldSecret))
	if err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	k := &KeyShare{
		Version:                tss.Version,
		Party:                  tss.PartyID(party),
		Threshold:              int(threshold),
		Parties:                parties,
		PublicKey:              wire.MustField(fields, keyShareFieldPublicKey),
		ChainCode:              wire.MustField(fields, keyShareFieldChainCode),
		secret:                 secretScalar,
		GroupCommitments:       groupCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      wire.MustField(fields, keyShareFieldPaillierPublicKey),
		paillierPrivateKey:     wire.MustField(fields, keyShareFieldPaillierPrivateKey),
		PaillierProof:          wire.MustField(fields, keyShareFieldPaillierProof),
		RingPedersenParams:     wire.MustField(fields, keyShareFieldRingPedersenParams),
		RingPedersenProof:      wire.MustField(fields, keyShareFieldRingPedersenProof),
		RingPedersenPublic:     ringPedersenPublic,
		PaillierPublicKeys:     paillierPublicKeys,
		ShareProof:             wire.MustField(fields, keyShareFieldShareProof),
		KeygenTranscriptHash:   wire.MustField(fields, keyShareFieldKeygenTranscriptHash),
		PaillierProofSessionID: paillierProofSessionID,
		PaillierProofDomain:    string(wire.MustField(fields, keyShareFieldPaillierProofDomain)),
		LogCiphertext:          wire.MustField(fields, keyShareFieldLogCiphertext),
		LogProof:               wire.MustField(fields, keyShareFieldLogProof),
		KeygenConfirmations:    keygenConfirmations,
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

func unmarshalPresignWithLimits(in []byte, limits tss.Limits) (*Presign, error) {
	version, fields, err := wire.UnmarshalWithLimits(in, presignWireType, wire.Limits{
		MaxTotalBytes: limits.MaxSerializedPresignBytes,
		MaxFields:     limits.MaxWireFields,
		MaxFieldBytes: limits.MaxWireFieldBytes,
	})
	if err != nil {
		return nil, err
	}
	if version != tss.Version {
		return nil, fmt.Errorf("unexpected presign wire version %d", version)
	}
	if err := wire.RequireExactTags(fields, presignFieldParty, presignFieldThreshold, presignFieldSigners, presignFieldR, presignFieldLittleR, presignFieldKShare, presignFieldChiShare, presignFieldDelta, presignFieldTranscriptHash, presignFieldContext, presignFieldContextHash, presignFieldAdditiveShift, presignFieldConsumed, presignFieldPublicKey, presignFieldKeygenTranscriptHash, presignFieldPartiesHash); err != nil {
		return nil, err
	}
	party, err := wire.Uint32Field(fields, presignFieldParty)
	if err != nil {
		return nil, err
	}
	threshold, err := wire.Uint32Field(fields, presignFieldThreshold)
	if err != nil {
		return nil, err
	}
	// Guard int conversion: on 32-bit platforms int is int32, so any uint32
	// above MaxInt32 would overflow.
	if threshold > math.MaxInt32 {
		return nil, fmt.Errorf("threshold overflows platform int: %d", threshold)
	}
	if int(threshold) > limits.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", threshold, limits.MaxThreshold)
	}
	signers, err := wire.Uint32ListFieldWithLimit[tss.PartyID](fields, presignFieldSigners, limits.MaxSigners)
	if err != nil {
		return nil, err
	}
	consumed, err := wire.BoolField(fields, presignFieldConsumed)
	if err != nil {
		return nil, err
	}
	ctx, err := decodePresignContext(wire.MustField(fields, presignFieldContext))
	if err != nil {
		return nil, err
	}
	kShare, err := newSecpSecretScalar(wire.MustField(fields, presignFieldKShare))
	if err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	chiShare, err := newSecpSecretScalar(wire.MustField(fields, presignFieldChiShare))
	if err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	delta, err := newSecpSecretScalar(wire.MustField(fields, presignFieldDelta))
	if err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	p := &Presign{
		mu:                   &sync.Mutex{},
		Version:              tss.Version,
		Party:                tss.PartyID(party),
		Threshold:            int(threshold),
		Signers:              signers,
		R:                    wire.MustField(fields, presignFieldR),
		LittleR:              wire.MustField(fields, presignFieldLittleR),
		TranscriptHash:       wire.MustField(fields, presignFieldTranscriptHash),
		Context:              ctx,
		ContextHash:          wire.MustField(fields, presignFieldContextHash),
		AdditiveShift:        wire.MustField(fields, presignFieldAdditiveShift),
		PublicKey:            wire.MustField(fields, presignFieldPublicKey),
		KeygenTranscriptHash: wire.MustField(fields, presignFieldKeygenTranscriptHash),
		PartiesHash:          wire.MustField(fields, presignFieldPartiesHash),
		Consumed:             consumed,
		kShare:               kShare,
		chiShare:             chiShare,
		delta:                delta,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func encodeVerificationShares(shares []VerificationShare) []byte {
	records := make([]wire.PartyBytes[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyBytes[tss.PartyID]{Party: share.Party, Bytes: share.PublicKey}
	}
	return wire.EncodePartyBytes(records)
}

func decodeVerificationSharesFieldWithLimit(fields []wire.Field, tag uint16, limits tss.Limits) ([]VerificationShare, error) {
	records, err := wire.PartyBytesFieldWithLimit[tss.PartyID](fields, tag, limits.MaxParties, limits.MaxPointBytes, "verification share")
	if err != nil {
		return nil, err
	}
	out := make([]VerificationShare, 0, len(records))
	for _, record := range records {
		out = append(out, VerificationShare{Party: record.Party, PublicKey: record.Bytes})
	}
	return out, nil
}

func encodePaillierPublicShares(shares []PaillierPublicShare) []byte {
	records := make([]wire.PartyBytePair[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyBytePair[tss.PartyID]{
			Party:  share.Party,
			First:  share.PublicKey,
			Second: share.Proof,
		}
	}
	return wire.EncodePartyBytePairs(records)
}

func decodePaillierPublicSharesFieldWithLimit(fields []wire.Field, tag uint16, limits tss.Limits) ([]PaillierPublicShare, error) {
	// The proof item inside a pair dominates; use the proof byte cap as per-item limit.
	records, err := wire.PartyBytePairsFieldWithLimit[tss.PartyID](fields, tag, limits.MaxParties, limits.MaxPaillierProofBytes, "Paillier public share")
	if err != nil {
		return nil, err
	}
	out := make([]PaillierPublicShare, 0, len(records))
	for _, record := range records {
		out = append(out, PaillierPublicShare{
			Party:     record.Party,
			PublicKey: record.First,
			Proof:     record.Second,
		})
	}
	return out, nil
}

func encodeRingPedersenPublicShares(shares []RingPedersenPublicShare) []byte {
	records := make([]wire.PartyBytePair[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyBytePair[tss.PartyID]{
			Party:  share.Party,
			First:  share.Params,
			Second: share.Proof,
		}
	}
	return wire.EncodePartyBytePairs(records)
}

func decodeRingPedersenPublicSharesFieldWithLimit(fields []wire.Field, tag uint16, limits tss.Limits) ([]RingPedersenPublicShare, error) {
	// The proof item inside a pair dominates; use the proof byte cap as per-item limit.
	records, err := wire.PartyBytePairsFieldWithLimit[tss.PartyID](fields, tag, limits.MaxParties, limits.MaxPaillierProofBytes, "Ring-Pedersen public share")
	if err != nil {
		return nil, err
	}
	out := make([]RingPedersenPublicShare, 0, len(records))
	for _, record := range records {
		out = append(out, RingPedersenPublicShare{
			Party:  record.Party,
			Params: record.First,
			Proof:  record.Second,
		})
	}
	return out, nil
}

func encodePresignContext(ctx PresignContext) []byte {
	raw, err := wire.Marshal(tss.Version, presignContextWireType, []wire.Field{
		{Tag: presignContextFieldKeyID, Value: []byte(ctx.KeyID)},
		{Tag: presignContextFieldChainID, Value: []byte(ctx.ChainID)},
		{Tag: presignContextFieldDerivationPath, Value: wire.EncodeUint32List(ctx.DerivationPath)},
		{Tag: presignContextFieldPolicyDomain, Value: []byte(ctx.PolicyDomain)},
		{Tag: presignContextFieldMessageDomain, Value: []byte(ctx.MessageDomain)},
	})
	if err != nil {
		return nil
	}
	return raw
}

func decodePresignContext(in []byte) (PresignContext, error) {
	version, fields, err := wire.Unmarshal(in, presignContextWireType)
	if err != nil {
		return PresignContext{}, err
	}
	if version != tss.Version {
		return PresignContext{}, fmt.Errorf("unexpected presign context wire version %d", version)
	}
	if err := wire.RequireExactTags(fields, presignContextFieldKeyID, presignContextFieldChainID, presignContextFieldDerivationPath, presignContextFieldPolicyDomain, presignContextFieldMessageDomain); err != nil {
		return PresignContext{}, err
	}
	path, err := wire.Uint32ListField[uint32](fields, presignContextFieldDerivationPath)
	if err != nil {
		return PresignContext{}, err
	}
	ctx := PresignContext{
		KeyID:          string(wire.MustField(fields, presignContextFieldKeyID)),
		ChainID:        string(wire.MustField(fields, presignContextFieldChainID)),
		DerivationPath: path,
		PolicyDomain:   string(wire.MustField(fields, presignContextFieldPolicyDomain)),
		MessageDomain:  string(wire.MustField(fields, presignContextFieldMessageDomain)),
	}
	if err := validatePresignContext(ctx); err != nil {
		return PresignContext{}, err
	}
	return ctx, nil
}
