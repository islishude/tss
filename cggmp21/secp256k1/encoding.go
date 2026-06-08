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
	// Tags validated; access fields by index.
	party, err := wire.DecodeUint32(fields[0].Value)
	if err != nil {
		return nil, err
	}
	threshold, err := wire.DecodeUint32(fields[1].Value)
	if err != nil {
		return nil, err
	}
	if threshold > math.MaxInt32 {
		return nil, fmt.Errorf("threshold overflows platform int: %d", threshold)
	}
	if int(threshold) > limits.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", threshold, limits.MaxThreshold)
	}
	parties, err := wire.DecodeUint32ListWithLimit[tss.PartyID](fields[2].Value, limits.MaxParties)
	if err != nil {
		return nil, err
	}
	groupCommitments, err := wire.DecodeBytesListWithLimit(fields[6].Value, limits.MaxThreshold, limits.MaxPointBytes)
	if err != nil {
		return nil, err
	}
	verificationShares, err := decodeVerificationSharesBytesWithLimit(fields[7].Value, limits)
	if err != nil {
		return nil, err
	}
	paillierPublicKeys, err := decodePaillierPublicSharesBytesWithLimit(fields[14].Value, limits)
	if err != nil {
		return nil, err
	}
	ringPedersenPublic, err := decodeRingPedersenPublicSharesBytesWithLimit(fields[13].Value, limits)
	if err != nil {
		return nil, err
	}
	paillierProofSessionID, err := tss.SessionIDFromBytes(fields[17].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid paillier proof session id: %w", err)
	}
	keygenConfirmations, err := wire.DecodeBytesListWithLimit(fields[21].Value, limits.MaxParties, limits.MaxWireFieldBytes)
	if err != nil {
		return nil, fmt.Errorf("keygen confirmations: %w", err)
	}
	secretScalar, err := newSecpSecretScalar(fields[5].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	k := &KeyShare{
		Version:                tss.Version,
		Party:                  tss.PartyID(party),
		Threshold:              int(threshold),
		Parties:                parties,
		PublicKey:              fields[3].Value,
		ChainCode:              fields[4].Value,
		secret:                 secretScalar,
		GroupCommitments:       groupCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      fields[8].Value,
		paillierPrivateKey:     fields[9].Value,
		PaillierProof:          fields[10].Value,
		RingPedersenParams:     fields[11].Value,
		RingPedersenProof:      fields[12].Value,
		RingPedersenPublic:     ringPedersenPublic,
		PaillierPublicKeys:     paillierPublicKeys,
		ShareProof:             fields[15].Value,
		KeygenTranscriptHash:   fields[16].Value,
		PaillierProofSessionID: paillierProofSessionID,
		PaillierProofDomain:    string(fields[18].Value),
		LogCiphertext:          fields[19].Value,
		LogProof:               fields[20].Value,
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
	// Tags validated; access fields by index.
	party, err := wire.DecodeUint32(fields[0].Value)
	if err != nil {
		return nil, err
	}
	threshold, err := wire.DecodeUint32(fields[1].Value)
	if err != nil {
		return nil, err
	}
	if threshold > math.MaxInt32 {
		return nil, fmt.Errorf("threshold overflows platform int: %d", threshold)
	}
	if int(threshold) > limits.MaxThreshold {
		return nil, fmt.Errorf("threshold too large: %d > %d", threshold, limits.MaxThreshold)
	}
	signers, err := wire.DecodeUint32ListWithLimit[tss.PartyID](fields[2].Value, limits.MaxSigners)
	if err != nil {
		return nil, err
	}
	consumed, err := wire.DecodeBool(fields[12].Value)
	if err != nil {
		return nil, err
	}
	ctx, err := decodePresignContext(fields[9].Value)
	if err != nil {
		return nil, err
	}
	kShare, err := newSecpSecretScalar(fields[5].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	chiShare, err := newSecpSecretScalar(fields[6].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	delta, err := newSecpSecretScalar(fields[7].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	p := &Presign{
		mu:                   &sync.Mutex{},
		Version:              tss.Version,
		Party:                tss.PartyID(party),
		Threshold:            int(threshold),
		Signers:              signers,
		R:                    fields[3].Value,
		LittleR:              fields[4].Value,
		TranscriptHash:       fields[8].Value,
		Context:              ctx,
		ContextHash:          fields[10].Value,
		AdditiveShift:        fields[11].Value,
		PublicKey:            fields[13].Value,
		KeygenTranscriptHash: fields[14].Value,
		PartiesHash:          fields[15].Value,
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

func decodeVerificationSharesBytesWithLimit(raw []byte, limits tss.Limits) ([]VerificationShare, error) {
	records, err := wire.DecodePartyBytesWithLimit[tss.PartyID](raw, limits.MaxParties, limits.MaxPointBytes, "verification share")
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

func decodePaillierPublicSharesBytesWithLimit(raw []byte, limits tss.Limits) ([]PaillierPublicShare, error) {
	records, err := wire.DecodePartyBytePairsWithLimit[tss.PartyID](raw, limits.MaxParties, limits.MaxPaillierProofBytes, "Paillier public share")
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

func decodeRingPedersenPublicSharesBytesWithLimit(raw []byte, limits tss.Limits) ([]RingPedersenPublicShare, error) {
	records, err := wire.DecodePartyBytePairsWithLimit[tss.PartyID](raw, limits.MaxParties, limits.MaxPaillierProofBytes, "Ring-Pedersen public share")
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
	path, err := wire.DecodeUint32List[uint32](fields[2].Value)
	if err != nil {
		return PresignContext{}, err
	}
	ctx := PresignContext{
		KeyID:          string(fields[0].Value),
		ChainID:        string(fields[1].Value),
		DerivationPath: path,
		PolicyDomain:   string(fields[3].Value),
		MessageDomain:  string(fields[4].Value),
	}
	if err := validatePresignContext(ctx); err != nil {
		return PresignContext{}, err
	}
	return ctx, nil
}
