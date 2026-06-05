package ed25519

import (
	"fmt"
	"math"

	"github.com/islishude/tss"

	"github.com/islishude/tss/internal/wire"
)

const keyShareWireType = "frost.ed25519.keyshare"

const (
	keyShareFieldParty uint16 = iota + 1
	keyShareFieldThreshold
	keyShareFieldParties
	keyShareFieldPublicKey
	keyShareFieldSecret
	keyShareFieldGroupCommitments
	keyShareFieldVerificationShares
	keyShareFieldKeygenTranscriptHash
	keyShareFieldChainCode
)

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keyShareWireType, []wire.Field{
		{Tag: keyShareFieldParty, Value: wire.Uint32(uint32(k.Party))},
		{Tag: keyShareFieldThreshold, Value: wire.Uint32(uint32(k.Threshold))},
		{Tag: keyShareFieldParties, Value: wire.EncodeUint32List(k.Parties)},
		{Tag: keyShareFieldPublicKey, Value: wire.NonNilBytes(k.PublicKey)},
		{Tag: keyShareFieldSecret, Value: wire.NonNilBytes(k.secret)},
		{Tag: keyShareFieldGroupCommitments, Value: wire.EncodeBytesList(k.GroupCommitments)},
		{Tag: keyShareFieldVerificationShares, Value: encodeVerificationShares(k.VerificationShares)},
		{Tag: keyShareFieldKeygenTranscriptHash, Value: wire.NonNilBytes(k.KeygenTranscriptHash)},
		{Tag: keyShareFieldChainCode, Value: wire.NonNilBytes(k.ChainCode)},
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
	if err := wire.RequireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares, keyShareFieldKeygenTranscriptHash, keyShareFieldChainCode); err != nil {
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
	// above MaxInt32 would overflow. The check is harmless (always false) on
	// 64-bit where int is int64.
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
	k := &KeyShare{
		Version:              tss.Version,
		Party:                tss.PartyID(party),
		Threshold:            int(threshold),
		Parties:              parties,
		PublicKey:            wire.MustField(fields, keyShareFieldPublicKey),
		ChainCode:            wire.MustField(fields, keyShareFieldChainCode),
		secret:               wire.MustField(fields, keyShareFieldSecret),
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		KeygenTranscriptHash: wire.MustField(fields, keyShareFieldKeygenTranscriptHash),
	}
	if err := k.ValidateConsistency(); err != nil {
		return nil, err
	}
	return k, nil
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

func encodeVerificationShares(shares []VerificationShare) []byte {
	records := make([]wire.PartyBytes[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyBytes[tss.PartyID]{Party: share.Party, Bytes: share.PublicKey}
	}
	return wire.EncodePartyBytes(records)
}
