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
	keyShareFieldKeygenSessionID
	keyShareFieldKeygenConfirmations
)

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	secretBytes, err := edSecretScalarBytes(k.secret)
	if err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keyShareWireType, []wire.Field{
		{Tag: keyShareFieldParty, Value: wire.Uint32(uint32(k.Party))},
		{Tag: keyShareFieldThreshold, Value: wire.Uint32(uint32(k.Threshold))},
		{Tag: keyShareFieldParties, Value: wire.EncodeUint32List(k.Parties)},
		{Tag: keyShareFieldPublicKey, Value: wire.NonNilBytes(k.PublicKey)},
		{Tag: keyShareFieldSecret, Value: wire.NonNilBytes(secretBytes)},
		{Tag: keyShareFieldGroupCommitments, Value: wire.EncodeBytesList(k.GroupCommitments)},
		{Tag: keyShareFieldVerificationShares, Value: encodeVerificationShares(k.VerificationShares)},
		{Tag: keyShareFieldKeygenTranscriptHash, Value: wire.NonNilBytes(k.KeygenTranscriptHash)},
		{Tag: keyShareFieldChainCode, Value: wire.NonNilBytes(k.ChainCode)},
		{Tag: keyShareFieldKeygenSessionID, Value: k.KeygenSessionID[:]},
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
	if err := wire.RequireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares, keyShareFieldKeygenTranscriptHash, keyShareFieldChainCode, keyShareFieldKeygenSessionID, keyShareFieldKeygenConfirmations); err != nil {
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
	groupCommitments, err := wire.DecodeBytesListWithLimit(fields[5].Value, limits.MaxThreshold, limits.MaxPointBytes)
	if err != nil {
		return nil, err
	}
	verificationShares, err := decodeVerificationSharesBytesWithLimit(fields[6].Value, limits)
	if err != nil {
		return nil, err
	}
	keygenConfirmations, err := wire.DecodeBytesListWithLimit(fields[10].Value, limits.MaxParties, limits.MaxWireFieldBytes)
	if err != nil {
		return nil, fmt.Errorf("keygen confirmations: %w", err)
	}
	keygenSessionID, err := tss.SessionIDFromBytes(fields[9].Value)
	if err != nil {
		return nil, fmt.Errorf("keygen session id: %w", err)
	}
	secretScalar, err := newEdSecretScalar(fields[4].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid secret scalar: %w", err)
	}
	k := &KeyShare{
		Version:              tss.Version,
		Party:                tss.PartyID(party),
		Threshold:            int(threshold),
		Parties:              parties,
		PublicKey:            fields[3].Value,
		ChainCode:            fields[8].Value,
		secret:               secretScalar,
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		KeygenSessionID:      keygenSessionID,
		KeygenTranscriptHash: fields[7].Value,
		KeygenConfirmations:  keygenConfirmations,
	}
	if err := k.ValidateConsistency(); err != nil {
		return nil, err
	}
	return k, nil
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

func encodeVerificationShares(shares []VerificationShare) []byte {
	records := make([]wire.PartyBytes[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyBytes[tss.PartyID]{Party: share.Party, Bytes: share.PublicKey}
	}
	return wire.EncodePartyBytes(records)
}
