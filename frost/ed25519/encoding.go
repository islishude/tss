package ed25519

import (
	"errors"
	"fmt"

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

func unmarshalKeyShare(in []byte) (*KeyShare, error) {
	version, fields, err := wire.Unmarshal(in, keyShareWireType)
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
	if uint64(threshold) > uint64(wire.MaxInt) {
		return nil, errors.New("threshold too large")
	}
	parties, err := wire.Uint32ListField[tss.PartyID](fields, keyShareFieldParties)
	if err != nil {
		return nil, err
	}
	groupCommitments, err := wire.BytesListField(fields, keyShareFieldGroupCommitments)
	if err != nil {
		return nil, err
	}
	verificationShares, err := decodeVerificationSharesField(fields, keyShareFieldVerificationShares)
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
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

func encodeVerificationShares(shares []VerificationShare) []byte {
	records := make([]wire.PartyBytes[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = wire.PartyBytes[tss.PartyID]{Party: share.Party, Bytes: share.PublicKey}
	}
	return wire.EncodePartyBytes(records)
}

func decodeVerificationSharesField(fields []wire.Field, tag uint16) ([]VerificationShare, error) {
	records, err := wire.PartyBytesField[tss.PartyID](fields, tag, "verification share")
	if err != nil {
		return nil, err
	}
	out := make([]VerificationShare, 0, len(records))
	for _, record := range records {
		out = append(out, VerificationShare{Party: record.Party, PublicKey: record.Bytes})
	}
	return out, nil
}
