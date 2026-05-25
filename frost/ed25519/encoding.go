package ed25519

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/codec"
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
)

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keyShareWireType, []wire.Field{
		{Tag: keyShareFieldParty, Value: codec.Uint32(uint32(k.Party))},
		{Tag: keyShareFieldThreshold, Value: codec.Uint32(uint32(k.Threshold))},
		{Tag: keyShareFieldParties, Value: codec.EncodeUint32List(k.Parties)},
		{Tag: keyShareFieldPublicKey, Value: codec.NonNilBytes(k.PublicKey)},
		{Tag: keyShareFieldSecret, Value: codec.NonNilBytes(k.Secret)},
		{Tag: keyShareFieldGroupCommitments, Value: codec.EncodeBytesList(k.GroupCommitments)},
		{Tag: keyShareFieldVerificationShares, Value: encodeVerificationShares(k.VerificationShares)},
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
	if err := codec.RequireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares); err != nil {
		return nil, err
	}
	party, err := codec.Uint32Field(fields, keyShareFieldParty)
	if err != nil {
		return nil, err
	}
	threshold, err := codec.Uint32Field(fields, keyShareFieldThreshold)
	if err != nil {
		return nil, err
	}
	if uint64(threshold) > uint64(codec.MaxInt) {
		return nil, errors.New("threshold too large")
	}
	parties, err := codec.Uint32ListField[tss.PartyID](fields, keyShareFieldParties)
	if err != nil {
		return nil, err
	}
	groupCommitments, err := codec.BytesListField(fields, keyShareFieldGroupCommitments)
	if err != nil {
		return nil, err
	}
	verificationShares, err := decodeVerificationSharesField(fields, keyShareFieldVerificationShares)
	if err != nil {
		return nil, err
	}
	k := &KeyShare{
		Version:            tss.Version,
		Party:              tss.PartyID(party),
		Threshold:          int(threshold),
		Parties:            parties,
		PublicKey:          codec.MustField(fields, keyShareFieldPublicKey),
		Secret:             codec.MustField(fields, keyShareFieldSecret),
		GroupCommitments:   groupCommitments,
		VerificationShares: verificationShares,
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

func encodeVerificationShares(shares []VerificationShare) []byte {
	records := make([]codec.PartyBytes[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = codec.PartyBytes[tss.PartyID]{Party: share.Party, Bytes: share.PublicKey}
	}
	return codec.EncodePartyBytes(records)
}

func decodeVerificationSharesField(fields []wire.Field, tag uint16) ([]VerificationShare, error) {
	records, err := codec.PartyBytesField[tss.PartyID](fields, tag, "verification share")
	if err != nil {
		return nil, err
	}
	out := make([]VerificationShare, 0, len(records))
	for _, record := range records {
		out = append(out, VerificationShare{Party: record.Party, PublicKey: record.Bytes})
	}
	return out, nil
}
