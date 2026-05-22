package ed25519

import (
	"encoding/binary"
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
)

func marshalKeyShare(k *KeyShare) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, keyShareWireType, []wire.Field{
		{Tag: keyShareFieldParty, Value: encodeUint32(uint32(k.Party))},
		{Tag: keyShareFieldThreshold, Value: encodeUint32(uint32(k.Threshold))},
		{Tag: keyShareFieldParties, Value: encodePartyIDs(k.Parties)},
		{Tag: keyShareFieldPublicKey, Value: bytesOrEmpty(k.PublicKey)},
		{Tag: keyShareFieldSecret, Value: bytesOrEmpty(k.Secret)},
		{Tag: keyShareFieldGroupCommitments, Value: encodeBytesList(k.GroupCommitments)},
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
	if err := requireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares); err != nil {
		return nil, err
	}
	party, err := decodeUint32Field(fields, keyShareFieldParty)
	if err != nil {
		return nil, err
	}
	threshold, err := decodeUint32Field(fields, keyShareFieldThreshold)
	if err != nil {
		return nil, err
	}
	if uint64(threshold) > uint64(maxInt()) {
		return nil, errors.New("threshold too large")
	}
	parties, err := decodePartyIDsField(fields, keyShareFieldParties)
	if err != nil {
		return nil, err
	}
	groupCommitments, err := decodeBytesListField(fields, keyShareFieldGroupCommitments)
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
		PublicKey:          mustWireField(fields, keyShareFieldPublicKey),
		Secret:             mustWireField(fields, keyShareFieldSecret),
		GroupCommitments:   groupCommitments,
		VerificationShares: verificationShares,
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

func validateStrictSortedParties(parties []tss.PartyID) error {
	if len(parties) == 0 {
		return errors.New("party set is empty")
	}
	var last tss.PartyID
	for i, id := range parties {
		if id == 0 {
			return errors.New("party id 0 is reserved")
		}
		if i > 0 && id <= last {
			return errors.New("party ids must be strictly increasing")
		}
		last = id
	}
	return nil
}

func requireExactTags(fields []wire.Field, tags ...uint16) error {
	if len(fields) != len(tags) {
		return fmt.Errorf("got %d fields, want %d", len(fields), len(tags))
	}
	for i, tag := range tags {
		if fields[i].Tag != tag {
			return fmt.Errorf("unexpected field tag %d at index %d", fields[i].Tag, i)
		}
	}
	return nil
}

func encodeVerificationShares(shares []VerificationShare) []byte {
	out := encodeUint32(uint32(len(shares)))
	for _, share := range shares {
		out = append(out, encodeUint32(uint32(share.Party))...)
		out = appendBytes(out, share.PublicKey)
	}
	return out
}

func decodeVerificationSharesField(fields []wire.Field, tag uint16) ([]VerificationShare, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	count, offset, err := readUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([]VerificationShare, 0, count)
	for i := 0; i < int(count); i++ {
		party, next, err := readUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		publicKey, next, err := readBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, VerificationShare{Party: tss.PartyID(party), PublicKey: publicKey})
	}
	if offset != len(raw) {
		return nil, errors.New("trailing verification share bytes")
	}
	return out, nil
}

func encodePartyIDs(parties []tss.PartyID) []byte {
	out := encodeUint32(uint32(len(parties)))
	for _, id := range parties {
		out = append(out, encodeUint32(uint32(id))...)
	}
	return out
}

func decodePartyIDsField(fields []wire.Field, tag uint16) ([]tss.PartyID, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	count, offset, err := readUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if len(raw)-offset != int(count)*4 {
		return nil, errors.New("invalid party id list length")
	}
	out := make([]tss.PartyID, 0, count)
	for i := 0; i < int(count); i++ {
		id, next, err := readUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, tss.PartyID(id))
	}
	return out, nil
}

func encodeBytesList(items [][]byte) []byte {
	out := encodeUint32(uint32(len(items)))
	for _, item := range items {
		out = appendBytes(out, item)
	}
	return out
}

func decodeBytesListField(fields []wire.Field, tag uint16) ([][]byte, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	count, offset, err := readUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, count)
	for i := 0; i < int(count); i++ {
		item, next, err := readBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, item)
	}
	if offset != len(raw) {
		return nil, errors.New("trailing bytes list data")
	}
	return out, nil
}

func decodeUint32Field(fields []wire.Field, tag uint16) (uint32, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return 0, err
	}
	value, offset, err := readUint32(raw, 0)
	if err != nil {
		return 0, err
	}
	if offset != len(raw) {
		return 0, errors.New("trailing uint32 bytes")
	}
	return value, nil
}

func mustWireField(fields []wire.Field, tag uint16) []byte {
	value, _ := wire.Require(fields, tag)
	return value
}

func encodeUint32(v uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return out[:]
}

func appendBytes(out, value []byte) []byte {
	out = append(out, encodeUint32(uint32(len(value)))...)
	return append(out, value...)
}

func readBytes(in []byte, offset int) ([]byte, int, error) {
	length, offset, err := readUint32(in, offset)
	if err != nil {
		return nil, offset, err
	}
	if uint64(len(in)-offset) < uint64(length) {
		return nil, offset, errors.New("truncated byte field")
	}
	out := make([]byte, length)
	copy(out, in[offset:offset+int(length)])
	return out, offset + int(length), nil
}

func readUint32(in []byte, offset int) (uint32, int, error) {
	if len(in)-offset < 4 {
		return 0, offset, errors.New("truncated uint32")
	}
	return binary.BigEndian.Uint32(in[offset : offset+4]), offset + 4, nil
}

func bytesOrEmpty(in []byte) []byte {
	if in == nil {
		return []byte{}
	}
	return in
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
