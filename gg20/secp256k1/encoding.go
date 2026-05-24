package secp256k1

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType = "gg20.secp256k1.keyshare"
	presignWireType  = "gg20.secp256k1.presign"
)

const (
	keyShareFieldParty uint16 = iota + 1
	keyShareFieldThreshold
	keyShareFieldParties
	keyShareFieldPublicKey
	keyShareFieldSecret
	keyShareFieldGroupCommitments
	keyShareFieldVerificationShares
	keyShareFieldPaillierPublicKey
	keyShareFieldPaillierPrivateKey
	keyShareFieldPaillierProof
	keyShareFieldPaillierPublicKeys
	keyShareFieldShareProof
	keyShareFieldKeygenTranscriptHash
	keyShareFieldSecurityNotice
)

const (
	presignFieldParty uint16 = iota + 1
	presignFieldThreshold
	presignFieldSigners
	presignFieldR
	presignFieldLittleR
	presignFieldKShare
	presignFieldSigmaShare
	presignFieldDelta
	presignFieldTranscriptHash
	presignFieldConsumed
	presignFieldSecurityNotice
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
		{Tag: keyShareFieldPaillierPublicKey, Value: bytesOrEmpty(k.PaillierPublicKey)},
		{Tag: keyShareFieldPaillierPrivateKey, Value: bytesOrEmpty(k.PaillierPrivateKey)},
		{Tag: keyShareFieldPaillierProof, Value: bytesOrEmpty(k.PaillierProof)},
		{Tag: keyShareFieldPaillierPublicKeys, Value: encodePaillierPublicShares(k.PaillierPublicKeys)},
		{Tag: keyShareFieldShareProof, Value: bytesOrEmpty(k.ShareProof)},
		{Tag: keyShareFieldKeygenTranscriptHash, Value: bytesOrEmpty(k.KeygenTranscriptHash)},
		{Tag: keyShareFieldSecurityNotice, Value: []byte(k.SecurityNotice)},
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
	if err := requireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares, keyShareFieldPaillierPublicKey, keyShareFieldPaillierPrivateKey, keyShareFieldPaillierProof, keyShareFieldPaillierPublicKeys, keyShareFieldShareProof, keyShareFieldKeygenTranscriptHash, keyShareFieldSecurityNotice); err != nil {
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
	paillierPublicKeys, err := decodePaillierPublicSharesField(fields, keyShareFieldPaillierPublicKeys)
	if err != nil {
		return nil, err
	}
	k := &KeyShare{
		Version:              tss.Version,
		Party:                tss.PartyID(party),
		Threshold:            int(threshold),
		Parties:              parties,
		PublicKey:            mustWireField(fields, keyShareFieldPublicKey),
		Secret:               mustWireField(fields, keyShareFieldSecret),
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		PaillierPublicKey:    mustWireField(fields, keyShareFieldPaillierPublicKey),
		PaillierPrivateKey:   mustWireField(fields, keyShareFieldPaillierPrivateKey),
		PaillierProof:        mustWireField(fields, keyShareFieldPaillierProof),
		PaillierPublicKeys:   paillierPublicKeys,
		ShareProof:           mustWireField(fields, keyShareFieldShareProof),
		KeygenTranscriptHash: mustWireField(fields, keyShareFieldKeygenTranscriptHash),
		SecurityNotice:       string(mustWireField(fields, keyShareFieldSecurityNotice)),
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

// MarshalBinary encodes the presign record using canonical TLV wire format.
func (p *Presign) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return wire.Marshal(tss.Version, presignWireType, []wire.Field{
		{Tag: presignFieldParty, Value: encodeUint32(uint32(p.Party))},
		{Tag: presignFieldThreshold, Value: encodeUint32(uint32(p.Threshold))},
		{Tag: presignFieldSigners, Value: encodePartyIDs(p.Signers)},
		{Tag: presignFieldR, Value: bytesOrEmpty(p.R)},
		{Tag: presignFieldLittleR, Value: bytesOrEmpty(p.LittleR)},
		{Tag: presignFieldKShare, Value: bytesOrEmpty(p.KShare)},
		{Tag: presignFieldSigmaShare, Value: bytesOrEmpty(p.SigmaShare)},
		{Tag: presignFieldDelta, Value: bytesOrEmpty(p.Delta)},
		{Tag: presignFieldTranscriptHash, Value: bytesOrEmpty(p.TranscriptHash)},
		{Tag: presignFieldConsumed, Value: encodeBool(p.Consumed)},
		{Tag: presignFieldSecurityNotice, Value: []byte(p.SecurityNotice)},
	})
}

// UnmarshalPresign decodes a canonical GG20 presign record.
func UnmarshalPresign(in []byte) (*Presign, error) {
	version, fields, err := wire.Unmarshal(in, presignWireType)
	if err != nil {
		return nil, err
	}
	if version != tss.Version {
		return nil, fmt.Errorf("unexpected presign wire version %d", version)
	}
	if err := requireExactTags(fields, presignFieldParty, presignFieldThreshold, presignFieldSigners, presignFieldR, presignFieldLittleR, presignFieldKShare, presignFieldSigmaShare, presignFieldDelta, presignFieldTranscriptHash, presignFieldConsumed, presignFieldSecurityNotice); err != nil {
		return nil, err
	}
	party, err := decodeUint32Field(fields, presignFieldParty)
	if err != nil {
		return nil, err
	}
	threshold, err := decodeUint32Field(fields, presignFieldThreshold)
	if err != nil {
		return nil, err
	}
	if uint64(threshold) > uint64(maxInt()) {
		return nil, errors.New("threshold too large")
	}
	signers, err := decodePartyIDsField(fields, presignFieldSigners)
	if err != nil {
		return nil, err
	}
	consumed, err := decodeBoolField(fields, presignFieldConsumed)
	if err != nil {
		return nil, err
	}
	p := &Presign{
		Version:        tss.Version,
		Party:          tss.PartyID(party),
		Threshold:      int(threshold),
		Signers:        signers,
		R:              mustWireField(fields, presignFieldR),
		LittleR:        mustWireField(fields, presignFieldLittleR),
		KShare:         mustWireField(fields, presignFieldKShare),
		SigmaShare:     mustWireField(fields, presignFieldSigmaShare),
		Delta:          mustWireField(fields, presignFieldDelta),
		TranscriptHash: mustWireField(fields, presignFieldTranscriptHash),
		Consumed:       consumed,
		SecurityNotice: string(mustWireField(fields, presignFieldSecurityNotice)),
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// Validate checks local presign structure and scalar/point encodings.
func (p *Presign) Validate() error {
	if p == nil {
		return errors.New("nil presign")
	}
	if p.Version != tss.Version {
		return fmt.Errorf("unexpected presign version %d", p.Version)
	}
	if p.Threshold <= 0 || p.Threshold > len(p.Signers) {
		return errors.New("invalid presign threshold")
	}
	if err := validateStrictSortedParties(p.Signers); err != nil {
		return err
	}
	if !tss.ContainsParty(p.Signers, p.Party) {
		return errors.New("presign party is not in signer set")
	}
	if _, err := secp.PointFromBytes(p.R); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	if _, err := secp.ParseScalar(p.LittleR); err != nil {
		return fmt.Errorf("invalid little r: %w", err)
	}
	if _, err := secp.ParseScalar(p.KShare); err != nil {
		return fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secp.ParseScalar(p.SigmaShare); err != nil {
		return fmt.Errorf("invalid sigma share: %w", err)
	}
	if _, err := secp.ParseScalar(p.Delta); err != nil {
		return fmt.Errorf("invalid delta: %w", err)
	}
	if len(p.TranscriptHash) != 32 {
		return errors.New("invalid presign transcript hash")
	}
	return nil
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

func encodePaillierPublicShares(shares []PaillierPublicShare) []byte {
	out := encodeUint32(uint32(len(shares)))
	for _, share := range shares {
		out = append(out, encodeUint32(uint32(share.Party))...)
		out = appendBytes(out, share.PublicKey)
		out = appendBytes(out, share.Proof)
	}
	return out
}

func decodePaillierPublicSharesField(fields []wire.Field, tag uint16) ([]PaillierPublicShare, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return nil, err
	}
	count, offset, err := readUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	out := make([]PaillierPublicShare, 0, count)
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
		proof, next, err := readBytes(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out = append(out, PaillierPublicShare{Party: tss.PartyID(party), PublicKey: publicKey, Proof: proof})
	}
	if offset != len(raw) {
		return nil, errors.New("trailing Paillier public share bytes")
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

func decodeBoolField(fields []wire.Field, tag uint16) (bool, error) {
	raw, err := wire.Require(fields, tag)
	if err != nil {
		return false, err
	}
	if len(raw) != 1 {
		return false, errors.New("bool must be 1 byte")
	}
	switch raw[0] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("bool must be 0 or 1")
	}
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

func encodeBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
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
