package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/codec"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType = "cggmp21.secp256k1.keyshare"
	presignWireType  = "cggmp21.secp256k1.presign"
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
	presignFieldChiShare
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
		{Tag: keyShareFieldParty, Value: codec.Uint32(uint32(k.Party))},
		{Tag: keyShareFieldThreshold, Value: codec.Uint32(uint32(k.Threshold))},
		{Tag: keyShareFieldParties, Value: codec.EncodeUint32List(k.Parties)},
		{Tag: keyShareFieldPublicKey, Value: codec.NonNilBytes(k.PublicKey)},
		{Tag: keyShareFieldChainCode, Value: codec.NonNilBytes(k.ChainCode)},
		{Tag: keyShareFieldSecret, Value: codec.NonNilBytes(k.Secret)},
		{Tag: keyShareFieldGroupCommitments, Value: codec.EncodeBytesList(k.GroupCommitments)},
		{Tag: keyShareFieldVerificationShares, Value: encodeVerificationShares(k.VerificationShares)},
		{Tag: keyShareFieldPaillierPublicKey, Value: codec.NonNilBytes(k.PaillierPublicKey)},
		{Tag: keyShareFieldPaillierPrivateKey, Value: codec.NonNilBytes(k.PaillierPrivateKey)},
		{Tag: keyShareFieldPaillierProof, Value: codec.NonNilBytes(k.PaillierProof)},
		{Tag: keyShareFieldPaillierPublicKeys, Value: encodePaillierPublicShares(k.PaillierPublicKeys)},
		{Tag: keyShareFieldShareProof, Value: codec.NonNilBytes(k.ShareProof)},
		{Tag: keyShareFieldKeygenTranscriptHash, Value: codec.NonNilBytes(k.KeygenTranscriptHash)},
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
	if err := codec.RequireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldChainCode, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares, keyShareFieldPaillierPublicKey, keyShareFieldPaillierPrivateKey, keyShareFieldPaillierProof, keyShareFieldPaillierPublicKeys, keyShareFieldShareProof, keyShareFieldKeygenTranscriptHash, keyShareFieldSecurityNotice); err != nil {
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
	paillierPublicKeys, err := decodePaillierPublicSharesField(fields, keyShareFieldPaillierPublicKeys)
	if err != nil {
		return nil, err
	}
	k := &KeyShare{
		Version:              tss.Version,
		Party:                tss.PartyID(party),
		Threshold:            int(threshold),
		Parties:              parties,
		PublicKey:            codec.MustField(fields, keyShareFieldPublicKey),
		ChainCode:            codec.MustField(fields, keyShareFieldChainCode),
		Secret:               codec.MustField(fields, keyShareFieldSecret),
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		PaillierPublicKey:    codec.MustField(fields, keyShareFieldPaillierPublicKey),
		PaillierPrivateKey:   codec.MustField(fields, keyShareFieldPaillierPrivateKey),
		PaillierProof:        codec.MustField(fields, keyShareFieldPaillierProof),
		PaillierPublicKeys:   paillierPublicKeys,
		ShareProof:           codec.MustField(fields, keyShareFieldShareProof),
		KeygenTranscriptHash: codec.MustField(fields, keyShareFieldKeygenTranscriptHash),
		SecurityNotice:       string(codec.MustField(fields, keyShareFieldSecurityNotice)),
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
		{Tag: presignFieldParty, Value: codec.Uint32(uint32(p.Party))},
		{Tag: presignFieldThreshold, Value: codec.Uint32(uint32(p.Threshold))},
		{Tag: presignFieldSigners, Value: codec.EncodeUint32List(p.Signers)},
		{Tag: presignFieldR, Value: codec.NonNilBytes(p.R)},
		{Tag: presignFieldLittleR, Value: codec.NonNilBytes(p.LittleR)},
		{Tag: presignFieldKShare, Value: codec.NonNilBytes(p.KShare)},
		{Tag: presignFieldChiShare, Value: codec.NonNilBytes(p.ChiShare)},
		{Tag: presignFieldDelta, Value: codec.NonNilBytes(p.Delta)},
		{Tag: presignFieldTranscriptHash, Value: codec.NonNilBytes(p.TranscriptHash)},
		{Tag: presignFieldConsumed, Value: codec.Bool(p.Consumed)},
		{Tag: presignFieldSecurityNotice, Value: []byte(p.SecurityNotice)},
	})
}

// UnmarshalPresign decodes a canonical CGGMP21 presign record.
func UnmarshalPresign(in []byte) (*Presign, error) {
	version, fields, err := wire.Unmarshal(in, presignWireType)
	if err != nil {
		return nil, err
	}
	if version != tss.Version {
		return nil, fmt.Errorf("unexpected presign wire version %d", version)
	}
	if err := codec.RequireExactTags(fields, presignFieldParty, presignFieldThreshold, presignFieldSigners, presignFieldR, presignFieldLittleR, presignFieldKShare, presignFieldChiShare, presignFieldDelta, presignFieldTranscriptHash, presignFieldConsumed, presignFieldSecurityNotice); err != nil {
		return nil, err
	}
	party, err := codec.Uint32Field(fields, presignFieldParty)
	if err != nil {
		return nil, err
	}
	threshold, err := codec.Uint32Field(fields, presignFieldThreshold)
	if err != nil {
		return nil, err
	}
	if uint64(threshold) > uint64(codec.MaxInt) {
		return nil, errors.New("threshold too large")
	}
	signers, err := codec.Uint32ListField[tss.PartyID](fields, presignFieldSigners)
	if err != nil {
		return nil, err
	}
	consumed, err := codec.BoolField(fields, presignFieldConsumed)
	if err != nil {
		return nil, err
	}
	p := &Presign{
		Version:        tss.Version,
		Party:          tss.PartyID(party),
		Threshold:      int(threshold),
		Signers:        signers,
		R:              codec.MustField(fields, presignFieldR),
		LittleR:        codec.MustField(fields, presignFieldLittleR),
		KShare:         codec.MustField(fields, presignFieldKShare),
		ChiShare:       codec.MustField(fields, presignFieldChiShare),
		Delta:          codec.MustField(fields, presignFieldDelta),
		TranscriptHash: codec.MustField(fields, presignFieldTranscriptHash),
		Consumed:       consumed,
		SecurityNotice: string(codec.MustField(fields, presignFieldSecurityNotice)),
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
	if err := codec.ValidateStrictSortedIDs(p.Signers); err != nil {
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
	if _, err := secp.ParseScalar(p.ChiShare); err != nil {
		return fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secp.ParseScalar(p.Delta); err != nil {
		return fmt.Errorf("invalid delta: %w", err)
	}
	if len(p.TranscriptHash) != 32 {
		return errors.New("invalid presign transcript hash")
	}
	return nil
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

func encodePaillierPublicShares(shares []PaillierPublicShare) []byte {
	records := make([]codec.PartyBytePair[tss.PartyID], len(shares))
	for i, share := range shares {
		records[i] = codec.PartyBytePair[tss.PartyID]{
			Party:  share.Party,
			First:  share.PublicKey,
			Second: share.Proof,
		}
	}
	return codec.EncodePartyBytePairs(records)
}

func decodePaillierPublicSharesField(fields []wire.Field, tag uint16) ([]PaillierPublicShare, error) {
	records, err := codec.PartyBytePairsField[tss.PartyID](fields, tag, "Paillier public share")
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
