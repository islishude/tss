package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"

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
	keyShareFieldPaillierPrimalityProof
	keyShareFieldPaillierPrimalityProofs
	keyShareFieldPaillierPublicKeys
	keyShareFieldShareProof
	keyShareFieldKeygenTranscriptHash
	keyShareFieldPaillierProofSessionID
	keyShareFieldPaillierProofDomain
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
		{Tag: keyShareFieldChainCode, Value: wire.NonNilBytes(k.ChainCode)},
		{Tag: keyShareFieldSecret, Value: wire.NonNilBytes(k.secret)},
		{Tag: keyShareFieldGroupCommitments, Value: wire.EncodeBytesList(k.GroupCommitments)},
		{Tag: keyShareFieldVerificationShares, Value: encodeVerificationShares(k.VerificationShares)},
		{Tag: keyShareFieldPaillierPublicKey, Value: wire.NonNilBytes(k.PaillierPublicKey)},
		{Tag: keyShareFieldPaillierPrivateKey, Value: wire.NonNilBytes(k.paillierPrivateKey)},
		{Tag: keyShareFieldPaillierProof, Value: wire.NonNilBytes(k.PaillierProof)},
		{Tag: keyShareFieldPaillierPrimalityProof, Value: wire.NonNilBytes(k.PaillierPrimalityProof)},
		{Tag: keyShareFieldPaillierPrimalityProofs, Value: wire.EncodeBytesList(k.PaillierPrimalityProofs)},
		{Tag: keyShareFieldPaillierPublicKeys, Value: encodePaillierPublicShares(k.PaillierPublicKeys)},
		{Tag: keyShareFieldShareProof, Value: wire.NonNilBytes(k.ShareProof)},
		{Tag: keyShareFieldKeygenTranscriptHash, Value: wire.NonNilBytes(k.KeygenTranscriptHash)},
		{Tag: keyShareFieldPaillierProofSessionID, Value: k.PaillierProofSessionID.Bytes()},
		{Tag: keyShareFieldPaillierProofDomain, Value: []byte(k.PaillierProofDomain)},
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
	if err := wire.RequireExactTags(fields, keyShareFieldParty, keyShareFieldThreshold, keyShareFieldParties, keyShareFieldPublicKey, keyShareFieldChainCode, keyShareFieldSecret, keyShareFieldGroupCommitments, keyShareFieldVerificationShares, keyShareFieldPaillierPublicKey, keyShareFieldPaillierPrivateKey, keyShareFieldPaillierProof, keyShareFieldPaillierPrimalityProof, keyShareFieldPaillierPrimalityProofs, keyShareFieldPaillierPublicKeys, keyShareFieldShareProof, keyShareFieldKeygenTranscriptHash, keyShareFieldPaillierProofSessionID, keyShareFieldPaillierProofDomain); err != nil {
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
	paillierPublicKeys, err := decodePaillierPublicSharesField(fields, keyShareFieldPaillierPublicKeys)
	if err != nil {
		return nil, err
	}
	primalityProofs, err := wire.BytesListField(fields, keyShareFieldPaillierPrimalityProofs)
	if err != nil {
		return nil, err
	}
	paillierProofSessionID, err := tss.SessionIDFromBytes(wire.MustField(fields, keyShareFieldPaillierProofSessionID))
	if err != nil {
		return nil, fmt.Errorf("invalid paillier proof session id: %w", err)
	}
	k := &KeyShare{
		Version:                 tss.Version,
		Party:                   tss.PartyID(party),
		Threshold:               int(threshold),
		Parties:                 parties,
		PublicKey:               wire.MustField(fields, keyShareFieldPublicKey),
		ChainCode:               wire.MustField(fields, keyShareFieldChainCode),
		secret:                  wire.MustField(fields, keyShareFieldSecret),
		GroupCommitments:        groupCommitments,
		VerificationShares:      verificationShares,
		PaillierPublicKey:       wire.MustField(fields, keyShareFieldPaillierPublicKey),
		paillierPrivateKey:      wire.MustField(fields, keyShareFieldPaillierPrivateKey),
		PaillierProof:           wire.MustField(fields, keyShareFieldPaillierProof),
		PaillierPrimalityProof:  wire.MustField(fields, keyShareFieldPaillierPrimalityProof),
		PaillierPrimalityProofs: primalityProofs,
		PaillierPublicKeys:      paillierPublicKeys,
		ShareProof:              wire.MustField(fields, keyShareFieldShareProof),
		KeygenTranscriptHash:    wire.MustField(fields, keyShareFieldKeygenTranscriptHash),
		PaillierProofSessionID:  paillierProofSessionID,
		PaillierProofDomain:     string(wire.MustField(fields, keyShareFieldPaillierProofDomain)),
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
		{Tag: presignFieldParty, Value: wire.Uint32(uint32(p.Party))},
		{Tag: presignFieldThreshold, Value: wire.Uint32(uint32(p.Threshold))},
		{Tag: presignFieldSigners, Value: wire.EncodeUint32List(p.Signers)},
		{Tag: presignFieldR, Value: wire.NonNilBytes(p.R)},
		{Tag: presignFieldLittleR, Value: wire.NonNilBytes(p.LittleR)},
		{Tag: presignFieldKShare, Value: wire.NonNilBytes(p.KShare)},
		{Tag: presignFieldChiShare, Value: wire.NonNilBytes(p.ChiShare)},
		{Tag: presignFieldDelta, Value: wire.NonNilBytes(p.Delta)},
		{Tag: presignFieldTranscriptHash, Value: wire.NonNilBytes(p.TranscriptHash)},
		{Tag: presignFieldConsumed, Value: wire.Bool(p.Consumed)},
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
	if err := wire.RequireExactTags(fields, presignFieldParty, presignFieldThreshold, presignFieldSigners, presignFieldR, presignFieldLittleR, presignFieldKShare, presignFieldChiShare, presignFieldDelta, presignFieldTranscriptHash, presignFieldConsumed); err != nil {
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
	if uint64(threshold) > uint64(wire.MaxInt) {
		return nil, errors.New("threshold too large")
	}
	signers, err := wire.Uint32ListField[tss.PartyID](fields, presignFieldSigners)
	if err != nil {
		return nil, err
	}
	consumed, err := wire.BoolField(fields, presignFieldConsumed)
	if err != nil {
		return nil, err
	}
	p := &Presign{
		Version:        tss.Version,
		Party:          tss.PartyID(party),
		Threshold:      int(threshold),
		Signers:        signers,
		R:              wire.MustField(fields, presignFieldR),
		LittleR:        wire.MustField(fields, presignFieldLittleR),
		KShare:         wire.MustField(fields, presignFieldKShare),
		ChiShare:       wire.MustField(fields, presignFieldChiShare),
		Delta:          wire.MustField(fields, presignFieldDelta),
		TranscriptHash: wire.MustField(fields, presignFieldTranscriptHash),
		Consumed:       consumed,
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
	if err := wire.ValidateStrictSortedIDs(p.Signers); err != nil {
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

func decodePaillierPublicSharesField(fields []wire.Field, tag uint16) ([]PaillierPublicShare, error) {
	records, err := wire.PartyBytePairsField[tss.PartyID](fields, tag, "Paillier public share")
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
