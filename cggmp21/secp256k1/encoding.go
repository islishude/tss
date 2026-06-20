package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"unicode/utf8"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const (
	keyShareWireType           = "cggmp21.secp256k1.keyshare"
	presignWireType            = "cggmp21.secp256k1.presign"
	keyShareWireVersion uint16 = 1
	presignWireVersion  uint16 = 1
)

// WireType returns the canonical wire type identifier for keyShareState.
func (*keyShareState) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for keyShareState.
func (*keyShareState) WireVersion() uint16 { return keyShareWireVersion }

// MarshalWireMessage encodes keyShareState directly without an intermediate DTO.
func (state *keyShareState) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if state == nil {
		return nil, errors.New("nil key share state")
	}
	limits := DefaultLimits()
	threshold, err := uint32WireField(state.threshold, "threshold")
	if err != nil {
		return nil, err
	}
	parties, err := marshalPartySetValue(state.parties, limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("encode parties: %w", err)
	}
	secret, err := state.secret.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode secret: %w", err)
	}
	groupCommitmentBytes, err := secp.CommitmentPointsBytes(state.groupCommitments)
	if err != nil {
		return nil, fmt.Errorf("encode group commitments: %w", err)
	}
	groupCommitments, err := marshalBytesListValue(groupCommitmentBytes, limits.Curve.MaxPointBytes, limits.Threshold.MaxThreshold, "group commitments")
	if err != nil {
		return nil, err
	}
	partyData, err := marshalKeySharePartyDataMap(state.partyData, limits)
	if err != nil {
		return nil, err
	}
	paillierPrivateKey, err := state.paillierPrivateKey.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode paillier private key: %w", err)
	}
	shareProof, err := state.shareProof.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode share proof: %w", err)
	}
	logCiphertext, err := wire.EncodeBigPos(state.logCiphertext)
	if err != nil {
		return nil, fmt.Errorf("encode log ciphertext: %w", err)
	}
	logProof, err := state.logProof.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode log proof: %w", err)
	}
	securityParams, err := wire.MarshalRecordValue(
		state.securityParams,
		wire.WithFieldLimitsForMarshal(limits.fieldLimits()),
	)
	if err != nil {
		return nil, fmt.Errorf("encode security params: %w", err)
	}
	fields := []wire.Field{
		{Tag: 1, Value: wire.Uint32(state.party)},
		{Tag: 2, Value: threshold},
		{Tag: 3, Value: parties},
		{Tag: 4, Value: wire.NonNilBytes(bytes.Clone(state.publicKey))},
		{Tag: 5, Value: wire.NonNilBytes(bytes.Clone(state.chainCode))},
		{Tag: 6, Value: secret},
		{Tag: 7, Value: groupCommitments},
		{Tag: 8, Value: partyData},
		{Tag: 9, Value: paillierPrivateKey},
		{Tag: 10, Value: shareProof},
		{Tag: 11, Value: wire.NonNilBytes(bytes.Clone(state.keygenTranscriptHash))},
		{Tag: 12, Value: state.paillierProofSessionID[:]},
		{Tag: 13, Value: []byte(state.paillierProofDomain)},
		{Tag: 14, Value: logCiphertext},
		{Tag: 15, Value: logProof},
		{Tag: 16, Value: wire.NonNilBytes(bytes.Clone(state.resharePlanHash))},
		{Tag: 17, Value: wire.NonNilBytes(bytes.Clone(state.planHash))},
		{Tag: 18, Value: securityParams},
	}
	return wire.MarshalMessageBody(state, fields)
}

// UnmarshalWireMessage decodes keyShareState directly without an intermediate DTO.
func (state *keyShareState) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if state == nil {
		return errors.New("nil key share state")
	}
	limits := DefaultLimits()
	fields, err := wire.UnmarshalMessageBody(
		in,
		state,
		limits.frameLimits(limits.State.MaxSerializedKeyShareBytes),
	)
	if err != nil {
		return err
	}
	if err := requireKeyShareStateTags(fields); err != nil {
		return err
	}
	party, err := wire.DecodeUint32(fields[0].Value)
	if err != nil {
		return fmt.Errorf("invalid key share party: %w", err)
	}
	threshold, err := wire.DecodeUint32(fields[1].Value)
	if err != nil {
		return fmt.Errorf("invalid key share threshold: %w", err)
	}
	parties, err := unmarshalPartySetValue(fields[2].Value, limits.Threshold.MaxParties)
	if err != nil {
		return fmt.Errorf("invalid key share parties: %w", err)
	}
	if len(fields[3].Value) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("public key too large: %d > %d", len(fields[3].Value), limits.Curve.MaxPointBytes)
	}
	var secret secret.Scalar
	if err := secret.UnmarshalWireValue(fields[5].Value); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(fields[5].Value) != secp.ScalarSize {
		return fmt.Errorf("secret scalar length %d != %d", len(fields[5].Value), secp.ScalarSize)
	}
	groupCommitmentBytes, err := unmarshalBytesListValue(fields[6].Value, limits.Curve.MaxPointBytes, limits.Threshold.MaxThreshold, "group commitments")
	if err != nil {
		return err
	}
	groupCommitments, err := secp.CommitmentPointsFromBytes(groupCommitmentBytes)
	if err != nil {
		return fmt.Errorf("invalid group commitments: %w", err)
	}
	partyData, err := unmarshalKeySharePartyDataMap(fields[7].Value, limits)
	if err != nil {
		return err
	}
	var paillierPrivateKey pai.PrivateKey
	if err := paillierPrivateKey.UnmarshalWireValue(fields[8].Value); err != nil {
		return fmt.Errorf("invalid paillier private key: %w", err)
	}
	var shareProof schnorr.Proof
	if err := shareProof.UnmarshalWireValue(fields[9].Value); err != nil {
		return fmt.Errorf("invalid share proof: %w", err)
	}
	var paillierProofSessionID tss.SessionID
	if len(fields[11].Value) != len(paillierProofSessionID) {
		return fmt.Errorf("paillier proof session id length %d != %d", len(fields[11].Value), len(paillierProofSessionID))
	}
	copy(paillierProofSessionID[:], fields[11].Value)
	if !utf8.Valid(fields[12].Value) {
		return errors.New("paillier proof domain is not valid UTF-8")
	}
	logCiphertext, err := wire.DecodeBigPos(fields[13].Value)
	if err != nil {
		return fmt.Errorf("invalid log ciphertext: %w", err)
	}
	var logProof zkpai.LogStarProof
	if err := logProof.UnmarshalWireValue(fields[14].Value); err != nil {
		return fmt.Errorf("invalid log proof: %w", err)
	}
	if len(fields[16].Value) != 32 {
		return fmt.Errorf("plan hash length %d != 32", len(fields[16].Value))
	}
	var securityParams SecurityParams
	if err := wire.UnmarshalRecordValue(
		fields[17].Value,
		&securityParams,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return fmt.Errorf("invalid security params: %w", err)
	}
	if _, err := secpScalarFromSecret(&secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	decoded := keyShareState{
		securityParams:         securityParams,
		party:                  party,
		threshold:              int(threshold),
		parties:                parties,
		publicKey:              bytes.Clone(fields[3].Value),
		chainCode:              bytes.Clone(fields[4].Value),
		secret:                 secret.Clone(),
		groupCommitments:       cloneCommitmentPoints(groupCommitments),
		partyData:              partyData,
		paillierPrivateKey:     paillierPrivateKey.Clone(),
		shareProof:             shareProof.Clone(),
		keygenTranscriptHash:   bytes.Clone(fields[10].Value),
		paillierProofSessionID: paillierProofSessionID,
		paillierProofDomain:    string(fields[12].Value),
		logCiphertext:          logCiphertext,
		logProof:               logProof.Clone(),
		resharePlanHash:        bytes.Clone(fields[15].Value),
		planHash:               bytes.Clone(fields[16].Value),
	}
	if err := decoded.checkPartyDataKeys(); err != nil {
		return err
	}
	*state = decoded
	return nil
}

func requireKeyShareStateTags(fields []wire.Field) error {
	if len(fields) != 18 {
		return fmt.Errorf("key share state field count %d != 18", len(fields))
	}
	for i, field := range fields {
		want := uint16(i + 1)
		if field.Tag != want {
			return fmt.Errorf("key share state tag %d at index %d, want %d", field.Tag, i, want)
		}
	}
	return nil
}

func (state *keyShareState) checkPartyDataKeys() error {
	if len(state.partyData) != len(state.parties) {
		return fmt.Errorf("party data count %d != party count %d", len(state.partyData), len(state.parties))
	}
	for _, id := range state.parties {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		data, ok := state.partyData[id]
		if !ok {
			return fmt.Errorf("missing party data for participant %d", id)
		}
		if data.keygenConfirmation != nil && data.keygenConfirmation.Sender != id {
			return fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.keygenConfirmation.Sender, id)
		}
	}
	for id := range state.partyData {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		if !tss.ContainsParty(state.parties, id) {
			return fmt.Errorf("party data for non-participant %d", id)
		}
	}
	return nil
}

func uint32WireField(v int, name string) ([]byte, error) {
	if v < 0 || uint64(v) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("%s %d out of uint32 range", name, v)
	}
	return wire.Uint32(uint32(v)), nil
}

func marshalPartySetValue(parties tss.PartySet, maxItems int) ([]byte, error) {
	if maxItems > 0 && len(parties) > maxItems {
		return nil, fmt.Errorf("party count %d exceeds max_items=%d", len(parties), maxItems)
	}
	out := wire.Uint32(uint32(len(parties)))
	for _, id := range parties {
		out = append(out, wire.Uint32(id)...)
	}
	return out, nil
}

func unmarshalPartySetValue(raw []byte, maxItems int) (tss.PartySet, error) {
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if maxItems > 0 && int(count) > maxItems {
		return nil, fmt.Errorf("party count %d exceeds max_items=%d", count, maxItems)
	}
	if uint64(len(raw)-offset) != uint64(count)*4 {
		return nil, errors.New("invalid party list length")
	}
	out := make(tss.PartySet, int(count))
	for i := range int(count) {
		id, next, err := wire.ReadUint32(raw, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		out[i] = id
	}
	return out, nil
}

func marshalBytesListValue(values [][]byte, maxBytes, maxItems int, name string) ([]byte, error) {
	if maxItems > 0 && len(values) > maxItems {
		return nil, fmt.Errorf("%s count %d exceeds max_items=%d", name, len(values), maxItems)
	}
	out := wire.Uint32(uint32(len(values)))
	for i, value := range values {
		if maxBytes > 0 && len(value) > maxBytes {
			return nil, fmt.Errorf("%s item %d length %d exceeds max_bytes=%d", name, i, len(value), maxBytes)
		}
		out = wire.AppendBytes(out, wire.NonNilBytes(value))
	}
	return out, nil
}

func unmarshalBytesListValue(raw []byte, maxBytes, maxItems int, name string) ([][]byte, error) {
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if maxItems > 0 && int(count) > maxItems {
		return nil, fmt.Errorf("%s count %d exceeds max_items=%d", name, count, maxItems)
	}
	out := make([][]byte, int(count))
	for i := range int(count) {
		item, next, err := wire.ReadBytesWithLimit(raw, offset, maxBytes)
		if err != nil {
			return nil, fmt.Errorf("%s item %d: %w", name, i, err)
		}
		offset = next
		out[i] = item
	}
	if offset != len(raw) {
		return nil, fmt.Errorf("trailing %s data", name)
	}
	return out, nil
}

func marshalKeySharePartyDataMap(data map[tss.PartyID]keySharePartyData, limits Limits) ([]byte, error) {
	if len(data) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("party data count %d exceeds max_items=%d", len(data), limits.Threshold.MaxParties)
	}
	ids := make([]tss.PartyID, 0, len(data))
	for id, item := range data {
		if item.keygenConfirmation != nil && item.keygenConfirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", item.keygenConfirmation.Sender, id)
		}
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b tss.PartyID) int {
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		default:
			return 0
		}
	})
	out := wire.Uint32(uint32(len(ids)))
	for _, id := range ids {
		value, err := data[id].MarshalWireValue()
		if err != nil {
			return nil, fmt.Errorf("party data %d: %w", id, err)
		}
		out = wire.AppendBytes(out, wire.Uint32(id))
		out = wire.AppendBytes(out, value)
	}
	return out, nil
}

func unmarshalKeySharePartyDataMap(raw []byte, limits Limits) (map[tss.PartyID]keySharePartyData, error) {
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if int(count) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("party data count %d exceeds max_items=%d", count, limits.Threshold.MaxParties)
	}
	out := make(map[tss.PartyID]keySharePartyData, int(count))
	var prevKey []byte
	for i := range int(count) {
		keyBytes, next, err := wire.ReadBytesWithLimit(raw, offset, 4)
		if err != nil {
			return nil, fmt.Errorf("party data key %d: %w", i, err)
		}
		offset = next
		if len(keyBytes) != 4 {
			return nil, fmt.Errorf("party data key %d length %d, want 4", i, len(keyBytes))
		}
		if i > 0 && bytes.Compare(prevKey, keyBytes) >= 0 {
			return nil, fmt.Errorf("party data entries not strictly sorted at index %d", i)
		}
		prevKey = keyBytes
		valueBytes, next, err := wire.ReadBytesWithLimit(raw, offset, limits.State.MaxSerializedKeyShareBytes)
		if err != nil {
			return nil, fmt.Errorf("party data value %d: %w", i, err)
		}
		offset = next
		key, err := wire.DecodeUint32(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("party data key %d: %w", i, err)
		}
		id := key
		var value keySharePartyData
		if err := value.UnmarshalWireValue(valueBytes); err != nil {
			return nil, fmt.Errorf("party data %d: %w", id, err)
		}
		if _, ok := out[id]; ok {
			return nil, fmt.Errorf("party data duplicate key %d", id)
		}
		out[id] = value
	}
	if offset != len(raw) {
		return nil, errors.New("trailing party data map data")
	}
	return out, nil
}

// MarshalWireValue implements the wire.ValueMarshaler interface
func (data keySharePartyData) MarshalWireValue() ([]byte, error) {
	limits := DefaultLimits()
	paillierPublicKey, err := canonicalWireMessageBytes(data.paillierPublicKey, limits)
	if err != nil {
		return nil, fmt.Errorf("encode Paillier public key: %w", err)
	}
	paillierProof, err := canonicalWireMessageBytes(data.paillierProof, limits)
	if err != nil {
		return nil, fmt.Errorf("encode Paillier proof: %w", err)
	}
	ringPedersenParams, err := canonicalWireMessageBytes(data.ringPedersenParams, limits)
	if err != nil {
		return nil, fmt.Errorf("encode Ring-Pedersen parameters: %w", err)
	}
	ringPedersenProof, err := canonicalWireMessageBytes(data.ringPedersenProof, limits)
	if err != nil {
		return nil, fmt.Errorf("encode Ring-Pedersen proof: %w", err)
	}
	keygenConfirmation, err := wire.MarshalRecordValue(
		data.keygenConfirmation,
		wire.WithFieldLimitsForMarshal(limits.fieldLimits()),
	)
	if err != nil {
		return nil, fmt.Errorf("encode keygen confirmation: %w", err)
	}
	if err := checkKeySharePartyDataFieldSizes(data.verificationShare, paillierPublicKey, paillierProof, ringPedersenParams, ringPedersenProof, limits); err != nil {
		return nil, err
	}
	return wire.MarshalRecordFields([]wire.Field{
		{Tag: 1, Value: wire.NonNilBytes(bytes.Clone(data.verificationShare))},
		{Tag: 2, Value: paillierPublicKey},
		{Tag: 3, Value: paillierProof},
		{Tag: 4, Value: ringPedersenParams},
		{Tag: 5, Value: ringPedersenProof},
		{Tag: 6, Value: keygenConfirmation},
	})
}

// UnmarshalWireValue implements the wire.ValueUnmarshaler interface
func (data *keySharePartyData) UnmarshalWireValue(in []byte) error {
	if data == nil {
		return errors.New("nil key share party data")
	}
	limits := DefaultLimits()
	fields, err := wire.UnmarshalRecordFieldsWithLimits(
		in,
		limits.frameLimits(limits.State.MaxSerializedKeyShareBytes),
		"keySharePartyData",
	)
	if err != nil {
		return err
	}
	if err := requireKeySharePartyDataRecordTags(fields); err != nil {
		return err
	}
	if err := checkKeySharePartyDataFieldSizes(fields[0].Value, fields[1].Value, fields[2].Value, fields[3].Value, fields[4].Value, limits); err != nil {
		return err
	}
	paillierPublicKey, err := pai.UnmarshalPublicKeyWithMaxModulusBits(fields[1].Value, limits.Paillier.MaxModulusBits)
	if err != nil {
		return fmt.Errorf("invalid Paillier public key: %w", err)
	}
	paillierProof, err := tss.DecodeBinary[zkpai.ModulusProof](fields[2].Value)
	if err != nil {
		return fmt.Errorf("invalid Paillier proof: %w", err)
	}
	ringPedersenParams, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(fields[3].Value, limits.Paillier.MaxModulusBits)
	if err != nil {
		return fmt.Errorf("invalid Ring-Pedersen parameters: %w", err)
	}
	ringPedersenProof, err := tss.DecodeBinary[zkpai.RingPedersenProof](fields[4].Value)
	if err != nil {
		return fmt.Errorf("invalid Ring-Pedersen proof: %w", err)
	}
	var keygenConfirmation KeygenConfirmation
	if err := wire.UnmarshalRecordValue(
		fields[5].Value,
		&keygenConfirmation,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return fmt.Errorf("invalid keygen confirmation: %w", err)
	}
	*data = keySharePartyData{
		verificationShare:  bytes.Clone(fields[0].Value),
		paillierPublicKey:  paillierPublicKey,
		paillierProof:      paillierProof,
		ringPedersenParams: ringPedersenParams,
		ringPedersenProof:  ringPedersenProof,
		keygenConfirmation: keygenConfirmation.Clone(),
	}
	return nil
}

func requireKeySharePartyDataRecordTags(fields []wire.Field) error {
	if len(fields) != 6 {
		return fmt.Errorf("key share party data record field count %d != 6", len(fields))
	}
	for i, field := range fields {
		want := uint16(i + 1)
		if field.Tag != want {
			return fmt.Errorf("key share party data record tag %d at index %d, want %d", field.Tag, i, want)
		}
	}
	return nil
}

func checkKeySharePartyDataFieldSizes(verificationShare, paillierPublicKey, paillierProof, ringPedersenParams, ringPedersenProof []byte, limits Limits) error {
	if len(verificationShare) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("verification share too large: %d > %d", len(verificationShare), limits.Curve.MaxPointBytes)
	}
	if len(paillierPublicKey) > limits.Paillier.MaxPublicKeyBytes {
		return fmt.Errorf("paillier public key too large: %d > %d", len(paillierPublicKey), limits.Paillier.MaxPublicKeyBytes)
	}
	if len(paillierProof) > limits.ZK.MaxProofBytes {
		return fmt.Errorf("paillier proof too large: %d > %d", len(paillierProof), limits.ZK.MaxProofBytes)
	}
	if len(ringPedersenParams) > limits.Paillier.MaxRingPedersenBytes {
		return fmt.Errorf("Ring-Pedersen parameters too large: %d > %d", len(ringPedersenParams), limits.Paillier.MaxRingPedersenBytes)
	}
	if len(ringPedersenProof) > limits.Paillier.MaxProofBytes {
		return fmt.Errorf("Ring-Pedersen proof too large: %d > %d", len(ringPedersenProof), limits.Paillier.MaxProofBytes)
	}
	return nil
}

// WireType returns the canonical wire type identifier for KeyShare.
func (*KeyShare) WireType() string { return keyShareWireType }

// WireVersion returns the wire format version for KeyShare.
func (*KeyShare) WireVersion() uint16 { return keyShareWireVersion }

// MarshalWireMessage encodes KeyShare through its private state codec.
func (k *KeyShare) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	return k.state.MarshalWireMessage(opts...)
}

// UnmarshalWireMessage decodes KeyShare through its private state codec.
func (k *KeyShare) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var state keyShareState
	if err := state.UnmarshalWireMessage(in, opts...); err != nil {
		return err
	}
	k.state = &state
	return nil
}

// Clone returns an independently owned deep copy of the key share.
//
// The clone contains secret material and must be destroyed separately when it is
// no longer needed. Destroying the clone does not destroy the original, and
// destroying the original does not destroy the clone.
func (k *KeyShare) Clone() *KeyShare {
	return cloneKeyShareValue(k)
}

// presignWire is the wire DTO for Presign.
type presignWire struct {
	Party                tss.PartyID           `wire:"1,u32"`
	Threshold            int                   `wire:"2,u32"`
	Signers              tss.PartySet          `wire:"3,u32list"`
	R                    *secp.Point           `wire:"4,custom,len=33"`
	LittleR              secp.Scalar           `wire:"5,custom,len=32"`
	KShare               *secret.Scalar        `wire:"6,custom,len=32"`
	ChiShare             *secret.Scalar        `wire:"7,custom,len=32"`
	Delta                *secret.Scalar        `wire:"8,custom,len=32"`
	TranscriptHash       []byte                `wire:"9,bytes"`
	Context              PresignContext        `wire:"10,nested"`
	ContextHash          []byte                `wire:"11,bytes"`
	Consumed             bool                  `wire:"12,bool"`
	PublicKey            *secp.Point           `wire:"13,custom,len=33"`
	KeygenTranscriptHash []byte                `wire:"14,bytes"`
	PartiesHash          []byte                `wire:"15,bytes"`
	VerifyShares         []signVerifyShare     `wire:"16,recordlist,max_items=signers"`
	PlanHash             []byte                `wire:"17,bytes,len=32"`
	SecurityParams       SecurityParams        `wire:"18,record"`
	Derivation           *tss.DerivationResult `wire:"19,record"`
}

// WireType returns the canonical wire type identifier for presignWire.
func (presignWire) WireType() string { return presignWireType }

// WireVersion returns the wire format version for presignWire.
func (presignWire) WireVersion() uint16 { return presignWireVersion }

func decodePresignWire(w *presignWire) (*presignState, error) {
	if w.R == nil {
		return nil, errors.New("missing presign R")
	}
	if w.LittleR.IsZero() {
		return nil, errors.New("zero presign little r")
	}
	if w.PublicKey == nil {
		return nil, errors.New("missing presign public key")
	}
	if _, err := secpScalarFromSecret(w.KShare); err != nil {
		return nil, fmt.Errorf("invalid k share: %w", err)
	}
	if _, err := secpScalarFromSecret(w.ChiShare); err != nil {
		return nil, fmt.Errorf("invalid chi share: %w", err)
	}
	if _, err := secpScalarFromSecret(w.Delta); err != nil {
		return nil, fmt.Errorf("invalid delta: %w", err)
	}
	consumed := new(atomic.Bool)
	consumed.Store(w.Consumed)
	derivation := w.Derivation
	if derivation == nil {
		return nil, errors.New("missing presign derivation")
	}
	if err := validateDerivationResult(derivation, tss.DerivationSchemeBIP32Secp256k1); err != nil {
		return nil, fmt.Errorf("presign derivation result: %w", err)
	}
	return &presignState{
		securityParams:       w.SecurityParams,
		party:                w.Party,
		threshold:            w.Threshold,
		signers:              w.Signers,
		r:                    secp.Clone(w.R),
		littleR:              w.LittleR,
		transcriptHash:       slices.Clone(w.TranscriptHash),
		context:              w.Context,
		contextHash:          slices.Clone(w.ContextHash),
		derivation:           derivation,
		planHash:             slices.Clone(w.PlanHash),
		publicKey:            secp.Clone(w.PublicKey),
		keygenTranscriptHash: slices.Clone(w.KeygenTranscriptHash),
		partiesHash:          slices.Clone(w.PartiesHash),
		verifyShares:         tss.CloneSlice(w.VerifyShares),
		kShare:               w.KShare,
		chiShare:             w.ChiShare,
		delta:                w.Delta,
		consumed:             consumed,
		attempt:              newPresignAttemptBinding(w.Consumed),
	}, nil
}

// WireType returns the canonical wire type identifier for Presign.
func (*Presign) WireType() string { return presignWireType }

// WireVersion returns the wire format version for Presign.
func (*Presign) WireVersion() uint16 { return presignWireVersion }

// MarshalWireMessage encodes Presign through its private wire DTO.
func (p *Presign) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	return wire.Marshal(encodePresignWire(p), opts...)
}

// UnmarshalWireMessage decodes Presign through its private wire DTO.
func (p *Presign) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var w presignWire
	if err := wire.Unmarshal(in, &w, opts...); err != nil {
		return err
	}
	state, err := decodePresignWire(&w)
	if err != nil {
		return err
	}
	p.state = state
	return nil
}

func encodePresignWire(p *Presign) presignWire {
	return presignWire{
		Party:                p.state.party,
		Threshold:            p.state.threshold,
		Signers:              p.state.signers,
		R:                    p.state.r,
		LittleR:              p.state.littleR,
		KShare:               p.state.kShare,
		ChiShare:             p.state.chiShare,
		Delta:                p.state.delta,
		TranscriptHash:       p.state.transcriptHash,
		Context:              p.state.context,
		ContextHash:          p.state.contextHash,
		PlanHash:             p.state.planHash,
		Consumed:             IsPresignConsumed(p),
		PublicKey:            p.state.publicKey,
		KeygenTranscriptHash: p.state.keygenTranscriptHash,
		PartiesHash:          p.state.partiesHash,
		VerifyShares:         p.state.verifyShares,
		SecurityParams:       p.state.securityParams,
		Derivation:           p.state.derivation,
	}
}
