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
	resolved := wire.ResolveMarshalOptions(opts...)
	limits, err := keyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	}
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
	partyData, err := marshalKeySharePartyDataMap(state.partyData, limits, opts...)
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
		opts...,
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
	resolved := wire.ResolveUnmarshalOptions(opts...)
	limits, err := keyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return err
	}
	limits.State.MaxSerializedKeyShareBytes = resolved.FrameLimits.MaxTotalBytes
	limits.TLV.MaxFields = resolved.FrameLimits.MaxFields
	limits.TLV.MaxFieldBytes = resolved.FrameLimits.MaxFieldBytes
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimits(limits.fieldLimits()))
	}
	fields, err := wire.UnmarshalMessageBody(in, state, opts...)
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
	partyData, err := unmarshalKeySharePartyDataMap(fields[7].Value, limits, resolved.FrameLimits, opts...)
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
		opts...,
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

func keyShareCodecLimits(fieldLimits wire.FieldLimits) (Limits, error) {
	limits := DefaultLimits()
	if fieldLimits == nil {
		return limits, nil
	}
	required := []struct {
		name string
		dst  *int
	}{
		{name: "scalar", dst: &limits.Curve.MaxScalarBytes},
		{name: "point", dst: &limits.Curve.MaxPointBytes},
		{name: "parties", dst: &limits.Threshold.MaxParties},
		{name: "threshold", dst: &limits.Threshold.MaxThreshold},
		{name: "paillier_modulus_bits", dst: &limits.Paillier.MaxModulusBits},
		{name: "paillier_public_key", dst: &limits.Paillier.MaxPublicKeyBytes},
		{name: "paillier_private_key", dst: &limits.Paillier.MaxPrivateKeyBytes},
		{name: "paillier_ciphertext", dst: &limits.Paillier.MaxCiphertextBytes},
		{name: "paillier_proof", dst: &limits.Paillier.MaxProofBytes},
		{name: "ring_pedersen_params", dst: &limits.Paillier.MaxRingPedersenBytes},
		{name: "zk_proof", dst: &limits.ZK.MaxProofBytes},
	}
	for _, item := range required {
		value, ok := fieldLimits[item.name]
		if !ok {
			return Limits{}, fmt.Errorf("wire: missing field limit %q for key share state", item.name)
		}
		if value <= 0 {
			return Limits{}, fmt.Errorf("wire: field limit %q for key share state must be positive", item.name)
		}
		*item.dst = value
	}
	return limits, nil
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

func marshalKeySharePartyDataMap(data map[tss.PartyID]keySharePartyData, limits Limits, opts ...wire.MarshalOption) ([]byte, error) {
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
		value, err := marshalKeySharePartyData(data[id], limits, opts...)
		if err != nil {
			return nil, fmt.Errorf("party data %d: %w", id, err)
		}
		out = wire.AppendBytes(out, wire.Uint32(id))
		out = wire.AppendBytes(out, value)
	}
	return out, nil
}

func unmarshalKeySharePartyDataMap(
	raw []byte,
	limits Limits,
	frameLimits wire.FrameLimits,
	opts ...wire.UnmarshalOption,
) (map[tss.PartyID]keySharePartyData, error) {
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
		valueBytes, next, err := wire.ReadBytesWithLimit(raw, offset, frameLimits.MaxFieldBytes)
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
		if err := unmarshalKeySharePartyData(valueBytes, &value, limits, frameLimits, opts...); err != nil {
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
	return marshalKeySharePartyData(
		data,
		limits,
		wire.WithFieldLimitsForMarshal(limits.fieldLimits()),
	)
}

func marshalKeySharePartyData(data keySharePartyData, limits Limits, opts ...wire.MarshalOption) ([]byte, error) {
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
		opts...,
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
	frameLimits := limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)
	return unmarshalKeySharePartyData(
		in,
		data,
		limits,
		frameLimits,
		wire.WithFrameLimits(frameLimits),
		wire.WithFieldLimits(limits.fieldLimits()),
	)
}

func unmarshalKeySharePartyData(
	in []byte,
	data *keySharePartyData,
	limits Limits,
	frameLimits wire.FrameLimits,
	opts ...wire.UnmarshalOption,
) error {
	if data == nil {
		return errors.New("nil key share party data")
	}
	fields, err := wire.UnmarshalRecordFieldsWithLimits(
		in,
		frameLimits,
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
		opts...,
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

// WireType returns the canonical wire type identifier for presignState.
func (*presignState) WireType() string { return presignWireType }

// WireVersion returns the wire format version for presignState.
func (*presignState) WireVersion() uint16 { return presignWireVersion }

// MarshalWireMessage encodes presignState directly without an intermediate DTO.
func (state *presignState) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if state == nil {
		return nil, errors.New("nil presign state")
	}
	resolved := wire.ResolveMarshalOptions(opts...)
	limits, err := presignCodecLimits(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	}
	threshold, err := uint32WireField(state.threshold, "threshold")
	if err != nil {
		return nil, err
	}
	signers, err := marshalPartySetValue(state.signers, limits.Threshold.MaxSigners)
	if err != nil {
		return nil, fmt.Errorf("encode signers: %w", err)
	}
	r, err := state.r.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode presign R: %w", err)
	}
	if len(r) > limits.Curve.MaxPointBytes {
		return nil, fmt.Errorf("presign R too large: %d > %d", len(r), limits.Curve.MaxPointBytes)
	}
	littleR, err := state.littleR.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode little r: %w", err)
	}
	kShare, err := state.kShare.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode k share: %w", err)
	}
	chiShare, err := state.chiShare.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode chi share: %w", err)
	}
	delta, err := state.delta.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode delta: %w", err)
	}
	for name, raw := range map[string][]byte{
		"little r":  littleR,
		"k share":   kShare,
		"chi share": chiShare,
		"delta":     delta,
	} {
		if len(raw) != secp.ScalarSize {
			return nil, fmt.Errorf("%s length %d != %d", name, len(raw), secp.ScalarSize)
		}
		if len(raw) > limits.Curve.MaxScalarBytes {
			return nil, fmt.Errorf("%s too large: %d > %d", name, len(raw), limits.Curve.MaxScalarBytes)
		}
	}
	context, err := wire.Marshal(state.context, opts...)
	if err != nil {
		return nil, fmt.Errorf("encode presign context: %w", err)
	}
	publicKey, err := state.publicKey.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode presign public key: %w", err)
	}
	if len(publicKey) > limits.Curve.MaxPointBytes {
		return nil, fmt.Errorf("presign public key too large: %d > %d", len(publicKey), limits.Curve.MaxPointBytes)
	}
	verifyShares, err := marshalPresignVerifyShares(state.verifyShares, limits, opts...)
	if err != nil {
		return nil, err
	}
	securityParams, err := wire.MarshalRecordValue(state.securityParams, opts...)
	if err != nil {
		return nil, fmt.Errorf("encode presign security params: %w", err)
	}
	derivation, err := wire.MarshalRecordValue(state.derivation, opts...)
	if err != nil {
		return nil, fmt.Errorf("encode presign derivation: %w", err)
	}
	fields := []wire.Field{
		{Tag: 1, Value: wire.Uint32(state.party)},
		{Tag: 2, Value: threshold},
		{Tag: 3, Value: signers},
		{Tag: 4, Value: r},
		{Tag: 5, Value: littleR},
		{Tag: 6, Value: kShare},
		{Tag: 7, Value: chiShare},
		{Tag: 8, Value: delta},
		{Tag: 9, Value: wire.NonNilBytes(bytes.Clone(state.transcriptHash))},
		{Tag: 10, Value: context},
		{Tag: 11, Value: wire.NonNilBytes(bytes.Clone(state.contextHash))},
		{Tag: 12, Value: wire.Bool(state.consumed == nil || state.consumed.Load())},
		{Tag: 13, Value: publicKey},
		{Tag: 14, Value: wire.NonNilBytes(bytes.Clone(state.keygenTranscriptHash))},
		{Tag: 15, Value: wire.NonNilBytes(bytes.Clone(state.partiesHash))},
		{Tag: 16, Value: verifyShares},
		{Tag: 17, Value: wire.NonNilBytes(bytes.Clone(state.planHash))},
		{Tag: 18, Value: securityParams},
		{Tag: 19, Value: derivation},
	}
	return wire.MarshalMessageBody(state, fields)
}

// UnmarshalWireMessage decodes presignState directly without an intermediate DTO.
func (state *presignState) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if state == nil {
		return errors.New("nil presign state")
	}
	resolved := wire.ResolveUnmarshalOptions(opts...)
	limits, err := presignCodecLimits(resolved.FieldLimits)
	if err != nil {
		return err
	}
	limits.State.MaxSerializedPresignBytes = resolved.FrameLimits.MaxTotalBytes
	limits.TLV.MaxFields = resolved.FrameLimits.MaxFields
	limits.TLV.MaxFieldBytes = resolved.FrameLimits.MaxFieldBytes
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimits(limits.fieldLimits()))
	}
	fields, err := wire.UnmarshalMessageBody(in, state, opts...)
	if err != nil {
		return err
	}
	if err := requirePresignStateTags(fields); err != nil {
		return err
	}
	party, err := wire.DecodeUint32(fields[0].Value)
	if err != nil {
		return fmt.Errorf("invalid presign party: %w", err)
	}
	threshold, err := wire.DecodeUint32(fields[1].Value)
	if err != nil {
		return fmt.Errorf("invalid presign threshold: %w", err)
	}
	if uint64(threshold) > uint64(^uint(0)>>1) {
		return fmt.Errorf("presign threshold %d overflows int", threshold)
	}
	signers, err := unmarshalPartySetValue(fields[2].Value, limits.Threshold.MaxSigners)
	if err != nil {
		return fmt.Errorf("invalid presign signers: %w", err)
	}
	if len(fields[3].Value) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("presign R too large: %d > %d", len(fields[3].Value), limits.Curve.MaxPointBytes)
	}
	var r secp.Point
	if err := r.UnmarshalWireValue(fields[3].Value); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	var littleR secp.Scalar
	if err := littleR.UnmarshalWireValue(fields[4].Value); err != nil {
		return fmt.Errorf("invalid presign little r: %w", err)
	}
	if littleR.IsZero() {
		return errors.New("zero presign little r")
	}
	var kShare, chiShare, delta secret.Scalar
	secrets := []*secret.Scalar{&kShare, &chiShare, &delta}
	keepSecrets := false
	defer func() {
		if keepSecrets {
			return
		}
		for _, scalar := range secrets {
			scalar.Destroy()
		}
	}()
	for _, item := range []struct {
		name string
		raw  []byte
		dst  *secret.Scalar
	}{
		{name: "k share", raw: fields[5].Value, dst: &kShare},
		{name: "chi share", raw: fields[6].Value, dst: &chiShare},
		{name: "delta", raw: fields[7].Value, dst: &delta},
	} {
		if len(item.raw) > limits.Curve.MaxScalarBytes {
			return fmt.Errorf("%s too large: %d > %d", item.name, len(item.raw), limits.Curve.MaxScalarBytes)
		}
		if err := item.dst.UnmarshalWireValue(item.raw); err != nil {
			return fmt.Errorf("invalid %s: %w", item.name, err)
		}
		if _, err := secpScalarFromSecret(item.dst); err != nil {
			return fmt.Errorf("invalid %s: %w", item.name, err)
		}
	}
	var context PresignContext
	if err := wire.Unmarshal(fields[9].Value, &context, opts...); err != nil {
		return fmt.Errorf("invalid presign context: %w", err)
	}
	consumed, err := wire.DecodeBool(fields[11].Value)
	if err != nil {
		return fmt.Errorf("invalid presign consumed flag: %w", err)
	}
	if len(fields[12].Value) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("presign public key too large: %d > %d", len(fields[12].Value), limits.Curve.MaxPointBytes)
	}
	var publicKey secp.Point
	if err := publicKey.UnmarshalWireValue(fields[12].Value); err != nil {
		return fmt.Errorf("invalid presign public key: %w", err)
	}
	verifyShares, err := unmarshalPresignVerifyShares(
		fields[15].Value,
		limits,
		resolved.FrameLimits,
		opts...,
	)
	if err != nil {
		return err
	}
	if len(fields[16].Value) != 32 {
		return fmt.Errorf("presign plan hash length %d != 32", len(fields[16].Value))
	}
	var securityParams SecurityParams
	if err := wire.UnmarshalRecordValue(fields[17].Value, &securityParams, opts...); err != nil {
		return fmt.Errorf("invalid presign security params: %w", err)
	}
	var derivation tss.DerivationResult
	if err := wire.UnmarshalRecordValue(fields[18].Value, &derivation, opts...); err != nil {
		return fmt.Errorf("invalid presign derivation: %w", err)
	}
	if err := validateDerivationResult(&derivation, tss.DerivationSchemeBIP32Secp256k1); err != nil {
		return fmt.Errorf("presign derivation result: %w", err)
	}
	consumedState := new(atomic.Bool)
	consumedState.Store(consumed)
	decoded := presignState{
		securityParams:       securityParams,
		party:                party,
		threshold:            int(threshold),
		signers:              signers,
		r:                    secp.Clone(&r),
		littleR:              littleR,
		transcriptHash:       bytes.Clone(fields[8].Value),
		context:              context.Clone(),
		contextHash:          bytes.Clone(fields[10].Value),
		derivation:           derivation.Clone(),
		planHash:             bytes.Clone(fields[16].Value),
		publicKey:            secp.Clone(&publicKey),
		keygenTranscriptHash: bytes.Clone(fields[13].Value),
		partiesHash:          bytes.Clone(fields[14].Value),
		verifyShares:         tss.CloneSlice(verifyShares),
		kShare:               &kShare,
		chiShare:             &chiShare,
		delta:                &delta,
		consumed:             consumedState,
		attempt:              newPresignAttemptBinding(consumed),
	}
	keepSecrets = true
	*state = decoded
	return nil
}

func presignCodecLimits(fieldLimits wire.FieldLimits) (Limits, error) {
	limits := DefaultLimits()
	if fieldLimits == nil {
		return limits, nil
	}
	required := []struct {
		name string
		dst  *int
	}{
		{name: "scalar", dst: &limits.Curve.MaxScalarBytes},
		{name: "point", dst: &limits.Curve.MaxPointBytes},
		{name: "signers", dst: &limits.Threshold.MaxSigners},
		{name: "threshold", dst: &limits.Threshold.MaxThreshold},
		{name: "signprep_proof", dst: &limits.SignPrep.MaxProofBytes},
	}
	for _, item := range required {
		value, ok := fieldLimits[item.name]
		if !ok {
			return Limits{}, fmt.Errorf("wire: missing field limit %q for presign state", item.name)
		}
		if value <= 0 {
			return Limits{}, fmt.Errorf("wire: field limit %q for presign state must be positive", item.name)
		}
		*item.dst = value
	}
	return limits, nil
}

func requirePresignStateTags(fields []wire.Field) error {
	if len(fields) != 19 {
		return fmt.Errorf("presign state field count %d != 19", len(fields))
	}
	for i, field := range fields {
		want := uint16(i + 1)
		if field.Tag != want {
			return fmt.Errorf("presign state tag %d at index %d, want %d", field.Tag, i, want)
		}
	}
	return nil
}

func marshalPresignVerifyShares(
	shares []signVerifyShare,
	limits Limits,
	opts ...wire.MarshalOption,
) ([]byte, error) {
	if len(shares) > limits.Threshold.MaxSigners {
		return nil, fmt.Errorf("verify shares count %d exceeds max_items=%d", len(shares), limits.Threshold.MaxSigners)
	}
	out := wire.Uint32(uint32(len(shares)))
	for i, share := range shares {
		record, err := wire.MarshalRecordValue(share, opts...)
		if err != nil {
			return nil, fmt.Errorf("verify shares item %d: %w", i, err)
		}
		out = wire.AppendBytes(out, record)
	}
	return out, nil
}

func unmarshalPresignVerifyShares(
	raw []byte,
	limits Limits,
	frameLimits wire.FrameLimits,
	opts ...wire.UnmarshalOption,
) ([]signVerifyShare, error) {
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid verify shares count: %w", err)
	}
	if int(count) > limits.Threshold.MaxSigners {
		return nil, fmt.Errorf("verify shares count %d exceeds max_items=%d", count, limits.Threshold.MaxSigners)
	}
	out := make([]signVerifyShare, int(count))
	for i := range int(count) {
		record, next, err := wire.ReadBytesWithLimit(raw, offset, frameLimits.MaxFieldBytes)
		if err != nil {
			return nil, fmt.Errorf("verify shares item %d: %w", i, err)
		}
		offset = next
		if err := wire.UnmarshalRecordValue(record, &out[i], opts...); err != nil {
			return nil, fmt.Errorf("verify shares item %d: %w", i, err)
		}
	}
	if offset != len(raw) {
		return nil, errors.New("trailing verify shares data")
	}
	return out, nil
}

// WireType returns the canonical wire type identifier for Presign.
func (*Presign) WireType() string { return presignWireType }

// WireVersion returns the wire format version for Presign.
func (*Presign) WireVersion() uint16 { return presignWireVersion }

// MarshalWireMessage encodes Presign through its private state codec.
func (p *Presign) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil presign")
	}
	return p.state.MarshalWireMessage(opts...)
}

// UnmarshalWireMessage decodes Presign through its private state codec.
func (p *Presign) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	var state presignState
	if err := state.UnmarshalWireMessage(in, opts...); err != nil {
		return err
	}
	p.state = &state
	return nil
}
