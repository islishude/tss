package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/wire"
)

const (
	keyShareWireType    = "frost.ed25519.keyshare"
	keyShareWireVersion = 1
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
	limits, err := frostKeyShareCodecLimits(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	}
	if err := (&KeyShare{state: state}).ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	if state.threshold < 0 || uint64(state.threshold) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("threshold %d out of uint32 range", state.threshold)
	}
	if len(state.parties) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("party count %d exceeds max_items=%d", len(state.parties), limits.Threshold.MaxParties)
	}
	parties, err := wire.EncodeUint32ListChecked(state.parties)
	if err != nil {
		return nil, fmt.Errorf("encode parties: %w", err)
	}
	publicKey, err := state.publicKey.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	if len(publicKey) > limits.Curve.MaxPointBytes {
		return nil, fmt.Errorf("public key too large: %d > %d", len(publicKey), limits.Curve.MaxPointBytes)
	}
	secretBytes, err := state.secret.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode secret: %w", err)
	}
	if len(secretBytes) > limits.Curve.MaxScalarBytes {
		return nil, fmt.Errorf("secret scalar too large: %d > %d", len(secretBytes), limits.Curve.MaxScalarBytes)
	}
	groupCommitments, err := state.groupCommitments.MarshalWireValue()
	if err != nil {
		return nil, err
	}
	if err := checkFROSTGroupCommitmentLimits(groupCommitments, limits); err != nil {
		return nil, err
	}
	partyData, err := marshalFROSTKeySharePartyDataMap(state.partyData, limits, opts...)
	if err != nil {
		return nil, err
	}
	fields := []wire.Field{
		{Tag: 1, Value: wire.Uint32(state.party)},
		{Tag: 2, Value: wire.Uint32(uint32(state.threshold))},
		{Tag: 3, Value: parties},
		{Tag: 4, Value: publicKey},
		{Tag: 5, Value: wire.NonNilBytes(bytes.Clone(state.chainCode))},
		{Tag: 6, Value: secretBytes},
		{Tag: 7, Value: groupCommitments},
		{Tag: 8, Value: partyData},
		{Tag: 9, Value: state.keygenSessionID[:]},
		{Tag: 10, Value: wire.NonNilBytes(bytes.Clone(state.keygenTranscriptHash))},
		{Tag: 11, Value: wire.NonNilBytes(bytes.Clone(state.planHash))},
	}
	return wire.MarshalMessageBody(state, fields)
}

// UnmarshalWireMessage decodes keyShareState directly without an intermediate DTO.
func (state *keyShareState) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if state == nil {
		return errors.New("nil key share state")
	}
	resolved := wire.ResolveUnmarshalOptions(opts...)
	limits, err := frostKeyShareCodecLimits(resolved.FieldLimits)
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
	if err := requireFROSTKeyShareStateTags(fields); err != nil {
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
	if uint64(threshold) > uint64(^uint(0)>>1) {
		return fmt.Errorf("key share threshold %d overflows int", threshold)
	}
	parties, err := wire.DecodeUint32ListWithLimit[tss.PartyID](fields[2].Value, limits.Threshold.MaxParties)
	if err != nil {
		return fmt.Errorf("invalid key share parties: %w", err)
	}
	if len(fields[3].Value) > limits.Curve.MaxPointBytes {
		return fmt.Errorf("public key too large: %d > %d", len(fields[3].Value), limits.Curve.MaxPointBytes)
	}
	var publicKey publicKeyPoint
	if err := publicKey.UnmarshalWireValue(fields[3].Value); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(fields[5].Value) > limits.Curve.MaxScalarBytes {
		return fmt.Errorf("secret scalar too large: %d > %d", len(fields[5].Value), limits.Curve.MaxScalarBytes)
	}
	var scalar secret.Scalar
	if err := scalar.UnmarshalWireValue(fields[5].Value); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if err := validateEdSecretScalar(&scalar); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if err := checkFROSTGroupCommitmentLimits(fields[6].Value, limits); err != nil {
		return err
	}
	commitmentBytes, err := wire.DecodeBytesListWithLimit(
		fields[6].Value,
		limits.Threshold.MaxThreshold,
		limits.Curve.MaxPointBytes,
	)
	if err != nil {
		return fmt.Errorf("decode group commitments: %w", err)
	}
	groupCommitments, err := newGroupCommitmentsFromBytesList(commitmentBytes, int(threshold))
	if err != nil {
		return fmt.Errorf("invalid group commitments: %w", err)
	}
	partyData, err := unmarshalFROSTKeySharePartyDataMap(
		fields[7].Value,
		limits,
		resolved.FrameLimits,
		opts...,
	)
	if err != nil {
		return err
	}
	var keygenSessionID tss.SessionID
	if len(fields[8].Value) != len(keygenSessionID) {
		return fmt.Errorf("keygen session id length %d != %d", len(fields[8].Value), len(keygenSessionID))
	}
	copy(keygenSessionID[:], fields[8].Value)
	if len(fields[10].Value) != 32 {
		return fmt.Errorf("plan hash length %d != 32", len(fields[10].Value))
	}
	decoded := keyShareState{
		party:                party,
		threshold:            int(threshold),
		parties:              parties,
		publicKey:            publicKey,
		chainCode:            bytes.Clone(fields[4].Value),
		secret:               scalar.Clone(),
		groupCommitments:     groupCommitments,
		partyData:            partyData,
		keygenSessionID:      keygenSessionID,
		keygenTranscriptHash: bytes.Clone(fields[9].Value),
		planHash:             bytes.Clone(fields[10].Value),
	}
	if err := decoded.checkPartyDataKeys(); err != nil {
		return err
	}
	*state = decoded
	return nil
}

func frostKeyShareCodecLimits(fieldLimits wire.FieldLimits) (Limits, error) {
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

func requireFROSTKeyShareStateTags(fields []wire.Field) error {
	if len(fields) != 11 {
		return fmt.Errorf("key share state field count %d != 11", len(fields))
	}
	for i, field := range fields {
		want := uint16(i + 1)
		if field.Tag != want {
			return fmt.Errorf("key share state tag %d at index %d, want %d", field.Tag, i, want)
		}
	}
	return nil
}

func checkFROSTGroupCommitmentLimits(raw []byte, limits Limits) error {
	commitments, err := wire.DecodeBytesListWithLimit(
		raw,
		limits.Threshold.MaxThreshold,
		limits.Curve.MaxPointBytes,
	)
	if err != nil {
		return fmt.Errorf("invalid group commitments: %w", err)
	}
	if len(commitments) > limits.Threshold.MaxThreshold {
		return fmt.Errorf(
			"group commitment count %d exceeds max_items=%d",
			len(commitments),
			limits.Threshold.MaxThreshold,
		)
	}
	return nil
}

func marshalFROSTKeySharePartyDataMap(
	data map[tss.PartyID]keySharePartyData,
	limits Limits,
	opts ...wire.MarshalOption,
) ([]byte, error) {
	if len(data) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("party data count %d exceeds max_items=%d", len(data), limits.Threshold.MaxParties)
	}
	ids := make([]tss.PartyID, 0, len(data))
	for id, item := range data {
		if item.keygenConfirmation != nil && item.keygenConfirmation.Sender != id {
			return nil, fmt.Errorf(
				"keygen confirmation sender %d does not match party data key %d",
				item.keygenConfirmation.Sender,
				id,
			)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if uint64(len(ids)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("party data count %d exceeds uint32", len(ids))
	}
	out := wire.Uint32(uint32(len(ids)))
	for _, id := range ids {
		value, err := marshalFROSTKeySharePartyData(data[id], limits, opts...)
		if err != nil {
			return nil, fmt.Errorf("party data %d: %w", id, err)
		}
		out, err = wire.AppendBytesChecked(out, wire.Uint32(id))
		if err != nil {
			return nil, fmt.Errorf("party data key %d: %w", id, err)
		}
		out, err = wire.AppendBytesChecked(out, value)
		if err != nil {
			return nil, fmt.Errorf("party data value %d: %w", id, err)
		}
	}
	return out, nil
}

func unmarshalFROSTKeySharePartyDataMap(
	raw []byte,
	limits Limits,
	frameLimits wire.FrameLimits,
	opts ...wire.UnmarshalOption,
) (map[tss.PartyID]keySharePartyData, error) {
	count, offset, err := wire.ReadUint32(raw, 0)
	if err != nil {
		return nil, err
	}
	if uint64(count) > uint64(limits.Threshold.MaxParties) {
		return nil, fmt.Errorf("party data count %d exceeds max_items=%d", count, limits.Threshold.MaxParties)
	}
	out := make(map[tss.PartyID]keySharePartyData, int(count))
	var previous []byte
	for i := 0; i < int(count); i++ {
		keyBytes, next, err := wire.ReadBytesWithLimit(raw, offset, 4)
		if err != nil {
			return nil, fmt.Errorf("party data key %d: %w", i, err)
		}
		offset = next
		if len(keyBytes) != 4 {
			return nil, fmt.Errorf("party data key %d length %d, want 4", i, len(keyBytes))
		}
		if i > 0 && bytes.Compare(previous, keyBytes) >= 0 {
			return nil, fmt.Errorf("party data entries not strictly sorted at index %d", i)
		}
		previous = keyBytes
		valueBytes, next, err := wire.ReadBytesWithLimit(raw, offset, frameLimits.MaxFieldBytes)
		if err != nil {
			return nil, fmt.Errorf("party data value %d: %w", i, err)
		}
		offset = next
		id, err := wire.DecodeUint32(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("party data key %d: %w", i, err)
		}
		var value keySharePartyData
		if err := unmarshalFROSTKeySharePartyData(valueBytes, &value, limits, frameLimits, opts...); err != nil {
			return nil, fmt.Errorf("party data %d: %w", id, err)
		}
		if value.keygenConfirmation != nil && value.keygenConfirmation.Sender != id {
			return nil, fmt.Errorf(
				"keygen confirmation sender %d does not match party data key %d",
				value.keygenConfirmation.Sender,
				id,
			)
		}
		if _, exists := out[id]; exists {
			return nil, fmt.Errorf("party data duplicate key %d", id)
		}
		out[id] = value
	}
	if offset != len(raw) {
		return nil, errors.New("trailing party data map data")
	}
	return out, nil
}

// MarshalWireValue implements wire.ValueMarshaler for keySharePartyData.
func (data keySharePartyData) MarshalWireValue() ([]byte, error) {
	limits := DefaultLimits()
	return marshalFROSTKeySharePartyData(
		data,
		limits,
		wire.WithFieldLimitsForMarshal(limits.fieldLimits()),
	)
}

func marshalFROSTKeySharePartyData(
	data keySharePartyData,
	limits Limits,
	opts ...wire.MarshalOption,
) ([]byte, error) {
	verificationShare, err := data.verificationShare.MarshalWireValue()
	if err != nil {
		return nil, fmt.Errorf("encode verification share: %w", err)
	}
	if len(verificationShare) > limits.Curve.MaxPointBytes {
		return nil, fmt.Errorf(
			"verification share too large: %d > %d",
			len(verificationShare),
			limits.Curve.MaxPointBytes,
		)
	}
	fields := []wire.Field{{Tag: 1, Value: verificationShare}}
	if data.keygenConfirmation != nil {
		confirmation, err := wire.MarshalRecordValue(data.keygenConfirmation, opts...)
		if err != nil {
			return nil, fmt.Errorf("encode keygen confirmation: %w", err)
		}
		fields = append(fields, wire.Field{Tag: 2, Value: confirmation})
	}
	return wire.MarshalRecordFields(fields)
}

// UnmarshalWireValue implements wire.ValueUnmarshaler for keySharePartyData.
func (data *keySharePartyData) UnmarshalWireValue(in []byte) error {
	if data == nil {
		return errors.New("nil key share party data")
	}
	limits := DefaultLimits()
	frameLimits := limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)
	return unmarshalFROSTKeySharePartyData(
		in,
		data,
		limits,
		frameLimits,
		wire.WithFrameLimits(frameLimits),
		wire.WithFieldLimits(limits.fieldLimits()),
	)
}

func unmarshalFROSTKeySharePartyData(
	in []byte,
	data *keySharePartyData,
	limits Limits,
	frameLimits wire.FrameLimits,
	opts ...wire.UnmarshalOption,
) error {
	if data == nil {
		return errors.New("nil key share party data")
	}
	fields, err := wire.UnmarshalRecordFieldsWithLimits(in, frameLimits, "keySharePartyData")
	if err != nil {
		return err
	}
	if len(fields) != 1 && len(fields) != 2 {
		return fmt.Errorf("key share party data record field count %d is not 1 or 2", len(fields))
	}
	if fields[0].Tag != 1 {
		return fmt.Errorf("key share party data record first tag %d, want 1", fields[0].Tag)
	}
	if len(fields) == 2 && fields[1].Tag != 2 {
		return fmt.Errorf("key share party data record second tag %d, want 2", fields[1].Tag)
	}
	if len(fields[0].Value) > limits.Curve.MaxPointBytes {
		return fmt.Errorf(
			"verification share too large: %d > %d",
			len(fields[0].Value),
			limits.Curve.MaxPointBytes,
		)
	}
	var verificationShare verificationSharePoint
	if err := verificationShare.UnmarshalWireValue(fields[0].Value); err != nil {
		return fmt.Errorf("invalid verification share: %w", err)
	}
	var confirmation *KeygenConfirmation
	if len(fields) == 2 {
		var decoded KeygenConfirmation
		if err := wire.UnmarshalRecordValue(fields[1].Value, &decoded, opts...); err != nil {
			return fmt.Errorf("invalid keygen confirmation: %w", err)
		}
		confirmation = decoded.Clone()
	}
	*data = keySharePartyData{
		verificationShare:  verificationShare,
		keygenConfirmation: confirmation,
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
			return fmt.Errorf(
				"keygen confirmation sender %d does not match party data key %d",
				data.keygenConfirmation.Sender,
				id,
			)
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

// ValidateWithLimits checks KeyShare against explicit local resource limits.
func (k *KeyShare) ValidateWithLimits(limits Limits) error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if k.state.threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("threshold too large: %d > %d", k.state.threshold, limits.Threshold.MaxThreshold)
	}
	if len(k.state.parties) > limits.Threshold.MaxParties {
		return fmt.Errorf("parties too large: %d > %d", len(k.state.parties), limits.Threshold.MaxParties)
	}
	if k.state.groupCommitments.Len() > limits.Threshold.MaxThreshold {
		return fmt.Errorf(
			"group commitments too large: %d > %d",
			k.state.groupCommitments.Len(),
			limits.Threshold.MaxThreshold,
		)
	}
	for i, commitment := range k.state.groupCommitments.BytesList() {
		if len(commitment) > limits.Curve.MaxPointBytes {
			return fmt.Errorf(
				"group commitment %d too large: %d > %d",
				i,
				len(commitment),
				limits.Curve.MaxPointBytes,
			)
		}
	}
	if len(k.state.partyData) > limits.Threshold.MaxParties {
		return fmt.Errorf("party data too large: %d > %d", len(k.state.partyData), limits.Threshold.MaxParties)
	}
	confirmationCount := 0
	for id, data := range k.state.partyData {
		encoded := data.verificationShare.Bytes()
		if len(encoded) > limits.Curve.MaxPointBytes {
			return fmt.Errorf(
				"verification share for party %d too large: %d > %d",
				id,
				len(encoded),
				limits.Curve.MaxPointBytes,
			)
		}
		if data.keygenConfirmation != nil {
			confirmationCount++
		}
	}
	if confirmationCount > limits.Threshold.MaxParties {
		return fmt.Errorf(
			"keygen confirmations too large: %d > %d",
			confirmationCount,
			limits.Threshold.MaxParties,
		)
	}
	return k.ValidateConsistency()
}

// Clone returns an independently owned deep copy of the key share.
//
// The clone contains secret material and must be destroyed separately when it is
// no longer needed. Destroying the clone does not destroy the original, and
// destroying the original does not destroy the clone.
func (k *KeyShare) Clone() *KeyShare {
	return cloneKeyShareValue(k)
}
