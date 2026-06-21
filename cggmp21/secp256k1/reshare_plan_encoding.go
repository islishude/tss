package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const (
	resharePlanWireType           = "cggmp21.secp256k1.reshare-plan"
	resharePlanWireVersion uint16 = 1
)

// MarshalBinary returns the canonical wire encoding of p.
func (p *ResharePlan) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil reshare plan")
	}
	return p.MarshalBinaryWithLimits(p.limits)
}

// MarshalBinaryWithLimits returns the canonical wire encoding of p using
// explicit local resource limits.
func (p *ResharePlan) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil reshare plan")
	}
	if err := p.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	raw, err := p.MarshalWireMessage(wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil {
		return nil, err
	}
	if len(raw) > limits.State.MaxSerializedResharePlanBytes {
		return nil, fmt.Errorf("reshare plan too large: %d > %d", len(raw), limits.State.MaxSerializedResharePlanBytes)
	}
	return raw, nil
}

// UnmarshalBinary decodes and validates a canonical reshare plan.
func (p *ResharePlan) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical reshare plan into the receiver
// using explicit local resource limits.
func (p *ResharePlan) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if p == nil {
		return errors.New("nil reshare plan")
	}
	if len(in) > limits.State.MaxSerializedResharePlanBytes {
		return fmt.Errorf("reshare plan too large: %d > %d", len(in), limits.State.MaxSerializedResharePlanBytes)
	}
	var decoded ResharePlan
	if err := decoded.UnmarshalWireMessage(in,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedResharePlanBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	decoded.limits = limits
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*p = decoded
	return nil
}

// WireType returns the canonical wire type identifier for ResharePlan.
func (*ResharePlan) WireType() string { return resharePlanWireType }

// WireVersion returns the wire format version for ResharePlan.
func (*ResharePlan) WireVersion() uint16 { return resharePlanWireVersion }

// MarshalWireMessage encodes ResharePlan directly without an intermediate DTO.
func (p *ResharePlan) MarshalWireMessage(opts ...wire.MarshalOption) ([]byte, error) {
	if p == nil || p.state == nil {
		return nil, errors.New("nil reshare plan")
	}
	resolved := wire.ResolveMarshalOptions(opts...)
	config, err := resharePlanCodecConfig(resolved.FieldLimits)
	if err != nil {
		return nil, err
	}
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimitsForMarshal(config.limits.fieldLimits()))
	}
	if err := p.ValidateWithLimits(config.limits); err != nil {
		return nil, err
	}
	if err := checkResharePlanWireBytes([]byte(p.state.curveID), config.maxCurveIDBytes, "curve id"); err != nil {
		return nil, err
	}
	if err := checkResharePlanWireBytes(p.state.oldGroupPublicKey, config.limits.Curve.MaxPointBytes, "old group public key"); err != nil {
		return nil, err
	}
	oldGroupCommitments, err := marshalBytesListValue(
		p.state.oldGroupCommitments,
		config.limits.Curve.MaxPointBytes,
		config.limits.Threshold.MaxThreshold,
		"old group commitments",
	)
	if err != nil {
		return nil, err
	}
	oldVerificationShares, err := marshalResharePlanVerificationShares(p.state, config.limits)
	if err != nil {
		return nil, err
	}
	oldParties, err := marshalPartySetValue(p.state.oldParties, config.limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("encode old parties: %w", err)
	}
	oldThreshold, err := uint32WireField(p.state.oldThreshold, "old threshold")
	if err != nil {
		return nil, err
	}
	dealerParties, err := marshalPartySetValue(p.state.dealerParties, config.limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("encode dealer parties: %w", err)
	}
	newParties, err := marshalPartySetValue(p.state.newParties, config.limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("encode new parties: %w", err)
	}
	newThreshold, err := uint32WireField(p.state.newThreshold, "new threshold")
	if err != nil {
		return nil, err
	}
	if err := checkResharePlanWireBytes(p.state.chainCode, config.limits.Curve.MaxScalarBytes, "chain code"); err != nil {
		return nil, err
	}
	paillierBits, err := uint32WireField(p.state.paillierBits, "paillier bits")
	if err != nil {
		return nil, err
	}
	securityParams, err := wire.MarshalRecordValue(p.state.securityParams, opts...)
	if err != nil {
		return nil, fmt.Errorf("encode reshare security params: %w", err)
	}
	fields := []wire.Field{
		{Tag: 1, Value: p.state.sessionID[:]},
		{Tag: 2, Value: []byte(p.state.curveID)},
		{Tag: 3, Value: wire.NonNilBytes(bytes.Clone(p.state.oldGroupPublicKey))},
		{Tag: 4, Value: oldGroupCommitments},
		{Tag: 5, Value: oldVerificationShares},
		{Tag: 6, Value: oldParties},
		{Tag: 7, Value: oldThreshold},
		{Tag: 8, Value: dealerParties},
		{Tag: 9, Value: newParties},
		{Tag: 10, Value: newThreshold},
		{Tag: 11, Value: wire.NonNilBytes(bytes.Clone(p.state.chainCode))},
		{Tag: 12, Value: paillierBits},
		{Tag: 13, Value: securityParams},
	}
	return wire.MarshalMessageBody(p, fields)
}

// UnmarshalWireMessage decodes ResharePlan directly without an intermediate DTO.
func (p *ResharePlan) UnmarshalWireMessage(in []byte, opts ...wire.UnmarshalOption) error {
	if p == nil {
		return errors.New("nil reshare plan")
	}
	resolved := wire.ResolveUnmarshalOptions(opts...)
	config, err := resharePlanCodecConfig(resolved.FieldLimits)
	if err != nil {
		return err
	}
	config.limits.State.MaxSerializedResharePlanBytes = resolved.FrameLimits.MaxTotalBytes
	config.limits.TLV.MaxFields = resolved.FrameLimits.MaxFields
	config.limits.TLV.MaxFieldBytes = resolved.FrameLimits.MaxFieldBytes
	if resolved.FieldLimits == nil {
		opts = append(opts, wire.WithFieldLimits(config.limits.fieldLimits()))
	}
	fields, err := wire.UnmarshalMessageBody(in, p, opts...)
	if err != nil {
		return err
	}
	if err := requireResharePlanTags(fields); err != nil {
		return err
	}
	state, err := decodeResharePlanFields(fields, config, opts...)
	if err != nil {
		return err
	}
	decoded := ResharePlan{state: state, limits: config.limits}
	if err := decoded.ValidateWithLimits(config.limits); err != nil {
		return err
	}
	*p = decoded
	return nil
}

type resharePlanCodecOptions struct {
	limits          Limits
	maxCurveIDBytes int
}

func resharePlanCodecConfig(fieldLimits wire.FieldLimits) (resharePlanCodecOptions, error) {
	limits := DefaultLimits()
	defaults := limits.fieldLimits()
	if fieldLimits == nil {
		return resharePlanCodecOptions{
			limits:          limits,
			maxCurveIDBytes: defaults["curve_id"],
		}, nil
	}
	required := []struct {
		name string
		dst  *int
	}{
		{name: "point", dst: &limits.Curve.MaxPointBytes},
		{name: "scalar", dst: &limits.Curve.MaxScalarBytes},
		{name: "parties", dst: &limits.Threshold.MaxParties},
		{name: "threshold", dst: &limits.Threshold.MaxThreshold},
		{name: "paillier_modulus_bits", dst: &limits.Paillier.MaxModulusBits},
	}
	for _, item := range required {
		value, ok := fieldLimits[item.name]
		if !ok {
			return resharePlanCodecOptions{}, fmt.Errorf("wire: missing field limit %q for reshare plan", item.name)
		}
		if value <= 0 {
			return resharePlanCodecOptions{}, fmt.Errorf("wire: field limit %q for reshare plan must be positive", item.name)
		}
		*item.dst = value
	}
	curveIDBytes, ok := fieldLimits["curve_id"]
	if !ok {
		return resharePlanCodecOptions{}, fmt.Errorf("wire: missing field limit %q for reshare plan", "curve_id")
	}
	if curveIDBytes <= 0 {
		return resharePlanCodecOptions{}, fmt.Errorf("wire: field limit %q for reshare plan must be positive", "curve_id")
	}
	return resharePlanCodecOptions{
		limits:          limits,
		maxCurveIDBytes: curveIDBytes,
	}, nil
}

func requireResharePlanTags(fields []wire.Field) error {
	if len(fields) != 13 {
		return fmt.Errorf("reshare plan field count %d != 13", len(fields))
	}
	for i, field := range fields {
		want := uint16(i + 1)
		if field.Tag != want {
			return fmt.Errorf("reshare plan tag %d at index %d, want %d", field.Tag, i, want)
		}
	}
	return nil
}

func marshalResharePlanVerificationShares(state *resharePlanState, limits Limits) ([]byte, error) {
	if len(state.oldParties) > limits.Threshold.MaxParties {
		return nil, fmt.Errorf("old verification share count %d exceeds max_items=%d", len(state.oldParties), limits.Threshold.MaxParties)
	}
	shares := make([]wire.PartyBytes[tss.PartyID], 0, len(state.oldParties))
	for _, party := range state.oldParties {
		share := state.oldVerificationShares[party]
		if len(share) > limits.Curve.MaxPointBytes {
			return nil, fmt.Errorf("old verification share for party %d too large: %d > %d", party, len(share), limits.Curve.MaxPointBytes)
		}
		shares = append(shares, wire.PartyBytes[tss.PartyID]{
			Party: party,
			Bytes: bytes.Clone(share),
		})
	}
	return wire.EncodePartyBytesChecked(shares)
}

func decodeResharePlanFields(fields []wire.Field, config resharePlanCodecOptions, opts ...wire.UnmarshalOption) (*resharePlanState, error) {
	sessionID, err := tss.SessionIDFromBytes(fields[0].Value)
	if err != nil {
		return nil, fmt.Errorf("invalid reshare session id: %w", err)
	}
	curveID, err := decodeResharePlanString(fields[1].Value, config.maxCurveIDBytes, "curve id")
	if err != nil {
		return nil, err
	}
	if err := checkResharePlanWireBytes(fields[2].Value, config.limits.Curve.MaxPointBytes, "old group public key"); err != nil {
		return nil, err
	}
	oldGroupCommitments, err := unmarshalBytesListValue(
		fields[3].Value,
		config.limits.Curve.MaxPointBytes,
		config.limits.Threshold.MaxThreshold,
		"old group commitments",
	)
	if err != nil {
		return nil, err
	}
	oldVerificationShareRecords, err := wire.DecodePartyBytesWithLimit[tss.PartyID](
		fields[4].Value,
		config.limits.Threshold.MaxParties,
		config.limits.Curve.MaxPointBytes,
		"old verification shares",
	)
	if err != nil {
		return nil, err
	}
	oldParties, err := unmarshalPartySetValue(fields[5].Value, config.limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("invalid old parties: %w", err)
	}
	oldThreshold, err := decodeResharePlanUint32AsInt(fields[6].Value, "old threshold")
	if err != nil {
		return nil, err
	}
	dealerParties, err := unmarshalPartySetValue(fields[7].Value, config.limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("invalid dealer parties: %w", err)
	}
	newParties, err := unmarshalPartySetValue(fields[8].Value, config.limits.Threshold.MaxParties)
	if err != nil {
		return nil, fmt.Errorf("invalid new parties: %w", err)
	}
	newThreshold, err := decodeResharePlanUint32AsInt(fields[9].Value, "new threshold")
	if err != nil {
		return nil, err
	}
	if err := checkResharePlanWireBytes(fields[10].Value, config.limits.Curve.MaxScalarBytes, "chain code"); err != nil {
		return nil, err
	}
	paillierBits, err := decodeResharePlanUint32AsInt(fields[11].Value, "paillier bits")
	if err != nil {
		return nil, err
	}
	if paillierBits > config.limits.Paillier.MaxModulusBits {
		return nil, fmt.Errorf("paillier key size %d exceeds max %d", paillierBits, config.limits.Paillier.MaxModulusBits)
	}
	var securityParams SecurityParams
	if err := wire.UnmarshalRecordValue(fields[12].Value, &securityParams, opts...); err != nil {
		return nil, fmt.Errorf("invalid reshare security params: %w", err)
	}
	verificationShares, err := decodeResharePlanVerificationShares(oldVerificationShareRecords, oldParties)
	if err != nil {
		return nil, err
	}
	return &resharePlanState{
		sessionID:             sessionID,
		curveID:               curveID,
		oldGroupPublicKey:     bytes.Clone(fields[2].Value),
		oldGroupCommitments:   tss.CloneByteSlices(oldGroupCommitments),
		oldVerificationShares: verificationShares,
		oldParties:            oldParties.Clone(),
		oldThreshold:          oldThreshold,
		dealerParties:         dealerParties.Clone(),
		newParties:            newParties.Clone(),
		newThreshold:          newThreshold,
		chainCode:             bytes.Clone(fields[10].Value),
		paillierBits:          paillierBits,
		securityParams:        securityParams,
	}, nil
}

func decodeResharePlanVerificationShares(records []wire.PartyBytes[tss.PartyID], oldParties tss.PartySet) (map[tss.PartyID][]byte, error) {
	if len(records) != len(oldParties) {
		return nil, fmt.Errorf("old verification share count must equal old party count")
	}
	verificationShares := make(map[tss.PartyID][]byte, len(records))
	for i, share := range records {
		if share.Party != oldParties[i] {
			return nil, fmt.Errorf("old verification share %d is for party %d, want party %d", i, share.Party, oldParties[i])
		}
		if _, exists := verificationShares[share.Party]; exists {
			return nil, fmt.Errorf("duplicate old verification share for party %d", share.Party)
		}
		verificationShares[share.Party] = bytes.Clone(share.Bytes)
	}
	return verificationShares, nil
}

func decodeResharePlanUint32AsInt(raw []byte, name string) (int, error) {
	value, err := wire.DecodeUint32(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid reshare plan %s: %w", name, err)
	}
	if uint64(value) > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("reshare plan %s %d overflows int", name, value)
	}
	return int(value), nil
}

func decodeResharePlanString(raw []byte, maxBytes int, name string) (string, error) {
	if err := checkResharePlanWireBytes(raw, maxBytes, name); err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", fmt.Errorf("invalid reshare plan %s: string is not valid UTF-8", name)
	}
	return string(raw), nil
}

func checkResharePlanWireBytes(raw []byte, maxBytes int, name string) error {
	if maxBytes > 0 && len(raw) > maxBytes {
		return fmt.Errorf("reshare plan %s too large: %d > %d", name, len(raw), maxBytes)
	}
	return nil
}
