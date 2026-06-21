package ed25519

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestFROSTKeyShareCanonicalEncoding(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	raw1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("key share encoding is not deterministic")
	}
	reordered := cloneKeyShareValue(shares[1])
	reordered.state.partyData = make(map[tss.PartyID]keySharePartyData, len(reordered.state.parties))
	for _, id := range slices.Backward(reordered.state.parties) {

		reordered.state.partyData[id] = shares[1].state.partyData[id].Clone()
	}
	raw3, err := reordered.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw3) {
		t.Fatal("key share map insertion order changed canonical encoding")
	}
	decoded, err := tss.DecodeBinary[KeyShare](raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !mustKeyShareMetadata(t, decoded).PublicKey.Equal(mustKeyShareMetadata(t, shares[1]).PublicKey) {
		t.Fatal("public key mismatch after canonical round trip")
	}
	if _, err := tss.DecodeBinary[KeyShare]([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON key share encoding accepted")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := tss.DecodeBinary[KeyShare](trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
	}
}

func TestFROSTKeyShareCustomGroupCommitmentsEnforcesResourceLimit(t *testing.T) {
	t.Parallel()

	share := frostKeygen(t, 2, 3)[1]
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	commitments := share.state.groupCommitments.BytesList()
	commitments = append(commitments, append([]byte(nil), commitments[0]...))
	mutated, err := testutil.RewriteWireField(raw, keyShareWireType, 7, wire.EncodeBytesList(commitments))
	if err != nil {
		t.Fatal(err)
	}
	limits := testLimits()
	limits.Threshold.MaxThreshold = 2
	_, err = UnmarshalKeyShareWithLimits(mutated, limits)
	if err == nil {
		t.Fatal("key share accepted group commitments over resource limit")
	}
	if !strings.Contains(err.Error(), "count too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFROSTKeyShareCustomGroupCommitmentsRequiresExactThreshold(t *testing.T) {
	t.Parallel()

	share := frostKeygen(t, 2, 3)[1]
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	commitments := share.state.groupCommitments.BytesList()
	mutated, err := testutil.RewriteWireField(raw, keyShareWireType, 7, wire.EncodeBytesList(commitments[:1]))
	if err != nil {
		t.Fatal(err)
	}
	_, err = tss.DecodeBinary[KeyShare](mutated)
	if err == nil {
		t.Fatal("key share accepted group commitment count below threshold")
	}
	if !strings.Contains(err.Error(), "got 1 commitments, want 2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFROSTKeyShareRejectsNonCanonicalFields(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	unsorted := cloneKeyShareValue(shares[1])
	unsorted.state.parties[0], unsorted.state.parties[1] = unsorted.state.parties[1], unsorted.state.parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	malformed := cloneKeyShareValue(shares[1])
	malformed.state.publicKey = publicKeyPoint{p: fed.NewIdentityPoint()}
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("malformed public key encoded")
	}
}

func TestFROSTKeyShareRejectsPartyDataKeySetMismatch(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*keyShareState)
	}{
		{name: "missing", mutate: func(state *keyShareState) { delete(state.partyData, 3) }},
		{name: "extra", mutate: func(state *keyShareState) { state.partyData[4] = state.partyData[3] }},
		{name: "broadcast", mutate: func(state *keyShareState) {
			state.partyData[tss.BroadcastPartyId] = state.partyData[3]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneKeyShareValue(shares[1])
			tc.mutate(mutated.state)
			raw, err := mutated.state.MarshalWireMessage(
				wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
			)
			if err == nil {
				_, err = tss.DecodeBinary[KeyShare](raw)
			}
			if err == nil {
				t.Fatalf("key share accepted %s party data", tc.name)
			}
		})
	}
}

func TestFROSTKeyShareRejectsMalformedPartyData(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)

	t.Run("confirmation sender mismatch", func(t *testing.T) {
		mutated := cloneKeyShareValue(shares[1])
		data := mutated.state.partyData[1]
		if data.keygenConfirmation == nil {
			t.Fatal("missing keygen confirmation for party data")
		}
		data.keygenConfirmation.Sender = 2
		mutated.state.partyData[1] = data
		raw, err := mutated.state.MarshalWireMessage(
			wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
		)
		if err == nil {
			_, err = tss.DecodeBinary[KeyShare](raw)
		}
		if err == nil {
			t.Fatal("key share accepted confirmation sender that did not match party-data key")
		}
	})

	t.Run("partial confirmation set", func(t *testing.T) {
		missing := cloneKeyShareValue(shares[1])
		data := missing.state.partyData[1]
		data.keygenConfirmation = nil
		missing.state.partyData[1] = data
		if _, err := missing.MarshalBinary(); err == nil {
			t.Fatal("key share accepted partial confirmation set")
		}
	})
}

func TestFROSTKeyShareStateRejectsMalformedRawPointAndPartyData(t *testing.T) {
	t.Parallel()

	raw, err := frostKeygen(t, 2, 3)[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	malformedPoint, err := testutil.RewriteWireField(raw, keyShareWireType, 4, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[KeyShare](malformedPoint); err == nil {
		t.Fatal("key share accepted malformed public key")
	}

	for _, tc := range []struct {
		name   string
		mutate func(testing.TB, []byte) []byte
	}{
		{
			name: "missing verification share",
			mutate: func(t testing.TB, record []byte) []byte {
				fields, err := wire.UnmarshalRecordFieldsWithLimits(record, wire.DefaultFrameLimits(), "partyData")
				if err != nil {
					t.Fatal(err)
				}
				out, err := wire.MarshalRecordFields(fields[1:])
				if err != nil {
					t.Fatal(err)
				}
				return out
			},
		},
		{
			name: "unknown field",
			mutate: func(t testing.TB, record []byte) []byte {
				fields, err := wire.UnmarshalRecordFieldsWithLimits(record, wire.DefaultFrameLimits(), "partyData")
				if err != nil {
					t.Fatal(err)
				}
				fields = append(fields, wire.Field{Tag: 3, Value: []byte{1}})
				out, err := wire.MarshalRecordFields(fields)
				if err != nil {
					t.Fatal(err)
				}
				return out
			},
		},
		{
			name: "duplicate field",
			mutate: func(t testing.TB, record []byte) []byte {
				return mutateFROSTRecordFieldTag(t, record, 1, 1)
			},
		},
		{
			name: "trailing data",
			mutate: func(_ testing.TB, record []byte) []byte {
				return append(bytes.Clone(record), 0)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := mutateFirstFROSTPartyDataRecord(t, raw, tc.mutate)
			if _, err := tss.DecodeBinary[KeyShare](mutated); err == nil {
				t.Fatalf("key share accepted party data with %s", tc.name)
			}
		})
	}
}

func TestFROSTKeyShareRejectsRetiredRecordListLayout(t *testing.T) {
	t.Parallel()
	share := frostKeygen(t, 2, 3)[1]
	verificationShares, err := share.orderedVerificationShares()
	if err != nil {
		t.Fatal(err)
	}
	retiredVerificationShareRecords := make([][]byte, 0, len(verificationShares))
	for _, verificationShare := range verificationShares {
		record, err := wire.MarshalRecordFields([]wire.Field{
			{Tag: 1, Value: wire.Uint32(verificationShare.Party)},
			{Tag: 2, Value: verificationShare.PublicKey.Bytes()},
		})
		if err != nil {
			t.Fatal(err)
		}
		retiredVerificationShareRecords = append(retiredVerificationShareRecords, record)
	}
	confirmations, err := share.orderedKeygenConfirmations()
	if err != nil {
		t.Fatal(err)
	}
	confirmationRecords := make([][]byte, 0, len(confirmations))
	for _, confirmation := range confirmations {
		record, err := wire.MarshalRecordValue(
			confirmation,
			wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
		)
		if err != nil {
			t.Fatal(err)
		}
		confirmationRecords = append(confirmationRecords, record)
	}
	secretBytes, err := share.state.secret.MarshalWireValue()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wire.MarshalFields(keyShareWireVersion, keyShareWireType, []wire.Field{
		{Tag: 1, Value: wire.Uint32(share.state.party)},
		{Tag: 2, Value: wire.Uint32(uint32(share.state.threshold))},
		{Tag: 3, Value: wire.EncodeUint32List(share.state.parties)},
		{Tag: 4, Value: share.state.publicKey.Bytes()},
		{Tag: 5, Value: secretBytes},
		{Tag: 6, Value: wire.EncodeBytesList(share.state.groupCommitments.BytesList())},
		{Tag: 7, Value: encodeFROSTRecordList(retiredVerificationShareRecords)},
		{Tag: 8, Value: wire.NonNilBytes(bytes.Clone(share.state.keygenTranscriptHash))},
		{Tag: 9, Value: wire.NonNilBytes(bytes.Clone(share.state.chainCode))},
		{Tag: 10, Value: share.state.keygenSessionID[:]},
		{Tag: 11, Value: encodeFROSTRecordList(confirmationRecords)},
		{Tag: 12, Value: wire.NonNilBytes(bytes.Clone(share.state.planHash))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[KeyShare](raw); err == nil {
		t.Fatal("key share accepted retired record-list layout")
	}
}

func TestFROSTKeyShareRejectsOverflowThreshold(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the threshold field to uint32 values that overflow int on 32-bit platforms.
	for _, overflow := range []uint32{math.MaxInt32 + 1, math.MaxUint32} {
		mutated, err := testutil.RewriteWireField(raw, keyShareWireType, 2, wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tss.DecodeBinary[KeyShare](mutated); err == nil {
			t.Fatalf("threshold %d accepted", overflow)
		}
	}
}

// minimalFROSTKeyShare returns a FROST KeyShare with only public metadata populated.
func minimalFROSTKeyShare() *KeyShare {
	return &KeyShare{state: &keyShareState{
		party:                1,
		threshold:            2,
		parties:              tss.NewPartySet(1, 2, 3),
		publicKey:            publicKeyPoint{p: fed.NewGeneratorPoint()},
		chainCode:            make([]byte, 32),
		keygenSessionID:      tss.SessionID{},
		keygenTranscriptHash: []byte{0x01, 0x02},
	}}
}

func TestFROSTKeySharePublicMetadataReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.state.chainCode[0] = 0xaa
	publicKey := k.state.publicKey.Bytes()
	metadata := mustKeyShareMetadata(t, k)
	metadata.ChainCode[0] = 0xbb
	metadata.PublicKey.p.Set(fed.NewIdentityPoint())
	if k.state.chainCode[0] != 0xaa {
		t.Fatal("PublicMetadata() did not copy chain code")
	}
	if !bytes.Equal(k.state.publicKey.Bytes(), publicKey) {
		t.Fatal("PublicMetadata() did not copy public key")
	}
}

func TestFROSTKeyShareNilAccessors(t *testing.T) {
	t.Parallel()
	var nilKey *KeyShare
	if _, ok := nilKey.PublicMetadata(); ok {
		t.Fatal("nil PublicMetadata() should report false")
	}
	if nilKey.Algorithm() != tss.AlgorithmFROSTEd25519 {
		t.Fatal("nil KeyShare.Algorithm() should return AlgorithmFROSTEd25519")
	}
	if nilKey.PartyID() != 0 {
		t.Fatal("nil KeyShare.PartyID() should return 0")
	}
}

func TestFROSTKeyShareAlgorithm(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	if k.Algorithm() != tss.AlgorithmFROSTEd25519 {
		t.Fatalf("Algorithm() = %q, want %q", k.Algorithm(), tss.AlgorithmFROSTEd25519)
	}
}

func TestFROSTKeySharePartyID(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	if k.PartyID() != 1 {
		t.Fatalf("PartyID() = %d, want 1", k.PartyID())
	}
	// nil already tested above
}

func TestFROSTKeyShareInternalCloneIsDeepCopy(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.state.publicKey = publicKeyPoint{p: fed.NewGeneratorPoint()}
	original := k.state.publicKey.Bytes()
	clone := cloneKeyShareValue(k)
	clone.state.publicKey.p.Set(fed.NewIdentityPoint())
	if !bytes.Equal(k.state.publicKey.Bytes(), original) {
		t.Fatal("internal clone shares public-key backing array")
	}
}

func TestFROSTKeyShareStateRejectsMalformedPublicKey(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	mutated := cloneKeyShareValue(shares[1])
	mutated.state.publicKey = publicKeyPoint{}
	if _, err := mutated.state.MarshalWireMessage(
		wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
	); err == nil {
		t.Fatal("key share state accepted nil public key")
	}
}

func TestFROSTKeyShareStateCodecAppliesCallerLimits(t *testing.T) {
	t.Parallel()

	share := frostKeygen(t, 2, 3)[1]
	limits := testLimits()
	raw, err := share.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	smallFields := limits.fieldLimits()
	smallFields["point"] = len(share.state.publicKey.Bytes()) - 1
	if _, err := share.state.MarshalWireMessage(wire.WithFieldLimitsForMarshal(smallFields)); err == nil {
		t.Fatal("key share state marshal ignored caller field limits")
	}
	var decoded keyShareState
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw)-1)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err == nil {
		t.Fatal("key share state unmarshal ignored caller frame limits")
	}
	if err := decoded.UnmarshalWireMessage(
		raw,
		wire.WithFrameLimits(limits.frameLimits(len(raw))),
		wire.WithFieldLimits(smallFields),
	); err == nil {
		t.Fatal("key share state unmarshal ignored caller field limits")
	}
	missing := limits.fieldLimits()
	delete(missing, "point")
	if _, err := share.state.MarshalWireMessage(wire.WithFieldLimitsForMarshal(missing)); err == nil {
		t.Fatal("key share state marshal accepted missing field limit")
	}
}

func TestFROSTKeyShareStateRejectsNonCanonicalTopLevelTags(t *testing.T) {
	t.Parallel()

	raw, err := frostKeygen(t, 2, 3)[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	version, fields, err := wire.UnmarshalFields(raw, keyShareWireType)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := wire.MarshalFields(version, keyShareWireType, fields[:len(fields)-1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[KeyShare](missing); err == nil {
		t.Fatal("key share accepted missing field")
	}

	unknown := mutateFROSTWireFieldTag(t, raw, len(fields)-1, 12)
	if _, err := tss.DecodeBinary[KeyShare](unknown); err == nil {
		t.Fatal("key share accepted unknown field")
	}
	duplicate := mutateFROSTWireFieldTag(t, raw, 1, 1)
	if _, err := tss.DecodeBinary[KeyShare](duplicate); err == nil {
		t.Fatal("key share accepted duplicate/out-of-order field")
	}
}

func mutateFROSTWireFieldTag(t testing.TB, raw []byte, fieldIndex int, tag uint16) []byte {
	t.Helper()
	out := bytes.Clone(raw)
	offset := 4
	typeLen := int(binary.BigEndian.Uint16(out[offset : offset+2]))
	offset += 2 + typeLen + 2
	fieldCount := int(binary.BigEndian.Uint16(out[offset : offset+2]))
	offset += 2
	if fieldIndex < 0 || fieldIndex >= fieldCount {
		t.Fatalf("field index %d out of range %d", fieldIndex, fieldCount)
	}
	for i := range fieldCount {
		if i == fieldIndex {
			binary.BigEndian.PutUint16(out[offset:offset+2], tag)
			return out
		}
		valueLen := int(binary.BigEndian.Uint32(out[offset+2 : offset+6]))
		offset += 6 + valueLen
	}
	t.Fatal("field tag not found")
	return nil
}

func mutateFirstFROSTPartyDataRecord(
	t testing.TB,
	raw []byte,
	mutate func(testing.TB, []byte) []byte,
) []byte {
	t.Helper()
	version, fields, err := wire.UnmarshalFields(raw, keyShareWireType)
	if err != nil {
		t.Fatal(err)
	}
	for i := range fields {
		if fields[i].Tag != 8 {
			continue
		}
		count, offset, err := wire.ReadUint32(fields[i].Value, 0)
		if err != nil {
			t.Fatal(err)
		}
		out := wire.Uint32(count)
		for entry := 0; entry < int(count); entry++ {
			key, next, err := wire.ReadBytes(fields[i].Value, offset)
			if err != nil {
				t.Fatal(err)
			}
			offset = next
			value, next, err := wire.ReadBytes(fields[i].Value, offset)
			if err != nil {
				t.Fatal(err)
			}
			offset = next
			if entry == 0 {
				value = mutate(t, value)
			}
			out = wire.AppendBytes(out, key)
			out = wire.AppendBytes(out, value)
		}
		fields[i].Value = out
		mutated, err := wire.MarshalFields(version, keyShareWireType, fields)
		if err != nil {
			t.Fatal(err)
		}
		return mutated
	}
	t.Fatal("missing party data field")
	return nil
}

func encodeFROSTRecordList(records [][]byte) []byte {
	out := wire.Uint32(uint32(len(records)))
	for _, record := range records {
		out = append(out, wire.Uint32(uint32(len(record)))...)
		out = append(out, record...)
	}
	return out
}

func mutateFROSTRecordFieldTag(t testing.TB, raw []byte, fieldIndex int, tag uint16) []byte {
	t.Helper()
	out := bytes.Clone(raw)
	if len(out) < 2 {
		t.Fatal("record too short")
	}
	fieldCount := int(binary.BigEndian.Uint16(out[:2]))
	offset := 2
	if fieldIndex < 0 || fieldIndex >= fieldCount {
		t.Fatalf("field index %d out of range %d", fieldIndex, fieldCount)
	}
	for i := range fieldCount {
		if i == fieldIndex {
			binary.BigEndian.PutUint16(out[offset:offset+2], tag)
			return out
		}
		valueLen := int(binary.BigEndian.Uint32(out[offset+2 : offset+6]))
		offset += 6 + valueLen
	}
	t.Fatal("record field tag not found")
	return nil
}

func TestFROSTKeyShareStringAndGoStringDoNotLeak(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	s := k.String()
	if s == "" {
		t.Fatal("String() returned empty")
	}
	gs := k.GoString()
	if gs == "" {
		t.Fatal("GoString() returned empty")
	}
	// Redact marker must be present.
	if !strings.Contains(strings.ToLower(s), "redacted") {
		t.Fatalf("String() does not contain redacted marker: %s", s)
	}
	if !strings.Contains(strings.ToLower(gs), "redacted") {
		t.Fatalf("GoString() does not contain redacted marker: %s", gs)
	}
}

func TestFROSTKeyShareFormatNil(t *testing.T) {
	t.Parallel()
	var nilKey *KeyShare
	s := fmt.Sprintf("%v", nilKey)
	if s != "<nil>" {
		t.Fatalf("Format nil = %q, want <nil>", s)
	}
}

func TestFROSTKeyShareFormatRedacts(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	s := fmt.Sprintf("%v", k)
	if !strings.Contains(strings.ToLower(s), "redacted") {
		t.Fatalf("Format does not contain redacted marker: %s", s)
	}
}
