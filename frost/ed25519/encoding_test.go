package ed25519

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
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
	decoded, err := UnmarshalKeyShare(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PublicKey, shares[1].PublicKey) {
		t.Fatal("public key mismatch after canonical round trip")
	}
	if _, err := UnmarshalKeyShare([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON key share encoding accepted")
	}
	trailing := append(append([]byte(nil), raw1...), 0)
	if _, err := UnmarshalKeyShare(trailing); err == nil {
		t.Fatal("key share with trailing bytes accepted")
	}
}

func TestFROSTKeyShareRejectsNonCanonicalFields(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	unsorted := cloneFROSTKeyShare(shares[1])
	unsorted.Parties[0], unsorted.Parties[1] = unsorted.Parties[1], unsorted.Parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	malformed := cloneFROSTKeyShare(shares[1])
	malformed.PublicKey = []byte{0x01}
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("malformed public key encoded")
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
		mutated, err := rewriteFROSTWireField(raw, keyShareWireType, keyShareFieldThreshold, wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalKeyShare(mutated); err == nil {
			t.Fatalf("threshold %d accepted", overflow)
		}
	}
}

func FuzzFROSTKeyShareUnmarshal(f *testing.F) {
	shares := frostKeygenForFuzz(f, 1, 1)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		share, err := UnmarshalKeyShare(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, share, (*KeyShare).MarshalBinary, UnmarshalKeyShare)
	})
}

func FuzzFROSTKeygenCommitmentsPayloadUnmarshal(f *testing.F) {
	raw, err := marshalKeygenCommitmentsPayload(keygenCommitmentsPayload{
		Commitments: [][]byte{seedFROSTPoint(f)},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalKeygenCommitmentsPayload, unmarshalKeygenCommitmentsPayload)
	})
}

func FuzzFROSTKeygenSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalKeygenSharePayload(keygenSharePayload{Share: seedFROSTScalar(f)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalKeygenSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalKeygenSharePayload, unmarshalKeygenSharePayload)
	})
}

func FuzzFROSTNonceCommitmentPayloadUnmarshal(f *testing.F) {
	raw, err := marshalNonceCommitmentPayload(nonceCommitment{
		D: seedFROSTPoint(f),
		E: seedFROSTPoint(f),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"d":"x","e":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalNonceCommitmentPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalNonceCommitmentPayload, unmarshalNonceCommitmentPayload)
	})
}

func FuzzFROSTSignPartialPayloadUnmarshal(f *testing.F) {
	raw, err := marshalSignPartialPayload(signPartialPayload{Z: seedFROSTScalar(f)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"z":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalSignPartialPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalSignPartialPayload, unmarshalSignPartialPayload)
	})
}

func FuzzFROSTReshareCommitmentsPayloadUnmarshal(f *testing.F) {
	raw, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{
		Commitments: [][]byte{seedFROSTPoint(f)},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"commitments":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareCommitmentsPayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalReshareCommitmentsPayload, unmarshalReshareCommitmentsPayload)
	})
}

func FuzzFROSTReshareSharePayloadUnmarshal(f *testing.F) {
	raw, err := marshalReshareSharePayload(reshareSharePayload{Share: seedFROSTScalar(f)})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"share":"x"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := unmarshalReshareSharePayload(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, p, marshalReshareSharePayload, unmarshalReshareSharePayload)
	})
}

func frostKeygenForFuzz(f *testing.F, threshold, n int) map[tss.PartyID]*KeyShare {
	f.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		f.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			f.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	deliverFROSTKeygenMessages(f, parties, sessions, messages)
	out := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			f.Fatalf("keygen not complete for %d", id)
		}
		out[id] = share
	}
	return out
}

func cloneFROSTKeyShare(in *KeyShare) *KeyShare {
	if in == nil {
		return nil
	}
	out := *in
	out.Parties = append([]tss.PartyID(nil), in.Parties...)
	out.PublicKey = append([]byte(nil), in.PublicKey...)
	out.ChainCode = append([]byte(nil), in.ChainCode...)
	out.secret = in.secret.Clone()
	out.GroupCommitments = testutil.CloneByteSlices(in.GroupCommitments)
	out.VerificationShares = append([]VerificationShare(nil), in.VerificationShares...)
	for i := range out.VerificationShares {
		out.VerificationShares[i].PublicKey = append([]byte(nil), in.VerificationShares[i].PublicKey...)
	}
	out.KeygenSessionID = in.KeygenSessionID
	out.KeygenTranscriptHash = append([]byte(nil), in.KeygenTranscriptHash...)
	out.KeygenConfirmations = testutil.CloneByteSlices(in.KeygenConfirmations)
	return &out
}

func seedFROSTPoint(tb testing.TB) []byte {
	tb.Helper()
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		tb.Fatal(err)
	}
	return point.Bytes()
}

func seedFROSTScalar(tb testing.TB) []byte {
	tb.Helper()
	out, err := scalarBytes(big.NewInt(1))
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

func rewriteFROSTWireField(raw []byte, wireType string, tag uint16, value []byte) ([]byte, error) {
	version, fields, err := wire.UnmarshalFields(raw, wireType)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			fields[i].Value = make([]byte, len(value))
			copy(fields[i].Value, value)
			return wire.MarshalFields(version, wireType, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
}

// minimalFROSTKeyShare returns a FROST KeyShare with only public metadata populated.
func minimalFROSTKeyShare() *KeyShare {
	return &KeyShare{
		Version:              tss.Version,
		Party:                1,
		Threshold:            2,
		Parties:              []tss.PartyID{1, 2, 3},
		PublicKey:            make([]byte, 32),
		ChainCode:            make([]byte, 32),
		KeygenSessionID:      tss.SessionID{},
		KeygenTranscriptHash: []byte{0x01, 0x02},
	}
}

func TestFROSTKeyShareChainCodeBytesReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.ChainCode[0] = 0xaa
	cp := k.ChainCodeBytes()
	cp[0] = 0xbb
	if k.ChainCode[0] != 0xaa {
		t.Fatal("ChainCodeBytes() did not return a copy")
	}
}

func TestFROSTKeySharePublicKeyBytesReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.PublicKey[0] = 0x02
	cp := k.PublicKeyBytes()
	cp[0] = 0x03
	if k.PublicKey[0] != 0x02 {
		t.Fatal("PublicKeyBytes() did not return a copy")
	}
}

func TestFROSTKeyShareNilAccessors(t *testing.T) {
	t.Parallel()
	var nilKey *KeyShare
	if b := nilKey.ChainCodeBytes(); b != nil {
		t.Fatal("nil ChainCodeBytes() should return nil")
	}
	if b := nilKey.PublicKeyBytes(); b != nil {
		t.Fatal("nil PublicKeyBytes() should return nil")
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

func TestFROSTKeyShareCloneIsDeepCopy(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.PublicKey[0] = 0xab
	clone := k.Clone()
	clone.PublicKey[0] = 0xcd
	if k.PublicKey[0] != 0xab {
		t.Fatal("Clone shares PublicKey backing array")
	}
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
