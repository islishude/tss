package ed25519

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

type retiredFROSTKeyShareWire struct {
	Party                tss.PartyID           `wire:"1,u32"`
	Threshold            int                   `wire:"2,u32"`
	Parties              tss.PartySet          `wire:"3,u32list"`
	PublicKey            []byte                `wire:"4,bytes,max_bytes=point"`
	Secret               *secret.Scalar        `wire:"5,custom,len=32"`
	GroupCommitments     [][]byte              `wire:"6,byteslist,max_bytes=point,max_items=threshold"`
	VerificationShares   []VerificationShare   `wire:"7,recordlist,max_items=parties"`
	KeygenTranscriptHash []byte                `wire:"8,bytes"`
	ChainCode            []byte                `wire:"9,bytes"`
	KeygenSessionID      []byte                `wire:"10,bytes,len=32"`
	KeygenConfirmations  []*KeygenConfirmation `wire:"11,recordlist,max_items=parties"`
	PlanHash             []byte                `wire:"12,bytes,len=32"`
}

func (retiredFROSTKeyShareWire) WireType() string { return keyShareWireType }

func (retiredFROSTKeyShareWire) WireVersion() uint16 { return keyShareWireVersion }

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
	for i := len(reordered.state.parties) - 1; i >= 0; i-- {
		id := reordered.state.parties[i]
		reordered.state.partyData[id] = shares[1].state.partyData[id].Clone()
	}
	raw3, err := reordered.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw3) {
		t.Fatal("key share map insertion order changed canonical encoding")
	}
	decoded, err := UnmarshalKeyShare(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustKeyShareMetadata(t, decoded).PublicKey, mustKeyShareMetadata(t, shares[1]).PublicKey) {
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
	unsorted := cloneKeyShareValue(shares[1])
	unsorted.state.parties[0], unsorted.state.parties[1] = unsorted.state.parties[1], unsorted.state.parties[0]
	if _, err := unsorted.MarshalBinary(); err == nil {
		t.Fatal("unsorted party set encoded")
	}
	malformed := cloneKeyShareValue(shares[1])
	malformed.state.publicKey = []byte{0x01}
	if _, err := malformed.MarshalBinary(); err == nil {
		t.Fatal("malformed public key encoded")
	}
}

func TestFROSTKeyShareRejectsPartyDataKeySetMismatch(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*keyShareWire)
	}{
		{name: "missing", mutate: func(w *keyShareWire) { delete(w.PartyData, 3) }},
		{name: "extra", mutate: func(w *keyShareWire) { w.PartyData[4] = w.PartyData[3] }},
		{name: "broadcast", mutate: func(w *keyShareWire) {
			w.PartyData[tss.BroadcastPartyId] = w.PartyData[3]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := encodeKeyShareWire(shares[1])
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(w)
			if _, err := UnmarshalKeyShare(marshalFROSTKeyShareWireForTest(t, w)); err == nil {
				t.Fatalf("key share accepted %s party data", tc.name)
			}
		})
	}
}

func TestFROSTKeyShareRejectsMalformedPartyData(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)

	t.Run("confirmation sender mismatch", func(t *testing.T) {
		w, err := encodeKeyShareWire(shares[1])
		if err != nil {
			t.Fatal(err)
		}
		data := w.PartyData[1]
		confirmation, err := UnmarshalKeygenConfirmation(data.KeygenConfirmation)
		if err != nil {
			t.Fatal(err)
		}
		confirmation.Sender = 2
		data.KeygenConfirmation, err = confirmation.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		w.PartyData[1] = data
		if _, err := UnmarshalKeyShare(marshalFROSTKeyShareWireForTest(t, w)); err == nil {
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

func TestFROSTKeyShareRejectsRetiredRecordListLayout(t *testing.T) {
	t.Parallel()
	share := frostKeygen(t, 2, 3)[1]
	verificationShares, err := share.orderedVerificationShares()
	if err != nil {
		t.Fatal(err)
	}
	confirmations, err := share.orderedKeygenConfirmations()
	if err != nil {
		t.Fatal(err)
	}
	retired := retiredFROSTKeyShareWire{
		Party:                share.state.party,
		Threshold:            share.state.threshold,
		Parties:              share.state.parties,
		PublicKey:            share.state.publicKey,
		Secret:               share.state.secret,
		GroupCommitments:     share.state.groupCommitments,
		VerificationShares:   verificationShares,
		KeygenTranscriptHash: share.state.keygenTranscriptHash,
		ChainCode:            share.state.chainCode,
		KeygenSessionID:      share.state.keygenSessionID[:],
		KeygenConfirmations:  confirmations,
		PlanHash:             share.state.planHash,
	}
	raw, err := wire.Marshal(retired, wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShare(raw); err == nil {
		t.Fatal("key share accepted retired record-list layout")
	}
}

func marshalFROSTKeyShareWireForTest(t testing.TB, w *keyShareWire) []byte {
	t.Helper()
	raw, err := wire.Marshal(w, wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()))
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
		mutated, err := testutil.RewriteWireFieldByName(raw, keyShareWireType, keyShareWire{}, "Threshold", wire.Uint32(overflow))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalKeyShare(mutated); err == nil {
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
		publicKey:            make([]byte, 32),
		chainCode:            make([]byte, 32),
		keygenSessionID:      tss.SessionID{},
		keygenTranscriptHash: []byte{0x01, 0x02},
	}}
}

func TestFROSTKeySharePublicMetadataReturnsCopy(t *testing.T) {
	t.Parallel()
	k := minimalFROSTKeyShare()
	k.state.chainCode[0] = 0xaa
	k.state.publicKey[0] = 0x02
	metadata := mustKeyShareMetadata(t, k)
	metadata.ChainCode[0] = 0xbb
	metadata.PublicKey[0] = 0x03
	if k.state.chainCode[0] != 0xaa {
		t.Fatal("PublicMetadata() did not copy chain code")
	}
	if k.state.publicKey[0] != 0x02 {
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
	k.state.publicKey[0] = 0xab
	clone := cloneKeyShareValue(k)
	clone.state.publicKey[0] = 0xcd
	if k.state.publicKey[0] != 0xab {
		t.Fatal("internal clone shares public-key backing array")
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
