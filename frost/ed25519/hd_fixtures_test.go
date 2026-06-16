package ed25519

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

const (
	frostHDVectorParentPubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	frostHDVectorChainCodeHex = "2810999a530b5e7f455a3a97c36e0e23b3de096b69343ddfe87730990506b268"
)

type frostHDVectorCase struct {
	name      string
	index     uint32
	wantChain string
}

func frostHDVectorCases() []frostHDVectorCase {
	return []frostHDVectorCase{
		{name: "index=0", index: 0, wantChain: "9abd5509ba8a7a2350ce449e081f340f731f948792aa863888db8840b3b29064"},
		{name: "index=1", index: 1, wantChain: "20e93e203c1644a779dcd2ac88f8a8f984369ff886164363c3512e1a9196df15"},
		{name: "index=42", index: 42, wantChain: "328611b9d5d3d5ea3ed8d65a9658fc40a31fdc27f47752d8b6179fb738342317"},
		{name: "index=2147483647", index: 2147483647, wantChain: "2577db087974a0bcc158c2b39e93b57557babb250e9d22f42bce9800a5c91cfa"},
	}
}

func frostHDVectorParentPub(t testing.TB) []byte {
	t.Helper()
	return testutil.MustDecodeHex(t, frostHDVectorParentPubHex)
}

func frostHDVectorChainCode(t testing.TB) []byte {
	t.Helper()
	return testutil.MustDecodeHex(t, frostHDVectorChainCodeHex)
}

func assertFROSTHDDerivesChild(t testing.TB, parentPub []byte, result *tss.DerivationResult) {
	t.Helper()
	if len(result.AdditiveShift) != 32 {
		t.Fatalf("additive shift must be 32 bytes")
	}
	childFromShift, err := DerivePublicKey(parentPub, result.AdditiveShift)
	if err != nil {
		t.Fatalf("DerivePublicKey with shift: %v", err)
	}
	if !bytes.Equal(childFromShift, result.ChildPublicKey) {
		t.Error("DerivePublicKey(parentPub, shift) != childPub")
	}
}

func frostKeygenHD(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	return cachedFrostKeygen(t, threshold, n)
}
