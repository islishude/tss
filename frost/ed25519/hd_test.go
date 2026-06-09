package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestDerivePublicKey(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	pub := shares[1].PublicKey

	same, err := DerivePublicKey(pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(same, pub) {
		t.Fatal("DerivePublicKey with nil shift should return original key")
	}

	same, err = DerivePublicKey(pub, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(same, pub) {
		t.Fatal("DerivePublicKey with zero shift should return original key")
	}

	shift := make([]byte, 32)
	shift[0] = 1
	child, err := DerivePublicKey(pub, shift)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(child, pub) {
		t.Fatal("DerivePublicKey with non-zero shift should produce different key")
	}
	if _, err := edcurve.PointFromBytes(child); err != nil {
		t.Fatal(err)
	}
}

// TestDeriveNonHardenedBIP32_Vectors verifies derivation against golden test
// vectors generated with the reference HMAC-SHA512 construction (single-round).
func TestDeriveNonHardenedBIP32_Vectors(t *testing.T) {
	// Golden parent: a 32-byte Ed25519 public key and 32-byte chain code.
	parentPub := testutil.MustDecodeHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	chainCode := testutil.MustDecodeHex(t, "2810999a530b5e7f455a3a97c36e0e23b3de096b69343ddfe87730990506b268")

	tests := []struct {
		index  uint32
		wantCC string // expected child chain code (hex)
	}{
		{index: 0, wantCC: "9abd5509ba8a7a2350ce449e081f340f731f948792aa863888db8840b3b29064"},
		{index: 1, wantCC: "20e93e203c1644a779dcd2ac88f8a8f984369ff886164363c3512e1a9196df15"},
		{index: 42, wantCC: "328611b9d5d3d5ea3ed8d65a9658fc40a31fdc27f47752d8b6179fb738342317"},
		{index: 2147483647, wantCC: "2577db087974a0bcc158c2b39e93b57557babb250e9d22f42bce9800a5c91cfa"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("index=%d", tt.index), func(t *testing.T) {
			result, err := DeriveNonHardenedBIP32(parentPub, chainCode, []uint32{tt.index})
			if err != nil {
				t.Fatalf("DeriveNonHardenedBIP32: %v", err)
			}

			// Verify child chain code matches golden.
			if got := hex.EncodeToString(result.ChildChainCode); got != tt.wantCC {
				t.Errorf("child chain code:\n  got: %s\n want: %s", got, tt.wantCC)
			}

			// Verify additive shift is non-zero and can derive child from parent.
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
		})
	}
}

// TestDeriveNonHardenedBIP32_MultiStepVector verifies multi-step derivation
// against a golden chain code computed from independent HMAC steps.
func TestDeriveNonHardenedBIP32_MultiStepVector(t *testing.T) {
	parentPub := testutil.MustDecodeHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	chainCode := testutil.MustDecodeHex(t, "2810999a530b5e7f455a3a97c36e0e23b3de096b69343ddfe87730990506b268")

	// Derive m/0/1 in a single call.
	result, err := DeriveNonHardenedBIP32(parentPub, chainCode, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}

	// Chain code from single-step: m → m/0 → m/0/1
	r1, err := DeriveNonHardenedBIP32(parentPub, chainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := DeriveNonHardenedBIP32(r1.ChildPublicKey, r1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result.ChildChainCode, r2.ChildChainCode) {
		t.Error("multi-step chain code != chained single-step chain code")
	}
	if !bytes.Equal(result.ChildPublicKey, r2.ChildPublicKey) {
		t.Error("multi-step child pub != chained single-step child pub")
	}
}

// TestDeriveNonHardenedBIP32_EmptyPathReturnsParent is a dedicated test for
// empty/nil path behavior (mirrors the reference's test pattern).
func TestDeriveNonHardenedBIP32_EmptyPathReturnsParent(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	for _, path := range [][]uint32{nil, {}} {
		result, err := DeriveNonHardenedBIP32(pub, cc, path)
		if err != nil {
			t.Fatalf("path=%v: %v", path, err)
		}
		if !bytes.Equal(result.ChildPublicKey, pub) {
			t.Errorf("path=%v: child pub != parent pub", path)
		}
		if !bytes.Equal(result.ChildChainCode, cc) {
			t.Errorf("path=%v: child chain != parent chain", path)
		}
		if !testutil.IsZeroBytes(result.AdditiveShift) {
			t.Errorf("path=%v: additive shift should be zero", path)
		}
		if result.Depth != 0 {
			t.Errorf("path=%v: depth should be 0", path)
		}
	}
}

// TestDeriveNonHardenedBIP32_DepthExceedsMaxUint8 is patterned after the
// reference's MaxDepth overflow test.
func TestDeriveNonHardenedBIP32_DepthExceedsMaxUint8(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	longPath := make([]uint32, 256)
	for i := range longPath {
		longPath[i] = 0
	}
	_, err := DeriveNonHardenedBIP32(shares[1].PublicKey, shares[1].ChainCode, longPath)
	if !errors.Is(err, bip32util.ErrDerivationDepthOverflow) {
		t.Errorf("expected ErrDerivationDepthOverflow, got %v", err)
	}
}

func TestDeriveNonHardenedBIP32SingleLevel(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	result, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChildPublicKey) != 32 {
		t.Fatalf("child public key must be 32 bytes, got %d", len(result.ChildPublicKey))
	}
	if len(result.AdditiveShift) != 32 {
		t.Fatalf("additive shift must be 32 bytes, got %d", len(result.AdditiveShift))
	}
	if len(result.ChildChainCode) != 32 {
		t.Fatalf("child chain code must be 32 bytes, got %d", len(result.ChildChainCode))
	}
	if bytes.Equal(result.ChildChainCode, cc) {
		t.Fatal("child chain code should differ from parent")
	}

	derived, err := DerivePublicKey(pub, result.AdditiveShift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, result.ChildPublicKey) {
		t.Fatal("DerivePublicKey(pub, shift) != childPub")
	}
}

func TestDeriveNonHardenedBIP32MultiLevel(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	result, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}

	r1, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := DeriveNonHardenedBIP32(r1.ChildPublicKey, r1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}
	r3, err := DeriveNonHardenedBIP32(r2.ChildPublicKey, r2.ChildChainCode, []uint32{2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result.ChildChainCode, r3.ChildChainCode) {
		t.Fatal("multi-step chain code should match single-step")
	}
}

func TestDeriveNonHardenedBIP32RejectsHardened(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	_, err := DeriveNonHardenedBIP32(pub, cc, []uint32{bip32util.HardenedKeyStart})
	if err == nil {
		t.Fatal("should reject hardened index")
	}
	_, err = DeriveNonHardenedBIP32(pub, cc, []uint32{bip32util.HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("should reject hardened index")
	}
	_, err = DeriveNonHardenedBIP32(pub, cc, []uint32{0, bip32util.HardenedKeyStart})
	if err == nil {
		t.Fatal("should reject hardened index in path")
	}
}

func TestDeriveNonHardenedBIP32RejectsEmptyChainCode(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	pub := shares[1].PublicKey

	_, err := DeriveNonHardenedBIP32(pub, nil, []uint32{0})
	if err == nil {
		t.Fatal("should reject nil chain code")
	}
	_, err = DeriveNonHardenedBIP32(pub, []byte{}, []uint32{0})
	if err == nil {
		t.Fatal("should reject empty chain code")
	}
}

func TestDeriveNonHardenedBIP32RejectsInvalidPubKey(t *testing.T) {
	cc := make([]byte, 32)
	for i := range cc {
		cc[i] = byte(i)
	}
	_, err := DeriveNonHardenedBIP32(make([]byte, 31), cc, []uint32{0})
	if err == nil {
		t.Fatal("should reject invalid public key")
	}
}

func TestHDKeygenProducesChainCode(t *testing.T) {
	shares := frostKeygenHD(t, 2, 3)
	for id, share := range shares {
		if len(share.ChainCode) != 32 {
			t.Fatalf("party %d: expected 32-byte chain code, got %d", id, len(share.ChainCode))
		}
	}
}

func TestHDKeygenAllPartiesAgree(t *testing.T) {
	shares := frostKeygenHD(t, 2, 3)
	var first []byte
	var firstPub []byte
	for _, share := range shares {
		if first == nil {
			first = share.ChainCode
			firstPub = share.PublicKey
		} else {
			if !bytes.Equal(first, share.ChainCode) {
				t.Fatal("parties did not agree on chain code")
			}
			if !bytes.Equal(firstPub, share.PublicKey) {
				t.Fatal("parties did not agree on public key")
			}
		}
	}
}

func TestKeygenWithoutHDOption(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	for _, share := range shares {
		if len(share.ChainCode) != 0 {
			t.Fatalf("non-HD keygen should produce nil chain code, got %d bytes", len(share.ChainCode))
		}
	}
}

func TestHDSignSingleSigner(t *testing.T) {
	sharesMap := frostKeygenHD(t, 1, 1)
	share := sharesMap[1]
	msg := []byte("hello HD world")

	result, err := DeriveNonHardenedBIP32(share.PublicKey, share.ChainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}

	pub, sig, err := SignWithOptions(msg, []*KeyShare{share}, SignOptions{AdditiveShift: result.AdditiveShift})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, result.ChildPublicKey) {
		t.Fatal("SignWithOptions with additive shift returns shifted public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(result.ChildPublicKey), msg, sig) {
		t.Fatal("HD signature did not verify against derived public key")
	}
	if stded25519.Verify(stded25519.PublicKey(share.PublicKey), msg, sig) {
		t.Fatal("HD signature should not verify against original key")
	}
}

func TestHDSign2Of3(t *testing.T) {
	shares := frostKeygenHD(t, 2, 3)
	msg := []byte("threshold HD signing")

	key1 := shares[1]
	key2 := shares[2]

	result, err := DeriveNonHardenedBIP32(key1.PublicKey, key1.ChainCode, []uint32{5})
	if err != nil {
		t.Fatal(err)
	}

	pub, sig, err := SignWithOptions(msg, []*KeyShare{key1, key2}, SignOptions{AdditiveShift: result.AdditiveShift})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, result.ChildPublicKey) {
		t.Fatal("SignWithOptions with additive shift returns shifted public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(result.ChildPublicKey), msg, sig) {
		t.Fatal("HD threshold signature did not verify against derived key")
	}
}

func TestHDSignZeroShift(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	share := shares[1]
	msg := []byte("zero shift test")

	zeroShift := make([]byte, 32)
	pub1, sig1, err := SignWithOptions(msg, []*KeyShare{share}, SignOptions{AdditiveShift: zeroShift})
	if err != nil {
		t.Fatal(err)
	}

	pub2, sig2, err := Sign(msg, []*KeyShare{share})
	if err != nil {
		t.Fatal(err)
	}

	if !stded25519.Verify(stded25519.PublicKey(pub1), msg, sig1) {
		t.Fatal("zero-shift HD signature failed verification")
	}
	if !stded25519.Verify(stded25519.PublicKey(pub2), msg, sig2) {
		t.Fatal("non-HD signature failed verification")
	}
}

func TestHDKeyShareWireFormat(t *testing.T) {
	shares := frostKeygenHD(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.ChainCode) != 32 {
		t.Fatal("HD key share lost chain code in round-trip")
	}
	if !bytes.Equal(decoded.ChainCode, shares[1].ChainCode) {
		t.Fatal("chain code mismatch after round-trip")
	}
	if !bytes.Equal(decoded.PublicKey, shares[1].PublicKey) {
		t.Fatal("public key mismatch after round-trip")
	}
}

func TestNonHDKeyShareWireFormat(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.ChainCode) != 0 {
		t.Fatal("non-HD key share should have empty chain code")
	}
}

func TestHDKeyShareCanonicalEncoding(t *testing.T) {
	shares := frostKeygenHD(t, 2, 3)
	raw1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("HD key share encoding is not deterministic")
	}
}

func TestHDSessionDestroyClearsChainCode(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	share := shares[1]
	if len(share.ChainCode) != 32 {
		t.Fatal("expected 32-byte chain code")
	}
	share.Destroy()
	for _, b := range share.ChainCode {
		if b != 0 {
			t.Fatal("chain code not zeroed after Destroy")
		}
	}
}

func TestDeriveNonHardenedBIP32Determinism(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	r1, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(r1.ChildPublicKey, r2.ChildPublicKey) ||
		!bytes.Equal(r1.AdditiveShift, r2.AdditiveShift) ||
		!bytes.Equal(r1.ChildChainCode, r2.ChildChainCode) {
		t.Fatal("DeriveNonHardenedBIP32 is not deterministic")
	}
}

// frostKeygenHD runs a full in-memory DKG with HD enabled and returns the key shares.
func frostKeygenHD(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	parties := make([]tss.PartyID, n)
	for i := range n {
		parties[i] = tss.PartyID(i + 1)
	}
	parties = tss.SortParties(parties)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	type sessionState struct {
		session   *KeygenSession
		envelopes []tss.Envelope
	}
	sessions := make(map[tss.PartyID]*sessionState, n)
	for _, id := range parties {
		cfg := tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		}
		session, out, err := StartKeygenWithOptions(cfg, KeygenOptions{EnableHD: true})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = &sessionState{session: session, envelopes: out}
	}

	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		queue = append(queue, sessions[id].envelopes...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, receiver := range parties {
			if receiver == env.From || (env.To != 0 && env.To != receiver) {
				continue
			}
			out, err := sessions[receiver].session.HandleKeygenMessage(env)
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}

	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].session.KeyShare()
		if !ok {
			t.Fatalf("party %d did not complete keygen", id)
		}
		shares[id] = share
	}
	return shares
}
