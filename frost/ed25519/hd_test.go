package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func TestDerivePublicKey(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	pub := shares[1].PublicKey

	// Zero shift returns the original public key.
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

	// Non-zero shift produces a different key.
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

func TestDeriveBIP32SingleLevel(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	childPub, shift, childCC, err := DeriveBIP32(pub, cc, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(childPub) != 32 {
		t.Fatalf("child public key must be 32 bytes, got %d", len(childPub))
	}
	if len(shift) != 32 {
		t.Fatalf("additive shift must be 32 bytes, got %d", len(shift))
	}
	if len(childCC) != 32 {
		t.Fatalf("child chain code must be 32 bytes, got %d", len(childCC))
	}
	if bytes.Equal(childCC, cc) {
		t.Fatal("child chain code should differ from parent")
	}

	// Verify that DerivePublicKey with the shift matches the child key.
	derived, err := DerivePublicKey(pub, shift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, childPub) {
		t.Fatal("DerivePublicKey(pub, shift) != childPub")
	}
}

func TestDeriveBIP32MultiLevel(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	// Derive m/0/1/2 in one call.
	_, _, childCC1, err := DeriveBIP32(pub, cc, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}

	// Derive step by step.
	cp, _, ccc, err := DeriveBIP32(pub, cc, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	cp2, _, ccc2, err := DeriveBIP32(cp, ccc, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}
	_, _, ccc3, err := DeriveBIP32(cp2, ccc2, []uint32{2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(childCC1, ccc3) {
		t.Fatal("multi-step chain code should match single-step")
	}
}

func TestDeriveBIP32RejectsHardened(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	_, _, _, err := DeriveBIP32(pub, cc, []uint32{HardenedKeyStart})
	if err == nil {
		t.Fatal("should reject hardened index")
	}
	_, _, _, err = DeriveBIP32(pub, cc, []uint32{HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("should reject hardened index")
	}
	_, _, _, err = DeriveBIP32(pub, cc, []uint32{0, HardenedKeyStart})
	if err == nil {
		t.Fatal("should reject hardened index in path")
	}
}

func TestDeriveBIP32RejectsEmptyChainCode(t *testing.T) {
	shares := frostKeygen(t, 1, 1)
	pub := shares[1].PublicKey

	_, _, _, err := DeriveBIP32(pub, nil, []uint32{0})
	if err == nil {
		t.Fatal("should reject nil chain code")
	}
	_, _, _, err = DeriveBIP32(pub, []byte{}, []uint32{0})
	if err == nil {
		t.Fatal("should reject empty chain code")
	}
}

func TestDeriveBIP32RejectsEmptyPath(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	_, _, _, err := DeriveBIP32(pub, cc, nil)
	if err == nil {
		t.Fatal("should reject nil path")
	}
	_, _, _, err = DeriveBIP32(pub, cc, []uint32{})
	if err == nil {
		t.Fatal("should reject empty path")
	}
}

func TestDeriveBIP32RejectsInvalidPubKey(t *testing.T) {
	cc := make([]byte, 32)
	for i := range cc {
		cc[i] = byte(i)
	}
	// Wrong length public key should be rejected.
	_, _, _, err := DeriveBIP32(make([]byte, 31), cc, []uint32{0})
	if err == nil {
		t.Fatal("should reject invalid public key")
	}
}

func TestHardenedKeyStartConstant(t *testing.T) {
	if HardenedKeyStart != 1<<31 {
		t.Fatal("HardenedKeyStart must be 2^31")
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

	childPub, shift, _, err := DeriveBIP32(share.PublicKey, share.ChainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}

	pub, sig, err := SignWithOptions(msg, []*KeyShare{share}, SignOptions{AdditiveShift: shift})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, share.PublicKey) {
		t.Fatal("Sign returns original public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(childPub), msg, sig) {
		t.Fatal("HD signature did not verify against derived public key")
	}
	if stded25519.Verify(stded25519.PublicKey(share.PublicKey), msg, sig) {
		t.Fatal("HD signature should not verify against original key")
	}
}

func TestHDSign2Of3(t *testing.T) {
	shares := frostKeygenHD(t, 2, 3)
	msg := []byte("threshold HD signing")

	// Use parties 1 and 2.
	key1 := shares[1]
	key2 := shares[2]

	childPub, shift, _, err := DeriveBIP32(key1.PublicKey, key1.ChainCode, []uint32{5})
	if err != nil {
		t.Fatal(err)
	}

	pub, sig, err := SignWithOptions(msg, []*KeyShare{key1, key2}, SignOptions{AdditiveShift: shift})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pub, key1.PublicKey) {
		t.Fatal("Sign returns original public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(childPub), msg, sig) {
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

func TestDeriveBIP32Determinism(t *testing.T) {
	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].PublicKey
	cc := shares[1].ChainCode

	child1, shift1, cc1, err := DeriveBIP32(pub, cc, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	child2, shift2, cc2, err := DeriveBIP32(pub, cc, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(child1, child2) || !bytes.Equal(shift1, shift2) || !bytes.Equal(cc1, cc2) {
		t.Fatal("DeriveBIP32 is not deterministic")
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

	// Broadcast all round 1 messages.
	for _, id := range parties {
		for _, env := range sessions[id].envelopes {
			for _, receiver := range parties {
				if receiver == id {
					continue
				}
				// Only peer-to-peer messages check To.
				if env.To != 0 && env.To != receiver {
					continue
				}
				_, err := sessions[receiver].session.HandleKeygenMessage(env)
				if err != nil {
					t.Fatal(err)
				}
			}
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
