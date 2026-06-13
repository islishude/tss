package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"
)

func TestHDKeygenScenarios(t *testing.T) {
	t.Parallel()

	t.Run("HD produces chain code", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 2, 3)
		for id, share := range shares {
			if len(share.state.chainCode) != 32 {
				t.Fatalf("party %d: expected 32-byte chain code, got %d", id, len(share.state.chainCode))
			}
		}
	})

	t.Run("HD parties agree", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 2, 3)
		var first []byte
		var firstPub []byte
		for _, share := range shares {
			if first == nil {
				first = share.state.chainCode
				firstPub = share.state.publicKey
				continue
			}
			if !bytes.Equal(first, share.state.chainCode) {
				t.Fatal("parties did not agree on chain code")
			}
			if !bytes.Equal(firstPub, share.state.publicKey) {
				t.Fatal("parties did not agree on public key")
			}
		}
	})

	t.Run("non-HD omits chain code", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygen(t, 1, 1)
		for _, share := range shares {
			if len(share.state.chainCode) != 0 {
				t.Fatalf("non-HD keygen should produce nil chain code, got %d bytes", len(share.state.chainCode))
			}
		}
	})
}

func TestHDSignScenarios(t *testing.T) {
	t.Parallel()

	t.Run("single signer derived key", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 1, 1)
		share := shares[1]
		msg := []byte("hello HD world")

		result, err := DeriveNonHardenedBIP32(share.state.publicKey, share.state.chainCode, []uint32{0})
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
		if stded25519.Verify(stded25519.PublicKey(share.state.publicKey), msg, sig) {
			t.Fatal("HD signature should not verify against original key")
		}
	})

	t.Run("2-of-3 threshold derived key", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 2, 3)
		msg := []byte("threshold HD signing")

		key1 := shares[1]
		key2 := shares[2]

		result, err := DeriveNonHardenedBIP32(key1.state.publicKey, key1.state.chainCode, []uint32{5})
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
	})

	t.Run("zero shift matches normal signing", func(t *testing.T) {
		t.Parallel()

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
	})
}
