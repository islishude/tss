//go:build integration

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
			if len(share.state.ChainCode) != 32 {
				t.Fatalf("party %d: expected 32-byte chain code, got %d", id, len(share.state.ChainCode))
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
				first = share.state.ChainCode
				firstPub = share.state.PublicKey.Bytes()
				continue
			}
			if !bytes.Equal(first, share.state.ChainCode) {
				t.Fatal("parties did not agree on chain code")
			}
			if !bytes.Equal(firstPub, share.state.PublicKey.Bytes()) {
				t.Fatal("parties did not agree on public key")
			}
		}
	})

	t.Run("default keygen produces chain code", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygen(t, 1, 1)
		for _, share := range shares {
			if len(share.state.ChainCode) != 32 {
				t.Fatalf("default keygen should produce 32-byte chain code, got %d bytes", len(share.state.ChainCode))
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

		result, err := DeriveNonHardenedBIP32(share.state.PublicKey.Bytes(), share.state.ChainCode, []uint32{0})
		if err != nil {
			t.Fatal(err)
		}

		pub, sig, err := signFROSTSimulationWithOptions(msg, []*KeyShare{share}, testSignOptions{Context: testFROSTSigningContext([]uint32{0})})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, result.ChildPublicKey) {
			t.Fatal("signing with additive shift returns shifted public key")
		}
		if !stded25519.Verify(stded25519.PublicKey(result.ChildPublicKey), msg, sig) {
			t.Fatal("HD signature did not verify against derived public key")
		}
		if stded25519.Verify(stded25519.PublicKey(share.state.PublicKey.Bytes()), msg, sig) {
			t.Fatal("HD signature should not verify against original key")
		}
	})

	t.Run("2-of-3 threshold derived key", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 2, 3)
		msg := []byte("threshold HD signing")

		key1 := shares[1]
		key2 := shares[2]

		result, err := DeriveNonHardenedBIP32(key1.state.PublicKey.Bytes(), key1.state.ChainCode, []uint32{5})
		if err != nil {
			t.Fatal(err)
		}

		pub, sig, err := signFROSTSimulationWithOptions(msg, []*KeyShare{key1, key2}, testSignOptions{Context: testFROSTSigningContext([]uint32{5})})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, result.ChildPublicKey) {
			t.Fatal("signing with additive shift returns shifted public key")
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

		pub1, sig1, err := signFROSTSimulationWithOptions(msg, []*KeyShare{share}, testSignOptions{Context: testFROSTSigningContext()})
		if err != nil {
			t.Fatal(err)
		}
		pub2, sig2, err := signFROSTSimulation(msg, []*KeyShare{share}, testFROSTSigningContext())
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
