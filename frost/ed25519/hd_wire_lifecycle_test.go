package ed25519

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestHDKeyShareWireAndLifecycleScenarios(t *testing.T) {
	t.Parallel()

	t.Run("HD key share round trip", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 2, 3)
		raw, err := shares[1].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := tss.DecodeBinary[KeyShare](raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.state.ChainCode) != 32 {
			t.Fatal("HD key share lost chain code in round-trip")
		}
		if !bytes.Equal(decoded.state.ChainCode, shares[1].state.ChainCode) {
			t.Fatal("chain code mismatch after round-trip")
		}
		if !decoded.state.PublicKey.Equal(shares[1].state.PublicKey) {
			t.Fatal("public key mismatch after round-trip")
		}
	})

	t.Run("default key share round trip", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygen(t, 1, 1)
		raw, err := shares[1].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := tss.DecodeBinary[KeyShare](raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.state.ChainCode) != 32 {
			t.Fatal("default key share should have a 32-byte chain code")
		}
	})

	t.Run("HD key share canonical encoding", func(t *testing.T) {
		t.Parallel()

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
	})

	t.Run("Destroy clears chain code", func(t *testing.T) {
		t.Parallel()

		shares := frostKeygenHD(t, 1, 1)
		share := shares[1]
		if len(share.state.ChainCode) != 32 {
			t.Fatal("expected 32-byte chain code")
		}
		share.Destroy()
		for _, b := range share.state.ChainCode {
			if b != 0 {
				t.Fatal("chain code not zeroed after Destroy")
			}
		}
	})
}
