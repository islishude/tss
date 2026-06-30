package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestDeriveNonHardenedBIP32WrapperMatchesBIP32Util(t *testing.T) {
	t.Parallel()

	parent := mustParseXPub(t, xpubTV2Master)
	path := tss.DerivationPath{0, 1}

	got, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := bip32util.DeriveSecp256k1(parent.PublicKey, parent.ChainCode[:], path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.ChildPublicKey, want.ChildPublicKey) {
		t.Fatal("protocol wrapper returned a different child public key")
	}
	if !bytes.Equal(got.AdditiveShift, want.AdditiveShift) {
		t.Fatal("protocol wrapper returned a different additive shift")
	}
	if got.Scheme != tss.DerivationSchemeBIP32Secp256k1 {
		t.Fatalf("scheme = %q, want %q", got.Scheme, tss.DerivationSchemeBIP32Secp256k1)
	}
}

func TestDeriveNonHardenedBIP32HardenedPathRejected(t *testing.T) {
	t.Parallel()

	parent := mustParseXPub(t, xpubTV2Master)
	_, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], tss.DerivationPath{0, tss.HardenedKeyStart})
	if !errors.Is(err, tss.ErrHardenedDerivationUnsupported) {
		t.Fatalf("expected hardened path rejection, got %v", err)
	}
}

func TestDerivePublicKeyScenarios(t *testing.T) {
	t.Parallel()

	parent := mustParseXPub(t, xpubTV2Master)

	t.Run("nil shift returns parent", func(t *testing.T) {
		t.Parallel()

		got, err := DerivePublicKey(parent.PublicKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, parent.PublicKey) {
			t.Fatal("nil additive shift changed public key")
		}
	})

	t.Run("zero shift returns parent", func(t *testing.T) {
		t.Parallel()

		got, err := DerivePublicKey(parent.PublicKey, secp.ScalarZero().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, parent.PublicKey) {
			t.Fatal("zero additive shift changed public key")
		}
	})

	t.Run("non-zero shift derives valid child", func(t *testing.T) {
		t.Parallel()

		shift := make([]byte, secp.ScalarSize)
		shift[len(shift)-1] = 1
		got, err := DerivePublicKey(parent.PublicKey, shift)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, parent.PublicKey) {
			t.Fatal("non-zero additive shift did not change public key")
		}
		if _, err := secp.PointFromBytes(got); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid public key rejected", func(t *testing.T) {
		t.Parallel()

		badPub := bytes.Clone(parent.PublicKey)
		badPub[0] = 0x04
		if _, err := DerivePublicKey(badPub, nil); err == nil {
			t.Fatal("invalid public key accepted")
		}
	})

	t.Run("invalid shift rejected", func(t *testing.T) {
		t.Parallel()

		if _, err := DerivePublicKey(parent.PublicKey, make([]byte, secp.ScalarSize-1)); err == nil {
			t.Fatal("short additive shift accepted")
		}
		if _, err := DerivePublicKey(parent.PublicKey, bytes.Repeat([]byte{0xff}, secp.ScalarSize)); err == nil {
			t.Fatal("out-of-range additive shift accepted")
		}
	})
}
