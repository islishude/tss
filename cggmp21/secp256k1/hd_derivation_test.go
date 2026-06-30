package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
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
