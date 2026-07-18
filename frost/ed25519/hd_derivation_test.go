package ed25519

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

func TestDeriveNonHardenedBIP32MatchesPublicMetadata(t *testing.T) {
	t.Parallel()

	shares := frostKeygenHD(t, 1, 1)
	share := shares[1]
	metadata, ok := share.PublicMetadata()
	if !ok {
		t.Fatal("missing public metadata")
	}
	path := tss.DerivationPath{0, 7}
	limits := testLimits()
	if _, err := share.Derive(path); err == nil {
		t.Fatal("production derivation accepted a 1-of-1 key share")
	}

	fromShare, err := share.DeriveWithLimits(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	fromMetadata, err := DeriveNonHardenedBIP32(metadata.PublicKey.Bytes(), metadata.ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fromShare.ChildPublicKey, fromMetadata.ChildPublicKey) {
		t.Fatal("KeyShare.Derive child public key differs from public metadata derivation")
	}
	if fromShare.Scheme != tss.DerivationSchemeEd25519KhovratovichLaw {
		t.Fatalf("scheme = %q, want %q", fromShare.Scheme, tss.DerivationSchemeEd25519KhovratovichLaw)
	}
}

func TestDeriveNonHardenedBIP32HardenedPathRejected(t *testing.T) {
	t.Parallel()

	shares := frostKeygenHD(t, 1, 1)
	_, err := shares[1].DeriveWithLimits(tss.DerivationPath{0, tss.HardenedKeyStart}, testLimits())
	if !errors.Is(err, tss.ErrHardenedDerivationUnsupported) {
		t.Fatalf("expected hardened path rejection, got %v", err)
	}
}

func TestKeyShareDeriveRejectsDestroyedOrInconsistentShare(t *testing.T) {
	t.Parallel()
	shares := frostKeygenHD(t, 1, 1)
	limits := testLimits()

	t.Run("destroyed", func(t *testing.T) {
		share := cloneKeyShareValue(shares[1])
		share.Destroy()
		if _, err := share.DeriveWithLimits(tss.DerivationPath{0}, limits); err == nil {
			t.Fatal("destroyed key share derived a child key")
		}
	})

	t.Run("inconsistent chain code", func(t *testing.T) {
		share := cloneKeyShareValue(shares[1])
		defer share.Destroy()
		share.state.ChainCode[0] ^= 0xff
		if _, err := share.DeriveWithLimits(tss.DerivationPath{0}, limits); err == nil {
			t.Fatal("inconsistent key share derived a child key")
		}
	})
}
