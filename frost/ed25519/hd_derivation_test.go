package ed25519

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func TestDerivePublicKey(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 1, 1)
	pub := shares[1].state.PublicKey.Bytes()

	t.Run("nil shift returns original", func(t *testing.T) {
		t.Parallel()

		same, err := DerivePublicKey(pub, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(same, pub) {
			t.Fatal("DerivePublicKey with nil shift should return original key")
		}
	})

	t.Run("zero shift returns original", func(t *testing.T) {
		t.Parallel()

		same, err := DerivePublicKey(pub, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(same, pub) {
			t.Fatal("DerivePublicKey with zero shift should return original key")
		}
	})

	t.Run("non-zero shift derives valid child", func(t *testing.T) {
		t.Parallel()

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
	})

	t.Run("identity child is rejected", func(t *testing.T) {
		t.Parallel()

		parent := fed.NewIdentityPoint().ScalarBaseMult(edcurve.ScalarOne()).Bytes()
		negativeOne := new(big.Int).Sub(edcurve.Order(), big.NewInt(1))
		shift, err := scalarBytes(negativeOne)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DerivePublicKey(parent, shift); err == nil {
			t.Fatal("DerivePublicKey accepted identity child public key")
		}
	})
}

func TestDeriveNonHardenedBIP32MatchesPublicMetadata(t *testing.T) {
	t.Parallel()

	shares := frostKeygenHD(t, 1, 1)
	share := shares[1]
	metadata, ok := share.PublicMetadata()
	if !ok {
		t.Fatal("missing public metadata")
	}
	path := tss.DerivationPath{0, 7}

	fromShare, err := share.Derive(path)
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
	_, err := shares[1].Derive(tss.DerivationPath{0, tss.HardenedKeyStart})
	if !errors.Is(err, tss.ErrHardenedDerivationUnsupported) {
		t.Fatalf("expected hardened path rejection, got %v", err)
	}
}
