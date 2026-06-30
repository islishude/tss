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
