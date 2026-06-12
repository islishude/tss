package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss/internal/bip32util"
	"github.com/islishude/tss/internal/testutil"
)

func TestExtendedPublicKeySerializationScenarios(t *testing.T) {
	t.Parallel()

	t.Run("mainnet xpub round trip", func(t *testing.T) {
		t.Parallel()

		xpub := mustParseXPub(t, xpubTV1M0H1)
		serialized, err := xpub.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		parsed := mustParseXPub(t, xpubTV1M0H1)
		serialized2, err := parsed.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(serialized, serialized2) {
			t.Error("round-trip serialize mismatch")
		}

		s, err := xpub.String()
		if err != nil {
			t.Fatal(err)
		}
		if s != xpubTV1M0H1 {
			t.Errorf("xpub String round-trip:\n  got: %s\n want: %s", s, xpubTV1M0H1)
		}
	})

	t.Run("testnet tpub", func(t *testing.T) {
		t.Parallel()

		xpub := mustParseXPub(t, xpubTV2Master)
		tpub := &ExtendedPublicKey{
			Version:           bip32util.TPubVersion,
			Depth:             xpub.Depth,
			ParentFingerprint: xpub.ParentFingerprint,
			ChildNumber:       xpub.ChildNumber,
			ChainCode:         xpub.ChainCode,
			PublicKey:         xpub.PublicKey,
		}

		s, err := tpub.String()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) < 4 || s[:4] != "tpub" {
			t.Errorf("expected tpub prefix, got: %s", s)
		}

		parsed, err := ParseExtendedPublicKey(s)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Version != bip32util.TPubVersion {
			t.Error("parsed tpub has wrong version")
		}
		if !bytes.Equal(parsed.PublicKey, xpub.PublicKey) {
			t.Error("parsed tpub public key mismatch")
		}
	})
}

func TestExtendedPublicKeyRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	known := mustParseXPub(t, xpubTV2Master)

	tests := []struct {
		name    string
		run     func() error
		wantErr error
	}{
		{
			name: "bad checksum",
			run: func() error {
				broken := xpubTV2Master[:len(xpubTV2Master)-1] + "X"
				_, err := ParseExtendedPublicKey(broken)
				return err
			},
		},
		{
			name: "invalid version",
			run: func() error {
				bad := ExtendedPublicKey{
					Version:           [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
					Depth:             0,
					ParentFingerprint: known.ParentFingerprint,
					ChildNumber:       0,
					ChainCode:         known.ChainCode,
					PublicKey:         known.PublicKey,
				}
				_, err := bad.String()
				return err
			},
			wantErr: bip32util.ErrInvalidExtendedPublicKey,
		},
		{
			name: "invalid curve point",
			run: func() error {
				badXPub := &ExtendedPublicKey{
					Version:           known.Version,
					Depth:             known.Depth,
					ParentFingerprint: known.ParentFingerprint,
					ChildNumber:       known.ChildNumber,
					ChainCode:         known.ChainCode,
					PublicKey:         make([]byte, 33),
				}
				_, err := badXPub.String()
				return err
			},
			wantErr: bip32util.ErrInvalidExtendedPublicKey,
		},
		{
			name: "hardened derive",
			run: func() error {
				_, _, err := known.Derive([]uint32{bip32util.HardenedKeyStart})
				return err
			},
			wantErr: bip32util.ErrHardenedDerivationUnsupported,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.run()
			if tc.wantErr == nil {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestExtendedPublicKeyDeriveScenarios(t *testing.T) {
	t.Parallel()

	t.Run("matches DeriveNonHardenedBIP32Extended", func(t *testing.T) {
		t.Parallel()

		known := mustParseXPub(t, xpubTV2Master)
		path := []uint32{0, 1, 2}

		childXPub, shift, err := known.Derive(path)
		if err != nil {
			t.Fatal(err)
		}
		result, err := DeriveNonHardenedBIP32Extended(known.PublicKey, known.ChainCode[:], path)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(childXPub.PublicKey, result.ChildPublicKey) {
			t.Error("xpub Derive public key mismatch with DeriveNonHardenedBIP32Extended")
		}
		if !bytes.Equal(shift, result.AdditiveShift) {
			t.Error("xpub Derive additive shift mismatch")
		}
		if childXPub.Depth != result.Depth {
			t.Errorf("depth mismatch: xpub=%d, result=%d", childXPub.Depth, result.Depth)
		}
	})

	t.Run("parent fingerprint", func(t *testing.T) {
		t.Parallel()

		known := mustParseXPub(t, xpubTV2Master)
		childXPub, _, err := known.Derive([]uint32{0})
		if err != nil {
			t.Fatal(err)
		}

		expectedFP := bip32util.ComputeFingerprint(known.PublicKey)
		if childXPub.ParentFingerprint != expectedFP {
			t.Errorf("parent fingerprint mismatch:\n  got: %x\n want: %x",
				childXPub.ParentFingerprint[:], expectedFP[:])
		}
		if childXPub.Depth != 1 {
			t.Errorf("expected depth 1, got %d", childXPub.Depth)
		}
	})

	t.Run("BIP32 vector xpub derive", func(t *testing.T) {
		t.Parallel()

		parent := mustParseXPub(t, xpubTV1M0H)
		want := mustParseXPub(t, xpubTV1M0H1)

		child, shift, err := parent.Derive([]uint32{1})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(child.PublicKey, want.PublicKey) {
			t.Error("child public key mismatch")
		}
		_ = shift
		if child.Depth != 2 {
			t.Errorf("expected depth 2 (parent is at depth 1 from hardened root), got %d", child.Depth)
		}
		if child.ChildNumber != 1 {
			t.Errorf("expected child number 1, got %d", child.ChildNumber)
		}
	})

	t.Run("empty path returns self", func(t *testing.T) {
		t.Parallel()

		known := mustParseXPub(t, xpubTV2Master)
		child, shift, err := known.Derive(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(child.PublicKey, known.PublicKey) {
			t.Error("empty path Derive should return same public key")
		}
		if !testutil.IsZeroBytes(shift) {
			t.Error("empty path shift should be zero")
		}
	})
}
