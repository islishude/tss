package secp256k1

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/islishude/tss/internal/bip32util"
	"github.com/islishude/tss/internal/testutil"
)

// TestDeriveNonHardenedBIP32Vectors verifies DeriveNonHardenedBIP32 against
// official BIP-32 test vectors (non-hardened CKDpub only).
func TestDeriveNonHardenedBIP32Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parentXPub string
		wantXPub   string
		path       []uint32
	}{
		{name: "TV1: m/0H/1", parentXPub: xpubTV1M0H, wantXPub: xpubTV1M0H1, path: []uint32{1}},
		{name: "TV1: m/0H/1/2H/2", parentXPub: xpubTV1M0H12H, wantXPub: xpubTV1M0H12H2, path: []uint32{2}},
		{name: "TV1: m/0H/1/2H/2/1000000000", parentXPub: xpubTV1M0H12H2, wantXPub: xpubTV1M0H12H21000000000, path: []uint32{1000000000}},
		{name: "TV2: m/0", parentXPub: xpubTV2Master, wantXPub: xpubTV2M0, path: []uint32{0}},
		{name: "TV2: m/0/2147483647H/1", parentXPub: xpubTV2M02147483647H, wantXPub: xpubTV2M02147483647H1, path: []uint32{1}},
		{name: "TV2: m/0/2147483647H/1/2147483646H/2", parentXPub: xpubTV2M02147483647H12147483646H, wantXPub: xpubTV2M02147483647H12147483646H2, path: []uint32{2}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parent := mustParseXPub(t, tc.parentXPub)
			want := mustParseXPub(t, tc.wantXPub)

			result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], tc.path)
			if err != nil {
				t.Fatalf("DeriveNonHardenedBIP32: %v", err)
			}

			assertDerivationMatchesXPub(t, result, want)
			assertAdditiveShiftDerivesChild(t, parent, result)
		})
	}
}

func TestDeriveNonHardenedBIP32MultiStepConsistency(t *testing.T) {
	t.Parallel()

	root := mustParseXPub(t, xpubTV2Master)
	wantM0 := mustParseXPub(t, xpubTV2M0)

	oneStep, err := DeriveNonHardenedBIP32(root.PublicKey, root.ChainCode[:], []uint32{0})
	if err != nil {
		t.Fatalf("DeriveNonHardenedBIP32([0]): %v", err)
	}
	assertDerivationMatchesXPub(t, oneStep, wantM0)

	direct, err := DeriveNonHardenedBIP32(root.PublicKey, root.ChainCode[:], []uint32{0, 1, 2})
	if err != nil {
		t.Fatalf("DeriveNonHardenedBIP32([0,1,2]): %v", err)
	}

	step2, err := DeriveNonHardenedBIP32(oneStep.ChildPublicKey, oneStep.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatalf("chained DeriveNonHardenedBIP32([1] from m/0): %v", err)
	}
	chained, err := DeriveNonHardenedBIP32(step2.ChildPublicKey, step2.ChildChainCode, []uint32{2})
	if err != nil {
		t.Fatalf("chained DeriveNonHardenedBIP32([2] from m/0/1): %v", err)
	}

	if !bytes.Equal(direct.ChildPublicKey, chained.ChildPublicKey) {
		t.Error("multi-step vs chained public key mismatch")
	}
	if !bytes.Equal(direct.ChildChainCode, chained.ChildChainCode) {
		t.Error("multi-step vs chained chain code mismatch")
	}

	derivedFromRoot, err := DerivePublicKey(root.PublicKey, direct.AdditiveShift)
	if err != nil {
		t.Fatalf("DerivePublicKey with multi-step shift: %v", err)
	}
	if !bytes.Equal(derivedFromRoot, direct.ChildPublicKey) {
		t.Error("multi-step additive shift inconsistent with child pubkey")
	}

	t.Logf("additive shift [0]: %x", oneStep.AdditiveShift)
	t.Logf("multi-step shift [0,1,2]: %x", direct.AdditiveShift)
}

func TestDeriveNonHardenedBIP32RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)

	tests := []struct {
		name    string
		pub     []byte
		chain   []byte
		path    []uint32
		wantErr error
	}{
		{
			name:    "nil chain code",
			pub:     valid.PublicKey,
			chain:   nil,
			path:    []uint32{0},
			wantErr: bip32util.ErrChainCodeRequired,
		},
		{
			name:    "empty chain code",
			pub:     valid.PublicKey,
			chain:   []byte{},
			path:    []uint32{0},
			wantErr: bip32util.ErrChainCodeRequired,
		},
		{
			name:    "short chain code",
			pub:     valid.PublicKey,
			chain:   make([]byte, 31),
			path:    []uint32{0},
			wantErr: bip32util.ErrInvalidChainCodeLength,
		},
		{
			name:    "long chain code",
			pub:     valid.PublicKey,
			chain:   make([]byte, 33),
			path:    []uint32{0},
			wantErr: bip32util.ErrInvalidChainCodeLength,
		},
		{
			name:    "path too long",
			pub:     valid.PublicKey,
			chain:   valid.ChainCode[:],
			path:    makeSequentialPath(256),
			wantErr: bip32util.ErrDerivationDepthOverflow,
		},
		{
			name:    "hardened index in path",
			pub:     valid.PublicKey,
			chain:   valid.ChainCode[:],
			path:    []uint32{0, bip32util.HardenedKeyStart},
			wantErr: bip32util.ErrHardenedDerivationUnsupported,
		},
		{
			name:    "hardened first index",
			pub:     valid.PublicKey,
			chain:   valid.ChainCode[:],
			path:    []uint32{bip32util.HardenedKeyStart + 1},
			wantErr: bip32util.ErrHardenedDerivationUnsupported,
		},
		{
			name:    "invalid public key prefix",
			pub:     invalidPublicKeyPrefix(valid.PublicKey),
			chain:   valid.ChainCode[:],
			path:    []uint32{0},
			wantErr: bip32util.ErrInvalidPublicKey,
		},
		{
			name:    "wrong public key length",
			pub:     make([]byte, 32),
			chain:   valid.ChainCode[:],
			path:    []uint32{0},
			wantErr: bip32util.ErrInvalidPublicKey,
		},
		{
			name:    "all-zero public key",
			pub:     make([]byte, 33),
			chain:   slices.Clone(valid.ChainCode[:]),
			path:    []uint32{0},
			wantErr: bip32util.ErrInvalidPublicKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := DeriveNonHardenedBIP32(tc.pub, tc.chain, tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDeriveNonHardenedBIP32EmptyPathReturnsParent(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)

	tests := []struct {
		name    string
		path    []uint32
		nilPath bool
	}{
		{name: "nil path", path: nil, nilPath: true},
		{name: "empty path", path: []uint32{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.ChildPublicKey, valid.PublicKey) {
				t.Error("child public key should equal parent")
			}
			if !bytes.Equal(result.ChildChainCode, valid.ChainCode[:]) {
				t.Error("child chain code should equal parent")
			}
			if !testutil.IsZeroBytes(result.AdditiveShift) {
				t.Error("additive shift should be zero")
			}
			if tc.nilPath {
				if result.RequestedPath != nil {
					t.Error("RequestedPath should be nil")
				}
				if result.ResolvedPath != nil {
					t.Error("ResolvedPath should be nil")
				}
			}
		})
	}
}

func TestDeriveNonHardenedBIP32CumulativeShiftMatchesChildPublicKey(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)
	result, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0, 1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	assertAdditiveShiftDerivesChild(t, valid, result)
}

func TestDeriveNonHardenedBIP32DoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)
	origPub := slices.Clone(valid.PublicKey)
	origChain := slices.Clone(valid.ChainCode[:])
	origPath := []uint32{0, 1, 2}

	if _, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], origPath); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(valid.PublicKey, origPub) {
		t.Error("publicKey was mutated")
	}
	if !bytes.Equal(valid.ChainCode[:], origChain) {
		t.Error("chainCode was mutated")
	}
}

func TestDeriveNonHardenedBIP32ExtendedResultMetadata(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)
	path := []uint32{0, 1, 2}
	result, err := DeriveNonHardenedBIP32Extended(valid.PublicKey, valid.ChainCode[:], path)
	if err != nil {
		t.Fatal(err)
	}

	if result.Depth != 3 {
		t.Errorf("expected depth 3, got %d", result.Depth)
	}
	if result.ChildNumber != 2 {
		t.Errorf("expected child number 2, got %d", result.ChildNumber)
	}
	if len(result.RequestedPath) != 3 {
		t.Errorf("expected requested path length 3, got %d", len(result.RequestedPath))
	}
	if len(result.ResolvedPath) != 3 {
		t.Errorf("expected resolved path length 3, got %d", len(result.ResolvedPath))
	}
	for i, v := range path {
		if result.RequestedPath[i] != v {
			t.Errorf("requested path[%d] = %d, want %d", i, result.RequestedPath[i], v)
		}
		if result.ResolvedPath[i] != v {
			t.Errorf("resolved path[%d] = %d, want %d", i, result.ResolvedPath[i], v)
		}
	}
	if result.ParentFingerprint == ([4]byte{}) {
		t.Error("parent fingerprint should not be zero after multi-step derivation")
	}
}

func makeSequentialPath(n int) []uint32 {
	path := make([]uint32, n)
	for i := range path {
		path[i] = uint32(i)
	}
	return path
}

func invalidPublicKeyPrefix(pub []byte) []byte {
	invalid := make([]byte, len(pub))
	copy(invalid, pub)
	invalid[0] = 0x04
	return invalid
}
