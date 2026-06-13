package ed25519

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss/internal/bip32util"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestDerivePublicKey(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 1, 1)
	pub := shares[1].state.publicKey

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

// TestDeriveNonHardenedBIP32Vectors verifies derivation against golden test
// vectors generated with the reference HMAC-SHA512 construction (single-round).
func TestDeriveNonHardenedBIP32Vectors(t *testing.T) {
	t.Parallel()

	parentPub := frostHDVectorParentPub(t)
	chainCode := frostHDVectorChainCode(t)

	for _, tc := range frostHDVectorCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := DeriveNonHardenedBIP32(parentPub, chainCode, []uint32{tc.index})
			if err != nil {
				t.Fatalf("DeriveNonHardenedBIP32: %v", err)
			}
			if got := hex.EncodeToString(result.ChildChainCode); got != tc.wantChain {
				t.Errorf("child chain code:\n  got: %s\n want: %s", got, tc.wantChain)
			}
			assertFROSTHDDerivesChild(t, parentPub, result)
		})
	}
}

func TestDeriveNonHardenedBIP32MultiStepConsistency(t *testing.T) {
	t.Parallel()

	parentPub := frostHDVectorParentPub(t)
	chainCode := frostHDVectorChainCode(t)

	result, err := DeriveNonHardenedBIP32(parentPub, chainCode, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := DeriveNonHardenedBIP32(parentPub, chainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := DeriveNonHardenedBIP32(r1.ChildPublicKey, r1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result.ChildChainCode, r2.ChildChainCode) {
		t.Error("multi-step chain code != chained single-step chain code")
	}
	if !bytes.Equal(result.ChildPublicKey, r2.ChildPublicKey) {
		t.Error("multi-step child pub != chained single-step child pub")
	}
}

func TestDeriveNonHardenedBIP32EmptyPathReturnsParent(t *testing.T) {
	t.Parallel()

	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].state.publicKey
	cc := shares[1].state.chainCode

	tests := []struct {
		name string
		path []uint32
	}{
		{name: "nil path", path: nil},
		{name: "empty path", path: []uint32{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := DeriveNonHardenedBIP32(pub, cc, tc.path)
			if err != nil {
				t.Fatalf("path=%v: %v", tc.path, err)
			}
			if !bytes.Equal(result.ChildPublicKey, pub) {
				t.Errorf("path=%v: child pub != parent pub", tc.path)
			}
			if !bytes.Equal(result.ChildChainCode, cc) {
				t.Errorf("path=%v: child chain != parent chain", tc.path)
			}
			if !testutil.IsZeroBytes(result.AdditiveShift) {
				t.Errorf("path=%v: additive shift should be zero", tc.path)
			}
			if result.Depth != 0 {
				t.Errorf("path=%v: depth should be 0", tc.path)
			}
		})
	}
}

func TestDeriveNonHardenedBIP32RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	hdShares := frostKeygenHD(t, 1, 1)
	hdPub := hdShares[1].state.publicKey
	hdChain := hdShares[1].state.chainCode
	nonHDShares := frostKeygen(t, 1, 1)
	nonHDPub := nonHDShares[1].state.publicKey

	tests := []struct {
		name    string
		pub     []byte
		chain   []byte
		path    []uint32
		wantErr error
	}{
		{
			name:    "depth overflow",
			pub:     hdPub,
			chain:   hdChain,
			path:    makeFROSTHDPath(256, 0),
			wantErr: bip32util.ErrDerivationDepthOverflow,
		},
		{
			name:    "hardened first index",
			pub:     hdPub,
			chain:   hdChain,
			path:    []uint32{bip32util.HardenedKeyStart},
			wantErr: bip32util.ErrHardenedDerivationUnsupported,
		},
		{
			name:    "hardened index above start",
			pub:     hdPub,
			chain:   hdChain,
			path:    []uint32{bip32util.HardenedKeyStart + 1},
			wantErr: bip32util.ErrHardenedDerivationUnsupported,
		},
		{
			name:    "hardened index later in path",
			pub:     hdPub,
			chain:   hdChain,
			path:    []uint32{0, bip32util.HardenedKeyStart},
			wantErr: bip32util.ErrHardenedDerivationUnsupported,
		},
		{
			name:    "nil chain code",
			pub:     nonHDPub,
			chain:   nil,
			path:    []uint32{0},
			wantErr: bip32util.ErrChainCodeRequired,
		},
		{
			name:    "empty chain code",
			pub:     nonHDPub,
			chain:   []byte{},
			path:    []uint32{0},
			wantErr: bip32util.ErrChainCodeRequired,
		},
		{
			name:    "invalid public key",
			pub:     make([]byte, 31),
			chain:   makeFROSTHDChainCode(),
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

func TestDeriveNonHardenedBIP32SingleLevel(t *testing.T) {
	t.Parallel()

	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].state.publicKey
	cc := shares[1].state.chainCode

	result, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChildPublicKey) != 32 {
		t.Fatalf("child public key must be 32 bytes, got %d", len(result.ChildPublicKey))
	}
	if len(result.AdditiveShift) != 32 {
		t.Fatalf("additive shift must be 32 bytes, got %d", len(result.AdditiveShift))
	}
	if len(result.ChildChainCode) != 32 {
		t.Fatalf("child chain code must be 32 bytes, got %d", len(result.ChildChainCode))
	}
	if bytes.Equal(result.ChildChainCode, cc) {
		t.Fatal("child chain code should differ from parent")
	}
	assertFROSTHDDerivesChild(t, pub, result)
}

func TestDeriveNonHardenedBIP32Determinism(t *testing.T) {
	t.Parallel()

	shares := frostKeygenHD(t, 1, 1)
	pub := shares[1].state.publicKey
	cc := shares[1].state.chainCode
	path := []uint32{0, 1, 2}

	r1, err := DeriveNonHardenedBIP32(pub, cc, path)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := DeriveNonHardenedBIP32(pub, cc, path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(r1.ChildPublicKey, r2.ChildPublicKey) ||
		!bytes.Equal(r1.AdditiveShift, r2.AdditiveShift) ||
		!bytes.Equal(r1.ChildChainCode, r2.ChildChainCode) {
		t.Fatal("DeriveNonHardenedBIP32 is not deterministic")
	}

	rStep1, err := DeriveNonHardenedBIP32(pub, cc, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	rStep2, err := DeriveNonHardenedBIP32(rStep1.ChildPublicKey, rStep1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}
	rStep3, err := DeriveNonHardenedBIP32(rStep2.ChildPublicKey, rStep2.ChildChainCode, []uint32{2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1.ChildChainCode, rStep3.ChildChainCode) {
		t.Fatal("multi-step chain code should match single-step")
	}
}

func makeFROSTHDPath(n int, value uint32) []uint32 {
	path := make([]uint32, n)
	for i := range path {
		path[i] = value
	}
	return path
}

func makeFROSTHDChainCode() []byte {
	cc := make([]byte, 32)
	for i := range cc {
		cc[i] = byte(i)
	}
	return cc
}
