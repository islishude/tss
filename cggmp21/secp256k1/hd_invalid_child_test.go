package secp256k1

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestDeriveNonHardenedBIP32InvalidChildErrorMode(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)

	t.Run("IL>=order", func(t *testing.T) {
		orderBytes := secp.Order().Bytes()
		ilOrder := make([]byte, 32)
		copy(ilOrder[32-len(orderBytes):], orderBytes)

		_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0},
			tss.WithHMACFunc(fakeHMACForInvalidChild(ilOrder)))
		if !errors.Is(err, tss.ErrInvalidChild) {
			t.Errorf("expected tss.ErrInvalidChild for IL>=order, got %v", err)
		}
	})
}

func TestDeriveNonHardenedBIP32InvalidChildSkipMode(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)
	orderBytes := secp.Order().FillBytes(make([]byte, 32))

	callCount := 0
	result, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0},
		tss.WithInvalidChildMode(tss.SkipInvalidChild),
		tss.WithHMACFunc(func(key, data []byte) []byte {
			callCount++
			if callCount == 1 {
				return fakeHMACForInvalidChild(orderBytes)(key, data)
			}
			return bip32util.HMACSHA512(key, data)
		}))
	if err != nil {
		t.Fatalf("tss.SkipInvalidChild: %v", err)
	}
	if len(result.ResolvedPath) != 1 || result.ResolvedPath[0] != 1 {
		t.Errorf("expected resolved path [1], got %v", result.ResolvedPath)
	}
	if len(result.RequestedPath) != 1 || result.RequestedPath[0] != 0 {
		t.Errorf("expected requested path [0], got %v", result.RequestedPath)
	}
	if result.ChildNumber != 1 {
		t.Errorf("expected child number 1, got %d", result.ChildNumber)
	}
}

func TestDeriveNonHardenedBIP32InvalidChildSkipModeStopsBeforeHardenedRange(t *testing.T) {
	t.Parallel()

	valid := mustParseXPub(t, xpubTV2Master)
	orderBytes := secp.Order().FillBytes(make([]byte, 32))

	_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0x7FFFFFFF},
		tss.WithInvalidChildMode(tss.SkipInvalidChild),
		tss.WithHMACFunc(fakeHMACForInvalidChild(orderBytes)))
	if !errors.Is(err, tss.ErrHardenedDerivationUnsupported) {
		t.Errorf("expected tss.ErrHardenedDerivationUnsupported, got %v", err)
	}
}
