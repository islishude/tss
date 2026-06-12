package secp256k1

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// This test modifies package-level hmacSHA512 and must remain sequential.
func TestDeriveNonHardenedBIP32InvalidChildErrorMode(t *testing.T) {
	valid := mustParseXPub(t, xpubTV2Master)

	origHMAC := hmacSHA512
	t.Cleanup(func() { hmacSHA512 = origHMAC })

	hmacSHA512 = fakeHMACForInvalidChild(make([]byte, 32))
	_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0})
	if !errors.Is(err, bip32util.ErrInvalidChild) {
		t.Errorf("expected bip32util.ErrInvalidChild for IL==0, got %v", err)
	}

	orderBytes := secp.Order().Bytes()
	ilOrder := make([]byte, 32)
	copy(ilOrder[32-len(orderBytes):], orderBytes)
	hmacSHA512 = fakeHMACForInvalidChild(ilOrder)

	_, err = DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0})
	if !errors.Is(err, bip32util.ErrInvalidChild) {
		t.Errorf("expected bip32util.ErrInvalidChild for IL>=order, got %v", err)
	}
}

// This test modifies package-level hmacSHA512 and must remain sequential.
func TestDeriveNonHardenedBIP32InvalidChildSkipMode(t *testing.T) {
	valid := mustParseXPub(t, xpubTV2Master)

	origHMAC := hmacSHA512
	t.Cleanup(func() { hmacSHA512 = origHMAC })

	callCount := 0
	hmacSHA512 = func(key, data []byte) ([]byte, []byte) {
		callCount++
		if callCount == 1 {
			return make([]byte, 32), make([]byte, 32)
		}
		mac := hmac.New(sha512.New, key)
		mac.Write(data)
		I := mac.Sum(nil)
		return I[:32], I[32:]
	}

	result, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0},
		bip32util.WithInvalidChildMode(bip32util.SkipInvalidChild))
	if err != nil {
		t.Fatalf("bip32util.SkipInvalidChild: %v", err)
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

// This test modifies package-level hmacSHA512 and must remain sequential.
func TestDeriveNonHardenedBIP32InvalidChildSkipModeStopsBeforeHardenedRange(t *testing.T) {
	valid := mustParseXPub(t, xpubTV2Master)

	origHMAC := hmacSHA512
	t.Cleanup(func() { hmacSHA512 = origHMAC })

	hmacSHA512 = fakeHMACForInvalidChild(make([]byte, 32))
	_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0x7FFFFFFF},
		bip32util.WithInvalidChildMode(bip32util.SkipInvalidChild))
	if !errors.Is(err, bip32util.ErrHardenedDerivationUnsupported) {
		t.Errorf("expected bip32util.ErrHardenedDerivationUnsupported, got %v", err)
	}
}
