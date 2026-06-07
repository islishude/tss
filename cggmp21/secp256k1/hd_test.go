package secp256k1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"slices"
	"testing"

	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// ---------------------------------------------------------------------------
// BIP-32 test vector helpers
// ---------------------------------------------------------------------------

// TestDeriveNonHardenedBIP32Vectors verifies DeriveNonHardenedBIP32 against
// official BIP-32 test vectors (non-hardened CKDpub only).
func TestDeriveNonHardenedBIP32Vectors(t *testing.T) {
	t.Run("TV1: m/0H/1", func(t *testing.T) {
		parentXPub := "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
		wantXPub := "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

		parent, err := ParseExtendedPublicKey(parentXPub)
		if err != nil {
			t.Fatalf("parse parent xpub: %v", err)
		}
		want, err := ParseExtendedPublicKey(wantXPub)
		if err != nil {
			t.Fatalf("parse expected xpub: %v", err)
		}

		result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], []uint32{1})
		if err != nil {
			t.Fatalf("DeriveNonHardenedBIP32: %v", err)
		}

		if !bytes.Equal(result.ChildPublicKey, want.PublicKey) {
			t.Errorf("public key mismatch:\n  got: %x\n want: %x", result.ChildPublicKey, want.PublicKey)
		}
		if !bytes.Equal(result.ChildChainCode, want.ChainCode[:]) {
			t.Errorf("chain code mismatch:\n  got: %x\n want: %x", result.ChildChainCode, want.ChainCode[:])
		}

		// Additive shift must derive child from parent.
		derivedPub, err := DerivePublicKey(parent.PublicKey, result.AdditiveShift)
		if err != nil {
			t.Fatalf("DerivePublicKey with additive shift: %v", err)
		}
		if !bytes.Equal(derivedPub, result.ChildPublicKey) {
			t.Errorf("additive shift does not produce child public key")
		}
	})

	t.Run("TV1: m/0H/1/2H/2", func(t *testing.T) {
		parentXPub := "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
		wantXPub := "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"

		parent, _ := ParseExtendedPublicKey(parentXPub)
		want, _ := ParseExtendedPublicKey(wantXPub)

		result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], []uint32{2})
		if err != nil {
			t.Fatalf("DeriveNonHardenedBIP32: %v", err)
		}
		if !bytes.Equal(result.ChildPublicKey, want.PublicKey) {
			t.Errorf("public key mismatch")
		}
		if !bytes.Equal(result.ChildChainCode, want.ChainCode[:]) {
			t.Errorf("chain code mismatch")
		}
	})

	t.Run("TV1: m/0H/1/2H/2/1000000000", func(t *testing.T) {
		parentXPub := "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
		wantXPub := "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"

		parent, _ := ParseExtendedPublicKey(parentXPub)
		want, _ := ParseExtendedPublicKey(wantXPub)

		result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], []uint32{1000000000})
		if err != nil {
			t.Fatalf("DeriveNonHardenedBIP32: %v", err)
		}
		if !bytes.Equal(result.ChildPublicKey, want.PublicKey) {
			t.Errorf("public key mismatch")
		}
		if !bytes.Equal(result.ChildChainCode, want.ChainCode[:]) {
			t.Errorf("chain code mismatch")
		}
	})

	t.Run("TV2: m/0", func(t *testing.T) {
		parentXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
		wantXPub := "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

		parent, _ := ParseExtendedPublicKey(parentXPub)
		want, _ := ParseExtendedPublicKey(wantXPub)

		result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], []uint32{0})
		if err != nil {
			t.Fatalf("DeriveNonHardenedBIP32: %v", err)
		}
		if !bytes.Equal(result.ChildPublicKey, want.PublicKey) {
			t.Errorf("public key mismatch")
		}
		if !bytes.Equal(result.ChildChainCode, want.ChainCode[:]) {
			t.Errorf("chain code mismatch")
		}
	})

	t.Run("TV2: m/0/2147483647H/1", func(t *testing.T) {
		parentXPub := "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
		wantXPub := "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"

		parent, _ := ParseExtendedPublicKey(parentXPub)
		want, _ := ParseExtendedPublicKey(wantXPub)

		result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], []uint32{1})
		if err != nil {
			t.Fatalf("DeriveNonHardenedBIP32: %v", err)
		}
		if !bytes.Equal(result.ChildPublicKey, want.PublicKey) {
			t.Errorf("public key mismatch")
		}
		if !bytes.Equal(result.ChildChainCode, want.ChainCode[:]) {
			t.Errorf("chain code mismatch")
		}
	})

	t.Run("TV2: m/0/2147483647H/1/2147483646H/2", func(t *testing.T) {
		parentXPub := "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
		wantXPub := "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"

		parent, _ := ParseExtendedPublicKey(parentXPub)
		want, _ := ParseExtendedPublicKey(wantXPub)

		result, err := DeriveNonHardenedBIP32(parent.PublicKey, parent.ChainCode[:], []uint32{2})
		if err != nil {
			t.Fatalf("DeriveNonHardenedBIP32: %v", err)
		}
		if !bytes.Equal(result.ChildPublicKey, want.PublicKey) {
			t.Errorf("public key mismatch")
		}
		if !bytes.Equal(result.ChildChainCode, want.ChainCode[:]) {
			t.Errorf("chain code mismatch")
		}
	})
}

// TestDeriveNonHardenedBIP32MultiStep verifies multi-step vs chained consistency.
func TestDeriveNonHardenedBIP32MultiStep(t *testing.T) {
	masterXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	m0XPub := "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

	root, _ := ParseExtendedPublicKey(masterXPub)
	want, _ := ParseExtendedPublicKey(m0XPub)

	// Derive [0] in one step.
	result1, err := DeriveNonHardenedBIP32(root.PublicKey, root.ChainCode[:], []uint32{0})
	if err != nil {
		t.Fatalf("DeriveNonHardenedBIP32([0]): %v", err)
	}
	if !bytes.Equal(result1.ChildPublicKey, want.PublicKey) {
		t.Errorf("one-step m/0 pubkey mismatch")
	}
	if !bytes.Equal(result1.ChildChainCode, want.ChainCode[:]) {
		t.Errorf("one-step m/0 chain code mismatch")
	}

	// Derive [0, 1] in a single call, then compare to chained result.
	result2, err := DeriveNonHardenedBIP32(root.PublicKey, root.ChainCode[:], []uint32{0, 1})
	if err != nil {
		t.Fatalf("DeriveNonHardenedBIP32([0, 1]): %v", err)
	}

	// Chained: derive [1] from m/0.
	chained, err := DeriveNonHardenedBIP32(result1.ChildPublicKey, result1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatalf("chained DeriveNonHardenedBIP32([1] from m/0): %v", err)
	}

	if !bytes.Equal(result2.ChildPublicKey, chained.ChildPublicKey) {
		t.Errorf("multi-step vs chained public key mismatch")
	}

	// The additive shift from [0,1] should map root to final child.
	derivedFromRoot, err := DerivePublicKey(root.PublicKey, result2.AdditiveShift)
	if err != nil {
		t.Fatalf("DerivePublicKey with multi-step shift: %v", err)
	}
	if !bytes.Equal(derivedFromRoot, result2.ChildPublicKey) {
		t.Errorf("multi-step additive shift inconsistent with child pubkey")
	}

	t.Logf("additive shift [0]: %x", result1.AdditiveShift)
	t.Logf("chained shift [1]: %x", chained.AdditiveShift)
	t.Logf("multi-step shift [0,1]: %x", result2.AdditiveShift)
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

func TestDeriveNonHardenedBIP32Errors(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	t.Run("nil chain code", func(t *testing.T) {
		_, err := DeriveNonHardenedBIP32(valid.PublicKey, nil, []uint32{0})
		if !errors.Is(err, bip32util.ErrChainCodeRequired) {
			t.Errorf("expected bip32util.ErrChainCodeRequired, got %v", err)
		}
	})

	t.Run("empty chain code", func(t *testing.T) {
		_, err := DeriveNonHardenedBIP32(valid.PublicKey, []byte{}, []uint32{0})
		if !errors.Is(err, bip32util.ErrChainCodeRequired) {
			t.Errorf("expected bip32util.ErrChainCodeRequired, got %v", err)
		}
	})

	t.Run("wrong chain code length", func(t *testing.T) {
		_, err := DeriveNonHardenedBIP32(valid.PublicKey, make([]byte, 31), []uint32{0})
		if !errors.Is(err, bip32util.ErrInvalidChainCodeLength) {
			t.Errorf("expected bip32util.ErrInvalidChainCodeLength, got %v", err)
		}
		_, err = DeriveNonHardenedBIP32(valid.PublicKey, make([]byte, 33), []uint32{0})
		if !errors.Is(err, bip32util.ErrInvalidChainCodeLength) {
			t.Errorf("expected bip32util.ErrInvalidChainCodeLength, got %v", err)
		}
	})

	t.Run("path too long", func(t *testing.T) {
		longPath := make([]uint32, 256)
		for i := range longPath {
			longPath[i] = uint32(i)
		}
		_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], longPath)
		if !errors.Is(err, bip32util.ErrDerivationDepthOverflow) {
			t.Errorf("expected bip32util.ErrDerivationDepthOverflow, got %v", err)
		}
	})

	t.Run("hardened index rejected", func(t *testing.T) {
		_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0, bip32util.HardenedKeyStart})
		if !errors.Is(err, bip32util.ErrHardenedDerivationUnsupported) {
			t.Errorf("expected bip32util.ErrHardenedDerivationUnsupported, got %v", err)
		}
		_, err = DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{bip32util.HardenedKeyStart + 1})
		if !errors.Is(err, bip32util.ErrHardenedDerivationUnsupported) {
			t.Errorf("expected bip32util.ErrHardenedDerivationUnsupported, got %v", err)
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		invalidPub := make([]byte, 33)
		copy(invalidPub, valid.PublicKey)
		invalidPub[0] = 0x04 // uncompressed prefix
		_, err := DeriveNonHardenedBIP32(invalidPub, valid.ChainCode[:], []uint32{0})
		if !errors.Is(err, bip32util.ErrInvalidPublicKey) {
			t.Errorf("expected bip32util.ErrInvalidPublicKey, got %v", err)
		}
	})

	t.Run("wrong length public key", func(t *testing.T) {
		_, err := DeriveNonHardenedBIP32(make([]byte, 32), valid.ChainCode[:], []uint32{0})
		if !errors.Is(err, bip32util.ErrInvalidPublicKey) {
			t.Errorf("expected bip32util.ErrInvalidPublicKey, got %v", err)
		}
	})

	t.Run("all-zero public key", func(t *testing.T) {
		_, err := DeriveNonHardenedBIP32(make([]byte, 33), slices.Clone(valid.ChainCode[:]), []uint32{0})
		if !errors.Is(err, bip32util.ErrInvalidPublicKey) {
			t.Errorf("expected bip32util.ErrInvalidPublicKey, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Empty path
// ---------------------------------------------------------------------------

func TestDeriveNonHardenedBIP32_EmptyPathReturnsParent(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	// nil path
	result, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], nil)
	if err != nil {
		t.Fatalf("nil path: %v", err)
	}
	if !bytes.Equal(result.ChildPublicKey, valid.PublicKey) {
		t.Error("nil path: child public key should equal parent")
	}
	if !bytes.Equal(result.ChildChainCode, valid.ChainCode[:]) {
		t.Error("nil path: child chain code should equal parent")
	}
	if !isZeroBytes(result.AdditiveShift) {
		t.Error("nil path: additive shift should be zero")
	}
	if result.RequestedPath != nil {
		t.Error("nil path: RequestedPath should be nil")
	}
	if result.ResolvedPath != nil {
		t.Error("nil path: ResolvedPath should be nil")
	}

	// empty path
	result, err = DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{})
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if !bytes.Equal(result.ChildPublicKey, valid.PublicKey) {
		t.Error("empty path: child public key should equal parent")
	}
	if !bytes.Equal(result.ChildChainCode, valid.ChainCode[:]) {
		t.Error("empty path: child chain code should equal parent")
	}
	if !isZeroBytes(result.AdditiveShift) {
		t.Error("empty path: additive shift should be zero")
	}
}

// ---------------------------------------------------------------------------
// Cumulative shift and intermediate key checks
// ---------------------------------------------------------------------------

func TestDeriveNonHardenedBIP32_CumulativeShiftMatchesChildPublicKey(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	path := []uint32{0, 1, 2, 3, 4}
	result, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], path)
	if err != nil {
		t.Fatal(err)
	}

	derivedPub, err := DerivePublicKey(valid.PublicKey, result.AdditiveShift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivedPub, result.ChildPublicKey) {
		t.Error("cumulative shift does not produce child public key")
	}
}

func TestDeriveNonHardenedBIP32_MultiLevelUsesIntermediateParentPublicKey(t *testing.T) {
	// This test verifies that each HMAC step uses the intermediate child
	// public key, not the root. We verify by checking that multi-step
	// derivation matches chained single-step derivations.
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	// Chained: m → m/0 → m/0/1 → m/0/1/2
	step1, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	step2, err := DeriveNonHardenedBIP32(step1.ChildPublicKey, step1.ChildChainCode, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}
	step3, err := DeriveNonHardenedBIP32(step2.ChildPublicKey, step2.ChildChainCode, []uint32{2})
	if err != nil {
		t.Fatal(err)
	}

	// Single call: m → m/0/1/2
	direct, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(direct.ChildPublicKey, step3.ChildPublicKey) {
		t.Error("multi-step vs chained public key mismatch — intermediate keys not used correctly")
	}
	if !bytes.Equal(direct.ChildChainCode, step3.ChildChainCode) {
		t.Error("multi-step vs chained chain code mismatch")
	}
}

func TestDeriveNonHardenedBIP32_DoesNotMutateInputs(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	origPub := slices.Clone(valid.PublicKey)
	origChain := slices.Clone(valid.ChainCode[:])
	origPath := []uint32{0, 1, 2}

	_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], origPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(valid.PublicKey, origPub) {
		t.Error("publicKey was mutated")
	}
	if !bytes.Equal(valid.ChainCode[:], origChain) {
		t.Error("chainCode was mutated")
	}
}

// ---------------------------------------------------------------------------
// Invalid child tests (via HMAC hook)
// ---------------------------------------------------------------------------

// fakeHMACForInvalidChild forces IL to be a specific value to trigger
// invalid-child conditions for testing.
func fakeHMACForInvalidChild(ilValue []byte) func(key, data []byte) ([]byte, []byte) {
	return func(key, data []byte) ([]byte, []byte) {
		il := make([]byte, 32)
		copy(il, ilValue)
		ir := make([]byte, 32)
		// Use a deterministic IR from the real HMAC for chain code continuity.
		mac := hmac.New(sha512.New, key)
		mac.Write(data)
		I := mac.Sum(nil)
		copy(ir, I[32:])
		return il, ir
	}
}

func TestDeriveNonHardenedBIP32_InvalidChildErrorMode(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	// Inject fake HMAC that returns IL = 0 (invalid).
	origHMAC := hmacSHA512
	t.Cleanup(func() { hmacSHA512 = origHMAC })

	hmacSHA512 = fakeHMACForInvalidChild(make([]byte, 32))

	_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0})
	if !errors.Is(err, bip32util.ErrInvalidChild) {
		t.Errorf("expected bip32util.ErrInvalidChild for IL==0, got %v", err)
	}

	// Inject fake HMAC that returns IL >= q (the order).
	// Use the secp256k1 order bytes directly.
	order := secp.Order()
	orderBytes := order.Bytes()
	ilOrder := make([]byte, 32)
	copy(ilOrder[32-len(orderBytes):], orderBytes)
	hmacSHA512 = fakeHMACForInvalidChild(ilOrder)

	_, err = DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0})
	if !errors.Is(err, bip32util.ErrInvalidChild) {
		t.Errorf("expected bip32util.ErrInvalidChild for IL>=order, got %v", err)
	}
}

func TestDeriveNonHardenedBIP32_InvalidChildSkipMode(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	origHMAC := hmacSHA512
	t.Cleanup(func() { hmacSHA512 = origHMAC })

	// Make index 0 invalid but index 1 valid.
	callCount := 0
	hmacSHA512 = func(key, data []byte) ([]byte, []byte) {
		callCount++
		if callCount == 1 {
			// First call (index 0): return IL=0 (invalid)
			return make([]byte, 32), make([]byte, 32)
		}
		// Subsequent call (index 1): use real HMAC
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

	// The resolved path should have used index 1 instead of 0.
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

func TestDeriveNonHardenedBIP32_InvalidChildSkipModeStopsBeforeHardenedRange(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

	origHMAC := hmacSHA512
	t.Cleanup(func() { hmacSHA512 = origHMAC })

	// Always return IL=0 so every index is invalid.
	hmacSHA512 = fakeHMACForInvalidChild(make([]byte, 32))

	// Start from index 0x7FFFFFFF (last non-hardened). Skip should fail
	// because 0x80000000 is hardened.
	_, err := DeriveNonHardenedBIP32(valid.PublicKey, valid.ChainCode[:], []uint32{0x7FFFFFFF},
		bip32util.WithInvalidChildMode(bip32util.SkipInvalidChild))
	if !errors.Is(err, bip32util.ErrHardenedDerivationUnsupported) {
		t.Errorf("expected bip32util.ErrHardenedDerivationUnsupported, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// DerivationResult metadata checks
// ---------------------------------------------------------------------------

func TestDeriveNonHardenedBIP32Extended_ResultMetadata(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	valid, _ := ParseExtendedPublicKey(validXPub)

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
	// ParentFingerprint should be non-zero after derivation.
	zeroFP := [4]byte{}
	if result.ParentFingerprint == zeroFP {
		t.Error("parent fingerprint should not be zero after multi-step derivation")
	}
}

// ---------------------------------------------------------------------------
// XPub serialization / deserialization
// ---------------------------------------------------------------------------

func TestExtendedPublicKey_SerializeMainnetXPub_RoundTrip(t *testing.T) {
	original := "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
	xpub, err := ParseExtendedPublicKey(original)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip.
	serialized, err := xpub.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExtendedPublicKey(original)
	if err != nil {
		t.Fatal(err)
	}
	serialized2, err := parsed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serialized, serialized2) {
		t.Error("round-trip serialize mismatch")
	}

	// String round-trip.
	s, err := xpub.String()
	if err != nil {
		t.Fatal(err)
	}
	if s != original {
		t.Errorf("xpub String round-trip:\n  got: %s\n want: %s", s, original)
	}
}

func TestExtendedPublicKey_SerializeTestnetTPub(t *testing.T) {
	// Use a testnet tpub version. We take a known mainnet xpub, parse it,
	// change version to testnet, and verify serialization.
	mainnet := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	xpub, _ := ParseExtendedPublicKey(mainnet)

	// Create testnet version manually.
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

	// Parse back.
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
}

func TestExtendedPublicKey_ParseRejectsBadChecksum(t *testing.T) {
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	// Flip last character to break checksum.
	broken := validXPub[:len(validXPub)-1] + "X"
	_, err := ParseExtendedPublicKey(broken)
	if err == nil {
		t.Error("expected error for bad checksum")
	}
}

func TestExtendedPublicKey_ParseRejectsInvalidVersion(t *testing.T) {
	knownXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	known, _ := ParseExtendedPublicKey(knownXPub)

	bad := ExtendedPublicKey{
		Version:           [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
		Depth:             0,
		ParentFingerprint: known.ParentFingerprint,
		ChildNumber:       0,
		ChainCode:         known.ChainCode,
		PublicKey:         known.PublicKey,
	}
	// bad.String() calls Validate(), which rejects unknown version.
	_, err := bad.String()
	if !errors.Is(err, bip32util.ErrInvalidExtendedPublicKey) {
		t.Errorf("expected bip32util.ErrInvalidExtendedPublicKey from Validate, got %v", err)
	}
}

func TestExtendedPublicKey_ParseRejectsInvalidCurvePoint(t *testing.T) {
	knownXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	known, _ := ParseExtendedPublicKey(knownXPub)

	// Mutate the public key to an invalid point (all zeros - invalid prefix).
	badPub := make([]byte, 33)
	badXPub := &ExtendedPublicKey{
		Version:           known.Version,
		Depth:             known.Depth,
		ParentFingerprint: known.ParentFingerprint,
		ChildNumber:       known.ChildNumber,
		ChainCode:         known.ChainCode,
		PublicKey:         badPub,
	}
	// badXPub.String() calls Validate(), which rejects invalid curve point.
	_, err := badXPub.String()
	if !errors.Is(err, bip32util.ErrInvalidExtendedPublicKey) {
		t.Errorf("expected bip32util.ErrInvalidExtendedPublicKey from Validate for invalid point, got %v", err)
	}
}

func TestExtendedPublicKey_DeriveRejectsHardened(t *testing.T) {
	knownXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	known, _ := ParseExtendedPublicKey(knownXPub)

	_, _, err := known.Derive([]uint32{bip32util.HardenedKeyStart})
	if !errors.Is(err, bip32util.ErrHardenedDerivationUnsupported) {
		t.Errorf("expected bip32util.ErrHardenedDerivationUnsupported, got %v", err)
	}
}

func TestExtendedPublicKey_DeriveMatchesDeriveNonHardenedBIP32Extended(t *testing.T) {
	knownXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	known, _ := ParseExtendedPublicKey(knownXPub)

	path := []uint32{0, 1, 2}

	// Via ExtendedPublicKey.Derive
	childXPub, shift1, err := known.Derive(path)
	if err != nil {
		t.Fatal(err)
	}

	// Via DeriveNonHardenedBIP32Extended
	result, err := DeriveNonHardenedBIP32Extended(known.PublicKey, known.ChainCode[:], path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(childXPub.PublicKey, result.ChildPublicKey) {
		t.Error("xpub Derive public key mismatch with DeriveNonHardenedBIP32Extended")
	}
	if !bytes.Equal(shift1, result.AdditiveShift) {
		t.Error("xpub Derive additive shift mismatch")
	}
	if childXPub.Depth != result.Depth {
		t.Errorf("depth mismatch: xpub=%d, result=%d", childXPub.Depth, result.Depth)
	}
}

func TestExtendedPublicKey_Fingerprint(t *testing.T) {
	knownXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	known, _ := ParseExtendedPublicKey(knownXPub)

	childXPub, _, err := known.Derive([]uint32{0})
	if err != nil {
		t.Fatal(err)
	}

	// The child's parent fingerprint should be the fingerprint of the parent public key.
	expectedFP := bip32util.ComputeFingerprint(known.PublicKey)
	if childXPub.ParentFingerprint != expectedFP {
		t.Errorf("parent fingerprint mismatch:\n  got: %x\n want: %x",
			childXPub.ParentFingerprint[:], expectedFP[:])
	}

	// Depth should be 1 after one derivation step.
	if childXPub.Depth != 1 {
		t.Errorf("expected depth 1, got %d", childXPub.Depth)
	}
}

// TestExtendedPublicKey_BIP32VectorXPubDerive checks that an xpub derived from
// a known BIP32 vector node matches the expected xpub.
func TestExtendedPublicKey_BIP32VectorXPubDerive(t *testing.T) {
	parentXPub := "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	wantXPub := "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

	parent, _ := ParseExtendedPublicKey(parentXPub)
	want, _ := ParseExtendedPublicKey(wantXPub)

	child, shift, err := parent.Derive([]uint32{1})
	if err != nil {
		t.Fatal(err)
	}

	_ = shift
	if !bytes.Equal(child.PublicKey, want.PublicKey) {
		t.Error("child public key mismatch")
	}
	if child.Depth != 2 {
		t.Errorf("expected depth 2 (parent is at depth 1 from hardened root), got %d", child.Depth)
	}
	if child.ChildNumber != 1 {
		t.Errorf("expected child number 1, got %d", child.ChildNumber)
	}
}

// TestExtendedPublicKey_EmptyPathDerive returns self.
func TestExtendedPublicKey_EmptyPathDerive(t *testing.T) {
	knownXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	known, _ := ParseExtendedPublicKey(knownXPub)

	child, shift, err := known.Derive(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(child.PublicKey, known.PublicKey) {
		t.Error("empty path Derive should return same public key")
	}
	if !isZeroBytes(shift) {
		t.Error("empty path shift should be zero")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
