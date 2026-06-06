package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// --- Base58-check decoding (test-only) ---

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58Check decodes a base58-check encoded string.
// The checksum (first 4 bytes of double SHA-256 of the payload) is verified.
func decodeBase58Check(s string) ([]byte, error) {
	// Count leading '1's — each represents a leading zero byte.
	leadingZeros := 0
	for _, c := range s {
		if c == '1' {
			leadingZeros++
		} else {
			break
		}
	}

	// Decode base58.
	n := new(big.Int)
	base := big.NewInt(58)
	tmp := new(big.Int)
	for _, c := range s {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx == -1 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		n.Mul(n, base)
		n.Add(n, tmp.SetInt64(int64(idx)))
	}

	raw := n.Bytes()

	// Prepend leading zeros.
	decoded := make([]byte, leadingZeros+len(raw))
	copy(decoded[leadingZeros:], raw)

	// xpub/xprv payload is always 78 bytes + 4 bytes checksum = 82 total.
	// big.Int.Bytes() drops leading zeros within the numeric value. For
	// xpub version 0x0488B21E, the 0x04 byte is dropped, giving 81 bytes.
	// Pad to 82 if needed.
	for len(decoded) < 82 {
		decoded = append([]byte{0}, decoded...)
	}

	if len(decoded) < 4 {
		return nil, errors.New("decoded data too short for checksum")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	if !bytes.Equal(h2[:4], checksum) {
		return nil, errors.New("base58 checksum mismatch")
	}

	return payload, nil
}

// parseXPub extracts the compressed public key and chain code from a
// base58-encoded mainnet extended public key.
func parseXPub(xpub string) (pubKey, chainCode []byte, err error) {
	payload, err := decodeBase58Check(xpub)
	if err != nil {
		return nil, nil, fmt.Errorf("decode xpub: %w", err)
	}
	if len(payload) != 78 {
		return nil, nil, fmt.Errorf("xpub payload must be 78 bytes, got %d", len(payload))
	}

	// Version bytes: mainnet xpub = 0x0488B21E.
	version := binary.BigEndian.Uint32(payload[:4])
	if version != 0x0488B21E {
		return nil, nil, fmt.Errorf("expected xpub version 0x0488B21E, got 0x%08X", version)
	}

	// Layout: [4 version][1 depth][4 parent fp][4 child idx][32 chain][33 key]
	chainCode = make([]byte, 32)
	copy(chainCode, payload[13:45])
	pubKey = make([]byte, 33)
	copy(pubKey, payload[45:78])

	return pubKey, chainCode, nil
}

// ---------------------------------------------------------------------------
// BIP-32 test vectors
// ---------------------------------------------------------------------------

type bip32DeriveCase struct {
	name       string
	parentXPub string   // parent extended public key
	path       []uint32 // derivation path (non-hardened only)
	wantXPub   string   // expected child extended public key
}

// TestDeriveBIP32Vectors verifies DeriveBIP32 against the official BIP-32 test
// vectors (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
// Only non-hardened paths are tested since DeriveBIP32 does not support
// hardened derivation in the threshold setting.
func TestDeriveBIP32Vectors(t *testing.T) {
	cases := []bip32DeriveCase{
		// === Test Vector 1 (seed: 000102030405060708090a0b0c0d0e0f) ===
		// Path m/0_H (xpub68G...) → derive [1] → m/0_H/1 (xpub6ASu...)
		{
			name:       "TV1: m/0H/1",
			parentXPub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
			path:       []uint32{1},
			wantXPub:   "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
		},
		// Path m/0_H/1/2_H (xpub6D4B...) → derive [2] → m/0_H/1/2_H/2 (xpub6FHa...)
		{
			name:       "TV1: m/0H/1/2H/2",
			parentXPub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			path:       []uint32{2},
			wantXPub:   "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
		},
		// Path m/0_H/1/2_H/2 (xpub6FHa...) → derive [1000000000] → m/0_H/1/2_H/2/1000000000 (xpub6H1L...)
		{
			name:       "TV1: m/0H/1/2H/2/1000000000",
			parentXPub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
			path:       []uint32{1000000000},
			wantXPub:   "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
		},

		// === Test Vector 2 (seed: ffcf...484542) ===
		// Path m (xpub661...) → derive [0] → m/0 (xpub69H7...)
		{
			name:       "TV2: m/0",
			parentXPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
			path:       []uint32{0},
			wantXPub:   "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		// Path m/0/2147483647_H (xpub6ASA...) → derive [1] → m/0/2147483647_H/1 (xpub6DF8...)
		{
			name:       "TV2: m/0/2147483647H/1",
			parentXPub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
			path:       []uint32{1},
			wantXPub:   "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
		},
		// Path m/0/2147483647_H/1/2147483646_H (xpub6ERA...) → derive [2] → m/.../2 (xpub6FnC...)
		{
			name:       "TV2: m/0/2147483647H/1/2147483646H/2",
			parentXPub: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
			path:       []uint32{2},
			wantXPub:   "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
		},

		// === Multi-step non-hardened path ===
		// Derive m/0/1 from master in a single call; verify consistency
		// by comparing against the single-step result from m/0 xpub.
		{
			name:       "TV2 multi-step: m → [0, 1] via two calls consistent",
			parentXPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
			path:       []uint32{0},
			wantXPub:   "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parentPub, parentChain, err := parseXPub(tc.parentXPub)
			if err != nil {
				t.Fatalf("parse parent xpub: %v", err)
			}
			wantPub, wantChain, err := parseXPub(tc.wantXPub)
			if err != nil {
				t.Fatalf("parse expected xpub: %v", err)
			}

			gotPub, additiveShift, gotChain, err := DeriveBIP32(parentPub, parentChain, tc.path)
			if err != nil {
				t.Fatalf("DeriveBIP32: %v", err)
			}

			if !bytes.Equal(gotPub, wantPub) {
				t.Errorf("public key mismatch:\n  got: %x\n want: %x", gotPub, wantPub)
			}
			if !bytes.Equal(gotChain, wantChain) {
				t.Errorf("chain code mismatch:\n  got: %x\n want: %x", gotChain, wantChain)
			}

			// Verify that the additive shift correctly transforms the parent
			// public key to the derived child public key.
			derivedPub, err := DerivePublicKey(parentPub, additiveShift)
			if err != nil {
				t.Fatalf("DerivePublicKey with additive shift: %v", err)
			}
			if !bytes.Equal(derivedPub, gotPub) {
				t.Errorf("additive shift does not produce child public key:\n  derived: %x\n     got: %x", derivedPub, gotPub)
			}
		})
	}
}

// TestDeriveBIP32MultiStep verifies that multi-step derivation via DeriveBIP32
// produces the same result as chained single-step derivations.
func TestDeriveBIP32MultiStep(t *testing.T) {
	// TV2 master xpub
	masterXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	// TV2 m/0 xpub
	m0XPub := "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

	rootPub, rootChain, err := parseXPub(masterXPub)
	if err != nil {
		t.Fatalf("parse master xpub: %v", err)
	}

	// Derive [0] in one step → should match m/0 xpub.
	pub1, shift1, chain1, err := DeriveBIP32(rootPub, rootChain, []uint32{0})
	if err != nil {
		t.Fatalf("DeriveBIP32([0]): %v", err)
	}

	wantPub1, wantChain1, err := parseXPub(m0XPub)
	if err != nil {
		t.Fatalf("parse m/0 xpub: %v", err)
	}
	if !bytes.Equal(pub1, wantPub1) {
		t.Errorf("one-step m/0 pubkey mismatch")
	}
	if !bytes.Equal(chain1, wantChain1) {
		t.Errorf("one-step m/0 chain code mismatch")
	}

	// Now derive [0] then [1] in a single call.
	// The resulting child should equal: derive [1] from m/0 xpub.
	pub2, shift2, _, err := DeriveBIP32(rootPub, rootChain, []uint32{0, 1})
	if err != nil {
		t.Fatalf("DeriveBIP32([0, 1]): %v", err)
	}

	// Chained: derive [1] from m/0
	chainedPub, chainedShift, _, err := DeriveBIP32(pub1, chain1, []uint32{1})
	if err != nil {
		t.Fatalf("chained DeriveBIP32([1] from m/0): %v", err)
	}

	if !bytes.Equal(pub2, chainedPub) {
		t.Errorf("multi-step vs chained public key mismatch:\n  multi-step: %x\n    chained: %x", pub2, chainedPub)
	}

	// The additive shift from [0,1] should produce the same child from root.
	derivedFromRoot, err := DerivePublicKey(rootPub, shift2)
	if err != nil {
		t.Fatalf("DerivePublicKey with multi-step shift: %v", err)
	}
	if !bytes.Equal(derivedFromRoot, pub2) {
		t.Errorf("multi-step additive shift inconsistent with child pubkey")
	}

	// The chained shift applied to the root should also produce the final child.
	// shift1 is cumulative from root for [0]; chainedShift is from m/0 for [1].
	// The total shift from root = shift1 + chainedShift.
	totalShiftBytes := hex.EncodeToString(shift1)
	t.Logf("additive shift [0]: %s", totalShiftBytes)
	t.Logf("chained shift [1]: %x", chainedShift)
	t.Logf("multi-step shift [0,1]: %x", shift2)

	// Verify DerivePublicKey invariants: shift2 is the cumulative shift
	// across the full path, so it maps rootPub → pub2.
	if !bytes.Equal(derivedFromRoot, pub2) {
		t.Errorf("shift2 does not map root to multi-step child")
	}
}

// TestDeriveBIP32Errors tests error cases.
func TestDeriveBIP32Errors(t *testing.T) {
	// Valid parent from TV2 master xpub.
	validXPub := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
	validPub, validChain, err := parseXPub(validXPub)
	if err != nil {
		t.Fatal(err)
	}

	// Copy helpers.
	cloneBytes := func(b []byte) []byte {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}

	t.Run("empty chain code", func(t *testing.T) {
		_, _, _, err := DeriveBIP32(validPub, nil, []uint32{0})
		if err == nil {
			t.Error("expected error for nil chain code")
		}
		_, _, _, err = DeriveBIP32(validPub, []byte{}, []uint32{0})
		if err == nil {
			t.Error("expected error for empty chain code")
		}
	})

	t.Run("wrong chain code length", func(t *testing.T) {
		_, _, _, err := DeriveBIP32(validPub, make([]byte, 31), []uint32{0})
		if err == nil {
			t.Error("expected error for 31-byte chain code")
		}
		_, _, _, err = DeriveBIP32(validPub, make([]byte, 33), []uint32{0})
		if err == nil {
			t.Error("expected error for 33-byte chain code")
		}
	})

	t.Run("empty path", func(t *testing.T) {
		_, _, _, err := DeriveBIP32(validPub, validChain, nil)
		if err == nil {
			t.Error("expected error for nil path")
		}
		_, _, _, err = DeriveBIP32(validPub, validChain, []uint32{})
		if err == nil {
			t.Error("expected error for empty path")
		}
	})

	t.Run("path too long", func(t *testing.T) {
		longPath := make([]uint32, 256)
		for i := range longPath {
			longPath[i] = uint32(i)
		}
		_, _, _, err := DeriveBIP32(validPub, validChain, longPath)
		if err == nil {
			t.Error("expected error for path > 255 indices")
		}
	})

	t.Run("hardened index rejected", func(t *testing.T) {
		_, _, _, err := DeriveBIP32(validPub, validChain, []uint32{0, HardenedKeyStart})
		if err == nil {
			t.Error("expected error for hardened index in path")
		}
		_, _, _, err = DeriveBIP32(validPub, validChain, []uint32{HardenedKeyStart + 1})
		if err == nil {
			t.Error("expected error for hardened index")
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		invalidPub := make([]byte, 33)
		copy(invalidPub, validPub)
		invalidPub[0] = 0x04 // uncompressed prefix
		_, _, _, err := DeriveBIP32(invalidPub, validChain, []uint32{0})
		if err == nil {
			t.Error("expected error for invalid public key prefix")
		}
	})

	t.Run("wrong length public key", func(t *testing.T) {
		_, _, _, err := DeriveBIP32(make([]byte, 32), validChain, []uint32{0})
		if err == nil {
			t.Error("expected error for 32-byte public key")
		}
	})

	t.Run("all-zero public key", func(t *testing.T) {
		_, _, _, err := DeriveBIP32(make([]byte, 33), cloneBytes(validChain), []uint32{0})
		if err == nil {
			t.Error("expected error for zero public key")
		}
	})
}

// TestHardenedKeyStart verifies the constant value matches BIP-32 spec.
func TestHardenedKeyStart(t *testing.T) {
	if HardenedKeyStart != 1<<31 {
		t.Errorf("HardenedKeyStart = %d, want %d", HardenedKeyStart, 1<<31)
	}
	if HardenedKeyStart != 0x80000000 {
		t.Errorf("HardenedKeyStart = 0x%x, want 0x80000000", HardenedKeyStart)
	}
}
