package bip32util

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

const masterXPub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	errs := []error{
		ErrChainCodeRequired,
		ErrInvalidChainCodeLength,
		ErrInvalidPublicKey,
		ErrHardenedDerivationUnsupported,
		ErrInvalidChild,
		ErrDerivationDepthOverflow,
		ErrInvalidExtendedPublicKey,
	}
	for i, a := range errs {
		if a == nil {
			t.Errorf("sentinel error at index %d is nil", i)
		}
		for j := i + 1; j < len(errs); j++ {
			if errors.Is(a, errs[j]) || errors.Is(errs[j], a) {
				t.Errorf("errors at %d and %d should be distinct", i, j)
			}
		}
	}

	tests := []struct {
		name  string
		err   error
		match error
		want  bool
	}{
		{name: "chain code required matches itself", err: ErrChainCodeRequired, match: ErrChainCodeRequired, want: true},
		{name: "hardened derivation matches itself", err: ErrHardenedDerivationUnsupported, match: ErrHardenedDerivationUnsupported, want: true},
		{name: "distinct sentinels do not match", err: ErrChainCodeRequired, match: ErrInvalidChild, want: false},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := errors.Is(tc.err, tc.match); got != tc.want {
				t.Fatalf("errors.Is(%v, %v) = %v, want %v", tc.err, tc.match, got, tc.want)
			}
		})
	}
}

func TestBIP32Constants(t *testing.T) {
	t.Parallel()

	if HardenedKeyStart != 1<<31 {
		t.Fatalf("HardenedKeyStart = %d, want %d", HardenedKeyStart, 1<<31)
	}
	if XPubVersion == TPubVersion {
		t.Fatal("XPubVersion and TPubVersion must be distinct")
	}

	tests := []struct {
		name string
		got  [4]byte
		want [4]byte
	}{
		{name: "mainnet xpub version", got: XPubVersion, want: [4]byte{0x04, 0x88, 0xB2, 0x1E}},
		{name: "testnet tpub version", got: TPubVersion, want: [4]byte{0x04, 0x35, 0x87, 0xCF}},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.got != tc.want {
				t.Fatalf("%s = %x, want %x", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestIsKnownVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   [4]byte
		want bool
	}{
		{name: "mainnet xpub", in: XPubVersion, want: true},
		{name: "testnet tpub", in: TPubVersion, want: true},
		{name: "all zero", in: [4]byte{0x00, 0x00, 0x00, 0x00}, want: false},
		{name: "xprv", in: [4]byte{0x04, 0x88, 0xAD, 0xE4}, want: false},
		{name: "arbitrary", in: [4]byte{0xDE, 0xAD, 0xBE, 0xEF}, want: false},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := IsKnownVersion(tc.in); got != tc.want {
				t.Fatalf("IsKnownVersion(%x) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestBase58Check_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		setup  func() []byte
		assert func(t *testing.T, payload []byte, encoded string)
	}{
		{
			name:  "known master xpub",
			input: masterXPub,
			assert: func(t *testing.T, payload []byte, encoded string) {
				t.Helper()
				if encoded != masterXPub {
					t.Fatalf("round-trip = %s, want %s", encoded, masterXPub)
				}
				if version := [4]byte(payload[0:4]); version != XPubVersion {
					t.Fatalf("version = %x, want %x", version, XPubVersion)
				}
				if depth := payload[4]; depth != 0 {
					t.Fatalf("master depth = %d, want 0", depth)
				}
			},
		},
		{
			name: "arbitrary payload",
			setup: func() []byte {
				payload := make([]byte, 78)
				for i := range payload {
					payload[i] = byte(i)
				}
				return payload
			},
		},
		{
			name: "leading zeros",
			setup: func() []byte {
				payload := make([]byte, 78)
				payload[2] = 0x01
				return payload
			},
			assert: func(t *testing.T, _ []byte, encoded string) {
				t.Helper()
				if encoded[:2] != "11" {
					t.Fatalf("encoded leading zero prefix = %q, want %q", encoded[:2], "11")
				}
			},
		},
		{
			name: "large payload",
			setup: func() []byte {
				payload := make([]byte, 78)
				for i := range payload {
					payload[i] = byte(i % 256)
				}
				return payload
			},
			assert: func(t *testing.T, _ []byte, encoded string) {
				t.Helper()
				if len(encoded) < 100 || len(encoded) > 120 {
					t.Fatalf("encoded length = %d, want roughly 106", len(encoded))
				}
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var decoded []byte
			var err error
			var original []byte
			var encoded string
			if tc.input != "" {
				decoded, err = Base58CheckDecode(tc.input)
				if err != nil {
					t.Fatal(err)
				}
				original = decoded
				encoded = Base58CheckEncode(decoded)
			} else {
				original = tc.setup()
				encoded = Base58CheckEncode(original)
				decoded, err = Base58CheckDecode(encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(decoded, original) {
				t.Fatalf("decoded payload = %x, want %x", decoded, original)
			}
			if tc.assert != nil {
				tc.assert(t, decoded, encoded)
			}
		})
	}
}

func TestBase58CheckDecode_RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	valid := masterXPub
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "bad checksum", input: valid[:len(valid)-1] + "X", wantErr: "base58 checksum mismatch"},
		{name: "invalid zero character", input: "0abc"},
		{name: "invalid capital o character", input: "Oabc"},
		{name: "invalid capital i character", input: "Iabc"},
		{name: "invalid lowercase l character", input: "labc"},
		{name: "too short for checksum", input: "A"},
		{name: "empty string", input: ""},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := Base58CheckDecode(tc.input)
			if err == nil {
				t.Fatal("expected invalid Base58Check input to be rejected")
			}
			if tc.wantErr != "" && err.Error() != tc.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestKnownXPub_RoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []string{
		"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
		masterXPub,
		"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc[:20]+"...", func(t *testing.T) {
			t.Parallel()

			payload, err := Base58CheckDecode(tc)
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != 78 {
				t.Fatalf("payload length = %d, want 78", len(payload))
			}
			if reEncoded := Base58CheckEncode(payload); reEncoded != tc {
				t.Fatalf("round-trip = %s, want %s", reEncoded, tc)
			}
		})
	}
}

func TestBase58Check_XPubPayloadLayout(t *testing.T) {
	t.Parallel()

	payload, err := Base58CheckDecode(masterXPub)
	if err != nil {
		t.Fatal(err)
	}
	if version := [4]byte(payload[0:4]); version != XPubVersion {
		t.Fatalf("xpub version = %x, want %x", version, XPubVersion)
	}
	if depth := payload[4]; depth != 0 {
		t.Fatalf("master depth = %d, want 0", depth)
	}
	if chainCode := payload[13:45]; len(chainCode) != 32 {
		t.Fatalf("chain code length = %d, want 32", len(chainCode))
	}
	publicKey := payload[45:78]
	if len(publicKey) != 33 {
		t.Fatalf("public key length = %d, want 33", len(publicKey))
	}
	if publicKey[0] != 0x02 && publicKey[0] != 0x03 {
		t.Fatalf("public key prefix = 0x%02x, want 0x02 or 0x03", publicKey[0])
	}
}

func TestBase58Check_Deterministic(t *testing.T) {
	t.Parallel()

	payload := []byte("deterministic test payload for base58 check encoding")
	firstEncoded := Base58CheckEncode(payload)
	firstDecoded, err := Base58CheckDecode(masterXPub)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if got := Base58CheckEncode(payload); got != firstEncoded {
			t.Fatalf("encode iteration %d: got %s, want %s", i, got, firstEncoded)
		}
		got, err := Base58CheckDecode(masterXPub)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, firstDecoded) {
			t.Fatalf("decode iteration %d: got %x, want %x", i, got, firstDecoded)
		}
	}
}

func TestComputeFingerprint(t *testing.T) {
	t.Parallel()

	knownPubKey := []byte{
		0x03, 0xcb, 0xca, 0xa9, 0xac, 0x98, 0xc8, 0x77,
		0x22, 0x5b, 0xd4, 0xd7, 0xab, 0x88, 0x5c, 0x2a,
		0x71, 0x5e, 0x7b, 0x97, 0xdf, 0x3f, 0x2e, 0x6e,
		0x09, 0x89, 0x0b, 0x3c, 0x23, 0x0d, 0x4f, 0xdc, 0x70,
	}

	tests := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "deterministic",
			assert: func(t *testing.T) {
				t.Helper()
				pubKey := []byte{0x02, 0x01, 0x02, 0x03}
				if fp1, fp2 := ComputeFingerprint(pubKey), ComputeFingerprint(pubKey); fp1 != fp2 {
					t.Fatal("same key produced different fingerprints")
				}
			},
		},
		{
			name: "different keys differ",
			assert: func(t *testing.T) {
				t.Helper()
				fp1 := ComputeFingerprint([]byte{0x02, 0xaa})
				fp2 := ComputeFingerprint([]byte{0x02, 0xbb})
				if fp1 == fp2 {
					t.Fatal("different keys produced the same fingerprint")
				}
			},
		},
		{
			name: "known vector is nonzero and stable",
			assert: func(t *testing.T) {
				t.Helper()
				fp := ComputeFingerprint(knownPubKey)
				if fp == [4]byte{} {
					t.Fatal("known vector fingerprint is all-zero")
				}
				if fp2 := ComputeFingerprint(knownPubKey); fp != fp2 {
					t.Fatal("known vector fingerprint is not stable")
				}
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

func TestResolveDeriveConfig(t *testing.T) {
	t.Parallel()

	if ErrorOnInvalidChild == SkipInvalidChild {
		t.Fatal("ErrorOnInvalidChild and SkipInvalidChild must be distinct")
	}

	tests := []struct {
		name string
		opts []DeriveOption
		want InvalidChildMode
	}{
		{name: "nil options use default", opts: nil, want: ErrorOnInvalidChild},
		{name: "empty options use default", opts: []DeriveOption{}, want: ErrorOnInvalidChild},
		{name: "explicit mode overrides default", opts: []DeriveOption{WithInvalidChildMode(SkipInvalidChild)}, want: SkipInvalidChild},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := ResolveDeriveConfig(tc.opts)
			if cfg.InvalidChildMode != tc.want {
				t.Fatalf("InvalidChildMode = %d, want %d", cfg.InvalidChildMode, tc.want)
			}
		})
	}

	_ = ResolveDeriveConfig([]DeriveOption{WithInvalidChildMode(SkipInvalidChild)})
	if cfg := ResolveDeriveConfig(nil); cfg.InvalidChildMode != ErrorOnInvalidChild {
		t.Fatal("fresh config should keep default after prior override")
	}
}

// Test helper: verify that sha256d of a well-known xpub payload matches.
func TestXPubChecksum(t *testing.T) {
	t.Parallel()

	// Manual checksum verification for the TV2 master xpub.
	payload, err := Base58CheckDecode(masterXPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 78 {
		t.Fatalf("payload length = %d, want 78", len(payload))
	}

	// Compute expected checksum.
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	expectedChecksum := h2[:4]

	// Re-encode and verify it produces the same string.
	reEncoded := Base58CheckEncode(payload)
	if reEncoded != masterXPub {
		t.Errorf("checksum verification failed via round-trip:\n  got:  %s\n  want: %s", reEncoded, masterXPub)
	}
	_ = expectedChecksum
}
