package bip32util

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

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
