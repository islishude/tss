package bip32util

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestBase58CheckEncode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "empty payload",
			payload: []byte{},
			want:    "3QJmnh",
		},
		{
			name:    "single zero byte payload",
			payload: []byte{0x00},
			want:    "1Wh4bh",
		},
		{
			name:    "payload with leading zero bytes",
			payload: []byte{0x00, 0x00, 0x01},
			want:    "11BwW2qR",
		},
		{
			name:    "small arbitrary payload",
			payload: []byte{0x01, 0x02, 0x03},
			want:    "3DUz7ncyT",
		},
		{
			name:    "known bitcoin mainnet address payload",
			payload: mustDecodeHex(t, "00010966776006953d5567439e5e39f86a0d273bee"),
			want:    "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		},
		{
			name:    "known private key payload",
			payload: mustDecodeHex(t, "800000000000000000000000000000000000000000000000000000000000000000"),
			want:    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Base58CheckEncode(tt.payload)
			if got != tt.want {
				t.Fatalf("Base58CheckEncode(%x) = %q, want %q", tt.payload, got, tt.want)
			}
		})
	}
}

func TestBase58CheckDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want []byte
	}{
		{
			name: "empty payload",
			s:    "3QJmnh",
			want: []byte{},
		},
		{
			name: "single zero byte payload",
			s:    "1Wh4bh",
			want: []byte{0x00},
		},
		{
			name: "payload with leading zero bytes",
			s:    "11BwW2qR",
			want: []byte{0x00, 0x00, 0x01},
		},
		{
			name: "small arbitrary payload",
			s:    "3DUz7ncyT",
			want: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "known bitcoin mainnet address payload",
			s:    "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
			want: mustDecodeHex(t, "00010966776006953d5567439e5e39f86a0d273bee"),
		},
		{
			name: "known private key payload",
			s:    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU",
			want: mustDecodeHex(t, "800000000000000000000000000000000000000000000000000000000000000000"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Base58CheckDecode(tt.s)
			if err != nil {
				t.Fatalf("Base58CheckDecode(%q) returned unexpected error: %v", tt.s, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Base58CheckDecode(%q) = %x, want %x", tt.s, got, tt.want)
			}
		})
	}
}

func TestBase58CheckRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "nil payload", payload: nil},
		{name: "empty payload", payload: []byte{}},
		{name: "single zero byte", payload: []byte{0x00}},
		{name: "multiple leading zero bytes", payload: []byte{0x00, 0x00, 0x00, 0x01, 0x02}},
		{name: "short arbitrary bytes", payload: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "78 byte BIP32-size payload", payload: sequentialBytes(BIP32ExtendedKeyPayloadLen)},
		{name: "256 byte payload", payload: sequentialBytes(256)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded := Base58CheckEncode(tt.payload)
			decoded, err := Base58CheckDecode(encoded)
			if err != nil {
				t.Fatalf("Base58CheckDecode(Base58CheckEncode(%x)) returned unexpected error: %v", tt.payload, err)
			}
			if !bytes.Equal(decoded, tt.payload) {
				t.Fatalf("round trip decoded payload = %x, want %x", decoded, tt.payload)
			}
		})
	}
}

func TestBase58CheckDecodeRejectsInvalidCharacters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
	}{
		{name: "zero character", s: "0"},
		{name: "capital O", s: "O"},
		{name: "capital I", s: "I"},
		{name: "lowercase l", s: "l"},
		{name: "valid prefix then invalid character", s: "3QJmnh0"},
		{name: "non ASCII character", s: "3QJmnhé"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Base58CheckDecode(tt.s)
			if !errors.Is(err, ErrInvalidBase58Character) {
				t.Fatalf("Base58CheckDecode(%q) error = %v, want %v", tt.s, err, ErrInvalidBase58Character)
			}
		})
	}
}

func TestBase58CheckDecodeRejectsShortData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
	}{
		{name: "empty string", s: ""},
		{name: "one leading zero", s: "1"},
		{name: "two leading zeroes", s: "11"},
		{name: "three leading zeroes", s: "111"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Base58CheckDecode(tt.s)
			if !errors.Is(err, ErrDataTooShort) {
				t.Fatalf("Base58CheckDecode(%q) error = %v, want %v", tt.s, err, ErrDataTooShort)
			}
		})
	}
}

func TestBase58CheckDecodeRejectsBadChecksum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
	}{
		{name: "empty payload checksum mutated", s: mutateLastBase58Char("3QJmnh")},
		{name: "single zero byte checksum mutated", s: mutateLastBase58Char("1Wh4bh")},
		{name: "known address checksum mutated", s: mutateLastBase58Char("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Base58CheckDecode(tt.s)
			if !errors.Is(err, ErrInvalidChecksum) {
				t.Fatalf("Base58CheckDecode(%q) error = %v, want %v", tt.s, err, ErrInvalidChecksum)
			}
		})
	}
}

func mutateLastBase58Char(s string) string {
	if s == "" {
		panic("cannot mutate empty string")
	}

	last := s[len(s)-1]
	replacement := byte('1')
	if last == replacement {
		replacement = '2'
	}

	return s[:len(s)-1] + string(replacement)
}

func sequentialBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex string(%s): %s", s, err)
	}
	return out
}
