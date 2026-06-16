package bip32util

import (
	"testing"
)

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

func TestBIP32Constants(t *testing.T) {
	t.Parallel()

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
