package bip32util

import "testing"

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
