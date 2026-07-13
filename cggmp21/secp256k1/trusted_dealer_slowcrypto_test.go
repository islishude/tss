//go:build slowcrypto

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestSlowCrypto_CGGMPTrustedDealerImportProductionParameters(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 31
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	_, shares, err := GenerateTrustedDealerKeyShares(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(911),
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x75}, 32),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer shares[1].Destroy()
	defer shares[2].Destroy()
	reconstructed, err := ReconstructSecretKey(shares[1], shares[2])
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructed.Destroy()
	want, _ := secretKey.MarshalBinary()
	got, _ := reconstructed.MarshalBinary()
	defer clear(want)
	defer clear(got)
	if !bytes.Equal(got, want) {
		t.Fatal("production-parameter trusted import reconstructed the wrong key")
	}
}
