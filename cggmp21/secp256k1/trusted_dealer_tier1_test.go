//go:build tier1

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestTier1_CGGMPGenerateTrustedDealerKeySharesAndReconstruct(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 17
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	chainCode := bytes.Repeat([]byte{0x66}, 32)
	plan, shares, err := GenerateTrustedDealerKeyShares(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(903), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: chainCode, PaillierBits: int(params.MinPaillierBits), Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(904))
	if err != nil {
		t.Fatal(err)
	}
	for _, share := range shares {
		defer share.Destroy()
	}
	snapshot, ok := plan.Snapshot()
	if !ok || !bytes.Equal(snapshot.ChainCode, chainCode) {
		t.Fatal("offline import did not preserve chain code")
	}
	reconstructed, err := ReconstructSecretKeyWithLimits(limits, shares[1], shares[2])
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructed.Destroy()
	want, _ := secretKey.MarshalBinary()
	got, _ := reconstructed.MarshalBinary()
	defer clear(want)
	defer clear(got)
	if !bytes.Equal(got, want) {
		t.Fatal("reconstructed CGGMP21 secret does not match imported secret")
	}
	digest := sha256.Sum256([]byte("trusted dealer imported CGGMP21 key"))
	verificationKey, signature, err := signCGGMP21Simulation(digest[:], []*KeyShare{shares[1], shares[2]}, testPresignContext(), true, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(verificationKey, digest[:], signature) {
		t.Fatal("signature from imported CGGMP21 shares did not verify")
	}
}
