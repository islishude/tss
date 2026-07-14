//go:build integration

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestIntegration_CGGMP21_TrustedDealer_GenerateReconstructAndSign(t *testing.T) {
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
	parties := tss.NewPartySet(1, 2, 3)
	plan, shares, err := GenerateTrustedDealerKeyShares(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(903), Parties: parties, Threshold: 2,
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
	before := make(map[tss.PartyID][]byte, len(parties))
	for _, party := range parties {
		before[party], err = shares[party].MarshalBinaryWithLimits(limits)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(before[party])
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
	largerSubset, err := ReconstructSecretKeyWithLimits(limits, shares[1], shares[2], shares[3])
	if err != nil {
		t.Fatal(err)
	}
	defer largerSubset.Destroy()
	largerBytes, err := largerSubset.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(largerBytes)
	if !bytes.Equal(largerBytes, want) {
		t.Fatal("larger-subset reconstruction changed the imported secret")
	}
	if _, err := ReconstructSecretKeyWithLimits(limits, shares[1]); err == nil {
		t.Fatal("insufficient reconstruction subset accepted")
	}
	if _, err := ReconstructSecretKeyWithLimits(limits, shares[1], shares[1]); err == nil {
		t.Fatal("duplicate reconstruction share accepted")
	}
	sensitive := make([][]byte, 0, len(shares)+1)
	sensitive = append(sensitive, want)
	for _, share := range shares {
		value := share.state.Secret.FixedBytes()
		defer clear(value)
		sensitive = append(sensitive, value)
	}
	for _, tc := range []struct {
		name string
		args func(*testing.T) []*KeyShare
	}{
		{name: "nil candidate", args: func(*testing.T) []*KeyShare {
			return []*KeyShare{shares[1], nil}
		}},
		{name: "destroyed reference", args: func(t *testing.T) []*KeyShare {
			clone := shares[1].Clone()
			clone.Destroy()
			t.Cleanup(clone.Destroy)
			return []*KeyShare{clone, shares[2]}
		}},
		{name: "destroyed candidate", args: func(t *testing.T) []*KeyShare {
			clone := shares[2].Clone()
			clone.Destroy()
			t.Cleanup(clone.Destroy)
			return []*KeyShare{shares[1], clone}
		}},
		{name: "missing secret", args: func(t *testing.T) []*KeyShare {
			clone := shares[2].Clone()
			clone.state.Secret.Destroy()
			clone.state.Secret = nil
			t.Cleanup(clone.Destroy)
			return []*KeyShare{shares[1], clone}
		}},
		{name: "wrong secret", args: func(t *testing.T) []*KeyShare {
			clone := shares[2].Clone()
			clone.state.Secret.Destroy()
			var err error
			clone.state.Secret, err = newSecpSecretScalar(bytes.Repeat([]byte{1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(clone.Destroy)
			return []*KeyShare{shares[1], clone}
		}},
		{name: "wrong plan", args: func(t *testing.T) []*KeyShare {
			clone := shares[2].Clone()
			clone.state.PlanHash[0] ^= 1
			t.Cleanup(clone.Destroy)
			return []*KeyShare{shares[1], clone}
		}},
		{name: "wrong epoch", args: func(t *testing.T) []*KeyShare {
			clone := shares[2].Clone()
			clone.state.Epoch.EpochID[0] ^= 1
			t.Cleanup(clone.Destroy)
			return []*KeyShare{shares[1], clone}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reconstructed, err := ReconstructSecretKeyWithLimits(limits, tc.args(t)...)
			if reconstructed != nil {
				reconstructed.Destroy()
			}
			if err == nil {
				t.Fatal("invalid reconstruction input was accepted")
			}
			assertCGGMPErrorOmitsSecretHex(t, err, sensitive...)
		})
	}
	for _, party := range parties {
		after, err := shares[party].MarshalBinaryWithLimits(limits)
		if err != nil {
			t.Fatalf("reconstruction consumed party %d share: %v", party, err)
		}
		if !bytes.Equal(after, before[party]) {
			t.Fatalf("reconstruction mutated party %d share", party)
		}
		clear(after)
	}
	digest := sha256.Sum256([]byte("trusted dealer imported CGGMP21 key"))
	verificationKey, signature, err := signCGGMP21Simulation(digest[:], []*KeyShare{shares[1], shares[3]}, testPresignContext(), true, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(verificationKey, digest[:], signature) {
		t.Fatal("signature from imported CGGMP21 shares did not verify")
	}
}

func assertCGGMPErrorOmitsSecretHex(t testing.TB, err error, sensitive ...[]byte) {
	t.Helper()
	message := strings.ToLower(err.Error())
	for _, value := range sensitive {
		if len(value) == 0 {
			continue
		}
		if strings.Contains(message, hex.EncodeToString(value)) || strings.Contains(err.Error(), string(value)) {
			t.Fatal("error exposed secret reconstruction material")
		}
	}
}
