package secp256k1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/testvectors"
)

func TestCGGMPSecretKeySafetyAndPublicKey(t *testing.T) {
	t.Parallel()
	encoded := make([]byte, 32)
	encoded[31] = 7
	key, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if _, err := key.PublicKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(key); err == nil {
		t.Fatal("secret key JSON encoding succeeded")
	}
	if got := fmt.Sprintf("%x", key); got != "SecretKey{Scalar:<redacted>}" {
		t.Fatalf("secret key formatting was not redacted: %q", got)
	}
	if _, err := ParseSecretKey(make([]byte, 32)); err == nil {
		t.Fatal("zero secp256k1 secret key accepted")
	}
}

func TestCGGMPTrustedDealerContributionConcurrentClaimHasOneWinner(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 37
	secretKey, _ := ParseSecretKey(encoded)
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(912), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		PaillierBits: int(params.MinPaillierBits), Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(913))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	contribution := contributions[1]
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			scalar, chainCode, err := contribution.beginClaimForPlan(plan, 1)
			if err != nil {
				return
			}
			winners.Add(1)
			scalar.Destroy()
			clear(chainCode)
			contribution.commitClaim()
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent contribution claims had %d winners, want 1", winners.Load())
	}
}

func TestCGGMPTrustedDealerPlanAndContributionRoundTrip(t *testing.T) {
	t.Parallel()
	encoded := make([]byte, 32)
	encoded[31] = 11
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(901), Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x27}, 32), PaillierBits: int(params.MinPaillierBits),
		Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(902))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	rawPlan, err := plan.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	var decodedPlan TrustedDealerImportPlan
	if err := decodedPlan.UnmarshalBinaryWithLimits(rawPlan, limits); err != nil {
		t.Fatal(err)
	}
	left, _ := plan.Digest()
	right, _ := decodedPlan.Digest()
	if !bytes.Equal(left, right) {
		t.Fatal("trusted-dealer plan digest changed after round trip")
	}
	rawContribution, err := contributions[2].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	var decodedContribution TrustedDealerContribution
	if err := decodedContribution.UnmarshalBinaryWithLimits(rawContribution, limits); err != nil {
		t.Fatal(err)
	}
	defer decodedContribution.Destroy()
	if err := decodedContribution.validateForPlan(&decodedPlan, 2); err != nil {
		t.Fatalf("round-tripped contribution rejected: %v", err)
	}
	if err := decodedPlan.UnmarshalBinaryWithLimits(append(rawPlan, 0), limits); err == nil {
		t.Fatal("trusted-dealer plan accepted trailing data")
	}
	if err := decodedContribution.UnmarshalBinaryWithLimits(append(rawContribution, 0), limits); err == nil {
		t.Fatal("trusted-dealer contribution accepted trailing data")
	}
}

func TestFast_GoldenTrustedDealerImportPlanAndContribution(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 19
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(905), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x62}, 32), PaillierBits: int(params.MinPaillierBits),
		Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(906))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	planRaw, err := plan.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	contributionRaw, err := contributions[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/TrustedDealerImportPlan.golden", planRaw)
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/TrustedDealerContribution.golden", contributionRaw)
}

func FuzzCGGMPTrustedDealerImportPlan(f *testing.F) {
	encoded := make([]byte, 32)
	encoded[31] = 23
	secretKey, _ := ParseSecretKey(encoded)
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(907), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x73}, 32), PaillierBits: int(params.MinPaillierBits),
		Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(908))
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := plan.MarshalBinaryWithLimits(limits)
	f.Add(raw)
	secretKey.Destroy()
	destroyCGGMPContributions(contributions)
	f.Fuzz(func(t *testing.T, in []byte) {
		var decoded TrustedDealerImportPlan
		if err := decoded.UnmarshalBinaryWithLimits(in, limits); err != nil {
			return
		}
		canonical, err := decoded.MarshalBinaryWithLimits(limits)
		if err != nil || !bytes.Equal(canonical, in) {
			t.Fatal("accepted trusted-dealer plan was not canonical")
		}
	})
}

func FuzzCGGMPTrustedDealerContribution(f *testing.F) {
	encoded := make([]byte, 32)
	encoded[31] = 29
	secretKey, _ := ParseSecretKey(encoded)
	limits := testLimits()
	params := testSecurityParams()
	_, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(909), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x74}, 32), PaillierBits: int(params.MinPaillierBits),
		Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(910))
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := contributions[1].MarshalBinaryWithLimits(limits)
	f.Add(raw)
	secretKey.Destroy()
	destroyCGGMPContributions(contributions)
	f.Fuzz(func(t *testing.T, in []byte) {
		var decoded TrustedDealerContribution
		if err := decoded.UnmarshalBinaryWithLimits(in, limits); err != nil {
			return
		}
		defer decoded.Destroy()
		canonical, err := decoded.MarshalBinaryWithLimits(limits)
		if err != nil || !bytes.Equal(canonical, in) {
			t.Fatal("accepted trusted-dealer contribution was not canonical")
		}
	})
}
