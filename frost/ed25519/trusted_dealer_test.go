package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/testvectors"
)

func TestFROSTSecretKeyFromSeedMatchesStandardPublicKey(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{0x42}, stded25519.SeedSize)
	key, err := NewSecretKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	publicKey, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	want := stded25519.NewKeyFromSeed(seed).Public().(stded25519.PublicKey)
	if !bytes.Equal(publicKey.Bytes(), want) {
		t.Fatal("seed-derived FROST public key does not match crypto/ed25519")
	}
	if _, err := json.Marshal(key); err == nil {
		t.Fatal("secret key JSON encoding succeeded")
	}
	if got := fmt.Sprintf("%x", key); got != "SecretKey{Scalar:<redacted>}" {
		t.Fatalf("secret key formatting was not redacted: %q", got)
	}
}

func TestFROSTTrustedDealerContributionConcurrentClaimHasOneWinner(t *testing.T) {
	secretKey, _ := ParseSecretScalar(append([]byte{17}, make([]byte, 31)...))
	defer secretKey.Destroy()
	limits := testLimits()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(812), Parties: tss.NewPartySet(1, 2), Threshold: 2, Limits: &limits,
	}, testutil.DeterministicReader(813))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyFROSTContributions(contributions)
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

func TestFROSTTrustedDealerPlanAndContributionRoundTrip(t *testing.T) {
	t.Parallel()
	secretKey, err := ParseSecretScalar(append([]byte{7}, make([]byte, 31)...))
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(801), Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x31}, 32), Limits: &limits,
	}, testutil.DeterministicReader(802))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyFROSTContributions(contributions)
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
	session, out, err := StartTrustedDealerImport(plan, contributions[1], tss.LocalConfig{
		Self: 1,
		Rand: testutil.DeterministicReader(811),
	}, testFROSTGuard(1, plan.state.Parties, plan.state.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	defer clearEnvelopePayloads(out)
	if _, err := contributions[1].MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("successfully claimed contribution remained serializable")
	}
}

func TestGoldenFROSTTrustedDealerImportPlanAndContribution(t *testing.T) {
	secretKey, err := ParseSecretScalar(append([]byte{9}, make([]byte, 31)...))
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(805), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x61}, 32), Limits: &limits,
	}, testutil.DeterministicReader(806))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyFROSTContributions(contributions)
	planRaw, err := plan.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	contributionRaw, err := contributions[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/frost/TrustedDealerImportPlan.golden", planRaw)
	testvectors.CheckHexGolden(t, "wire/v1/frost/TrustedDealerContribution.golden", contributionRaw)
}

func FuzzFROSTTrustedDealerImportPlan(f *testing.F) {
	secretKey, _ := ParseSecretScalar(append([]byte{13}, make([]byte, 31)...))
	limits := testLimits()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(807), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x71}, 32), Limits: &limits,
	}, testutil.DeterministicReader(808))
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := plan.MarshalBinaryWithLimits(limits)
	f.Add(raw)
	secretKey.Destroy()
	destroyFROSTContributions(contributions)
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

func FuzzFROSTTrustedDealerContribution(f *testing.F) {
	secretKey, _ := ParseSecretScalar(append([]byte{15}, make([]byte, 31)...))
	limits := testLimits()
	_, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(809), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x72}, 32), Limits: &limits,
	}, testutil.DeterministicReader(810))
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := contributions[1].MarshalBinaryWithLimits(limits)
	f.Add(raw)
	secretKey.Destroy()
	destroyFROSTContributions(contributions)
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

func TestFROSTGenerateTrustedDealerKeySharesAndReconstruct(t *testing.T) {
	seed := bytes.Repeat([]byte{0x19}, stded25519.SeedSize)
	secretKey, err := NewSecretKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	chainCode := bytes.Repeat([]byte{0x55}, 32)
	plan, shares, err := GenerateTrustedDealerKeyShares(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(803), Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
		ChainCode: chainCode, Limits: &limits,
	}, testutil.DeterministicReader(804))
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
	reconstructed, err := ReconstructSecretKey(shares[1], shares[3])
	if err != nil {
		t.Fatal(err)
	}
	defer reconstructed.Destroy()
	want, _ := secretKey.MarshalBinary()
	got, _ := reconstructed.MarshalBinary()
	defer clear(want)
	defer clear(got)
	if !bytes.Equal(got, want) {
		t.Fatal("reconstructed FROST secret does not match imported secret")
	}
	message := []byte("trusted dealer imported FROST key")
	verificationKey, signature, err := signFROSTSimulation(message, []*KeyShare{shares[1], shares[3]}, tss.SigningContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !stded25519.Verify(stded25519.PublicKey(verificationKey), message, signature) {
		t.Fatal("signature from imported FROST shares did not verify")
	}
	if _, err := ReconstructSecretKey(shares[1]); err == nil {
		t.Fatal("reconstruction accepted fewer than threshold shares")
	}
	if _, err := ReconstructSecretKey(shares[1], shares[1]); err == nil {
		t.Fatal("reconstruction accepted a duplicate party share")
	}
}
