package secp256k1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/testvectors"
)

func TestCGGMPTrustedDealerGuardFailureDoesNotClaimAndSuccessfulStartConsumes(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 41
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	parties := tss.NewPartySet(1, 2)
	sessionID := testutil.MustSessionID(914)
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: sessionID, Parties: parties, Threshold: 2,
		PaillierBits: int(params.MinPaillierBits), Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(915))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	contribution := contributions[1]

	if _, _, err := StartTrustedDealerImport(plan, contribution, tss.LocalConfig{Self: 1}, nil); !errors.Is(err, tss.ErrMissingEnvelopeGuard) {
		t.Fatalf("missing guard error = %v, want ErrMissingEnvelopeGuard", err)
	}
	if _, err := contribution.MarshalBinaryWithLimits(limits); err != nil {
		t.Fatalf("guard rejection claimed contribution: %v", err)
	}
	session, out, err := StartTrustedDealerImport(plan, contribution, tss.LocalConfig{
		Self: 1, Rand: testutil.DeterministicReader(916),
	}, paperKeygenTestGuard(1, parties, sessionID))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	if len(out) != 1 || out[0].PayloadType != payloadFigure6Commitment {
		t.Fatalf("trusted import start output = %v", out)
	}
	if _, _, err := StartTrustedDealerImport(plan, contribution, tss.LocalConfig{
		Self: 1, Rand: testutil.DeterministicReader(917),
	}, paperKeygenTestGuard(1, parties, sessionID)); err == nil {
		t.Fatal("consumed trusted-dealer contribution was replayed")
	}
}

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

func TestCGGMPTrustedDealerPlanSnapshotDeepCopiesCommitments(t *testing.T) {
	t.Parallel()

	encoded := make([]byte, 32)
	encoded[31] = 29
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(924), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		PaillierBits: int(params.MinPaillierBits), Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(925))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)

	snapshot, ok := plan.Snapshot()
	if !ok {
		t.Fatal("trusted-dealer plan snapshot unavailable")
	}
	if len(snapshot.Commitments) != len(snapshot.Parties) || len(snapshot.ChainCodeCommitments) != len(snapshot.Parties) {
		t.Fatal("trusted-dealer snapshot omitted public commitments")
	}
	wantConstant := bytes.Clone(snapshot.Commitments[1])
	wantChainCode := bytes.Clone(snapshot.ChainCodeCommitments[1])
	defer clear(wantConstant)
	defer clear(wantChainCode)
	snapshot.Commitments[1][0] ^= 1
	snapshot.ChainCodeCommitments[1][0] ^= 1
	delete(snapshot.Commitments, 2)
	delete(snapshot.ChainCodeCommitments, 2)

	second, ok := plan.Snapshot()
	if !ok {
		t.Fatal("trusted-dealer plan snapshot unavailable after caller mutation")
	}
	if !bytes.Equal(second.Commitments[1], wantConstant) {
		t.Fatal("constant-term commitment snapshot aliases plan state")
	}
	if !bytes.Equal(second.ChainCodeCommitments[1], wantChainCode) {
		t.Fatal("chain-code commitment snapshot aliases plan state")
	}
	if len(second.Commitments) != len(second.Parties) || len(second.ChainCodeCommitments) != len(second.Parties) {
		t.Fatal("snapshot map mutation changed plan state")
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

func TestCGGMPTrustedDealerContributionRejectsBindingMutations(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 43
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(918), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		PaillierBits: int(params.MinPaillierBits), Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(919))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	raw, err := contributions[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(t *testing.T) *TrustedDealerContribution {
		t.Helper()
		var contribution TrustedDealerContribution
		if err := contribution.UnmarshalBinaryWithLimits(raw, limits); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(contribution.Destroy)
		return &contribution
	}

	t.Run("wrong party", func(t *testing.T) {
		if err := decode(t).validateForPlan(plan, 2); err == nil {
			t.Fatal("contribution accepted for another party")
		}
	})
	t.Run("wrong session", func(t *testing.T) {
		contribution := decode(t)
		contribution.state.SessionID = testutil.MustSessionID(920)
		if err := contribution.validateForPlan(plan, 1); err == nil {
			t.Fatal("cross-session contribution accepted")
		}
	})
	t.Run("wrong plan", func(t *testing.T) {
		contribution := decode(t)
		contribution.state.PlanHash[0] ^= 1
		if err := contribution.validateForPlan(plan, 1); err == nil {
			t.Fatal("wrong-plan contribution accepted")
		}
	})
	t.Run("wrong scalar commitment", func(t *testing.T) {
		contribution := decode(t)
		contribution.state.Scalar.Destroy()
		contribution.state.Scalar, err = newSecpSecretScalar(bytes.Repeat([]byte{0x01}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if err := contribution.validateForPlan(plan, 1); err == nil {
			t.Fatal("contribution with wrong scalar commitment accepted")
		}
	})
	t.Run("wrong chain code commitment", func(t *testing.T) {
		contribution := decode(t)
		contribution.state.ChainCode[0] ^= 1
		if err := contribution.validateForPlan(plan, 1); err == nil {
			t.Fatal("contribution with wrong chain code accepted")
		}
	})
	t.Run("wrong security profile plan", func(t *testing.T) {
		mutatedPlan := cloneCGGMPTrustedDealerPlan(plan)
		mutatedPlan.state.SecurityParams.ChallengeBits--
		if err := mutatedPlan.ValidateWithLimits(limits); err != nil {
			t.Fatal(err)
		}
		if err := decode(t).validateForPlan(mutatedPlan, 1); err == nil {
			t.Fatal("contribution accepted under a different security profile")
		}
	})
}

func TestCGGMPTrustedDealerPlanBindsCompleteImportIntent(t *testing.T) {
	encoded := make([]byte, 32)
	encoded[31] = 47
	secretKey, err := ParseSecretKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	params := testSecurityParams()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(921), Parties: tss.NewPartySet(1, 2), Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x91}, 32), PaillierBits: int(params.MinPaillierBits),
		Limits: &limits, SecurityParams: &params,
	}, testutil.DeterministicReader(922))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	baseDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(baseDigest)
	before, err := contributions[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)

	tests := []struct {
		name   string
		mutate func(*trustedDealerImportPlanState)
	}{
		{name: "session", mutate: func(s *trustedDealerImportPlanState) { s.SessionID = testutil.MustSessionID(923) }},
		{name: "threshold", mutate: func(s *trustedDealerImportPlanState) { s.Threshold = 1 }},
		{name: "party set", mutate: func(s *trustedDealerImportPlanState) {
			s.Parties = tss.NewPartySet(1, 3)
			s.Commitments[1].Party = 3
		}},
		{name: "target public key", mutate: func(s *trustedDealerImportPlanState) { s.PublicKey = testCurvePointBytes(t, 19) }},
		{name: "chain code", mutate: func(s *trustedDealerImportPlanState) { s.ChainCode[0] ^= 1 }},
		{name: "commitment order", mutate: func(s *trustedDealerImportPlanState) {
			s.Commitments[0], s.Commitments[1] = s.Commitments[1], s.Commitments[0]
		}},
		{name: "constant commitment", mutate: func(s *trustedDealerImportPlanState) {
			s.Commitments[0].ConstantCommitment = testCurvePointBytes(t, 23)
		}},
		{name: "chain code commitment", mutate: func(s *trustedDealerImportPlanState) { s.Commitments[0].ChainCodeCommit[0] ^= 1 }},
		{name: "Paillier bits", mutate: func(s *trustedDealerImportPlanState) { s.PaillierBits++ }},
		{name: "security profile", mutate: func(s *trustedDealerImportPlanState) { s.SecurityParams.ChallengeBits-- }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneCGGMPTrustedDealerPlan(plan)
			tc.mutate(mutated.state)
			mutatedDigest, digestErr := mutated.Digest()
			if digestErr == nil {
				defer clear(mutatedDigest)
				if bytes.Equal(mutatedDigest, baseDigest) {
					t.Fatal("mutated import intent retained the original plan digest")
				}
			}
			if err := contributions[1].validateForPlan(mutated, 1); err == nil {
				t.Fatal("contribution was accepted under a substituted import intent")
			}
			if err := contributions[1].validateForPlan(plan, 1); err != nil {
				t.Fatalf("rejected mutation damaged the original contribution: %v", err)
			}
		})
	}
	after, err := contributions[1].MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("plan mutation checks changed the trusted contribution")
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
