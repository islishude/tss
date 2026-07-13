package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
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

func TestFROSTTrustedDealerStartRejectsMismatchedContributionsWithoutConsumption(t *testing.T) {
	t.Run("wrong party", func(t *testing.T) {
		plan, contributions := newFROSTTrustedDealerFixture(t, 820, 7, 0x31, 821)
		assertFROSTTrustedDealerStartRejected(t, plan, contributions[1], 2, 822)
		assertFROSTContributionAvailable(t, contributions[1])
	})

	t.Run("wrong session", func(t *testing.T) {
		plan, _ := newFROSTTrustedDealerFixture(t, 823, 9, 0x32, 824)
		_, otherContributions := newFROSTTrustedDealerFixture(t, 825, 9, 0x32, 826)
		assertFROSTTrustedDealerStartRejected(t, plan, otherContributions[1], 1, 827)
		assertFROSTContributionAvailable(t, otherContributions[1])
	})

	t.Run("wrong plan", func(t *testing.T) {
		plan, _ := newFROSTTrustedDealerFixture(t, 828, 11, 0x33, 829)
		_, otherContributions := newFROSTTrustedDealerFixture(t, 828, 13, 0x34, 830)
		assertFROSTTrustedDealerStartRejected(t, plan, otherContributions[1], 1, 831)
		assertFROSTContributionAvailable(t, otherContributions[1])
	})

	t.Run("substituted scalar", func(t *testing.T) {
		plan, contributions := newFROSTTrustedDealerFixture(t, 832, 15, 0x35, 833)
		raw, err := contributions[1].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		var substituted TrustedDealerContribution
		if err := substituted.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		defer substituted.Destroy()
		original, err := edScalarFromSecret(substituted.state.Scalar)
		if err != nil {
			t.Fatal(err)
		}
		defer original.Set(fed.NewScalar())
		offset := edcurve.ScalarOne()
		defer offset.Set(fed.NewScalar())
		replacement := fed.NewScalar().Add(original, offset)
		defer replacement.Set(fed.NewScalar())
		if replacement.Equal(edcurve.ScalarZero()) == 1 {
			replacement.Add(replacement, offset)
		}
		replacementSecret, err := newEdSecretScalarFromFed(replacement)
		if err != nil {
			t.Fatal(err)
		}
		substituted.state.Scalar.Destroy()
		substituted.state.Scalar = replacementSecret

		assertFROSTTrustedDealerStartRejected(t, plan, &substituted, 1, 834)
		assertFROSTContributionAvailable(t, &substituted)
	})
}

func TestFROSTTrustedDealerCommitmentBindingsRejectBeforeAcceptance(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*keygenCommitmentsPayload)
	}{
		{
			name: "changed constant commitment",
			mutate: func(payload *keygenCommitmentsPayload) {
				original := payload.Commitments.points[0]
				mutated := fed.NewIdentityPoint().Add(original, fed.NewGeneratorPoint())
				if mutated.Equal(fed.NewIdentityPoint()) == 1 {
					mutated.Add(mutated, fed.NewGeneratorPoint())
				}
				payload.Commitments.points[0] = mutated
			},
		},
		{
			name: "changed chain-code commitment",
			mutate: func(payload *keygenCommitmentsPayload) {
				payload.ChainCodeCommit = bytes.Clone(payload.ChainCodeCommit)
				payload.ChainCodeCommit[0] ^= 1
			},
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan, contributions := newFROSTTrustedDealerFixture(t, int64(835+i), 17, 0x36, int64(837+i))
			session1, out1, err := StartTrustedDealerImport(
				plan,
				contributions[1],
				tss.LocalConfig{Self: 1, Rand: testutil.DeterministicReader(int64(840 + i))},
				testFROSTGuard(1, plan.state.Parties, plan.state.SessionID),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer session1.Destroy()
			defer clearEnvelopePayloads(out1)
			session2, out2, err := StartTrustedDealerImport(
				plan,
				contributions[2],
				tss.LocalConfig{Self: 2, Rand: testutil.DeterministicReader(int64(842 + i))},
				testFROSTGuard(2, plan.state.Parties, plan.state.SessionID),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer session2.Destroy()
			defer clearEnvelopePayloads(out2)

			env := mustFROSTEnvelope(t, out2, payloadKeygenCommitments, tss.BroadcastPartyId)
			payload, err := unmarshalKeygenCommitmentsPayload(env.Payload)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&payload)
			mutated, err := marshalKeygenCommitmentsPayloadWithLimits(payload, session1.limits)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(mutated)
			env.Payload = mutated

			out, err := session1.Handle(testutil.DeliverEnvelope(env))
			protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
			if protocolErr.Blame != nil {
				t.Fatal("trusted-dealer plan binding failure produced blame")
			}
			if len(out) != 0 {
				t.Fatalf("rejected trusted-dealer commitment produced %d envelopes", len(out))
			}
			if !session1.aborted || session1.local != nil {
				t.Fatal("trusted-dealer commitment rejection did not abort and clear local material")
			}
			remoteSlot := session1.round1.slots[2]
			if remoteSlot.commitments != nil || remoteSlot.share != nil || remoteSlot.chainCodeCommit != nil {
				t.Fatal("trusted-dealer commitment rejection mutated the remote inbox slot")
			}
		})
	}
}

func TestFROSTTrustedDealerContributionReplayBoundaries(t *testing.T) {
	t.Run("live contribution is one use", func(t *testing.T) {
		plan, contributions := newFROSTTrustedDealerFixture(t, 845, 19, 0x37, 846)
		session, out, err := StartTrustedDealerImport(
			plan,
			contributions[1],
			tss.LocalConfig{Self: 1, Rand: testutil.DeterministicReader(847)},
			testFROSTGuard(1, plan.state.Parties, plan.state.SessionID),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Destroy()
		defer clearEnvelopePayloads(out)
		assertFROSTTrustedDealerStartRejected(t, plan, contributions[1], 1, 848)
	})

	t.Run("serialized copies require durable run deduplication", func(t *testing.T) {
		plan, contributions := newFROSTTrustedDealerFixture(t, 849, 21, 0x38, 850)
		raw, err := contributions[1].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		var first, second TrustedDealerContribution
		if err := first.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		defer first.Destroy()
		if err := second.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		defer second.Destroy()

		for i, contribution := range []*TrustedDealerContribution{&first, &second} {
			session, out, err := StartTrustedDealerImport(
				plan,
				contribution,
				tss.LocalConfig{Self: 1, Rand: testutil.DeterministicReader(int64(851 + i))},
				testFROSTGuard(1, plan.state.Parties, plan.state.SessionID),
			)
			if err != nil {
				t.Fatalf("serialized contribution copy %d did not start independently: %v", i, err)
			}
			session.Destroy()
			clearEnvelopePayloads(out)
		}
	})
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

	allShares, err := ReconstructSecretKey(shares[1], shares[2], shares[3])
	if err != nil {
		t.Fatal(err)
	}
	allSharesPublic, err := allShares.PublicKey()
	allShares.Destroy()
	if err != nil || !allSharesPublic.Equal(mustPublicKey(t, secretKey)) {
		t.Fatal("reconstruction from more than threshold shares produced the wrong public key")
	}

	before1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before1)
	before3, err := shares[3].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before3)
	nonConsuming, err := ReconstructSecretKey(shares[1], shares[3])
	if err != nil {
		t.Fatal(err)
	}
	nonConsuming.Destroy()
	after1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after1)
	after3, err := shares[3].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after3)
	if !bytes.Equal(before1, after1) || !bytes.Equal(before3, after3) {
		t.Fatal("reconstruction consumed or mutated an input key share")
	}

	destroyed := cloneKeyShareValue(shares[2])
	destroyed.Destroy()
	if _, err := ReconstructSecretKey(shares[1], destroyed); err == nil {
		t.Fatal("reconstruction accepted a destroyed share")
	}

	for _, tc := range []struct {
		name      string
		sessionID tss.SessionID
		reader    int64
	}{
		{name: "different lifecycle session", sessionID: testutil.MustSessionID(852), reader: 853},
		{name: "same session with different generation commitments", sessionID: plan.state.SessionID, reader: 854},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, otherShares, err := GenerateTrustedDealerKeyShares(secretKey, TrustedDealerImportOption{
				SessionID: tc.sessionID,
				Parties:   tss.NewPartySet(1, 2, 3),
				Threshold: 2,
				ChainCode: chainCode,
				Limits:    &limits,
			}, testutil.DeterministicReader(tc.reader))
			if err != nil {
				t.Fatal(err)
			}
			for _, share := range otherShares {
				defer share.Destroy()
			}
			if !mustKeyShareMetadata(t, shares[1]).PublicKey.Equal(mustKeyShareMetadata(t, otherShares[2]).PublicKey) {
				t.Fatal("mixed-lifecycle fixture did not preserve the same group public key")
			}
			if _, err := ReconstructSecretKey(shares[1], otherShares[2]); err == nil || !strings.Contains(err.Error(), "same lifecycle generation") {
				t.Fatalf("mixed lifecycle reconstruction error = %v", err)
			}
		})
	}
}

func newFROSTTrustedDealerFixture(t *testing.T, sessionSeed int64, scalarByte, chainCodeByte byte, readerSeed int64) (*TrustedDealerImportPlan, map[tss.PartyID]*TrustedDealerContribution) {
	t.Helper()
	encoded := make([]byte, 32)
	encoded[0] = scalarByte
	secretKey, err := ParseSecretScalar(encoded)
	clear(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	limits := testLimits()
	chainCode := bytes.Repeat([]byte{chainCodeByte}, 32)
	defer clear(chainCode)
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: testutil.MustSessionID(sessionSeed),
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
		ChainCode: chainCode,
		Limits:    &limits,
	}, testutil.DeterministicReader(readerSeed))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { destroyFROSTContributions(contributions) })
	return plan, contributions
}

func assertFROSTTrustedDealerStartRejected(t *testing.T, plan *TrustedDealerImportPlan, contribution *TrustedDealerContribution, self tss.PartyID, readerSeed int64) {
	t.Helper()
	session, out, err := StartTrustedDealerImport(
		plan,
		contribution,
		tss.LocalConfig{Self: self, Rand: testutil.DeterministicReader(readerSeed)},
		testFROSTGuard(self, plan.state.Parties, plan.state.SessionID),
	)
	clearEnvelopePayloads(out)
	if session != nil {
		session.Destroy()
		t.Fatal("rejected trusted-dealer start returned a session")
	}
	if len(out) != 0 {
		t.Fatalf("rejected trusted-dealer start returned %d outbound envelopes", len(out))
	}
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	if protocolErr.Blame != nil {
		t.Fatal("local trusted-dealer start rejection produced blame")
	}
}

func assertFROSTContributionAvailable(t *testing.T, contribution *TrustedDealerContribution) {
	t.Helper()
	raw, err := contribution.MarshalBinary()
	if err != nil {
		t.Fatalf("rejected trusted-dealer start consumed its contribution: %v", err)
	}
	clear(raw)
}

func mustPublicKey(t *testing.T, secretKey *SecretKey) PublicKeyPoint {
	t.Helper()
	publicKey, err := secretKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}
