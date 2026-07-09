//go:build integration

package secp256k1

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSATamperedEncKBlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := startTestPresign(shares[1], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startTestPresign(shares[2], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload[0] ^= 1
	if _, err := s1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected tampered EncK rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], tss.NewPartySet(1, 2), nil))
	}
}

func TestThresholdECDSATamperedRound2ProofBlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*presignRound2Payload)
	}{
		{name: "delta", mutate: func(p *presignRound2Payload) { p.Delta.Proof.TranscriptHash[0] ^= 1 }},
		{name: "sigma", mutate: func(p *presignRound2Payload) { p.Sigma.Proof.TranscriptHash[0] ^= 1 }},
		{name: "echo", mutate: func(p *presignRound2Payload) { p.Round1Echo[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			s1, out1, err := startTestPresign(shares[1], sessionID, tss.NewPartySet(1, 2))
			if err != nil {
				t.Fatal(err)
			}
			s2, out2, err := startTestPresign(shares[2], sessionID, tss.NewPartySet(1, 2))
			if err != nil {
				t.Fatal(err)
			}
			_ = deliverPresignMessagesTo(t, s1, 1, out2)
			round2 := deliverPresignMessagesTo(t, s2, 2, out1)
			if len(round2) != 1 || round2[0].To != 1 {
				t.Fatalf("unexpected round2 messages: %#v", round2)
			}
			mutated, err := mutatePresignRound2Payload(round2[0].Payload, tc.mutate)
			if err != nil {
				t.Fatal(err)
			}
			round2[0].Payload = mutated
			_, err = s1.Handle(testutil.DeliverEnvelope(round2[0]))
			if err == nil {
				t.Fatal("expected tampered round2 proof rejection")
			}
			var protocolErr *tss.ProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.Party != 2 {
				t.Fatalf("unexpected error: %v", err)
			}
			_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], tss.NewPartySet(1, 2), nil))
		})
	}
}

func TestThresholdECDSAPaillierPublicKeyMismatchRejected(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := startTestPresign(shares[1], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startTestPresign(shares[2], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalPresignRound1Payload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	paillierPublicKey, err := shares[1].paillierPublicFor(1, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierPublicKey = paillierPublicKey
	mutated, err := payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	if _, err := s1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected presign Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], tss.NewPartySet(1, 2), nil))
	}
}

// TestThresholdECDSA_PresignRoundTripScenarios verifies that presign
// marshal/unmarshal round-trips produce consumed snapshots. Serialized presigns
// are recovery-only handles; they must not create a second usable presign.
func TestThresholdECDSA_PresignRoundTripScenarios(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		threshold   int
		n           int
		signers     tss.PartySet
		preConsume  bool // whether to consume before round-trip
		digestLabel string
	}{
		{
			name:        "fresh round-trip 1-of-1",
			threshold:   1,
			n:           1,
			signers:     tss.NewPartySet(1),
			preConsume:  false,
			digestLabel: "fresh round-trip",
		},
		{
			name:        "consumed round-trip 2-of-3",
			threshold:   2,
			n:           3,
			signers:     tss.NewPartySet(1, 2),
			preConsume:  true,
			digestLabel: "consumed round-trip",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := CachedKeygenShares(t, tc.threshold, tc.n)
			presigns := secpPresign(t, shares, tc.signers)
			presign := presigns[tc.signers[0]]

			digest := sha256.Sum256([]byte(tc.digestLabel))

			if tc.preConsume {
				sessionID, err := tss.NewSessionID(nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := StartSignDigest(shares[tc.signers[0]], presign, sessionID, digest[:]); err != nil {
					t.Fatalf("StartSignDigest: %v", err)
				}
			}

			raw, err := presign.MarshalBinaryWithLimits(testLimits())
			if err != nil {
				t.Fatalf("Presign MarshalBinary: %v", err)
			}
			if !IsPresignConsumed(presign) {
				t.Fatal("MarshalBinary did not consume the local presign handle")
			}
			restored, err := tss.DecodeBinaryWithLimits[Presign](raw, testLimits())
			if err != nil {
				t.Fatalf("UnmarshalPresign: %v", err)
			}

			if !IsPresignConsumed(restored) {
				t.Fatal("serialized presign restored as reusable")
			}
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = StartSignDigestWithStore(shares[tc.signers[0]], restored, sessionID, digest[:], newTestSignAttemptStore())
			_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
		})
	}
}

func TestThresholdECDSA_PresignRejectsKeyBindingMismatchBeforeConsume(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	presigns := secpPresign(t, shares, signers)
	presign := clonePresignForTest(presigns[1])
	presign.state.KeygenTranscriptHash = append([]byte(nil), presign.state.KeygenTranscriptHash...)
	presign.state.KeygenTranscriptHash[0] ^= 1
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("key binding mismatch"))
	_, _, err = StartSignDigest(shares[1], presign, signID, digest[:])
	if err == nil || !strings.Contains(err.Error(), "keygen transcript binding") {
		t.Fatalf("expected key binding rejection, got %v", err)
	}
	if IsPresignConsumed(presign) {
		t.Fatal("presign was consumed before key binding validation completed")
	}
}
