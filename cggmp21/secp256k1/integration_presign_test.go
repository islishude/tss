//go:build integration || vectorgen

package secp256k1

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// TestThresholdECDSA_PresignReuseRejected verifies that a presign cannot be
// reused: same session re-sign attempt, cross-session reuse, and cross-digest
// reuse all fail.
func TestThresholdECDSA_PresignReuseRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		newSession bool // create a new session ID for the reuse attempt
		newDigest  bool // use a different digest for the reuse attempt
		wantCode   string
	}{
		{
			name:       "same session same digest",
			newSession: false,
			newDigest:  false,
			wantCode:   tss.ErrCodeConsumed,
		},
		{
			name:       "different session same digest",
			newSession: true,
			newDigest:  false,
			wantCode:   tss.ErrCodeConsumed,
		},
		{
			name:       "same session different digest",
			newSession: false,
			newDigest:  true,
			wantCode:   tss.ErrCodeConsumed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := CachedKeygenShares(t, 2, 3, false)
			signers := []tss.PartyID{1, 2}
			presigns := secpPresign(t, shares, signers)
			presign := presigns[1]

			digest := sha256.Sum256([]byte("reuse"))
			signID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}

			if _, _, err := StartSignDigest(shares[1], presign, signID, digest[:]); err != nil {
				t.Fatalf("first StartSignDigest: %v", err)
			}

			reuseSessionID := signID
			if tc.newSession {
				var err error
				reuseSessionID, err = tss.NewSessionID(nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			reuseDigest := digest[:]
			if tc.newDigest {
				d := sha256.Sum256([]byte("reuse different digest"))
				reuseDigest = d[:]
			}

			_, _, err = StartSignDigest(shares[1], presign, reuseSessionID, reuseDigest)
			_ = testutil.AssertProtocolError(t, err, tc.wantCode)
		})
	}
}

func TestThresholdECDSATamperedEncKBlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload[0] ^= 1
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected tampered EncK rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
	}
}

func TestThresholdECDSATamperedRound2ProofBlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	for _, tc := range []struct {
		name   string
		mutate func(*presignRound2Payload)
	}{
		{name: "delta", mutate: func(p *presignRound2Payload) { p.Delta.Proof[0] ^= 1 }},
		{name: "sigma", mutate: func(p *presignRound2Payload) { p.Sigma.Proof[0] ^= 1 }},
		{name: "echo", mutate: func(p *presignRound2Payload) { p.Round1Echo[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			s1, out1, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			s2, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
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
			round2[0] = round2[0].RecomputeTranscriptHash()
			_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(round2[0]))
			if err == nil {
				t.Fatal("expected tampered round2 proof rejection")
			}
			var protocolErr *tss.ProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.Party != 2 {
				t.Fatalf("unexpected error: %v", err)
			}
			_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
		})
	}
}

func TestThresholdECDSAPaillierPublicKeyMismatchRejected(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalPresignRound1Payload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierPublicKey = shares[1].PaillierPublicKey
	mutated, err := marshalPresignRound1Payload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected presign Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
	}
}

// TestThresholdECDSA_PresignRoundTripScenarios verifies that presign
// marshal/unmarshal round-trip preserves the consumed state correctly:
// fresh presigns can still sign, consumed presigns stay consumed.
func TestThresholdECDSA_PresignRoundTripScenarios(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		threshold   int
		n           int
		signers     []tss.PartyID
		preConsume  bool // whether to consume before round-trip
		digestLabel string
	}{
		{
			name:        "fresh round-trip 1-of-1",
			threshold:   1,
			n:           1,
			signers:     []tss.PartyID{1},
			preConsume:  false,
			digestLabel: "fresh round-trip",
		},
		{
			name:        "consumed round-trip 2-of-3",
			threshold:   2,
			n:           3,
			signers:     []tss.PartyID{1, 2},
			preConsume:  true,
			digestLabel: "consumed round-trip",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := CachedKeygenShares(t, tc.threshold, tc.n, false)
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

			raw, err := presign.MarshalBinary()
			if err != nil {
				t.Fatalf("Presign MarshalBinary: %v", err)
			}
			restored, err := UnmarshalPresign(raw)
			if err != nil {
				t.Fatalf("UnmarshalPresign: %v", err)
			}

			if tc.preConsume {
				if !IsPresignConsumed(restored) {
					t.Fatal("consumed state was not preserved through round-trip")
				}
				// Attempting to sign with the consumed restored presign must fail.
				sessionID2, err := tss.NewSessionID(nil)
				if err != nil {
					t.Fatal(err)
				}
				_, _, err = StartSignDigest(shares[tc.signers[0]], restored, sessionID2, digest[:])
				_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
			} else {
				if restored.Consumed {
					t.Fatal("fresh presign after round-trip is consumed")
				}
				sessionID, err := tss.NewSessionID(nil)
				if err != nil {
					t.Fatal(err)
				}
				signSession, _, err := StartSignDigestWithStore(shares[tc.signers[0]], restored, sessionID, digest[:], newTestPresignStore())
				if err != nil {
					t.Fatalf("StartSignDigest with round-tripped presign: %v", err)
				}
				sig, ok := signSession.Signature()
				if !ok {
					t.Fatal("expected sign session to produce a signature")
				}
				if !VerifyDigest(shares[tc.signers[0]].PublicKey, digest[:], sig) {
					t.Fatal("ECDSA signature from round-tripped presign did not verify")
				}
			}
		})
	}
}

func TestThresholdECDSA_PresignRejectsKeyBindingMismatchBeforeConsume(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	presign := (presigns[1]).Clone()
	presign.KeygenTranscriptHash = append([]byte(nil), presign.KeygenTranscriptHash...)
	presign.KeygenTranscriptHash[0] ^= 1
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("key binding mismatch"))
	_, _, err = StartSignDigest(shares[1], presign, signID, digest[:])
	if err == nil || !strings.Contains(err.Error(), "keygen transcript binding") {
		t.Fatalf("expected key binding rejection, got %v", err)
	}
	if presign.Consumed {
		t.Fatal("presign was consumed before key binding validation completed")
	}
}
