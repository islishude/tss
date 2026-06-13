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

func TestThresholdECDSA_PresignCopiesShareClaim(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		run  func(t *testing.T, share *KeyShare, presign *Presign, digest []byte)
	}{
		{
			name: "original consumes test copy",
			run: func(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
				cp := clonePresignForTest(presign)
				startSignDigestMustSucceed(t, share, presign, digest)
				startSignDigestMustBeConsumed(t, share, cp, digest)
				if !IsPresignConsumed(cp) {
					t.Fatal("test copy did not observe shared consumed claim")
				}
			},
		},
		{
			name: "test copy consumes original",
			run: func(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
				cp := clonePresignForTest(presign)
				startSignDigestMustSucceed(t, share, cp, digest)
				startSignDigestMustBeConsumed(t, share, presign, digest)
				if !IsPresignConsumed(presign) {
					t.Fatal("original did not observe shared consumed claim")
				}
			},
		},
		{
			name: "shallow copy consumes original",
			run: func(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
				cp := *presign
				startSignDigestMustSucceed(t, share, &cp, digest)
				startSignDigestMustBeConsumed(t, share, presign, digest)
				if !IsPresignConsumed(presign) {
					t.Fatal("original did not observe shallow-copy consumed claim")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := CachedKeygenShares(t, 2, 3, false)
			signers := []tss.PartyID{1, 2}
			presigns := secpPresign(t, shares, signers)
			digest := sha256.Sum256([]byte(tc.name))
			tc.run(t, shares[1], presigns[1], digest[:])
		})
	}
}

func TestThresholdECDSA_RestoredPresignStoreClaimsOnce(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restoredA, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	restoredB, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}

	store := newTestPresignStore()
	digest := sha256.Sum256([]byte("restored store claims once"))
	startSignDigestWithStoreMustSucceed(t, shares[1], restoredA, digest[:], store)
	startSignDigestWithStoreMustBeConsumed(t, shares[1], restoredB, digest[:], store)
	if !IsPresignConsumed(restoredB) {
		t.Fatal("store conflict did not leave restored presign consumed")
	}
}

func TestThresholdECDSA_PresignStoreAlreadyConsumedFailClosed(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	digest := sha256.Sum256([]byte("store already consumed"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	session, out, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], fixedErrPresignStore{err: ErrPresignAlreadyConsumed})
	if session != nil || out != nil {
		t.Fatal("already-consumed store returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
	if !IsPresignConsumed(presigns[1]) {
		t.Fatal("already-consumed store error rolled back local claim")
	}
}

func TestThresholdECDSA_PresignStoreTemporaryErrorRollsBack(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	digest := sha256.Sum256([]byte("store temporary error"))
	storeErr := errors.New("temporary store failure")
	store := &retryPresignStore{err: storeErr}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	session, out, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store)
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected temporary store error, got %v", err)
	}
	if session != nil || out != nil {
		t.Fatal("temporary store error returned signing output")
	}
	if IsPresignConsumed(presigns[1]) {
		t.Fatal("temporary store error did not roll back local claim")
	}

	startSignDigestWithStoreMustSucceed(t, shares[1], presigns[1], digest[:], store)
}

func TestThresholdECDSA_StartSignRequiresPresignStore(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresignWithContext(t, shares, []tss.PartyID{1, 2}, testPresignContext())
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID)
	session, out, err := StartSign(shares[1], presigns[1], sessionID, SignRequest{
		Context: testPresignContext(),
		Message: []byte("missing store"),
		LowS:    true,
	}, guard)
	if session != nil || out != nil {
		t.Fatal("StartSign without store returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	if IsPresignConsumed(presigns[1]) {
		t.Fatal("StartSign without store consumed presign")
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

type fixedErrPresignStore struct {
	err error
}

func (s fixedErrPresignStore) ClaimPresign([]byte) error {
	return s.err
}

type retryPresignStore struct {
	err   error
	calls int
}

func (s *retryPresignStore) ClaimPresign([]byte) error {
	s.calls++
	if s.calls == 1 {
		return s.err
	}
	return nil
}

func startSignDigestMustSucceed(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := StartSignDigest(share, presign, sessionID, digest)
	if err != nil {
		t.Fatalf("StartSignDigest: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("StartSignDigest returned no signing partial")
	}
}

func startSignDigestMustBeConsumed(t *testing.T, share *KeyShare, presign *Presign, digest []byte) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := StartSignDigest(share, presign, sessionID, digest)
	if session != nil || out != nil {
		t.Fatal("consumed presign returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
}

func startSignDigestWithStoreMustSucceed(t *testing.T, share *KeyShare, presign *Presign, digest []byte, store PresignStore) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := StartSignDigestWithStore(share, presign, sessionID, digest, store)
	if err != nil {
		t.Fatalf("StartSignDigestWithStore: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("StartSignDigestWithStore returned no signing partial")
	}
}

func startSignDigestWithStoreMustBeConsumed(t *testing.T, share *KeyShare, presign *Presign, digest []byte, store PresignStore) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := StartSignDigestWithStore(share, presign, sessionID, digest, store)
	if session != nil || out != nil {
		t.Fatal("consumed store returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
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
				if IsPresignConsumed(restored) {
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
	presign := clonePresignForTest(presigns[1])
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
	if IsPresignConsumed(presign) {
		t.Fatal("presign was consumed before key binding validation completed")
	}
}
