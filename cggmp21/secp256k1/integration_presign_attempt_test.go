//go:build integration

package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// TestThresholdECDSA_PresignAttemptBinding verifies that the same intent resumes
// idempotently while cross-session and cross-digest reuse fail.
func TestThresholdECDSA_PresignAttemptBinding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		newSession bool // create a new session ID for the reuse attempt
		newDigest  bool // use a different digest for the reuse attempt
		wantResume bool
	}{
		{
			name:       "same session same digest",
			newSession: false,
			newDigest:  false,
			wantResume: true,
		},
		{
			name:       "different session same digest",
			newSession: true,
			newDigest:  false,
		},
		{
			name:       "same session different digest",
			newSession: false,
			newDigest:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := CachedKeygenShares(t, 2, 3)
			signers := tss.NewPartySet(1, 2)
			presigns := secpPresign(t, shares, signers)
			presign := presigns[1]

			digest := sha256.Sum256([]byte("reuse"))
			signID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}

			store := newTestSignAttemptStore()
			_, firstOut, err := StartSignDigestWithStore(shares[1], presign, signID, digest[:], store)
			if err != nil {
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

			_, resumedOut, err := StartSignDigestWithStore(shares[1], presign, reuseSessionID, reuseDigest, store)
			if tc.wantResume {
				if err != nil {
					t.Fatalf("same attempt did not resume: %v", err)
				}
				firstRaw, _ := firstOut[0].MarshalBinary()
				resumedRaw, _ := resumedOut[0].MarshalBinary()
				if !bytes.Equal(firstRaw, resumedRaw) {
					t.Fatal("same attempt returned a different envelope")
				}
				return
			}
			_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
			_, recoveredOut, err := StartSignDigestWithStore(shares[1], presign, signID, digest[:], store)
			if err != nil {
				t.Fatalf("original attempt was not recoverable after conflict: %v", err)
			}
			firstRaw, _ := firstOut[0].MarshalBinary()
			recoveredRaw, _ := recoveredOut[0].MarshalBinary()
			if !bytes.Equal(firstRaw, recoveredRaw) {
				t.Fatal("conflict recovery changed the original envelope")
			}
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
			shares := CachedKeygenShares(t, 2, 3)
			signers := tss.NewPartySet(1, 2)
			presigns := secpPresign(t, shares, signers)
			digest := sha256.Sum256([]byte(tc.name))
			tc.run(t, shares[1], presigns[1], digest[:])
		})
	}
}

func TestThresholdECDSA_RestoredPresignRejectsNewSignAttempt(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !IsPresignConsumed(presigns[1]) {
		t.Fatal("MarshalBinary did not consume the local presign handle")
	}
	restoredA, err := tss.DecodeBinary[Presign](raw)
	if err != nil {
		t.Fatal(err)
	}
	restoredB, err := tss.DecodeBinary[Presign](raw)
	if err != nil {
		t.Fatal(err)
	}

	store := newTestSignAttemptStore()
	digest := sha256.Sum256([]byte("restored store claims once"))
	startSignDigestWithStoreMustBeConsumed(t, shares[1], restoredA, digest[:], store)
	startSignDigestWithStoreMustBeConsumed(t, shares[1], restoredB, digest[:], store)
	if !IsPresignConsumed(restoredA) || !IsPresignConsumed(restoredB) {
		t.Fatal("restored presign snapshots became reusable")
	}
}

func TestThresholdECDSA_SignAttemptConflictFailsClosed(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	digest := sha256.Sum256([]byte("store intent conflict"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	session, out, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], fixedErrSignAttemptStore{err: ErrSignAttemptConflict})
	if session != nil || out != nil {
		t.Fatal("already-consumed store returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
	if !IsPresignConsumed(presigns[1]) {
		t.Fatal("already-consumed store error rolled back local claim")
	}
}

func TestThresholdECDSA_SignAttemptOutcomeUnknownResumesSameIntent(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	digest := sha256.Sum256([]byte("store temporary error"))
	storeErr := errors.New("commit response lost")
	store := &outcomeUnknownSignAttemptStore{inner: newTestSignAttemptStore(), err: storeErr}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	session, out, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store)
	if !errors.Is(err, ErrSignAttemptOutcomeUnknown) {
		t.Fatalf("expected outcome-unknown error, got %v", err)
	}
	if session != nil || out != nil {
		t.Fatal("outcome-unknown commit returned signing output")
	}
	if !IsPresignConsumed(presigns[1]) {
		t.Fatal("outcome-unknown commit did not retain local binding")
	}
	var unknown *SignAttemptOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("outcome-unknown error type = %T, want SignAttemptOutcomeUnknownError", err)
	}
	if unknown.Descriptor.SessionID != sessionID ||
		unknown.Descriptor.Party != shares[1].PartyID() ||
		!bytes.Equal(unknown.Descriptor.ContextHash, mustPresignContextHash(t, presigns[1])) {
		t.Fatal("outcome-unknown descriptor did not preserve recovery identity")
	}

	metadata, err := LoadSignAttemptMetadata(context.Background(), presigns[1], store)
	if err != nil {
		t.Fatalf("load sign attempt metadata: %v", err)
	}
	if metadata.Descriptor.SessionID != sessionID || metadata.Completed || metadata.DeliveryComplete {
		t.Fatal("metadata did not describe the committed incomplete attempt")
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), metadata.Descriptor.SessionID)
	session, out, err = startSignDigestBound(context.Background(), shares[1], presigns[1], sessionID, digest[:], mustPresignContextHash(t, presigns[1]), store, guard, testLimits())
	if err != nil {
		t.Fatalf("resume same attempt: %v", err)
	}
	if session == nil || len(out) != 1 {
		t.Fatal("resume same attempt did not return the durable outbox")
	}
}

func TestThresholdECDSA_StartSignCommitIsFirstDurableDecision(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	digest := sha256.Sum256([]byte("commit before load"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &loadCountingSignAttemptStore{inner: newTestSignAttemptStore()}
	if _, out, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store); err != nil {
		t.Fatal(err)
	} else if len(out) != 1 {
		t.Fatal("StartSign did not return committed outbox")
	}
	if store.loadCount() != 0 {
		t.Fatalf("StartSign called LoadSignAttempt %d time(s) before/after commit", store.loadCount())
	}
}

func TestThresholdECDSA_StartSignRequiresSignAttemptStore(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresignWithContext(t, shares, tss.NewPartySet(1, 2), testPresignContext())
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
	plan, err := NewSignPlan(SignPlanOption{
		Key:     shares[1],
		Presign: presigns[1],
		Intent: SignIntent{
			SessionID: sessionID,
			Context:   testPresignContext(),
			Message:   []byte("missing store"),
			Signers:   presigns[1].state.Signers,
		},
		Limits: testLimitsPtr(),
	})
	if err != nil {
		t.Fatalf("NewSignPlan: %v", err)
	}
	var session *SignSession
	var out []tss.Envelope
	session, out, err = StartSign(shares[1], plan, SignRuntime{
		Local:   tss.LocalConfig{Self: 1, Context: context.Background()},
		Guard:   guard,
		Presign: presigns[1],
	})
	if session != nil || out != nil {
		t.Fatal("StartSign without store returned signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	if IsPresignConsumed(presigns[1]) {
		t.Fatal("StartSign without store consumed presign")
	}
}
