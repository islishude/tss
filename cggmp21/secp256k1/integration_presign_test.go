//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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
			shares := CachedKeygenShares(t, 2, 3, false)
			signers := []tss.PartyID{1, 2}
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
			shares := CachedKeygenShares(t, 2, 3, false)
			signers := []tss.PartyID{1, 2}
			presigns := secpPresign(t, shares, signers)
			digest := sha256.Sum256([]byte(tc.name))
			tc.run(t, shares[1], presigns[1], digest[:])
		})
	}
}

func TestThresholdECDSA_RestoredSignAttemptStoreSerializesIntents(t *testing.T) {
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

	store := newTestSignAttemptStore()
	digest := sha256.Sum256([]byte("restored store claims once"))
	startSignDigestWithStoreMustSucceed(t, shares[1], restoredA, digest[:], store)
	startSignDigestWithStoreMustBeConsumed(t, shares[1], restoredB, digest[:], store)
	if !IsPresignConsumed(restoredB) {
		t.Fatal("store conflict did not leave restored presign consumed")
	}
}

func TestThresholdECDSA_SignAttemptConflictFailsClosed(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
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
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
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

	guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
	session, out, err = startSignDigestBound(context.Background(), shares[1], presigns[1], sessionID, digest[:], presigns[1].ContextHashBytes(), true, store, guard)
	if err != nil {
		t.Fatalf("resume same attempt: %v", err)
	}
	if session == nil || len(out) != 1 {
		t.Fatal("resume same attempt did not return the durable outbox")
	}
}

func TestThresholdECDSA_StartSignCommitIsFirstDurableDecision(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
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

func TestThresholdECDSA_CorruptSignAttemptLoadDiscardsPresign(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := loadErrSignAttemptStore{err: ErrSignAttemptCorrupt}

	resumePresign, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
	session, out, err := ResumeSign(context.Background(), shares[1], resumePresign, store, guard)
	if !errors.Is(err, ErrSignAttemptCorrupt) {
		t.Fatalf("ResumeSign corrupt load error = %v", err)
	}
	if session != nil || out != nil {
		t.Fatal("ResumeSign returned output for a corrupt durable attempt")
	}
	if !IsPresignConsumed(resumePresign) {
		t.Fatal("ResumeSign released the presign after a corrupt durable load")
	}
}

func TestThresholdECDSA_SignAttemptRestartReplaysExactEnvelope(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	rawFresh, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("restart exact outbox"))
	store := newTestSignAttemptStore()
	_, firstOut, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store)
	if err != nil {
		t.Fatal(err)
	}
	rawConsumed, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	for name, raw := range map[string][]byte{
		"fresh snapshot":    rawFresh,
		"consumed snapshot": rawConsumed,
	} {
		t.Run(name, func(t *testing.T) {
			restored, err := UnmarshalPresign(raw)
			if err != nil {
				t.Fatal(err)
			}
			guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
			_, resumedOut, err := ResumeSign(context.Background(), shares[1], restored, store, guard)
			if err != nil {
				t.Fatal(err)
			}
			firstRaw, _ := firstOut[0].MarshalBinary()
			resumedRaw, _ := resumedOut[0].MarshalBinary()
			if !bytes.Equal(firstRaw, resumedRaw) {
				t.Fatal("restart did not replay the exact committed envelope")
			}
		})
	}
}

func TestThresholdECDSA_SignAttemptResumeSkipsReplayAfterDeliveryComplete(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	rawPresign, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("delivery complete resume"))
	store := newTestSignAttemptStore()
	session, out, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatal("StartSign did not return outbox")
	}
	ack1 := testBroadcastAck(out[0], 1)
	ack2 := testBroadcastAck(out[0], 2)
	cert, err := tss.NewBroadcastCertificate(out[0], tss.PartySet{1, 2}, []tss.BroadcastAck{ack1, ack2})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.UpdateDelivery(context.Background(), nil, cert); err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalPresign(rawPresign)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
	resumed, resumedOut, err := ResumeSign(context.Background(), shares[1], restored, store, guard)
	if err != nil {
		t.Fatal(err)
	}
	if resumed == nil {
		t.Fatal("ResumeSign returned nil session")
	}
	if len(resumedOut) != 0 {
		t.Fatal("ResumeSign replayed outbox after durable delivery completion")
	}
}

func TestThresholdECDSA_SignAttemptCompletionSurvivesRestart(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	rawPresign, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("completion restart"))
	stores := map[tss.PartyID]*testSignAttemptStore{
		1: newTestSignAttemptStore(),
		2: newTestSignAttemptStore(),
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	out := make(map[tss.PartyID]tss.Envelope, len(signers))
	for _, id := range signers {
		session, envelopes, err := StartSignDigestWithStore(shares[id], presigns[id], sessionID, digest[:], stores[id])
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		out[id] = envelopes[0]
	}
	if _, err := sessions[1].HandleSignMessage(testutil.DeliverEnvelope(out[2])); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions[2].HandleSignMessage(testutil.DeliverEnvelope(out[1])); err != nil {
		t.Fatal(err)
	}
	signature, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature was not completed")
	}

	restored, err := UnmarshalPresign(rawPresign)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
	resumed, resumedOut, err := ResumeSign(context.Background(), shares[1], restored, stores[1], guard)
	if err != nil {
		t.Fatal(err)
	}
	if len(resumedOut) != 1 {
		t.Fatal("completed attempt did not retain the exact replayable outbox")
	}
	originalRaw, _ := out[1].MarshalBinary()
	resumedRaw, _ := resumedOut[0].MarshalBinary()
	if !bytes.Equal(originalRaw, resumedRaw) {
		t.Fatal("completed attempt replayed a different envelope")
	}
	resumedSignature, ok := resumed.Signature()
	if !ok || !bytes.Equal(signature.R, resumedSignature.R) || !bytes.Equal(signature.S, resumedSignature.S) {
		t.Fatal("completed signature did not survive restart")
	}
}

func TestThresholdECDSA_SignAttemptCompletionIsDurableBeforeVisible(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("completion visibility"))
	completionErr := errors.New("completion response lost")
	store1 := &completionOutcomeUnknownStore{inner: newTestSignAttemptStore(), err: completionErr}
	store2 := newTestSignAttemptStore()
	session1, out1, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store1)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartSignDigestWithStore(shares[2], presigns[2], sessionID, digest[:], store2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session1.HandleSignMessage(testutil.DeliverEnvelope(out2[0])); !errors.Is(err, completionErr) {
		t.Fatalf("completion persistence error = %v", err)
	}
	if _, ok := session1.Signature(); ok {
		t.Fatal("signature became visible before durable completion was confirmed")
	}
	if err := session1.RetryCompletion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := session1.Signature(); !ok {
		t.Fatal("signature unavailable after idempotent completion retry")
	}
	if len(out1) != 1 {
		t.Fatal("initial exact outbox was not returned")
	}
}

func TestThresholdECDSA_BurnPresignBlocksRestoredCopies(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	store := newTestSignAttemptStore()
	if err := BurnPresign(context.Background(), store, presigns[1], "operator discard"); err != nil {
		t.Fatal(err)
	}
	if !IsPresignConsumed(presigns[1]) {
		t.Fatal("BurnPresign did not mark the local handle consumed")
	}
	restored, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("burned presign"))
	session, out, err := StartSignDigestWithStore(shares[1], restored, sessionID, digest[:], store)
	if session != nil || out != nil {
		t.Fatal("burned restored presign produced signing output")
	}
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeConsumed)
	if !IsPresignConsumed(restored) {
		t.Fatal("burned restored presign was not locally consumed")
	}
}

func TestThresholdECDSA_BurnPresignAfterCommitPreservesResume(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	store := newTestSignAttemptStore()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("commit before burn"))
	_, firstOut, err := StartSignDigestWithStore(shares[1], presigns[1], sessionID, digest[:], store)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := BurnPresign(context.Background(), store, restored, "too late"); !errors.Is(err, ErrSignAttemptConflict) {
		t.Fatalf("burn after commit error = %v", err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
	resumed, resumedOut, err := ResumeSign(context.Background(), shares[1], restored, store, guard)
	if err != nil {
		t.Fatal(err)
	}
	if resumed == nil || len(resumedOut) != 1 {
		t.Fatal("committed attempt was not resumable after failed burn")
	}
	firstRaw, _ := firstOut[0].MarshalBinary()
	resumedRaw, _ := resumedOut[0].MarshalBinary()
	if !bytes.Equal(firstRaw, resumedRaw) {
		t.Fatal("failed burn changed the committed outbox")
	}
}

func TestThresholdECDSA_SignAttemptConcurrentSameIntentIsIdempotent(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("concurrent same attempt"))
	store := newTestSignAttemptStore()
	const workers = 8
	type result struct {
		raw []byte
		err error
	}
	var wg sync.WaitGroup
	results := make(chan result, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
			_, out, err := startSignDigestBound(context.Background(), shares[1], presigns[1], sessionID, digest[:], presigns[1].ContextHashBytes(), true, store, guard)
			if err != nil {
				results <- result{err: err}
				return
			}
			raw, err := out[0].MarshalBinary()
			results <- result{raw: raw, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var first []byte
	for result := range results {
		if result.err != nil {
			t.Fatalf("same-intent concurrent start: %v", result.err)
		}
		if first == nil {
			first = result.raw
			continue
		}
		if !bytes.Equal(first, result.raw) {
			t.Fatal("same-intent concurrent start produced different envelopes")
		}
	}
}

func TestThresholdECDSA_SignAttemptConcurrentConflictsHaveOneWinner(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	store := newTestSignAttemptStore()
	type attempt struct {
		session tss.SessionID
		digest  [sha256.Size]byte
	}
	attempts := make([]attempt, 2)
	for i := range attempts {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		attempts[i] = attempt{
			session: sessionID,
			digest:  sha256.Sum256([]byte{byte(i + 1)}),
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(attempts))
	for _, candidate := range attempts {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), candidate.session)
			_, _, err := startSignDigestBound(context.Background(), shares[1], presigns[1], candidate.session, candidate.digest[:], presigns[1].ContextHashBytes(), true, store, guard)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	conflicts := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		var protocolErr *tss.ProtocolError
		if errors.As(err, &protocolErr) && protocolErr.Code == tss.ErrCodeConsumed {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent conflict error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want 1 each", successes, conflicts)
	}
}

func TestThresholdECDSA_StartSignRequiresSignAttemptStore(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresignWithContext(t, shares, []tss.PartyID{1, 2}, testPresignContext())
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), tss.PartySet(shares[1].Parties()), sessionID)
	session, out, err := StartSign(context.Background(), shares[1], presigns[1], sessionID, SignRequest{
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

type fixedErrSignAttemptStore struct {
	err error
}

type loadErrSignAttemptStore struct {
	err error
}

func (s loadErrSignAttemptStore) LoadSignAttempt(context.Context, []byte) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, s.err
}

func (s loadErrSignAttemptStore) CommitSignAttempt(context.Context, SignAttemptRecord) (SignAttemptCommit, error) {
	return SignAttemptCommit{}, errors.New("unexpected commit after load error")
}

func (s loadErrSignAttemptStore) UpdateSignAttemptDelivery(context.Context, SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, errors.New("unexpected delivery update after load error")
}

func (s loadErrSignAttemptStore) CompleteSignAttempt(context.Context, SignAttemptResult) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, errors.New("unexpected completion after load error")
}

func (s loadErrSignAttemptStore) BurnPresign(context.Context, SignAttemptBurn) error {
	return errors.New("unexpected burn after load error")
}

func (s fixedErrSignAttemptStore) LoadSignAttempt(context.Context, []byte) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, ErrSignAttemptNotFound
}

func (s fixedErrSignAttemptStore) CommitSignAttempt(context.Context, SignAttemptRecord) (SignAttemptCommit, error) {
	return SignAttemptCommit{}, s.err
}

func (s fixedErrSignAttemptStore) UpdateSignAttemptDelivery(context.Context, SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, s.err
}

func (s fixedErrSignAttemptStore) CompleteSignAttempt(context.Context, SignAttemptResult) (SignAttemptRecord, error) {
	return SignAttemptRecord{}, s.err
}

func (s fixedErrSignAttemptStore) BurnPresign(context.Context, SignAttemptBurn) error {
	return s.err
}

type outcomeUnknownSignAttemptStore struct {
	inner *testSignAttemptStore
	err   error
	once  bool
}

type completionOutcomeUnknownStore struct {
	inner *testSignAttemptStore
	err   error
	once  bool
}

type loadCountingSignAttemptStore struct {
	inner *testSignAttemptStore
	loads atomic.Int32
}

func (s *loadCountingSignAttemptStore) loadCount() int {
	return int(s.loads.Load())
}

func (s *loadCountingSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	s.loads.Add(1)
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *loadCountingSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	return s.inner.CommitSignAttempt(ctx, candidate)
}

func (s *loadCountingSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *loadCountingSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	return s.inner.CompleteSignAttempt(ctx, result)
}

func (s *loadCountingSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	return s.inner.BurnPresign(ctx, burn)
}

func (s *completionOutcomeUnknownStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *completionOutcomeUnknownStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	return s.inner.CommitSignAttempt(ctx, candidate)
}

func (s *completionOutcomeUnknownStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *completionOutcomeUnknownStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	record, err := s.inner.CompleteSignAttempt(ctx, result)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if !s.once {
		s.once = true
		return SignAttemptRecord{}, s.err
	}
	return record, nil
}

func (s *completionOutcomeUnknownStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	return s.inner.BurnPresign(ctx, burn)
}

func (s *outcomeUnknownSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	return s.inner.LoadSignAttempt(ctx, presignID)
}

func (s *outcomeUnknownSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	commit, err := s.inner.CommitSignAttempt(ctx, candidate)
	if err != nil {
		return SignAttemptCommit{}, err
	}
	if !s.once {
		s.once = true
		return SignAttemptCommit{}, s.err
	}
	return commit, nil
}

func (s *outcomeUnknownSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	return s.inner.UpdateSignAttemptDelivery(ctx, update)
}

func (s *outcomeUnknownSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	return s.inner.CompleteSignAttempt(ctx, result)
}

func (s *outcomeUnknownSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	return s.inner.BurnPresign(ctx, burn)
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

func startSignDigestWithStoreMustSucceed(t *testing.T, share *KeyShare, presign *Presign, digest []byte, store SignAttemptStore) {
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

func startSignDigestWithStoreMustBeConsumed(t *testing.T, share *KeyShare, presign *Presign, digest []byte, store SignAttemptStore) {
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
	payload.PaillierPublicKey = shares[1].PaillierPublicKeyBytes()
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
				signSession, _, err := StartSignDigestWithStore(shares[tc.signers[0]], restored, sessionID, digest[:], newTestSignAttemptStore())
				if err != nil {
					t.Fatalf("StartSignDigest with round-tripped presign: %v", err)
				}
				sig, ok := signSession.Signature()
				if !ok {
					t.Fatal("expected sign session to produce a signature")
				}
				if !VerifyDigest(shares[tc.signers[0]].PublicKeyBytes(), digest[:], sig) {
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
	presign.state.keygenTranscriptHash = append([]byte(nil), presign.state.keygenTranscriptHash...)
	presign.state.keygenTranscriptHash[0] ^= 1
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
