//go:build integration

package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSA_CorruptSignAttemptLoadDiscardsPresign(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := loadErrSignAttemptStore{err: ErrSignAttemptCorrupt}

	resumePresign, err := tss.DecodeBinary[Presign](raw)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
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
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
			restored, err := tss.DecodeBinary[Presign](raw)
			if err != nil {
				t.Fatal(err)
			}
			guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
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
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
	cert, err := tss.NewBroadcastCertificate(out[0], tss.NewPartySet(1, 2), []tss.BroadcastAck{ack1, ack2})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.UpdateDelivery(context.Background(), nil, cert); err != nil {
		t.Fatal(err)
	}
	restored, err := tss.DecodeBinary[Presign](rawPresign)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
	guard.AckVerifier = testBroadcastAckVerifier()
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
	contentID, err := restored.contentIDWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	tampered := store.attempts[string(contentID)]
	tampered.DeliveryState.Acks[0].Signature[0] ^= 1
	store.attempts[string(contentID)] = tampered
	store.mu.Unlock()
	secondRestored, err := tss.DecodeBinary[Presign](rawPresign)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondRestored.Destroy)
	strictGuard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
	strictGuard.AckVerifier = testBroadcastAckVerifier()
	badSession, badOut, err := ResumeSign(context.Background(), shares[1], secondRestored, store, strictGuard)
	if !errors.Is(err, ErrSignAttemptCorrupt) || badSession != nil || badOut != nil {
		t.Fatalf("ResumeSign unauthenticated delivery state = session:%v out:%d err:%v", badSession != nil, len(badOut), err)
	}
}

func TestThresholdECDSA_SignAttemptCompletionSurvivesRestart(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
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
	if _, err := sessions[1].Handle(testutil.DeliverEnvelope(out[2])); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions[2].Handle(testutil.DeliverEnvelope(out[1])); err != nil {
		t.Fatal(err)
	}
	signature, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature was not completed")
	}

	restored, err := tss.DecodeBinary[Presign](rawPresign)
	if err != nil {
		t.Fatal(err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
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
	if len(resumed.sigmaOpenings) != 0 {
		t.Fatal("completed attempt recovery retained attempt-owned sigma identification witnesses")
	}
	if len(restored.state.sigmaOpenings) != 0 || len(restored.state.SigmaOpeningRecords) != 1 {
		t.Fatal("completed attempt recovery mutated caller-owned presign witness records")
	}
	contentID, err := restored.contentIDWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	stores[1].mu.Lock()
	tampered := stores[1].attempts[string(contentID)]
	tampered.SignatureRecoveryID ^= 1
	stores[1].attempts[string(contentID)] = tampered
	stores[1].mu.Unlock()
	secondRestored, err := tss.DecodeBinary[Presign](rawPresign)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondRestored.Destroy)
	strictGuard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
	badSession, badOut, err := ResumeSign(context.Background(), shares[1], secondRestored, stores[1], strictGuard)
	if !errors.Is(err, ErrSignAttemptCorrupt) || badSession != nil || badOut != nil {
		t.Fatalf("ResumeSign mismatched recovery ID = session:%v out:%d err:%v", badSession != nil, len(badOut), err)
	}
}

func TestThresholdECDSA_SignAttemptCompletionIsDurableBeforeVisible(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
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
	if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); !errors.Is(err, completionErr) {
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
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
	restored, err := tss.DecodeBinary[Presign](raw)
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
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
	restored, err := tss.DecodeBinary[Presign](raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := BurnPresign(context.Background(), store, restored, "too late"); !errors.Is(err, ErrSignAttemptConflict) {
		t.Fatalf("burn after commit error = %v", err)
	}
	guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
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
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
		wg.Go(func() {
			guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), sessionID)
			_, out, err := startSignDigestBound(context.Background(), shares[1], presigns[1], sessionID, digest[:], mustPresignContextHash(t, presigns[1]), store, guard, testLimits())
			if err != nil {
				results <- result{err: err}
				return
			}
			raw, err := out[0].MarshalBinary()
			results <- result{raw: raw, err: err}
		})
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
	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2))
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
		wg.Go(func() {
			guard := testCGGMP21Guard(shares[1].PartyID(), mustKeyShareParties(t, shares[1]), candidate.session)
			_, _, err := startSignDigestBound(context.Background(), shares[1], presigns[1], candidate.session, candidate.digest[:], mustPresignContextHash(t, presigns[1]), store, guard, testLimits())
			errs <- err
		})
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
