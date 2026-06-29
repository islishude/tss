// Package secp256k1test provides conformance tests for public CGGMP21
// secp256k1 integration interfaces.
package secp256k1test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/cggmp21/secp256k1"
)

// SignAttemptStoreFactory creates a fresh store and canonical records for one
// conformance subtest. The returned records must share the same presign content
// ID. SameIntentDifferentAttempt must keep Candidate.IntentHash but change
// Candidate.AttemptHash. DifferentIntent must change Candidate.IntentHash.
type SignAttemptStoreFactory func(testing.TB) SignAttemptStoreFixture

// SignAttemptStoreFixture supplies one fresh store and record set to the
// conformance suite.
type SignAttemptStoreFixture struct {
	Store                      secp256k1.SignAttemptStore
	Candidate                  secp256k1.SignAttemptRecord
	SameIntentDifferentAttempt secp256k1.SignAttemptRecord
	DifferentIntent            secp256k1.SignAttemptRecord
}

// RunSignAttemptStoreSuite verifies the durable semantics required by
// secp256k1.SignAttemptStore. It does not verify backend-specific encryption,
// key derivation, crash injection, or KMS behavior; implementations should add
// backend tests for those properties.
func RunSignAttemptStoreSuite(t testing.TB, factory SignAttemptStoreFactory) {
	t.Helper()

	run := func(name string, fn func(testing.TB, SignAttemptStoreFixture)) {
		t.Helper()
		if runner, ok := t.(interface {
			Run(string, func(*testing.T)) bool
		}); ok {
			runner.Run(name, func(st *testing.T) {
				st.Helper()
				fixture := newSignAttemptStoreFixture(st, factory)
				fn(st, fixture)
			})
			return
		}
		fixture := newSignAttemptStoreFixture(t, factory)
		fn(t, fixture)
	}

	run("same candidate commit is idempotent", checkSignAttemptCommitIdempotent)
	run("same intent but different attempt conflicts as non-determinism", checkSignAttemptNonDeterminism)
	run("different intent conflicts", checkSignAttemptConflict)
	run("burn before commit blocks commit", checkSignAttemptBurnBeforeCommit)
	run("burn after commit preserves resume", checkSignAttemptBurnAfterCommit)
	run("completion is idempotent", checkSignAttemptCompletionIdempotent)
	run("different completion result conflicts", checkSignAttemptCompletionConflict)
	run("delivery ack is idempotent", checkSignAttemptDeliveryAckIdempotent)
	run("delivery certificate marks delivery complete", checkSignAttemptDeliveryCertificate)
	run("load merges base delivery and completion", checkSignAttemptLoadMergesState)
}

func newSignAttemptStoreFixture(t testing.TB, factory SignAttemptStoreFactory) SignAttemptStoreFixture {
	t.Helper()
	if factory == nil {
		t.Fatal("nil SignAttemptStoreFactory")
	}
	fixture := factory(t)
	if fixture.Store == nil {
		t.Fatal("nil SignAttemptStore")
	}
	if err := fixture.Candidate.Validate(); err != nil {
		t.Fatalf("invalid Candidate: %v", err)
	}
	if err := fixture.SameIntentDifferentAttempt.Validate(); err != nil {
		t.Fatalf("invalid SameIntentDifferentAttempt: %v", err)
	}
	if err := fixture.DifferentIntent.Validate(); err != nil {
		t.Fatalf("invalid DifferentIntent: %v", err)
	}
	if !bytes.Equal(fixture.Candidate.PresignContentID, fixture.SameIntentDifferentAttempt.PresignContentID) ||
		!bytes.Equal(fixture.Candidate.PresignContentID, fixture.DifferentIntent.PresignContentID) {
		t.Fatal("fixture records must share one presign content ID")
	}
	if !bytes.Equal(fixture.Candidate.IntentHash, fixture.SameIntentDifferentAttempt.IntentHash) {
		t.Fatal("SameIntentDifferentAttempt must preserve Candidate.IntentHash")
	}
	if bytes.Equal(fixture.Candidate.AttemptHash, fixture.SameIntentDifferentAttempt.AttemptHash) {
		t.Fatal("SameIntentDifferentAttempt must change Candidate.AttemptHash")
	}
	if bytes.Equal(fixture.Candidate.IntentHash, fixture.DifferentIntent.IntentHash) {
		t.Fatal("DifferentIntent must change Candidate.IntentHash")
	}
	return fixture
}

func checkSignAttemptCommitIdempotent(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	first, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate)
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if first.Status != secp256k1.SignAttemptCreated {
		t.Fatalf("first status = %d, want SignAttemptCreated", first.Status)
	}
	second, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if second.Status != secp256k1.SignAttemptExistingSame {
		t.Fatalf("second status = %d, want SignAttemptExistingSame", second.Status)
	}
	if !first.Record.SameBaseAttempt(second.Record) {
		t.Fatal("idempotent commit changed the immutable base attempt")
	}
}

func checkSignAttemptNonDeterminism(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.SameIntentDifferentAttempt); !errors.Is(err, secp256k1.ErrSignAttemptNonDeterminism) {
		t.Fatalf("same intent different attempt error = %v, want ErrSignAttemptNonDeterminism", err)
	}
}

func checkSignAttemptConflict(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.DifferentIntent); !errors.Is(err, secp256k1.ErrSignAttemptConflict) {
		t.Fatalf("different intent error = %v, want ErrSignAttemptConflict", err)
	}
}

func checkSignAttemptBurnBeforeCommit(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if err := fixture.Store.BurnPresign(ctx, secp256k1.SignAttemptBurn{
		PresignContentID: bytes.Clone(fixture.Candidate.PresignContentID),
		Reason:           "conformance burn before commit",
	}); err != nil {
		t.Fatalf("burn before commit: %v", err)
	}
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); !errors.Is(err, secp256k1.ErrSignAttemptBurned) {
		t.Fatalf("commit after burn error = %v, want ErrSignAttemptBurned", err)
	}
	if _, err := fixture.Store.LoadSignAttempt(ctx, fixture.Candidate.PresignContentID); !errors.Is(err, secp256k1.ErrSignAttemptBurned) {
		t.Fatalf("load after burn error = %v, want ErrSignAttemptBurned", err)
	}
}

func checkSignAttemptBurnAfterCommit(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	if err := fixture.Store.BurnPresign(ctx, secp256k1.SignAttemptBurn{
		PresignContentID: bytes.Clone(fixture.Candidate.PresignContentID),
		Reason:           "conformance burn after commit",
	}); !errors.Is(err, secp256k1.ErrSignAttemptConflict) {
		t.Fatalf("burn after commit error = %v, want ErrSignAttemptConflict", err)
	}
	loaded, err := fixture.Store.LoadSignAttempt(ctx, fixture.Candidate.PresignContentID)
	if err != nil {
		t.Fatalf("load after burn-after-commit: %v", err)
	}
	if !fixture.Candidate.SameBaseAttempt(loaded) {
		t.Fatal("burn after commit changed the resumable attempt")
	}
}

func checkSignAttemptCompletionIdempotent(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	result := signAttemptResult(fixture.Candidate, 2)
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	first, err := fixture.Store.CompleteSignAttempt(ctx, result)
	if err != nil {
		t.Fatalf("first completion: %v", err)
	}
	second, err := fixture.Store.CompleteSignAttempt(ctx, result)
	if err != nil {
		t.Fatalf("second completion: %v", err)
	}
	if !first.Equal(second) || !second.Completed {
		t.Fatal("idempotent completion changed the durable result")
	}
}

func checkSignAttemptCompletionConflict(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	if _, err := fixture.Store.CompleteSignAttempt(ctx, signAttemptResult(fixture.Candidate, 2)); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	if _, err := fixture.Store.CompleteSignAttempt(ctx, signAttemptResult(fixture.Candidate, 3)); !errors.Is(err, secp256k1.ErrSignAttemptConflict) {
		t.Fatalf("different completion error = %v, want ErrSignAttemptConflict", err)
	}
}

func checkSignAttemptDeliveryAckIdempotent(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	env := signAttemptEnvelope(t, fixture.Candidate)
	ack := signAttemptAck(env, fixture.Candidate.DeliveryPolicy.Recipients[0])
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	first, err := fixture.Store.UpdateSignAttemptDelivery(ctx, secp256k1.SignAttemptDeliveryUpdate{
		PresignContentID: bytes.Clone(fixture.Candidate.PresignContentID),
		AttemptHash:      bytes.Clone(fixture.Candidate.AttemptHash),
		Ack:              &ack,
	})
	if err != nil {
		t.Fatalf("first ack: %v", err)
	}
	second, err := fixture.Store.UpdateSignAttemptDelivery(ctx, secp256k1.SignAttemptDeliveryUpdate{
		PresignContentID: bytes.Clone(fixture.Candidate.PresignContentID),
		AttemptHash:      bytes.Clone(fixture.Candidate.AttemptHash),
		Ack:              &ack,
	})
	if err != nil {
		t.Fatalf("second ack: %v", err)
	}
	if len(first.DeliveryState.Acks) != 1 || len(second.DeliveryState.Acks) != 1 {
		t.Fatal("duplicate delivery ack was not idempotent")
	}
}

func checkSignAttemptDeliveryCertificate(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	cert := signAttemptCertificate(t, fixture.Candidate)
	updated, err := fixture.Store.UpdateSignAttemptDelivery(ctx, secp256k1.SignAttemptDeliveryUpdate{
		PresignContentID: bytes.Clone(fixture.Candidate.PresignContentID),
		AttemptHash:      bytes.Clone(fixture.Candidate.AttemptHash),
		Certificate:      cert,
	})
	if err != nil {
		t.Fatalf("certificate update: %v", err)
	}
	if !updated.DeliveryState.DeliveryComplete || updated.DeliveryState.Certificate == nil {
		t.Fatal("certificate update did not mark delivery complete")
	}
	if len(updated.DeliveryState.Acks) != len(fixture.Candidate.DeliveryPolicy.Recipients) {
		t.Fatal("certificate update did not journal all recipient acknowledgments")
	}
}

func checkSignAttemptLoadMergesState(t testing.TB, fixture SignAttemptStoreFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.Store.CommitSignAttempt(ctx, fixture.Candidate); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}
	cert := signAttemptCertificate(t, fixture.Candidate)
	if _, err := fixture.Store.UpdateSignAttemptDelivery(ctx, secp256k1.SignAttemptDeliveryUpdate{
		PresignContentID: bytes.Clone(fixture.Candidate.PresignContentID),
		AttemptHash:      bytes.Clone(fixture.Candidate.AttemptHash),
		Certificate:      cert,
	}); err != nil {
		t.Fatalf("certificate update: %v", err)
	}
	result := signAttemptResult(fixture.Candidate, 2)
	if _, err := fixture.Store.CompleteSignAttempt(ctx, result); err != nil {
		t.Fatalf("completion: %v", err)
	}
	loaded, err := fixture.Store.LoadSignAttempt(ctx, fixture.Candidate.PresignContentID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !fixture.Candidate.SameBaseAttempt(loaded) {
		t.Fatal("loaded record changed immutable base attempt")
	}
	if !loaded.DeliveryState.DeliveryComplete || !loaded.Completed {
		t.Fatal("loaded record did not merge delivery and completion state")
	}
	if !bytes.Equal(loaded.SignatureS, result.Signature.S) {
		t.Fatal("loaded record lost completion signature")
	}
}

func signAttemptEnvelope(t testing.TB, record secp256k1.SignAttemptRecord) tss.Envelope {
	t.Helper()
	var env tss.Envelope
	if err := env.UnmarshalBinary(record.CanonicalBaseEnvelopeBytes); err != nil {
		t.Fatalf("decode candidate envelope: %v", err)
	}
	return env
}

func signAttemptAck(env tss.Envelope, party tss.PartyID) tss.BroadcastAck {
	return tss.BroadcastAck{
		Party:          party,
		Signature:      []byte{byte(party)},
		PayloadHash:    tss.PayloadHashFromEnvelope(env),
		EnvelopeDigest: env.Digest(),
	}
}

func signAttemptCertificate(t testing.TB, record secp256k1.SignAttemptRecord) *tss.BroadcastCertificate {
	t.Helper()
	env := signAttemptEnvelope(t, record)
	acks := make([]tss.BroadcastAck, 0, len(record.DeliveryPolicy.Recipients))
	for _, party := range record.DeliveryPolicy.Recipients {
		acks = append(acks, signAttemptAck(env, party))
	}
	cert, err := tss.NewBroadcastCertificate(env, record.DeliveryPolicy.Recipients, acks)
	if err != nil {
		t.Fatalf("new broadcast certificate: %v", err)
	}
	return cert
}

func signAttemptResult(record secp256k1.SignAttemptRecord, s byte) secp256k1.SignAttemptResult {
	return secp256k1.SignAttemptResult{
		PresignContentID: bytes.Clone(record.PresignContentID),
		AttemptHash:      bytes.Clone(record.AttemptHash),
		Signature: secp256k1.Signature{
			R:          bytes.Repeat([]byte{1}, 32),
			S:          bytes.Repeat([]byte{s}, 32),
			RecoveryID: 1,
		},
	}
}
