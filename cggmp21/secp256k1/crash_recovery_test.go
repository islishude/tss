//go:build integration

package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/tssrun"
)

// TestCGGMP21_KeyShare_PostCrashIntegrity verifies that a CGGMP21
// KeyShare survives marshal/unmarshal (simulating a process restart)
// and remains usable for presigning and signing.
func TestCGGMP21_KeyShare_PostCrashIntegrity(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)

	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := tss.DecodeBinary[KeyShare](raw)
	if err != nil {
		t.Fatal(err)
	}

	restoredMeta := mustKeyShareMetadata(t, restored)
	shareMeta := mustKeyShareMetadata(t, shares[1])
	if string(restoredMeta.PublicKey) != string(shareMeta.PublicKey) {
		t.Error("PublicKey mismatch after round-trip")
	}
	if restored.PartyID() != shares[1].PartyID() {
		t.Error("Party mismatch after round-trip")
	}
	if restored.Threshold() != shares[1].Threshold() {
		t.Error("Threshold mismatch after round-trip")
	}
	if !restoredMeta.Parties.Contains(restored.PartyID()) {
		t.Error("restored Party not in restored Parties")
	}
	if string(restoredMeta.KeygenTranscriptHash) != string(shareMeta.KeygenTranscriptHash) {
		t.Error("KeygenTranscriptHash mismatch after round-trip")
	}
	restoredPaillier, ok := restored.PaillierPublicShare(restored.PartyID())
	if !ok {
		t.Fatal("missing restored Paillier public share")
	}
	sharePaillier, ok := shares[1].PaillierPublicShare(shares[1].PartyID())
	if !ok {
		t.Fatal("missing original Paillier public share")
	}
	if string(restoredPaillier.PublicKey) != string(sharePaillier.PublicKey) {
		t.Error("PaillierPublicKey mismatch after round-trip")
	}

	if err := restored.ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("Validate failed on restored share: %v", err)
	}

	// Verify signing works with the restored share.
	sid, _ := tss.NewSessionID(nil)
	digest := sha256.Sum256([]byte("crash recovery test"))
	presigns := secpPresign(t, map[tss.PartyID]*KeyShare{1: restored, 2: shares[2], 3: shares[3]},
		tss.NewPartySet(1, 2, 3))
	_, outbox, err := StartSignDigest(shares[1], presigns[1], sid, digest[:])
	if err != nil {
		t.Fatalf("StartSignDigest with restored share failed: %v", err)
	}
	if len(outbox) == 0 {
		t.Fatal("expected partial signature output from StartSignDigest")
	}
}

// TestCGGMP21_Presign_PostCrashRecovery verifies that persisting an available
// Presign is side-effect free and that a first signing attempt can claim the
// restored record after a process restart.
func TestCGGMP21_Presign_PostCrashRecovery(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2, 3))

	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)

	restored, err := tss.DecodeBinary[Presign](raw)
	if err != nil {
		t.Fatal(err)
	}
	restoredRaw, err := restored.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(restoredRaw)
	if !bytes.Equal(raw, restoredRaw) {
		t.Fatal("available presign artifact changed across restart")
	}

	sid, _ := tss.NewSessionID(nil)
	digest := sha256.Sum256([]byte("fresh presign recovery"))
	store := newTestLifecycleStore()
	session, out, err := StartSignDigestWithStore(shares[1], restored, sid, digest[:], store)
	if err != nil {
		t.Fatalf("first post-restart sign attempt failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatal("first post-restart sign attempt did not expose its committed outbox")
	}
	query := session.attempt.Query()
	if _, err := store.QueryAttemptOutcome(context.Background(), query); err != nil {
		t.Fatalf("committed post-restart attempt is unavailable: %v", err)
	}
	if _, err := store.PreparePresignCandidate(context.Background(), query.Binding, query.PresignID); !errors.Is(err, tssrun.ErrPresignUnavailable) {
		t.Fatalf("claimed presign remained available after commit: %v", err)
	}
}

// TestCGGMP21_Presign_ClaimedPostCrash verifies that durable attempt state,
// rather than a caller-owned Presign encoding, remains authoritative after a
// signing process restart.
func TestCGGMP21_Presign_ClaimedPostCrash(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2, 3))

	sid, _ := tss.NewSessionID(nil)
	digest := sha256.Sum256([]byte("consume presign"))
	store := newTestLifecycleStore()
	session, _, err := StartSignDigestWithStore(shares[1], presigns[1], sid, digest[:], store)
	if err != nil {
		t.Fatalf("StartSignDigest failed: %v", err)
	}
	query := session.attempt.Query()
	if _, err := store.PreparePresignCandidate(context.Background(), query.Binding, query.PresignID); !errors.Is(err, tssrun.ErrPresignUnavailable) {
		t.Fatalf("claimed presign remained available after sign commit: %v", err)
	}
	if _, _, err := ResumeSign(context.Background(), store, query, session.Guard()); err != nil {
		t.Fatalf("durable attempt did not resume after process restart: %v", err)
	}
}

// TestCGGMP21_Presign_DestroyMarshal verifies that Destroy()
// renders the Presign unencodable.
func TestCGGMP21_Presign_DestroyMarshal(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	presigns := secpPresign(t, shares, tss.NewPartySet(1, 2, 3))

	_, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	presigns[1].Destroy()

	_, err = presigns[1].MarshalBinary()
	if err == nil {
		t.Fatal("MarshalBinary succeeded on destroyed presign")
	}
}

// TestCGGMP21_KeyShare_DeterministicMarshal verifies that marshaling
// the same KeyShare twice produces identical bytes.
func TestCGGMP21_KeyShare_DeterministicMarshal(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)

	raw1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw1, raw2) {
		t.Fatal("MarshalBinary is not deterministic")
	}

	restored, err := tss.DecodeBinary[KeyShare](raw1)
	if err != nil {
		t.Fatal(err)
	}
	rawAgain, err := restored.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, rawAgain) {
		t.Error("marshal/unmarshal/marshal round-trip changed encoding")
	}
}
