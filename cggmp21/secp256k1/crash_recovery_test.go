//go:build integration

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// TestCGGMP21_KeyShare_PostCrashIntegrity verifies that a CGGMP21
// KeyShare survives marshal/unmarshal (simulating a process restart)
// and remains usable for presigning and signing.
func TestCGGMP21_KeyShare_PostCrashIntegrity(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3, false)

	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	if string(restored.PublicKey) != string(shares[1].PublicKey) {
		t.Error("PublicKey mismatch after round-trip")
	}
	if restored.Party != shares[1].Party {
		t.Error("Party mismatch after round-trip")
	}
	if restored.Threshold != shares[1].Threshold {
		t.Error("Threshold mismatch after round-trip")
	}
	if !tss.PartySet(restored.Parties).Contains(restored.Party) {
		t.Error("restored Party not in restored Parties")
	}
	if string(restored.KeygenTranscriptHash) != string(shares[1].KeygenTranscriptHash) {
		t.Error("KeygenTranscriptHash mismatch after round-trip")
	}
	if string(restored.PaillierPublicKey) != string(shares[1].PaillierPublicKey) {
		t.Error("PaillierPublicKey mismatch after round-trip")
	}

	if err := restored.Validate(); err != nil {
		t.Fatalf("Validate failed on restored share: %v", err)
	}

	// Verify signing works with the restored share.
	sid, _ := tss.NewSessionID(nil)
	digest := sha256.Sum256([]byte("crash recovery test"))
	presigns := secpPresign(t, map[tss.PartyID]*KeyShare{1: restored, 2: shares[2], 3: shares[3]},
		[]tss.PartyID{1, 2, 3})
	_, outbox, err := StartSignDigest(shares[1], presigns[1], sid, digest[:])
	if err != nil {
		t.Fatalf("StartSignDigest with restored share failed: %v", err)
	}
	if len(outbox) == 0 {
		t.Fatal("expected partial signature output from StartSignDigest")
	}
}

// TestCGGMP21_Presign_PostCrashRecovery verifies that a fresh Presign
// survives marshal/unmarshal and starts signing successfully.
func TestCGGMP21_Presign_PostCrashRecovery(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2, 3})

	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}

	if IsPresignConsumed(restored) {
		t.Fatal("restored presign is already consumed")
	}

	sid, _ := tss.NewSessionID(nil)
	digest := sha256.Sum256([]byte("fresh presign recovery"))
	guard := testCGGMP21Guard(shares[1].Party, tss.PartySet(shares[1].Parties), sid)
	if _, _, err := startSignDigestBound(shares[1], restored, sid, digest[:], restored.ContextHash, true, nil, guard); err == nil {
		t.Fatal("startSignDigestBound without PresignStore succeeded")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
	sid, _ = tss.NewSessionID(nil)
	_, outbox, err := StartSignDigestWithStore(shares[1], restored, sid, digest[:], newTestPresignStore())
	if err != nil {
		t.Fatalf("StartSignDigest with restored presign failed: %v", err)
	}
	if len(outbox) == 0 {
		t.Fatal("expected partial signature from restored presign")
	}
}

// TestCGGMP21_Presign_ConsumedPostCrash verifies that a consumed
// Presign remains consumed after marshal/unmarshal.
func TestCGGMP21_Presign_ConsumedPostCrash(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2, 3})

	sid, _ := tss.NewSessionID(nil)
	digest := sha256.Sum256([]byte("consume presign"))
	_, _, err := StartSignDigest(shares[1], presigns[1], sid, digest[:])
	if err != nil {
		t.Fatalf("StartSignDigest failed: %v", err)
	}

	if !IsPresignConsumed(presigns[1]) {
		t.Fatal("presign not marked consumed after StartSignDigest")
	}

	raw, err := presigns[1].MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary on consumed presign failed: %v", err)
	}

	restored, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPresignConsumed(restored) {
		t.Fatal("consumed flag not preserved through marshal/unmarshal")
	}

	sid2, _ := tss.NewSessionID(nil)
	digest2 := sha256.Sum256([]byte("attempt reuse"))
	_, _, err = StartSignDigest(shares[1], restored, sid2, digest2[:])
	if err == nil {
		t.Fatal("StartSignDigest succeeded with consumed presign")
	}
}

// TestCGGMP21_Presign_DestroyMarshal verifies that Destroy()
// renders the Presign unencodable.
func TestCGGMP21_Presign_DestroyMarshal(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3, false)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2, 3})

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

	shares := CachedKeygenShares(t, 2, 3, false)

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

	restored, err := UnmarshalKeyShare(raw1)
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
