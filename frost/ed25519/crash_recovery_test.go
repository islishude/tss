//go:build integration

package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/islishude/tss"
)

// TestFROSTKeyShareCrashRecovery verifies that a FROST KeyShare
// survives marshal/unmarshal (simulating a process restart where
// the share was persisted to disk) and remains usable for signing.
func TestFROSTKeyShareCrashRecovery(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)

	// Marshal party 1's key share as if persisting before a crash.
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal as if reloading after restart.
	restored, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Verify structural integrity of the restored share.
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

	// Verify the restored share is internally consistent.
	if err := restored.ValidateConsistency(); err != nil {
		t.Fatalf("ValidateConsistency failed on restored share: %v", err)
	}

	// Verify signing still works with the restored share.
	pub, sig, err := Sign([]byte("crash recovery test"), []*KeyShare{restored, shares[2]})
	if err != nil {
		t.Fatalf("Sign with restored share failed: %v", err)
	}
	if !stded25519.Verify(stded25519.PublicKey(pub), []byte("crash recovery test"), sig) {
		t.Fatal("restored share produced invalid signature")
	}
}

// TestFROSTKeyShareDestroyPersistence verifies that after Destroy(),
// the key share can no longer be used for signing.
func TestFROSTKeyShareDestroyPersistence(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 2)
	share := shares[1].Clone()

	// Before destroy, signing works.
	pub, sig, err := Sign([]byte("pre-destroy"), []*KeyShare{share, shares[2]})
	if err != nil {
		t.Fatal(err)
	}
	if !stded25519.Verify(stded25519.PublicKey(pub), []byte("pre-destroy"), sig) {
		t.Fatal("pre-destroy signature invalid")
	}

	// Destroy the share.
	share.Destroy()

	// After destroy, Sign should fail.
	_, _, err = Sign([]byte("post-destroy"), []*KeyShare{share, shares[2]})
	if err == nil {
		t.Fatal("expected Sign to fail with destroyed share")
	}
}

// TestFROSTKeyShareDeterministicMarshal verifies that marshaling
// the same share twice produces identical bytes.
func TestFROSTKeyShareDeterministicMarshal(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)

	raw1, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw1, raw2) {
		t.Fatal("MarshalBinary is not deterministic across repeated calls")
	}

	// Verify unmarshal consistency.
	restored1, err := UnmarshalKeyShare(raw1)
	if err != nil {
		t.Fatal(err)
	}
	restored2, err := UnmarshalKeyShare(raw2)
	if err != nil {
		t.Fatal(err)
	}
	raw1b, _ := restored1.MarshalBinary()
	raw2b, _ := restored2.MarshalBinary()
	if !bytes.Equal(raw1, raw1b) {
		t.Error("round-trip produced different encoding")
	}
	if !bytes.Equal(raw2, raw2b) {
		t.Error("round-trip produced different encoding (second call)")
	}
}
