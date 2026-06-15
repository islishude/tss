//go:build tier1

package paillier

import (
	"testing"
)

// TestCheckPaillierModulus verifies the minimum bit-length check on Paillier
// moduli.
func TestCheckPaillierModulus(t *testing.T) {
	t.Parallel()

	sp := DefaultSecurityParams()

	// Test with a key that meets the minimum (requires keygen)
	sk1024 := testPaillierKey(t, 1024)
	err := sp.CheckPaillierModulus(&sk1024.PublicKey)
	if err == nil {
		t.Error("DefaultSecurityParams should reject 1024-bit modulus (MinPaillierBits=3072)")
	}

	// Explicit reduced parameters should accept 1024-bit.
	fast := fastSecurityParams()
	if err := fast.CheckPaillierModulus(&sk1024.PublicKey); err != nil {
		t.Errorf("test security params rejected 1024-bit modulus: %v", err)
	}
}

// TestEncProofTranscriptBindsSecurityParams verifies that EncProof
// verification fails when SecurityParams differ from those used during
// proof creation. The transcript must bind Ell, EllPrime, Epsilon, and
// ChallengeBits so a malicious prover cannot downgrade parameters.
func TestEncProofTranscriptBindsSecurityParams(t *testing.T) {
	t.Parallel()

	p1, stmt, _, proof := encProofFixture(t)
	encState := []byte("enc matrix")
	if err := VerifyEnc(p1, encState, stmt, proof); err != nil {
		t.Fatal(err)
	}

	// Different epsilon: the transcript includes Epsilon, so the challenge
	// will differ, causing verification to fail.
	p3 := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon + 1, ChallengeBits: p1.ChallengeBits, MinPaillierBits: p1.MinPaillierBits}
	if err := VerifyEnc(p3, encState, stmt, proof); err == nil {
		t.Fatal("EncProof verified with wrong Epsilon (transcript should bind it)")
	}

	p4 := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon, ChallengeBits: p1.ChallengeBits + 1, MinPaillierBits: p1.MinPaillierBits}
	if err := VerifyEnc(p4, encState, stmt, proof); err == nil {
		t.Fatal("EncProof verified with wrong ChallengeBits (transcript should bind it)")
	}
}

// TestAffGProofTranscriptBindsSecurityParams verifies that AffGProof
// verification fails when SecurityParams differ, confirming that the
// transcript binds all security parameters.
func TestAffGProofTranscriptBindsSecurityParams(t *testing.T) {
	t.Parallel()

	p1, stmt, _, proof := affGProofFixture(t)
	affgState := []byte("affg matrix")
	if err := VerifyAffG(p1, affgState, stmt, proof); err != nil {
		t.Fatal(err)
	}
	pDiff := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon + 1, ChallengeBits: p1.ChallengeBits, MinPaillierBits: p1.MinPaillierBits}
	if err := VerifyAffG(pDiff, affgState, stmt, proof); err == nil {
		t.Fatal("AffGProof verified with wrong Epsilon (transcript should bind it)")
	}
}

// TestLogStarProofTranscriptBindsSecurityParams verifies that LogStarProof
// verification fails when SecurityParams differ, confirming that the
// transcript binds all security parameters.
func TestLogStarProofTranscriptBindsSecurityParams(t *testing.T) {
	t.Parallel()

	p1, stmt, _, proof := logStarProofFixture(t)
	logState := []byte("logstar matrix")
	if err := VerifyLogStar(p1, logState, stmt, proof); err != nil {
		t.Fatal(err)
	}
	pDiff := SecurityParams{Ell: p1.Ell, EllPrime: p1.EllPrime, Epsilon: p1.Epsilon + 1, ChallengeBits: p1.ChallengeBits, MinPaillierBits: p1.MinPaillierBits}
	if err := VerifyLogStar(pDiff, logState, stmt, proof); err == nil {
		t.Fatal("LogStarProof verified with wrong Epsilon (transcript should bind it)")
	}
}
