package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// TestEncryptionProofLeakageResistance verifies that an EncryptionProof does
// not leak its witness through the Fiat-Shamir response z = e·m + α. Given
// the public values (z, e, ScalarCommitment), the number of candidate m values
// that satisfy both the range constraint and the curve equation must be
// computationally infeasible to enumerate.
func TestEncryptionProofLeakageResistance(t *testing.T) {
	t.Parallel()
	skipProofLeakageInShort(t)
	sk := testPaillierKey(t, 1024)
	domain := []byte("leakage test enc")
	scalar := big.NewInt(123456789)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveEncryption(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncryption(domain, &sk.PublicKey, ciphertext, proof) {
		t.Fatal("encryption proof did not verify")
	}

	z := new(big.Int).SetBytes(proof.Response)
	e := challenge([]byte(encryptionChallengeLabel),
		encryptionTranscript(domain, &sk.PublicKey, ciphertext,
			proof.ScalarCommitment, proof.Bound,
			new(big.Int).SetBytes(proof.CipherCommitment),
			proof.PointCommitment))

	// Given z = e·m + α with α ∈ [0, 2^{l+ε}), we have:
	//   α = z - e·m ∈ [0, 2^{l+ε})
	//   → m ∈ ((z - 2^{l+ε})/e, z/e]
	//
	// The candidate interval width is approximately 2^{l+ε}/e.
	// With l=256, ε=128, and e ∈ [0, 2^l): interval ≈ 2^384 / 2^256 = 2^128.
	maxMask := twoToThe(maskBits)
	lower := new(big.Int).Sub(z, maxMask)
	if lower.Sign() < 0 {
		lower.SetInt64(0)
	}
	lower.Div(lower, e)

	upper := new(big.Int).Div(z, e)

	candidateRange := new(big.Int).Sub(upper, lower)
	minRange := twoToThe(80) // 2^80 is infeasible to brute-force
	if candidateRange.Cmp(minRange) < 0 {
		t.Fatalf("candidate interval too small: %s (need ≥ 2^80)", candidateRange)
	}
	t.Logf("enc proof: candidate interval size ≈ 2^%d bits", candidateRange.BitLen())

	// Verify that brute-forcing the lower portion of the interval fails
	// (confirming the curve commitment uniquely identifies the witness and
	// would require ~2^128 checks).
	scalarCommitment, _ := secp.PointFromBytes(proof.ScalarCommitment)
	checked := 0
	bruteLimit := 20000
	for m := new(big.Int).Set(lower); m.Cmp(upper) <= 0 && checked < bruteLimit; m.Add(m, big.NewInt(1)) {
		pt := secp.ScalarBaseMult(secp.ScalarFromBigInt(m))
		if secp.Equal(pt, scalarCommitment) {
			t.Fatalf("witness recovered with only %d checks (statistical hiding broken)", checked+1)
		}
		checked++
	}
	t.Logf("brute-force check: %d candidates tested, witness not found (expected)", checked)
}

// TestMTAResponseProofLeakageResistance verifies that the MtA response proof
// does not leak the responder scalar b through BResponse = e·b + μ.
func TestMTAResponseProofLeakageResistance(t *testing.T) {
	t.Parallel()
	skipProofLeakageInShort(t)
	sk := testPaillierKey(t, 1024)
	domain := []byte("leakage test mta")
	a := big.NewInt(42)
	b := big.NewInt(17)
	beta := big.NewInt(19)
	encA, _, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, betaRandomness := mtaResponseForTest(t, sk, encA, b, beta)
	proof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, proof) {
		t.Fatal("MtA response proof did not verify")
	}

	zB := new(big.Int).SetBytes(proof.BResponse)
	e := challenge([]byte(mtaChallengeLabel),
		mtaTranscript(domain, &sk.PublicKey, encA, response,
			bCommitment, proof.BetaCommitment,
			new(big.Int).SetBytes(proof.CipherCommitment),
			proof.BCommitment, proof.BetaNonce))

	// Same analysis as EncryptionProof: candidate b interval ≈ 2^{l+ε} / e.
	maxMask := twoToThe(maskBits)
	lower := new(big.Int).Sub(zB, maxMask)
	if lower.Sign() < 0 {
		lower.SetInt64(0)
	}
	lower.Div(lower, e)

	upper := new(big.Int).Div(zB, e)

	candidateRange := new(big.Int).Sub(upper, lower)
	minRange := twoToThe(80)
	if candidateRange.Cmp(minRange) < 0 {
		t.Fatalf("MtA b candidate interval too small: %s (need ≥ 2^80)", candidateRange)
	}
	t.Logf("mta b: candidate interval size ≈ 2^%d bits", candidateRange.BitLen())

	// Also check zBeta response for beta leakage.
	zBeta := new(big.Int).SetBytes(proof.BetaResponse)
	lowerBeta := new(big.Int).Sub(zBeta, maxMask)
	if lowerBeta.Sign() < 0 {
		lowerBeta.SetInt64(0)
	}
	lowerBeta.Div(lowerBeta, e)
	upperBeta := new(big.Int).Div(zBeta, e)
	betaRange := new(big.Int).Sub(upperBeta, lowerBeta)
	if betaRange.Cmp(minRange) < 0 {
		t.Fatalf("MtA beta candidate interval too small: %s (need ≥ 2^80)", betaRange)
	}
	t.Logf("mta beta: candidate interval size ≈ 2^%d bits", betaRange.BitLen())
}

// TestLogProofLeakageResistance verifies that the Π^log proof does not leak
// the discrete logarithm through Response = e·a + α.
func TestLogProofLeakageResistance(t *testing.T) {
	t.Parallel()
	skipProofLeakageInShort(t)
	sk := testPaillierKey(t, 1024)
	domain := []byte("leakage test log")
	scalar := big.NewInt(99)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	pointBytes, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveLog(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness, pointBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyLog(domain, &sk.PublicKey, ciphertext, proof) {
		t.Fatal("log proof did not verify")
	}

	z := new(big.Int).SetBytes(proof.Response)
	e := challenge([]byte(logChallengeLabel),
		logTranscript(domain, &sk.PublicKey, ciphertext,
			proof.Point,
			new(big.Int).SetBytes(proof.CipherCommitment),
			proof.PointCommitment))

	maxMask := twoToThe(maskBits)
	lower := new(big.Int).Sub(z, maxMask)
	if lower.Sign() < 0 {
		lower.SetInt64(0)
	}
	lower.Div(lower, e)

	upper := new(big.Int).Div(z, e)

	candidateRange := new(big.Int).Sub(upper, lower)
	minRange := twoToThe(80)
	if candidateRange.Cmp(minRange) < 0 {
		t.Fatalf("log proof candidate interval too small: %s (need ≥ 2^80)", candidateRange)
	}
	t.Logf("log proof: candidate interval size ≈ 2^%d bits", candidateRange.BitLen())
}

// TestProofsUseV1Version moved to new_proofs_test.go.
// TestChallengeLabelsV1 moved to unit_test.go.

func skipProofLeakageInShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping 1024-bit Paillier proof leakage test in short mode")
	}
}
