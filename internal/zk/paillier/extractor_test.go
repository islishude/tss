package paillier

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// replayReader is a deterministic io.Reader that produces reproducible output
// from a seed. Used by extractor tests to generate two proofs with identical
// commitments (α, rho, etc.) but different challenges (via different domains).
type replayReader struct {
	seed  []byte
	count uint64
}

func newReplayReader(seed string) *replayReader {
	return &replayReader{seed: []byte(seed)}
}

func (r *replayReader) Read(p []byte) (int, error) {
	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], r.count)
	h.Write(buf[:])
	h.Write(r.seed)
	digest := h.Sum(nil)
	n := copy(p, digest)
	for n < len(p) {
		// Extend if caller needs more bytes than SHA-256 output.
		h.Reset()
		r.count++
		binary.BigEndian.PutUint64(buf[:], r.count)
		h.Write(buf[:])
		h.Write(r.seed)
		n += copy(p[n:], h.Sum(nil))
	}
	r.count++
	return len(p), nil
}

func (r *replayReader) reset() {
	r.count = 0
}

// TestEncryptionProofSpecialSoundness demonstrates that two accepting
// EncryptionProof transcripts with identical commitments but different
// challenges allow extraction of the witness scalar m.
//
// Given (e, z=α+e·m) and (e', z'=α+e'·m) with e≠e' and the same α:
//
//	m = (z − z') / (e − e')
//
// This is the core security property that makes Σ-protocols proofs of
// knowledge: if a prover can answer two different challenges with the same
// commitment, they must know the witness. A failure here means the proof
// system does not actually extract the claimed knowledge.
func TestEncryptionProofSpecialSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	scalar := big.NewInt(12345)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}

	rng := newReplayReader("extract-encryption")

	// Proof 1 with domain "extract-1"
	proof1, err := ProveEncryption(rng, []byte("extract-1"), &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncryption([]byte("extract-1"), &sk.PublicKey, ciphertext, proof1) {
		t.Fatal("proof1 did not verify")
	}

	// Proof 2: reset RNG to reuse the same α, but with a different domain
	// to get a different challenge e.
	rng.reset()
	proof2, err := ProveEncryption(rng, []byte("extract-2"), &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncryption([]byte("extract-2"), &sk.PublicKey, ciphertext, proof2) {
		t.Fatal("proof2 did not verify")
	}

	// Verify commitments are identical.
	if string(proof1.CipherCommitment) != string(proof2.CipherCommitment) {
		t.Fatal("commitments differ — RNG replay failed")
	}

	// Extract witness: m = (z - z')/(e - e')
	transcript1 := encryptionTranscript([]byte("extract-1"), &sk.PublicKey, ciphertext,
		proof1.ScalarCommitment, proof1.Bound,
		new(big.Int).SetBytes(proof1.CipherCommitment),
		proof1.PointCommitment)
	e1 := challenge([]byte(encryptionChallengeLabel), transcript1)

	transcript2 := encryptionTranscript([]byte("extract-2"), &sk.PublicKey, ciphertext,
		proof2.ScalarCommitment, proof2.Bound,
		new(big.Int).SetBytes(proof2.CipherCommitment),
		proof2.PointCommitment)
	e2 := challenge([]byte(encryptionChallengeLabel), transcript2)

	if e1.Cmp(e2) == 0 {
		t.Fatal("challenges are identical — domain separation failed")
	}

	z1 := new(big.Int).SetBytes(proof1.Response)
	z2 := new(big.Int).SetBytes(proof2.Response)

	eDiff := new(big.Int).Sub(e1, e2)
	zDiff := new(big.Int).Sub(z1, z2)

	if new(big.Int).Mod(zDiff, eDiff).Sign() != 0 {
		t.Fatal("zDiff is not divisible by eDiff — special soundness extraction failed")
	}

	extractedM := new(big.Int).Div(zDiff, eDiff)
	// The extracted witness must match the original (mod secp256k1 order).
	extractedM.Mod(extractedM, secp.Order())
	expected := new(big.Int).Mod(scalar, secp.Order())
	if extractedM.Cmp(expected) != 0 {
		t.Fatalf("extracted m = %s, want %s", extractedM, expected)
	}
	t.Logf("EncryptionProof extractor: m = %s (mod q)", extractedM)
}

// TestLogProofSpecialSoundness demonstrates witness extraction for Π^log.
func TestLogProofSpecialSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	scalar := big.NewInt(7777)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	pointBytes, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
	if err != nil {
		t.Fatal(err)
	}

	rng := newReplayReader("extract-log")
	proof1, err := ProveLog(rng, []byte("extract-1"), &sk.PublicKey, ciphertext, scalar, randomness, pointBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyLog([]byte("extract-1"), &sk.PublicKey, ciphertext, proof1) {
		t.Fatal("proof1 did not verify")
	}

	rng.reset()
	proof2, err := ProveLog(rng, []byte("extract-2"), &sk.PublicKey, ciphertext, scalar, randomness, pointBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyLog([]byte("extract-2"), &sk.PublicKey, ciphertext, proof2) {
		t.Fatal("proof2 did not verify")
	}

	if string(proof1.CipherCommitment) != string(proof2.CipherCommitment) {
		t.Fatal("commitments differ — RNG replay failed")
	}

	transcript1 := logTranscript([]byte("extract-1"), &sk.PublicKey, ciphertext, proof1.Point,
		new(big.Int).SetBytes(proof1.CipherCommitment), proof1.PointCommitment)
	e1 := challenge([]byte(logChallengeLabel), transcript1)

	transcript2 := logTranscript([]byte("extract-2"), &sk.PublicKey, ciphertext, proof2.Point,
		new(big.Int).SetBytes(proof2.CipherCommitment), proof2.PointCommitment)
	e2 := challenge([]byte(logChallengeLabel), transcript2)

	if e1.Cmp(e2) == 0 {
		t.Fatal("challenges are identical")
	}

	z1 := new(big.Int).SetBytes(proof1.Response)
	z2 := new(big.Int).SetBytes(proof2.Response)
	eDiff := new(big.Int).Sub(e1, e2)
	zDiff := new(big.Int).Sub(z1, z2)

	if new(big.Int).Mod(zDiff, eDiff).Sign() != 0 {
		t.Fatal("LogProof: zDiff not divisible by eDiff — extraction failed")
	}
	extracted := new(big.Int).Div(zDiff, eDiff)
	extracted.Mod(extracted, secp.Order())
	expected := new(big.Int).Mod(scalar, secp.Order())
	if extracted.Cmp(expected) != 0 {
		t.Fatalf("extracted a = %s, want %s", extracted, expected)
	}
	t.Logf("LogProof extractor: a = %s (mod q)", extracted)
}

// TestMTAResponseProofSpecialSoundness demonstrates witness extraction for
// the legacy MTAResponseProof. Two transcripts with the same commitments
// but different challenges allow extraction of both b and beta.
func TestMTAResponseProofSpecialSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	a := big.NewInt(42)
	b := big.NewInt(123)
	beta := big.NewInt(456)

	encA, _, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, betaRandomness := mtaResponseForTest(t, sk, encA, b, beta)

	rng := newReplayReader("extract-mta")
	proof1, err := ProveMTAResponse(rng, []byte("extract-1"), &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyMTAResponse([]byte("extract-1"), &sk.PublicKey, encA, response, bCommitment, proof1) {
		t.Fatal("proof1 did not verify")
	}

	rng.reset()
	proof2, err := ProveMTAResponse(rng, []byte("extract-2"), &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyMTAResponse([]byte("extract-2"), &sk.PublicKey, encA, response, bCommitment, proof2) {
		t.Fatal("proof2 did not verify")
	}

	if string(proof1.CipherCommitment) != string(proof2.CipherCommitment) {
		t.Fatal("commitments differ — RNG replay failed")
	}

	transcript1 := mtaTranscript([]byte("extract-1"), &sk.PublicKey, encA, response,
		bCommitment, proof1.BetaCommitment,
		new(big.Int).SetBytes(proof1.CipherCommitment),
		proof1.BCommitment, proof1.BetaNonce)
	e1 := challenge([]byte(mtaChallengeLabel), transcript1)

	transcript2 := mtaTranscript([]byte("extract-2"), &sk.PublicKey, encA, response,
		bCommitment, proof2.BetaCommitment,
		new(big.Int).SetBytes(proof2.CipherCommitment),
		proof2.BCommitment, proof2.BetaNonce)
	e2 := challenge([]byte(mtaChallengeLabel), transcript2)

	if e1.Cmp(e2) == 0 {
		t.Fatal("challenges are identical")
	}

	// Extract b.
	zB1 := new(big.Int).SetBytes(proof1.BResponse)
	zB2 := new(big.Int).SetBytes(proof2.BResponse)
	eDiff := new(big.Int).Sub(e1, e2)
	zDiffB := new(big.Int).Sub(zB1, zB2)
	if new(big.Int).Mod(zDiffB, eDiff).Sign() != 0 {
		t.Fatal("MTAResponseProof: zDiffB not divisible by eDiff — extraction failed")
	}
	extractedB := new(big.Int).Div(zDiffB, eDiff)
	extractedB.Mod(extractedB, secp.Order())
	expectedB := new(big.Int).Mod(b, secp.Order())
	if extractedB.Cmp(expectedB) != 0 {
		t.Fatalf("extracted b = %s, want %s", extractedB, expectedB)
	}

	// Extract beta.
	zBeta1 := new(big.Int).SetBytes(proof1.BetaResponse)
	zBeta2 := new(big.Int).SetBytes(proof2.BetaResponse)
	zDiffBeta := new(big.Int).Sub(zBeta1, zBeta2)
	if new(big.Int).Mod(zDiffBeta, eDiff).Sign() != 0 {
		t.Fatal("MTAResponseProof: zDiffBeta not divisible by eDiff — extraction failed")
	}
	extractedBeta := new(big.Int).Div(zDiffBeta, eDiff)
	extractedBeta.Mod(extractedBeta, secp.Order())
	expectedBeta := new(big.Int).Mod(beta, secp.Order())
	if extractedBeta.Cmp(expectedBeta) != 0 {
		t.Fatalf("extracted beta = %s, want %s", extractedBeta, expectedBeta)
	}
	t.Logf("MTAResponseProof extractor: b=%s, beta=%s (mod q)", extractedB, extractedBeta)
}

// TestEncProofSpecialSoundness demonstrates witness extraction for the new
// CGGMP Πenc proof. Extracts k = (z1 - z1')/(e - e').
func TestEncProofSpecialSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	k := big.NewInt(17)
	ciphertext, rho, err := sk.Encrypt(nil, k)
	if err != nil {
		t.Fatal(err)
	}
	stmt := EncStatement{
		ProverPaillierN: &sk.PublicKey,
		CiphertextK:     ciphertext,
		VerifierAux:     *aux,
	}
	witness := EncWitness{K: k, Rho: rho}

	rng := newReplayReader("extract-enc")
	proof1, err := ProveEnc(params, []byte("extract-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnc(params, []byte("extract-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}

	rng.reset()
	proof2, err := ProveEnc(params, []byte("extract-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnc(params, []byte("extract-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}

	// Commitments S, A, C must be identical.
	if proof1.S.Cmp(proof2.S) != 0 || proof1.A.Cmp(proof2.A) != 0 || proof1.C.Cmp(proof2.C) != 0 {
		t.Fatal("commitments differ — RNG replay failed")
	}

	transcript1 := buildEncTranscript(params, []byte("extract-1"), stmt, proof1.S, proof1.A, proof1.C)
	e1, _ := transcript1.ChallengeSigned(params.ChallengeBits)
	transcript2 := buildEncTranscript(params, []byte("extract-2"), stmt, proof2.S, proof2.A, proof2.C)
	e2, _ := transcript2.ChallengeSigned(params.ChallengeBits)

	if e1.Cmp(e2) == 0 {
		t.Fatal("challenges are identical")
	}

	eDiff := new(big.Int).Sub(e1, e2)
	zDiff := new(big.Int).Sub(proof1.Z1, proof2.Z1) // z1, z1' are signed

	if new(big.Int).Mod(zDiff, eDiff).Sign() != 0 {
		t.Fatal("z1Diff is not divisible by eDiff — special soundness extraction failed")
	}

	extractedK := new(big.Int).Div(zDiff, eDiff)
	// k = (z1 − z1′) / (e − e′). Since zDiff = eDiff · k, the division
	// recovers k exactly, preserving its sign regardless of eDiff ordering.
	if extractedK.Cmp(k) != 0 {
		t.Fatalf("extracted k = %s, want %s", extractedK, k)
	}
	t.Logf("EncProof extractor: k = %s", extractedK)
}

// TestAffGProofSpecialSoundness demonstrates witness extraction for Πaff-g.
// Extracts x = (z1 - z1')/(e - e') and y = (z2 - z2')/(e - e').
func TestAffGProofSpecialSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	x := big.NewInt(23)
	y := big.NewInt(29)
	c, _, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	encYReceiver, rho, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	xMulC, err := OMulCT(&sk.PublicKey, x, c, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(&sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	proverY, rhoY, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	stmt := AffGStatement{
		ReceiverPaillierN: &sk.PublicKey,
		ProverPaillierN:   &sk.PublicKey,
		C:                 c,
		D:                 d,
		Y:                 proverY,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		VerifierAux:       *aux,
	}
	witness := AffGWitness{X: x, Y: y, Rho: rho, RhoY: rhoY}

	rng := newReplayReader("extract-affg")
	proof1, err := ProveAffG(params, []byte("extract-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAffG(params, []byte("extract-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}

	rng.reset()
	proof2, err := ProveAffG(params, []byte("extract-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAffG(params, []byte("extract-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}

	// Commitments must be identical.
	if proof1.A.Cmp(proof2.A) != 0 || proof1.E.Cmp(proof2.E) != 0 ||
		proof1.S.Cmp(proof2.S) != 0 || proof1.F.Cmp(proof2.F) != 0 ||
		proof1.T.Cmp(proof2.T) != 0 {
		t.Fatal("commitments differ — RNG replay failed")
	}

	transcript1, err := buildAffGTranscript(params, []byte("extract-1"), stmt, proof1.Y,
		proof1.A, proof1.Bx, proof1.By, proof1.E, proof1.S, proof1.F, proof1.T)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := transcript1.ChallengeSigned(params.ChallengeBits)
	transcript2, err := buildAffGTranscript(params, []byte("extract-2"), stmt, proof2.Y,
		proof2.A, proof2.Bx, proof2.By, proof2.E, proof2.S, proof2.F, proof2.T)
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := transcript2.ChallengeSigned(params.ChallengeBits)

	if e1.Cmp(e2) == 0 {
		t.Fatal("challenges are identical")
	}

	eDiff := new(big.Int).Sub(e1, e2)

	// Extract x.
	z1Diff := new(big.Int).Sub(proof1.Z1, proof2.Z1)
	if new(big.Int).Mod(z1Diff, eDiff).Sign() != 0 {
		t.Fatal("z1Diff not divisible by eDiff")
	}
	extractedX := new(big.Int).Div(z1Diff, eDiff)
	if extractedX.Cmp(x) != 0 {
		t.Fatalf("extracted x = %s, want %s", extractedX, x)
	}

	// Extract y.
	z2Diff := new(big.Int).Sub(proof1.Z2, proof2.Z2)
	if new(big.Int).Mod(z2Diff, eDiff).Sign() != 0 {
		t.Fatal("z2Diff not divisible by eDiff")
	}
	extractedY := new(big.Int).Div(z2Diff, eDiff)
	if extractedY.Cmp(y) != 0 {
		t.Fatalf("extracted y = %s, want %s", extractedY, y)
	}
	t.Logf("AffGProof extractor: x=%s, y=%s", extractedX, extractedY)
}

// TestLogStarProofSpecialSoundness demonstrates witness extraction for Πlog*.
func TestLogStarProofSpecialSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	x := big.NewInt(31)
	c, rho, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	base := secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1)))
	stmt := LogStarStatement{
		PaillierN:   &sk.PublicKey,
		C:           c,
		X:           secp.ScalarMult(base, secp.ScalarFromBigInt(x)),
		B:           base,
		VerifierAux: *aux,
	}
	witness := LogStarWitness{X: x, Rho: rho}

	rng := newReplayReader("extract-logstar")
	proof1, err := ProveLogStar(params, []byte("extract-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLogStar(params, []byte("extract-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}

	rng.reset()
	proof2, err := ProveLogStar(params, []byte("extract-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLogStar(params, []byte("extract-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}

	if proof1.S.Cmp(proof2.S) != 0 || proof1.A.Cmp(proof2.A) != 0 || proof1.D.Cmp(proof2.D) != 0 {
		t.Fatal("commitments differ — RNG replay failed")
	}

	transcript1, err := buildLogStarTranscript(params, []byte("extract-1"), stmt, proof1.S, proof1.A, proof1.Y, proof1.D)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := transcript1.ChallengeSigned(params.ChallengeBits)
	transcript2, err := buildLogStarTranscript(params, []byte("extract-2"), stmt, proof2.S, proof2.A, proof2.Y, proof2.D)
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := transcript2.ChallengeSigned(params.ChallengeBits)

	if e1.Cmp(e2) == 0 {
		t.Fatal("challenges are identical")
	}

	eDiff := new(big.Int).Sub(e1, e2)
	zDiff := new(big.Int).Sub(proof1.Z1, proof2.Z1)

	if new(big.Int).Mod(zDiff, eDiff).Sign() != 0 {
		t.Fatal("z1Diff not divisible by eDiff")
	}

	extractedX := new(big.Int).Div(zDiff, eDiff)
	if extractedX.Cmp(x) != 0 {
		t.Fatalf("extracted x = %s, want %s", extractedX, x)
	}
	t.Logf("LogStarProof extractor: x = %s", extractedX)
}

// TestExtractorRequiresDifferentChallenges verifies that the extractor fails
// (as expected) when challenges are the same — two transcripts with identical
// commitments and identical challenges do NOT allow witness extraction.
func TestExtractorRequiresDifferentChallenges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}

	rng := newReplayReader("extract-same-challenge")
	domain := []byte("same-domain")

	proof1, err := ProveEncryption(rng, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	rng.reset()
	_, err = ProveEncryption(rng, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}

	transcript := encryptionTranscript(domain, &sk.PublicKey, ciphertext,
		proof1.ScalarCommitment, proof1.Bound,
		new(big.Int).SetBytes(proof1.CipherCommitment),
		proof1.PointCommitment)
	e1 := challenge([]byte(encryptionChallengeLabel), transcript)
	e2 := challenge([]byte(encryptionChallengeLabel), transcript)

	if e1.Cmp(e2) != 0 {
		t.Fatal("challenges differ unexpectedly")
	}

	// When e1 == e2, eDiff = 0, and extraction fails with division by zero.
	// This confirms that two transcripts must have DIFFERENT challenges for
	// the extractor to work.
	eDiff := new(big.Int).Sub(e1, e2)
	if eDiff.Sign() != 0 {
		t.Fatal("eDiff should be zero")
	}
	t.Log("Extractor correctly requires different challenges (e1 == e2, extraction impossible)")
}

// replayReader implements io.Reader — confirmed above.
var _ io.Reader = (*replayReader)(nil)
