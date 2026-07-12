//go:build tier1

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

// TestEncProofSpecialSoundness demonstrates witness extraction for the new
// CGGMP Πenc proof. Extracts k = (z1 - z1')/(e - e').
func TestEncProofSpecialSoundness(t *testing.T) {
	t.Parallel()
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
		ProverPaillierN: sk.PublicKey,
		CiphertextK:     ciphertext,
		VerifierAux:     aux,
	}
	witness := EncWitness{
		K:   testSecpSecretScalar(t, k),
		Rho: testSecretScalarFixed(t, rho, modulusBytes(sk.N)),
	}

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

	transcript1, err := buildEncTranscript(params, []byte("extract-1"), stmt, proof1.S, proof1.A, proof1.C)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := transcript1.ChallengeSigned(params.ChallengeBits)
	transcript2, err := buildEncTranscript(params, []byte("extract-2"), stmt, proof2.S, proof2.A, proof2.C)
	if err != nil {
		t.Fatal(err)
	}
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
	t.Parallel()
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
	xMulC, err := OMulCT(
		sk.PublicKey,
		testSignedSecret(t, x, signedPowerOfTwoBytes(params.Ell)),
		c,
		signedPowerOfTwoBytes(params.Ell),
	)
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	proverY, rhoY, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	stmt := AffGStatement{
		ReceiverPaillierN: sk.PublicKey,
		ProverPaillierN:   sk.PublicKey,
		C:                 c,
		D:                 d,
		Y:                 proverY,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		K:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		VerifierAux:       aux,
	}
	witness := AffGWitness{
		X:    testSecpSecretScalar(t, x),
		Y:    testSignedSecret(t, y, signedPowerOfTwoBytes(params.EllPrime)),
		Rho:  testSecretScalarFixed(t, rho, modulusBytes(sk.N)),
		RhoY: testSecretScalarFixed(t, rhoY, modulusBytes(sk.N)),
	}

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
		proof1.A, proof1.Bx, proof1.By, proof1.E, proof1.S, proof1.F, proof1.T,
		proof1.YPoint, proof1.BetaPointCommitment, proof1.AlphaPoint, proof1.ProductPointCommitment)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := transcript1.ChallengeSigned(params.ChallengeBits)
	transcript2, err := buildAffGTranscript(params, []byte("extract-2"), stmt, proof2.Y,
		proof2.A, proof2.Bx, proof2.By, proof2.E, proof2.S, proof2.F, proof2.T,
		proof2.YPoint, proof2.BetaPointCommitment, proof2.AlphaPoint, proof2.ProductPointCommitment)
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
	t.Parallel()
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
		PaillierN:   sk.PublicKey,
		C:           c,
		X:           secp.ScalarMult(base, secp.ScalarFromBigInt(x)),
		B:           base,
		VerifierAux: aux,
	}
	witness := LogStarWitness{
		X:   testSecpSecretScalar(t, x),
		Rho: testSecretScalarFixed(t, rho, modulusBytes(sk.N)),
	}

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

// replayReader implements io.Reader — confirmed above.
var _ io.Reader = (*replayReader)(nil)
