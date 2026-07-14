//go:build tier1

package paillier

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
	"strconv"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
	zkchallenge "github.com/islishude/tss/internal/zk/challenge"
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
	aux, _, err := testIndependentRingPedersenParams(t, nil, sk)
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
		t.Fatal("special-soundness extraction returned the wrong plaintext witness")
	}
}

// TestAffGProofSpecialSoundness demonstrates witness extraction for Πaff-g.
// Extracts x = (z1 - z1')/(e - e') and y = (z2 - z2')/(e - e').
func TestAffGProofSpecialSoundness(t *testing.T) {
	t.Parallel()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := testIndependentRingPedersenParams(t, nil, sk)
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

	transcript1, err := buildAffGTranscript(params, []byte("extract-1"), stmt,
		proof1.A, proof1.Bx, proof1.By, proof1.E, proof1.S, proof1.F, proof1.T)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := transcript1.ChallengeSigned(params.ChallengeBits)
	transcript2, err := buildAffGTranscript(params, []byte("extract-2"), stmt,
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
		t.Fatal("special-soundness extraction returned the wrong affine multiplier")
	}

	// Extract y.
	z2Diff := new(big.Int).Sub(proof1.Z2, proof2.Z2)
	if new(big.Int).Mod(z2Diff, eDiff).Sign() != 0 {
		t.Fatal("z2Diff not divisible by eDiff")
	}
	extractedY := new(big.Int).Div(z2Diff, eDiff)
	if extractedY.Cmp(y) != 0 {
		t.Fatal("special-soundness extraction returned the wrong affine addend")
	}
}

// TestLogStarProofSpecialSoundness demonstrates witness extraction for Πlog*.
func TestLogStarProofSpecialSoundness(t *testing.T) {
	t.Parallel()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, _, err := testIndependentRingPedersenParams(t, nil, sk)
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
		t.Fatal("special-soundness extraction returned the wrong logarithm witness")
	}
}

// TestMulProofSpecialSoundness extracts the encrypted multiplier from two
// accepting Πmul transcripts with identical commitments.
func TestMulProofSpecialSoundness(t *testing.T) {
	t.Parallel()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	xValue := big.NewInt(7)
	x := testSecpSecretScalar(t, xValue)
	xCipher, rhoX, err := sk.EncryptSecret(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	yCipher, _, err := sk.Encrypt(nil, big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	zero, rhoC, err := sk.Encrypt(nil, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	xSigned := testSignedSecret(t, xValue, signedPowerOfTwoBytes(params.Ell))
	product, err := OMulCT(sk.PublicKey, xSigned, yCipher, xSigned.FixedLen())
	if err != nil {
		t.Fatal(err)
	}
	product, err = OAdd(sk.PublicKey, product, zero)
	if err != nil {
		t.Fatal(err)
	}
	stmt := MulStatement{PaillierN: sk.PublicKey, X: xCipher, Y: yCipher, C: product}
	witness := MulWitness{
		X: x, RhoX: rhoX,
		RhoC: testSecretScalarFixed(t, rhoC, modulusBytes(sk.N)),
	}
	rng := newReplayReader("extract-mul")
	proof1, err := ProveMul(params, []byte("extract-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	rng.reset()
	proof2, err := ProveMul(params, []byte("extract-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMul(params, []byte("extract-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMul(params, []byte("extract-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}
	if proof1.A.Cmp(proof2.A) != 0 || proof1.B.Cmp(proof2.B) != 0 {
		t.Fatal("commitments differ — RNG replay failed")
	}
	tr1, err := buildMulTranscript(params, []byte("extract-1"), stmt, proof1.A, proof1.B)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := buildMulTranscript(params, []byte("extract-2"), stmt, proof2.A, proof2.B)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := tr1.ChallengeSigned(params.ChallengeBits)
	e2, _ := tr2.ChallengeSigned(params.ChallengeBits)
	extracted := extractLinearWitness(t, proof1.Z, proof2.Z, e1, e2)
	if extracted.Cmp(xValue) != 0 {
		t.Fatal("special-soundness extraction returned the wrong multiplication witness")
	}
}

// TestMulStarProofSpecialSoundness extracts the scalar bound to both the
// Paillier and curve equations from two accepting Πmul* transcripts.
func TestMulStarProofSpecialSoundness(t *testing.T) {
	t.Parallel()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, lambda, err := testIndependentRingPedersenParams(t, nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	xValue := big.NewInt(9)
	x := testSecpSecretScalar(t, xValue)
	ciphertext, _, err := sk.Encrypt(nil, big.NewInt(13))
	if err != nil {
		t.Fatal(err)
	}
	zero, rho, err := sk.Encrypt(nil, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	xSigned := testSignedSecret(t, xValue, signedPowerOfTwoBytes(params.Ell))
	product, err := OMulCT(sk.PublicKey, xSigned, ciphertext, xSigned.FixedLen())
	if err != nil {
		t.Fatal(err)
	}
	product, err = OAdd(sk.PublicKey, product, zero)
	if err != nil {
		t.Fatal(err)
	}
	base := secp.ScalarBaseMult(secp.ScalarOne())
	stmt := MulStarStatement{
		PaillierN: sk.PublicKey, C: ciphertext, D: product,
		X: secp.ScalarMult(base, secp.ScalarFromBigInt(xValue)), B: base, VerifierAux: aux,
	}
	witness := MulStarWitness{X: x, Rho: testSecretScalarFixed(t, rho, modulusBytes(sk.N))}
	rng := newReplayReader("extract-mulstar")
	proof1, err := ProveMulStar(params, []byte("extract-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	rng.reset()
	proof2, err := ProveMulStar(params, []byte("extract-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMulStar(params, []byte("extract-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMulStar(params, []byte("extract-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}
	if proof1.A.Cmp(proof2.A) != 0 || !secp.Equal(proof1.Bx, proof2.Bx) || proof1.S.Cmp(proof2.S) != 0 || proof1.E.Cmp(proof2.E) != 0 {
		t.Fatal("commitments differ — RNG replay failed")
	}
	tr1, err := buildMulStarTranscript(params, []byte("extract-1"), stmt, proof1.A, proof1.Bx, proof1.S, proof1.E)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := buildMulStarTranscript(params, []byte("extract-2"), stmt, proof2.A, proof2.Bx, proof2.S, proof2.E)
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := tr1.ChallengeSigned(params.ChallengeBits)
	e2, _ := tr2.ChallengeSigned(params.ChallengeBits)
	extracted := extractLinearWitness(t, proof1.Z1, proof2.Z1, e1, e2)
	if extracted.Cmp(xValue) != 0 {
		t.Fatal("special-soundness extraction returned the wrong multiplication-star witness")
	}
}

// TestEncElgProofSpecialSoundness extracts both Figure 24 scalar witnesses
// from two accepting transcripts with identical prover commitments.
func TestEncElgProofSpecialSoundness(t *testing.T) {
	params, stmt, witness := testEncElgRelation(t)
	rng := newReplayReader("extract-enc-elg")
	proof1, err := ProveEncElg(params, []byte("extract-enc-elg-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	defer proof1.Destroy()
	rng.reset()
	proof2, err := ProveEncElg(params, []byte("extract-enc-elg-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	defer proof2.Destroy()
	if err := VerifyEncElg(params, []byte("extract-enc-elg-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncElg(params, []byte("extract-enc-elg-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}
	if proof1.PlaintextCommitment.Cmp(proof2.PlaintextCommitment) != 0 ||
		proof1.CiphertextCommitment.Cmp(proof2.CiphertextCommitment) != 0 ||
		!bytes.Equal(proof1.ElGamalCommitment, proof2.ElGamalCommitment) ||
		!bytes.Equal(proof1.ExponentMaskCommitment, proof2.ExponentMaskCommitment) ||
		proof1.RangeMaskCommitment.Cmp(proof2.RangeMaskCommitment) != 0 {
		t.Fatal("commitments differ — RNG replay failed")
	}
	transcript1, err := buildEncElgTranscript(params, []byte("extract-enc-elg-1"), stmt,
		proof1.PlaintextCommitment, proof1.CiphertextCommitment, proof1.ElGamalCommitment,
		proof1.ExponentMaskCommitment, proof1.RangeMaskCommitment)
	if err != nil {
		t.Fatal(err)
	}
	eScalar1, e1, err := transcript1.ChallengeScalar(params.ChallengeBits)
	if err != nil {
		t.Fatal(err)
	}
	transcript2, err := buildEncElgTranscript(params, []byte("extract-enc-elg-2"), stmt,
		proof2.PlaintextCommitment, proof2.CiphertextCommitment, proof2.ElGamalCommitment,
		proof2.ExponentMaskCommitment, proof2.RangeMaskCommitment)
	if err != nil {
		t.Fatal(err)
	}
	eScalar2, e2, err := transcript2.ChallengeScalar(params.ChallengeBits)
	if err != nil {
		t.Fatal(err)
	}
	extractedPlaintext := extractLinearWitness(t, proof1.PlaintextResponse, proof2.PlaintextResponse, e1, e2)
	defer secret.ClearBigInt(extractedPlaintext)
	wantPlaintext, err := secretScalarBig(witness.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.ClearBigInt(wantPlaintext)
	if extractedPlaintext.Cmp(wantPlaintext) != 0 {
		t.Fatal("two accepting transcripts did not extract the Figure 24 plaintext")
	}
	w1, err := secp.ScalarFromBytesAllowZero(proof1.ExponentResponse)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := secp.ScalarFromBytesAllowZero(proof2.ExponentResponse)
	if err != nil {
		t.Fatal(err)
	}
	denominator := secp.ScalarSub(eScalar1, eScalar2)
	denominatorInverse, err := secp.ScalarInvert(denominator)
	if err != nil {
		t.Fatal("challenges are identical")
	}
	extractedExponent := secp.ScalarMul(secp.ScalarSub(w1, w2), denominatorInverse)
	wantExponent, err := secpScalarFromSecretAllowZero(witness.Exponent, "exponent")
	if err != nil {
		t.Fatal(err)
	}
	if !extractedExponent.Equal(wantExponent) {
		t.Fatal("two accepting transcripts did not extract the Figure 24 exponent")
	}
}

// TestElogProofSpecialSoundness extracts both Figure 23 scalar witnesses from
// two accepting transcripts with identical prover commitments.
func TestElogProofSpecialSoundness(t *testing.T) {
	stmt, witness := testElogRelation(t)
	rng := newReplayReader("extract-elog")
	proof1, err := ProveElog([]byte("extract-elog-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	defer proof1.Destroy()
	rng.reset()
	proof2, err := ProveElog([]byte("extract-elog-2"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	defer proof2.Destroy()
	if err := VerifyElog([]byte("extract-elog-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyElog([]byte("extract-elog-2"), stmt, proof2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(proof1.A, proof2.A) || !bytes.Equal(proof1.N, proof2.N) || !bytes.Equal(proof1.B, proof2.B) {
		t.Fatal("commitments differ — RNG replay failed")
	}
	root1, err := elogTranscript([]byte("extract-elog-1"), stmt, proof1.A, proof1.N, proof1.B)
	if err != nil {
		t.Fatal(err)
	}
	e1, err := zkchallenge.DeriveCanonicalNonZeroSecp256k1(paillierChallengeDerivationLabel, root1, challengeCounterLimit)
	if err != nil {
		t.Fatal(err)
	}
	root2, err := elogTranscript([]byte("extract-elog-2"), stmt, proof2.A, proof2.N, proof2.B)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := zkchallenge.DeriveCanonicalNonZeroSecp256k1(paillierChallengeDerivationLabel, root2, challengeCounterLimit)
	if err != nil {
		t.Fatal(err)
	}
	denominatorInverse, err := secp.ScalarInvert(secp.ScalarSub(e1, e2))
	if err != nil {
		t.Fatal("challenges are identical")
	}
	z1, _ := secp.ScalarFromBytesAllowZero(proof1.Z)
	z2, _ := secp.ScalarFromBytesAllowZero(proof2.Z)
	u1, _ := secp.ScalarFromBytesAllowZero(proof1.U)
	u2, _ := secp.ScalarFromBytesAllowZero(proof2.U)
	extractedLambda := secp.ScalarMul(secp.ScalarSub(z1, z2), denominatorInverse)
	extractedY := secp.ScalarMul(secp.ScalarSub(u1, u2), denominatorInverse)
	wantLambda, err := secpScalarFromSecretAllowZero(witness.Lambda, "lambda")
	if err != nil {
		t.Fatal(err)
	}
	wantY, err := secpScalarFromSecretAllowZero(witness.Y, "y")
	if err != nil {
		t.Fatal(err)
	}
	if !extractedLambda.Equal(wantLambda) || !extractedY.Equal(wantY) {
		t.Fatal("two accepting transcripts did not extract the Figure 23 witnesses")
	}
}

// TestAffGStarProofSpecialSoundness extracts both Figure 27 plaintext
// witnesses from one differing bit among two accepting transcripts.
func TestAffGStarProofSpecialSoundness(t *testing.T) {
	params := SecurityParams{Ell: 8, EllPrime: 16, Epsilon: 8, ChallengeBits: 8, MinPaillierBits: 512}
	sk0 := testPaillierKey(t, 512)
	defer sk0.Destroy()
	sk1 := testAuxPaillierKey(t, 512)
	defer sk1.Destroy()
	xValue := big.NewInt(7)
	yValue := big.NewInt(-19)
	x := testSecpSecretScalar(t, xValue)
	y := testSignedSecret(t, yValue, signedPowerOfTwoBytes(params.EllPrime))
	cPlaintext := testSecpSecretScalar(t, big.NewInt(11))
	c, cRandomness, err := sk0.EncryptSecret(testutil.DeterministicReader(3921), cPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	cRandomness.Destroy()
	encY0, rho, err := sk0.EncryptSignedSecret(testutil.DeterministicReader(3922), y)
	if err != nil {
		t.Fatal(err)
	}
	defer rho.Destroy()
	xSigned := testSignedSecret(t, xValue, signedPowerOfTwoBytes(params.Ell))
	xC, err := OMulCT(sk0.PublicKey, xSigned, c, xSigned.FixedLen())
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(sk0.PublicKey, xC, encY0)
	if err != nil {
		t.Fatal(err)
	}
	yCiphertext, mu, err := sk1.EncryptSignedSecret(testutil.DeterministicReader(3923), y)
	if err != nil {
		t.Fatal(err)
	}
	defer mu.Destroy()
	stmt := AffGStarStatement{
		ReceiverPaillierN: sk0.PublicKey,
		ProverPaillierN:   sk1.PublicKey,
		C:                 c,
		D:                 d,
		Y:                 yCiphertext,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(xValue)),
	}
	witness := AffGStarWitness{X: x, Y: y, Rho: rho, Mu: mu}
	rng := newReplayReader("extract-aff-g-star")
	proof1, err := ProveAffGStar(params, []byte("extract-aff-g-star-1"), stmt, witness, rng)
	if err != nil {
		t.Fatal(err)
	}
	defer proof1.Destroy()
	if err := VerifyAffGStar(params, []byte("extract-aff-g-star-1"), stmt, proof1); err != nil {
		t.Fatal(err)
	}
	bits1 := affGStarChallenges(proof1.TranscriptHash, len(proof1.A))
	var (
		proof2      *AffGStarProof
		proof2State []byte
	)
	round := -1
	// Distinct transcript states can legitimately map to the same 8-bit
	// challenge. Try deterministic domain-separated states until special
	// soundness has the two different challenges it requires.
	for variant := 2; variant <= 256 && proof2 == nil; variant++ {
		proof2State = strconv.AppendInt([]byte("extract-aff-g-star-"), int64(variant), 10)
		rng.reset()
		candidate, proveErr := ProveAffGStar(params, proof2State, stmt, witness, rng)
		if proveErr != nil {
			t.Fatal(proveErr)
		}
		candidateBits := affGStarChallenges(candidate.TranscriptHash, len(candidate.A))
		for i := range proof1.A {
			if affGStarChallengeBit(bits1, i) != affGStarChallengeBit(candidateBits, i) {
				proof2 = candidate
				round = i
				break
			}
		}
		if proof2 == nil {
			candidate.Destroy()
		}
	}
	if proof2 == nil || round < 0 {
		t.Fatal("could not derive distinct challenges from domain-separated transcript states")
	}
	defer proof2.Destroy()
	if err := VerifyAffGStar(params, proof2State, stmt, proof2); err != nil {
		t.Fatal(err)
	}
	if !equalByteLists(proof1.A, proof2.A) || !equalByteLists(proof1.B, proof2.B) || !equalByteLists(proof1.R, proof2.R) {
		t.Fatal("commitments differ — RNG replay failed")
	}
	z1, _ := wire.DecodeBigInt(proof1.Z[round])
	z2, _ := wire.DecodeBigInt(proof2.Z[round])
	zPrime1, _ := wire.DecodeBigInt(proof1.ZPrime[round])
	zPrime2, _ := wire.DecodeBigInt(proof2.ZPrime[round])
	if affGStarChallengeBit(bits1, round) == 0 {
		z1, z2 = z2, z1
		zPrime1, zPrime2 = zPrime2, zPrime1
	}
	extractedX := new(big.Int).Sub(z1, z2)
	extractedY := new(big.Int).Sub(zPrime1, zPrime2)
	defer secret.ClearBigInt(extractedX)
	defer secret.ClearBigInt(extractedY)
	if extractedX.Cmp(xValue) != 0 || extractedY.Cmp(yValue) != 0 {
		t.Fatal("two accepting bit transcripts did not extract the Figure 27 witnesses")
	}
}

func extractLinearWitness(t *testing.T, firstResponse, secondResponse, firstChallenge, secondChallenge *big.Int) *big.Int {
	t.Helper()
	challengeDiff := new(big.Int).Sub(firstChallenge, secondChallenge)
	if challengeDiff.Sign() == 0 {
		t.Fatal("challenges are identical")
	}
	responseDiff := new(big.Int).Sub(firstResponse, secondResponse)
	if new(big.Int).Mod(responseDiff, challengeDiff).Sign() != 0 {
		t.Fatal("response difference is not divisible by challenge difference")
	}
	return new(big.Int).Div(responseDiff, challengeDiff)
}

// replayReader implements io.Reader — confirmed above.
var _ io.Reader = (*replayReader)(nil)
