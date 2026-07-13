package paillier

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestDecProofFigure28RelationAndMutations(t *testing.T) {
	params := testSetupLessParams()
	_, stmt, witness := testDecFigure28Fixture(t, params)
	state := []byte("dec/session/party-3")
	proof, err := ProveDec(params, state, stmt, witness, testutil.DeterministicReader(3001))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proof.Destroy)
	if got, want := len(proof.A), int(params.ChallengeBits); got != want {
		t.Fatalf("proof rounds = %d, want %d", got, want)
	}
	if err := VerifyDec(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}

	encoded, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded DecProof
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(decoded.Destroy)
	if err := VerifyDec(params, state, stmt, &decoded); err != nil {
		t.Fatal(err)
	}

	if err := VerifyDec(params, []byte("wrong-state"), stmt, proof); err == nil {
		t.Fatal("wrong transcript state was accepted")
	}
	mutations := []func(*DecProof){
		func(p *DecProof) { p.A[0][len(p.A[0])-1] ^= 1 },
		func(p *DecProof) { p.B[0][len(p.B[0])-1] ^= 1 },
		func(p *DecProof) { p.C[0][len(p.C[0])-1] ^= 1 },
		func(p *DecProof) { p.Z[0][len(p.Z[0])-1] ^= 1 },
		func(p *DecProof) { p.W[0][len(p.W[0])-1] ^= 1 },
		func(p *DecProof) { p.Nu[0][len(p.Nu[0])-1] ^= 1 },
		func(p *DecProof) { p.TranscriptHash[0] ^= 1 },
	}
	for i, mutate := range mutations {
		candidate := proof.Clone()
		mutate(candidate)
		if err := VerifyDec(params, state, stmt, candidate); err == nil {
			t.Fatalf("DecProof mutation %d verified", i)
		}
		candidate.Destroy()
	}

	outOfRange := proof.Clone()
	tooLarge := new(big.Int).Lsh(big.NewInt(1), uint(params.EncRange()+2))
	outOfRange.Z[0], err = wire.EncodeBigInt(tooLarge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDec(params, state, stmt, outOfRange); err == nil {
		t.Fatal("out-of-range x response was accepted")
	}
	outOfRange.Destroy()

	wrongBase := stmt
	wrongBase.PlaintextBase = secp.ScalarBaseMult(secp.ScalarFromUint64(13))
	if err := VerifyDec(params, state, wrongBase, proof); err == nil {
		t.Fatal("proof was accepted with a different plaintext base")
	}
	identityBase := stmt
	identityBase.PlaintextBase = secp.NewInfinity()
	if err := VerifyDec(params, state, identityBase, proof); err == nil {
		t.Fatal("identity plaintext base was accepted")
	}
	missingRound := proof.Clone()
	missingRound.Nu = missingRound.Nu[:len(missingRound.Nu)-1]
	if err := VerifyDec(params, state, stmt, missingRound); err == nil {
		t.Fatal("inconsistent round lists were accepted")
	}
	missingRound.Destroy()
}

func TestDecProofRejectsWrongRecoveredRelation(t *testing.T) {
	params := testSetupLessParams()
	_, stmt, witness := testDecFigure28Fixture(t, params)
	wrong := stmt
	wrong.D = new(big.Int).Set(stmt.K)
	if _, err := ProveDec(params, []byte("dec/relation"), wrong, witness, testutil.DeterministicReader(3010)); err == nil {
		t.Fatal("witness for a different K^x*D relation was accepted")
	}
}

func TestDecProofAcceptsIdentityPlaintextCommitmentForZeroMessage(t *testing.T) {
	params := testSetupLessParams()
	_, stmt, witness := testDecFigure28FixtureWithY(t, params, big.NewInt(0))
	if stmt.S.Inf == 0 {
		t.Fatal("zero plaintext did not produce the identity commitment")
	}
	state := []byte("dec/figure9/zero-chi")
	proof, err := ProveDec(params, state, stmt, witness, testutil.DeterministicReader(3012))
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Destroy()
	if err := VerifyDec(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}
}

func TestDecProofAcceptsAggregatedFigure9PlaintextRange(t *testing.T) {
	params := testSetupLessParams()
	// A Figure 9 plaintext aggregates pairwise affine terms. It can therefore
	// exceed one EllPrime-bit mask while remaining inside the public Πdec
	// aggregation bound.
	target := new(big.Int).Lsh(big.NewInt(1), uint(params.EllPrime+1))
	_, stmt, witness := testDecFigure28FixtureWithY(t, params, target)
	proof, err := ProveDec(params, []byte("dec/figure9/aggregated"), stmt, witness, testutil.DeterministicReader(3013))
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Destroy()
	if err := VerifyDec(params, []byte("dec/figure9/aggregated"), stmt, proof); err != nil {
		t.Fatal(err)
	}
}

func TestDecProofRejectsPlaintextBeyondFigure9AggregationRange(t *testing.T) {
	params := testSetupLessParams()
	target := new(big.Int).Lsh(big.NewInt(1), uint(params.DecPlaintextRange()+1))
	_, stmt, witness := testDecFigure28FixtureWithY(t, params, target)
	if _, err := ProveDec(params, []byte("dec/figure9/out-of-range"), stmt, witness, testutil.DeterministicReader(3014)); err == nil {
		t.Fatal("Πdec accepted a plaintext beyond the Figure 9 aggregation range")
	}
}

func TestDecProofBitChallengeSpecialSoundness(t *testing.T) {
	params := testSetupLessParams()
	_, stmt, witness := testDecFigure28Fixture(t, params)
	statePrefix := []byte("dec/extract/")
	proof1, err := ProveDec(params, append(bytes.Clone(statePrefix), 0), stmt, witness, testutil.DeterministicReader(3020))
	if err != nil {
		t.Fatal(err)
	}
	defer proof1.Destroy()
	bits1 := decChallenges(proof1.TranscriptHash, len(proof1.A))
	var proof2 *DecProof
	round := -1
	for counter := byte(1); counter != 0; counter++ {
		candidate, proveErr := ProveDec(params, append(bytes.Clone(statePrefix), counter), stmt, witness, testutil.DeterministicReader(3020))
		if proveErr != nil {
			t.Fatal(proveErr)
		}
		if !equalByteLists(proof1.A, candidate.A) || !equalByteLists(proof1.B, candidate.B) || !equalByteLists(proof1.C, candidate.C) {
			candidate.Destroy()
			t.Fatal("replayed prover randomness did not reproduce commitments")
		}
		candidateBits := decChallenges(candidate.TranscriptHash, len(candidate.A))
		for i := range proof1.A {
			if decChallengeBit(bits1, i) != decChallengeBit(candidateBits, i) {
				proof2 = candidate
				round = i
				break
			}
		}
		if round >= 0 {
			break
		}
		candidate.Destroy()
	}
	if round < 0 {
		t.Fatal("256 independent transcript states produced identical bit challenges")
	}
	defer proof2.Destroy()
	z1, _ := wire.DecodeBigInt(proof1.Z[round])
	z2, _ := wire.DecodeBigInt(proof2.Z[round])
	w1, _ := wire.DecodeBigInt(proof1.W[round])
	w2, _ := wire.DecodeBigInt(proof2.W[round])
	if decChallengeBit(bits1, round) == 0 {
		z1, z2 = z2, z1
		w1, w2 = w2, w1
	}
	extractedX := new(big.Int).Sub(z1, z2)
	extractedY := new(big.Int).Sub(w1, w2)
	wantX, err := secretScalarBig(witness.X)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.ClearBigInt(wantX)
	wantY, err := signedSecretBig(witness.Y)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.ClearBigInt(wantY)
	if extractedX.Cmp(wantX) != 0 || extractedY.Cmp(wantY) != 0 {
		t.Fatal("two accepting bit transcripts did not extract the Figure 28 witnesses")
	}
}

func testSetupLessParams() SecurityParams {
	return SecurityParams{Ell: 8, EllPrime: 16, Epsilon: 8, ChallengeBits: 8, MinPaillierBits: 512}
}

func testDecFigure28Fixture(t *testing.T, params SecurityParams) (*big.Int, DecStatement, DecWitness) {
	return testDecFigure28FixtureWithY(t, params, big.NewInt(-19))
}

func testDecFigure28FixtureWithY(t *testing.T, params SecurityParams, target *big.Int) (*big.Int, DecStatement, DecWitness) {
	t.Helper()
	sk := testPaillierKey(t, 512)
	t.Cleanup(sk.Destroy)
	x := testSecpSecretScalar(t, big.NewInt(7))
	kPlaintext := testSecpSecretScalar(t, big.NewInt(11))
	k, kRandomness, err := sk.EncryptSecret(testutil.DeterministicReader(3030), kPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	kRandomness.Destroy()
	targetY := testSignedSecret(t, target, signedPowerOfTwoBytes(params.DecPlaintextRange()))
	encY, targetRandomness, err := sk.EncryptSignedSecret(testutil.DeterministicReader(3031), targetY)
	if err != nil {
		t.Fatal(err)
	}
	targetRandomness.Destroy()
	negativeX := testSignedSecret(t, big.NewInt(-7), signedPowerOfTwoBytes(params.Ell))
	kNegativeX, err := OMulCT(sk.PublicKey, negativeX, k, negativeX.FixedLen())
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(sk.PublicKey, encY, kNegativeX)
	if err != nil {
		t.Fatal(err)
	}
	xSigned := testSignedSecret(t, big.NewInt(7), signedPowerOfTwoBytes(params.Ell))
	kX, err := OMulCT(sk.PublicKey, xSigned, k, xSigned.FixedLen())
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := OAdd(sk.PublicKey, kX, d)
	if err != nil {
		t.Fatal(err)
	}
	recoveredY, recoveredRandomness, err := sk.RecoverOpening(aggregate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(recoveredY.Destroy)
	t.Cleanup(recoveredRandomness.Destroy)
	reencoded, err := sk.EncryptSignedWithSecretRandomness(recoveredY, recoveredRandomness)
	if err != nil {
		t.Fatal(err)
	}
	if reencoded.Cmp(aggregate) != 0 {
		t.Fatal("RecoverOpening did not reproduce K^x*D")
	}
	xEncoded := x.FixedBytes()
	defer clear(xEncoded)
	xScalar, err := secp.ScalarFromBytes(xEncoded)
	if err != nil {
		t.Fatal(err)
	}
	defer xScalar.Set(secp.ScalarZero())
	yBig, err := signedSecretBig(recoveredY)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.ClearBigInt(yBig)
	yScalar := secp.ScalarFromBigInt(yBig)
	defer yScalar.Set(secp.ScalarZero())
	plaintextBase := secp.ScalarBaseMult(secp.ScalarFromUint64(9))
	stmt := DecStatement{
		PaillierN:     sk.PublicKey,
		K:             k,
		D:             d,
		X:             secp.ScalarBaseMult(xScalar),
		S:             secp.ScalarMult(plaintextBase, yScalar),
		PlaintextBase: plaintextBase,
	}
	return aggregate, stmt, DecWitness{X: x, Y: recoveredY, Rho: recoveredRandomness}
}

func equalByteLists(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !bytes.Equal(left[i], right[i]) {
			return false
		}
	}
	return true
}
