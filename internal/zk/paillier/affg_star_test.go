package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestAffGStarProofRoundTripAndRejectsMutations(t *testing.T) {
	params := SecurityParams{
		Ell:             8,
		EllPrime:        16,
		Epsilon:         8,
		ChallengeBits:   8,
		MinPaillierBits: 512,
	}
	sk0 := testPaillierKey(t, 512)
	t.Cleanup(sk0.Destroy)
	sk1 := testAuxPaillierKey(t, 512)
	t.Cleanup(sk1.Destroy)

	x := testSecpSecretScalar(t, big.NewInt(7))
	y := testSignedSecret(t, big.NewInt(-19), signedPowerOfTwoBytes(params.EllPrime))
	cPlaintext := testSecpSecretScalar(t, big.NewInt(11))
	c, cRandomness, err := sk0.EncryptSecret(testutil.DeterministicReader(2901), cPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	cRandomness.Destroy()
	encY0, rho, err := sk0.EncryptSignedSecret(testutil.DeterministicReader(2902), y)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rho.Destroy)
	xSigned := testSignedSecret(t, big.NewInt(7), signedPowerOfTwoBytes(params.Ell))
	xC, err := OMulCT(sk0.PublicKey, xSigned, c, xSigned.FixedLen())
	if err != nil {
		t.Fatal(err)
	}
	d, err := OAdd(sk0.PublicKey, xC, encY0)
	if err != nil {
		t.Fatal(err)
	}
	yCiphertext, mu, err := sk1.EncryptSignedSecret(testutil.DeterministicReader(2903), y)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mu.Destroy)
	xEncoded := x.FixedBytes()
	defer clear(xEncoded)
	xScalar, err := secp.ScalarFromBytes(xEncoded)
	if err != nil {
		t.Fatal(err)
	}
	defer xScalar.Set(secp.ScalarZero())
	stmt := AffGStarStatement{
		ReceiverPaillierN: sk0.PublicKey,
		ProverPaillierN:   sk1.PublicKey,
		C:                 c,
		D:                 d,
		Y:                 yCiphertext,
		X:                 secp.ScalarBaseMult(xScalar),
	}
	witness := AffGStarWitness{X: x, Y: y, Rho: rho, Mu: mu}
	state := []byte("aff-g-star/session/party-2")
	proof, err := ProveAffGStar(params, state, stmt, witness, testutil.DeterministicReader(2904))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proof.Destroy)
	if got, want := len(proof.A), int(params.ChallengeBits); got != want {
		t.Fatalf("proof rounds = %d, want %d", got, want)
	}
	if err := VerifyAffGStar(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}

	encoded, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded AffGStarProof
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(decoded.Destroy)
	if err := VerifyAffGStar(params, state, stmt, &decoded); err != nil {
		t.Fatal(err)
	}

	if err := VerifyAffGStar(params, []byte("wrong-state"), stmt, proof); err == nil {
		t.Fatal("wrong transcript state was accepted")
	}
	mutatedCommitment := proof.Clone()
	mutatedCommitment.A[0][len(mutatedCommitment.A[0])-1] ^= 1
	if err := VerifyAffGStar(params, state, stmt, mutatedCommitment); err == nil {
		t.Fatal("mutated affine commitment was accepted")
	}
	mutatedCommitment.Destroy()

	outOfRange := proof.Clone()
	tooLarge := new(big.Int).Lsh(big.NewInt(1), uint(params.EncRange()+2))
	outOfRange.Z[0], err = wire.EncodeBigInt(tooLarge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAffGStar(params, state, stmt, outOfRange); err == nil {
		t.Fatal("out-of-range affine response was accepted")
	}
	outOfRange.Destroy()

	missingRound := proof.Clone()
	missingRound.Lambda = missingRound.Lambda[:len(missingRound.Lambda)-1]
	if err := VerifyAffGStar(params, state, stmt, missingRound); err == nil {
		t.Fatal("inconsistent round lists were accepted")
	}
	missingRound.Destroy()

	wrongStatement := stmt
	wrongStatement.D = new(big.Int).Set(stmt.C)
	if err := VerifyAffGStar(params, state, wrongStatement, proof); err == nil {
		t.Fatal("proof was accepted for a different affine statement")
	}
}

func TestAffGStarRejectsInvalidWitnessRelation(t *testing.T) {
	params := SecurityParams{Ell: 8, EllPrime: 16, Epsilon: 8, ChallengeBits: 8, MinPaillierBits: 512}
	sk0 := testPaillierKey(t, 512)
	t.Cleanup(sk0.Destroy)
	sk1 := testAuxPaillierKey(t, 512)
	t.Cleanup(sk1.Destroy)
	x := testSecpSecretScalar(t, big.NewInt(3))
	y := testSignedSecret(t, big.NewInt(5), signedPowerOfTwoBytes(params.EllPrime))
	c, cRandomness, err := sk0.EncryptSecret(testutil.DeterministicReader(2910), x)
	if err != nil {
		t.Fatal(err)
	}
	cRandomness.Destroy()
	d, rho, err := sk0.EncryptSignedSecret(testutil.DeterministicReader(2911), y)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rho.Destroy)
	yCiphertext, mu, err := sk1.EncryptSignedSecret(testutil.DeterministicReader(2912), y)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mu.Destroy)
	xEncoded := x.FixedBytes()
	defer clear(xEncoded)
	xScalar, err := secp.ScalarFromBytes(xEncoded)
	if err != nil {
		t.Fatal(err)
	}
	defer xScalar.Set(secp.ScalarZero())
	stmt := AffGStarStatement{
		ReceiverPaillierN: sk0.PublicKey,
		ProverPaillierN:   sk1.PublicKey,
		C:                 c,
		D:                 d, // Deliberately omits C^x.
		Y:                 yCiphertext,
		X:                 secp.ScalarBaseMult(xScalar),
	}
	if _, err := ProveAffGStar(params, []byte("state"), stmt,
		AffGStarWitness{X: x, Y: y, Rho: rho, Mu: mu},
		testutil.DeterministicReader(2913),
	); err == nil {
		t.Fatal("invalid affine witness relation was accepted")
	}
}
