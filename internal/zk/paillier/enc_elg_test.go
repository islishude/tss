package paillier

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestEncElgProofCompletenessAndCanonicalWire(t *testing.T) {
	params, stmt, witness := testEncElgRelation(t)
	state := []byte("enc-elg-session")
	proof, err := ProveEncElg(params, state, stmt, witness, testutil.DeterministicReader(2401))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncElg(params, state, stmt, proof); err != nil {
		t.Fatalf("verify valid proof: %v", err)
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded EncElgProof
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncElg(params, state, stmt, &decoded); err != nil {
		t.Fatalf("verify decoded proof: %v", err)
	}
	reencoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(reencoded) {
		t.Fatal("EncElgProof did not re-encode canonically")
	}

	clone := proof.Clone()
	clone.ElGamalCommitment[0] ^= 1
	if string(clone.ElGamalCommitment) == string(proof.ElGamalCommitment) {
		t.Fatal("Clone aliases point encoding")
	}
	clone.Destroy()
	if clone.PlaintextCommitment != nil || clone.ElGamalCommitment != nil || clone.TranscriptHash != nil {
		t.Fatal("Destroy did not release proof fields")
	}
}

func TestEncElgProofRejectsMutationsAndRangeBoundary(t *testing.T) {
	params, stmt, witness := testEncElgRelation(t)
	state := []byte("enc-elg-session")
	proof, err := ProveEncElg(params, state, stmt, witness, testutil.DeterministicReader(2402))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncElg(params, []byte("other-session"), stmt, proof); err == nil {
		t.Fatal("accepted proof under a different state domain")
	}

	mutatedStatement := stmt
	mutatedStatement.CombinedCommitment = secp.Add(
		stmt.CombinedCommitment,
		secp.ScalarMult(stmt.Generator, secp.ScalarFromBigInt(big.NewInt(1))),
	)
	if err := VerifyEncElg(params, state, mutatedStatement, proof); err == nil {
		t.Fatal("accepted proof for a mutated combined commitment")
	}

	outOfRange := proof.Clone()
	outOfRange.PlaintextResponse = new(big.Int).Lsh(big.NewInt(1), uint(params.EncRange()+1))
	if err := VerifyEncElg(params, state, stmt, outOfRange); err == nil {
		t.Fatal("accepted plaintext response at excluded upper boundary")
	}

	nonCanonical := proof.Clone()
	nonCanonical.ExponentResponse = secp.Order().FillBytes(make([]byte, secp.ScalarSize))
	if err := nonCanonical.Validate(); err == nil {
		t.Fatal("accepted non-canonical exponent response")
	}
}

func TestEncElgProofRejectsWrongWitness(t *testing.T) {
	params, stmt, witness := testEncElgRelation(t)
	witness.Exponent = testSecpSecretScalar(t, big.NewInt(20))
	if _, err := ProveEncElg(params, nil, stmt, witness, testutil.DeterministicReader(2403)); err == nil {
		t.Fatal("accepted an exponent that does not open the statement")
	}
}

func TestEncElgProofRejectsNonCanonicalPositiveWireInteger(t *testing.T) {
	params, stmt, witness := testEncElgRelation(t)
	proof, err := ProveEncElg(params, nil, stmt, witness, testutil.DeterministicReader(2404))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := prependZeroToWireField(raw, encElgProofType, EncElgProof{}, "PlaintextCommitment")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinary[EncElgProof](mutated); err == nil {
		t.Fatal("accepted non-canonical positive integer")
	}
}

func testEncElgRelation(t *testing.T) (SecurityParams, EncElgStatement, EncElgWitness) {
	t.Helper()
	params := fastProofParams()
	sk := testPaillierKey(t, 512)
	aux, lambda, err := testIndependentRingPedersenParams(t, testutil.DeterministicReader(2400), sk)
	if err != nil {
		t.Fatal(err)
	}
	lambda.Destroy()
	x := big.NewInt(17)
	xSecret := testSecpSecretScalar(t, x)
	ciphertext, rho, err := sk.EncryptSecret(testutil.DeterministicReader(2399), xSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rho.Destroy)
	generator := secp.Clone(secp.G)
	elgamalBase := secp.ScalarMult(generator, secp.ScalarFromBigInt(big.NewInt(7)))
	a := secp.ScalarFromBigInt(big.NewInt(19))
	stmt := EncElgStatement{
		Generator:          generator,
		PaillierN:          sk.PublicKey,
		Ciphertext:         ciphertext,
		ElGamalBase:        elgamalBase,
		ExponentCommitment: secp.ScalarMult(generator, a),
		CombinedCommitment: secp.Add(
			secp.ScalarMult(elgamalBase, a),
			secp.ScalarMult(generator, secp.ScalarFromBigInt(x)),
		),
		VerifierAux: aux,
	}
	return params, stmt, EncElgWitness{
		Plaintext:  xSecret,
		Randomness: rho,
		Exponent:   testSecpSecretScalar(t, big.NewInt(19)),
	}
}
