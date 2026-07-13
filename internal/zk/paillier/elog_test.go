package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestElogProofCompletenessAndCanonicalWire(t *testing.T) {
	stmt, witness := testElogRelation(t)
	proof, err := ProveElog([]byte("elog-session"), stmt, witness, testutil.DeterministicReader(2301))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyElog([]byte("elog-session"), stmt, proof); err != nil {
		t.Fatalf("verify valid proof: %v", err)
	}

	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded ElogProof
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if err := VerifyElog([]byte("elog-session"), stmt, &decoded); err != nil {
		t.Fatalf("verify decoded proof: %v", err)
	}
	reencoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(reencoded) {
		t.Fatal("ElogProof did not re-encode canonically")
	}

	clone := proof.Clone()
	clone.A[0] ^= 1
	if string(clone.A) == string(proof.A) {
		t.Fatal("Clone aliases commitment bytes")
	}
	clone.Destroy()
	if clone.A != nil || clone.Z != nil || clone.TranscriptHash != nil {
		t.Fatal("Destroy did not release proof fields")
	}
}

func TestElogProofRejectsDomainAndStatementMutation(t *testing.T) {
	stmt, witness := testElogRelation(t)
	proof, err := ProveElog([]byte("elog-session"), stmt, witness, testutil.DeterministicReader(2302))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyElog([]byte("other-session"), stmt, proof); err == nil {
		t.Fatal("accepted proof under a different state domain")
	}

	mutated := stmt
	mutated.ElGamalCommitment = secp.Add(stmt.ElGamalCommitment, secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	if err := VerifyElog([]byte("elog-session"), mutated, proof); err == nil {
		t.Fatal("accepted proof for a mutated ElGamal commitment")
	}

	bad := proof.Clone()
	bad.Z = make([]byte, secp.ScalarSize)
	order := secp.Order()
	order.FillBytes(bad.Z)
	if err := bad.Validate(); err == nil {
		t.Fatal("accepted non-canonical response scalar")
	}
}

func TestElogProofRejectsMismatchedWitness(t *testing.T) {
	stmt, witness := testElogRelation(t)
	witness.Y = testSecpSecretScalar(t, big.NewInt(14))
	if _, err := ProveElog(nil, stmt, witness, testutil.DeterministicReader(2303)); err == nil {
		t.Fatal("accepted mismatched y witness")
	}
}

func testElogRelation(t *testing.T) (ElogStatement, ElogWitness) {
	t.Helper()
	g := secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1)))
	h := secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(7)))
	x := secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(11)))
	y := secp.ScalarFromBigInt(big.NewInt(13))
	lambda := secp.ScalarFromBigInt(big.NewInt(17))
	return ElogStatement{
			Generator:         g,
			LambdaCommitment:  secp.ScalarMult(g, lambda),
			ElGamalCommitment: secp.Add(secp.ScalarMult(g, y), secp.ScalarMult(x, lambda)),
			ElGamalBase:       x,
			ResultCommitment:  secp.ScalarMult(h, y),
			ResultBase:        h,
		}, ElogWitness{
			Y:      testSecpSecretScalar(t, big.NewInt(13)),
			Lambda: testSecpSecretScalar(t, big.NewInt(17)),
		}
}
