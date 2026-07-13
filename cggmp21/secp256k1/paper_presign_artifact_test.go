package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestNormalizedPresignArtifactAllowsLocalZeroChi(t *testing.T) {
	signers := tss.PartySet{1, 2}
	gammaScalar := secp.ScalarFromUint64(7)
	gamma := secp.ScalarBaseMult(gammaScalar)
	gammaInverse, err := secp.ScalarInvert(gammaScalar)
	if err != nil {
		t.Fatal(err)
	}
	secretKey := secp.ScalarFromUint64(11)
	publicKey := secp.ScalarBaseMult(secretKey)

	k1 := secp.ScalarFromUint64(3)
	k2 := secp.ScalarSub(gammaInverse, k1)
	chi1 := secp.ScalarZero()
	chi2 := secp.ScalarMul(secretKey, gammaInverse)
	commitments := []normalizedPresignCommitment{
		makeNormalizedCommitment(t, 1, gamma, k1, chi1),
		makeNormalizedCommitment(t, 2, gamma, k2, chi2),
	}
	if len(commitments[0].STilde) != 0 {
		t.Fatal("zero local chi did not use the canonical identity encoding")
	}
	if err := validateNormalizedPresignArtifact(signers, commitments, 1, gamma, publicKey, k1, chi1); err != nil {
		t.Fatal(err)
	}

	message := secp.ScalarFromUint64(13)
	littleR := secp.ScalarFromFieldElement(gamma.X)
	sigma1 := secp.ScalarAdd(secp.ScalarMul(k1, message), secp.ScalarMul(chi1, littleR))
	sigma2 := secp.ScalarAdd(secp.ScalarMul(k2, message), secp.ScalarMul(chi2, littleR))
	if err := verifyFigure10Partial(gamma, commitments[0], message, littleR, sigma1); err != nil {
		t.Fatal(err)
	}
	if err := verifyFigure10Partial(gamma, commitments[1], message, littleR, sigma2); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizedPresignArtifactRejectsAggregateAndLocalMismatch(t *testing.T) {
	signers := tss.PartySet{1, 2}
	gammaScalar := secp.ScalarFromUint64(7)
	gamma := secp.ScalarBaseMult(gammaScalar)
	gammaInverse, err := secp.ScalarInvert(gammaScalar)
	if err != nil {
		t.Fatal(err)
	}
	secretKey := secp.ScalarFromUint64(11)
	publicKey := secp.ScalarBaseMult(secretKey)
	k1 := secp.ScalarFromUint64(3)
	k2 := secp.ScalarSub(gammaInverse, k1)
	chi1 := secp.ScalarZero()
	chi2 := secp.ScalarMul(secretKey, gammaInverse)
	valid := []normalizedPresignCommitment{
		makeNormalizedCommitment(t, 1, gamma, k1, chi1),
		makeNormalizedCommitment(t, 2, gamma, k2, chi2),
	}

	tests := []struct {
		name        string
		commitments []normalizedPresignCommitment
		k           secp.Scalar
		chi         secp.Scalar
	}{
		{name: "wrong order", commitments: []normalizedPresignCommitment{valid[1], valid[0]}, k: k1, chi: chi1},
		{name: "aggregate delta", commitments: []normalizedPresignCommitment{valid[0], makeNormalizedCommitment(t, 2, gamma, secp.ScalarAdd(k2, secp.ScalarOne()), chi2)}, k: k1, chi: chi1},
		{name: "aggregate chi", commitments: []normalizedPresignCommitment{valid[0], makeNormalizedCommitment(t, 2, gamma, k2, secp.ScalarAdd(chi2, secp.ScalarOne()))}, k: k1, chi: chi1},
		{name: "local opening", commitments: valid, k: secp.ScalarAdd(k1, secp.ScalarOne()), chi: chi1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateNormalizedPresignArtifact(signers, tc.commitments, 1, gamma, publicKey, tc.k, tc.chi); err == nil {
				t.Fatal("invalid normalized presign artifact accepted")
			}
		})
	}
}

func TestFigure10PartialRejectsInvalidSigma(t *testing.T) {
	gamma := secp.ScalarBaseMult(secp.ScalarFromUint64(7))
	k := secp.ScalarFromUint64(3)
	chi := secp.ScalarZero()
	commitment := makeNormalizedCommitment(t, 1, gamma, k, chi)
	message := secp.ScalarFromUint64(13)
	littleR := secp.ScalarFromFieldElement(gamma.X)
	sigma := secp.ScalarMul(k, message)
	if err := verifyFigure10Partial(gamma, commitment, message, littleR, secp.ScalarAdd(sigma, secp.ScalarOne())); err == nil {
		t.Fatal("invalid Figure 10 partial accepted")
	}
}

func makeNormalizedCommitment(t testing.TB, party tss.PartyID, gamma *secp.Point, k, chi secp.Scalar) normalizedPresignCommitment {
	t.Helper()
	delta, err := encodePresignGroupElement(secp.ScalarMult(gamma, k))
	if err != nil {
		t.Fatal(err)
	}
	sPoint, err := encodePresignGroupElement(secp.ScalarMult(gamma, chi))
	if err != nil {
		t.Fatal(err)
	}
	return normalizedPresignCommitment{Party: party, DeltaTilde: delta, STilde: sPoint}
}
