//go:build tier1

package paillier

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestNewProofUnmarshalRejectsNonCanonicalPositiveIntegers(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 1024)
	params := SecurityParams{
		Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 1024,
	}
	aux, _, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}

	k := big.NewInt(17)
	ciphertextK, rhoK, err := sk.Encrypt(nil, k)
	if err != nil {
		t.Fatal(err)
	}
	encStmt := EncStatement{
		ProverPaillierN: sk.PublicKey,
		CiphertextK:     ciphertextK,
		VerifierAux:     aux,
	}
	encProof, err := ProveEnc(params, []byte("enc canonical"), encStmt, EncWitness{
		K:   testSecpSecretScalar(t, k),
		Rho: testSecretScalarFixed(t, rhoK, modulusBytes(sk.N)),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnc(params, []byte("enc canonical"), encStmt, encProof); err != nil {
		t.Fatal(err)
	}
	encRaw, err := encProof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"S", "A", "C", "Z2"} {
		t.Run(fmt.Sprintf("enc field %s", name), func(t *testing.T) {
			mutated, err := prependZeroToWireField(encRaw, encProofType, EncProof{}, name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tss.DecodeBinary[EncProof](mutated); err == nil {
				t.Fatal("EncProof accepted non-canonical positive integer")
			}
		})
	}

	x := big.NewInt(23)
	y := big.NewInt(29)
	encX, _, err := sk.Encrypt(nil, x)
	if err != nil {
		t.Fatal(err)
	}
	encYReceiver, rhoYReceiver, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	xMulC, err := OMulCT(
		sk.PublicKey,
		testSignedSecret(t, x, signedPowerOfTwoBytes(params.Ell)),
		encX,
		signedPowerOfTwoBytes(params.Ell),
	)
	if err != nil {
		t.Fatal(err)
	}
	responseD, err := OAdd(sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	encYProver, rhoYProver, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	affGStmt := AffGStatement{
		ReceiverPaillierN: sk.PublicKey,
		ProverPaillierN:   sk.PublicKey,
		C:                 encX,
		D:                 responseD,
		Y:                 encYProver,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		K:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		VerifierAux:       aux,
	}
	affGProof, err := ProveAffG(params, []byte("affg canonical"), affGStmt, AffGWitness{
		X:    testSecpSecretScalar(t, x),
		Y:    testSignedSecret(t, y, signedPowerOfTwoBytes(params.EllPrime)),
		Rho:  testSecretScalarFixed(t, rhoYReceiver, modulusBytes(sk.N)),
		RhoY: testSecretScalarFixed(t, rhoYProver, modulusBytes(sk.N)),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAffG(params, []byte("affg canonical"), affGStmt, affGProof); err != nil {
		t.Fatal(err)
	}
	affGRaw, err := affGProof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"A", "By", "E", "S",
		"F", "T", "Y", "W", "WY",
	} {
		t.Run(fmt.Sprintf("affg field %s", name), func(t *testing.T) {
			mutated, err := prependZeroToWireField(affGRaw, affGProofType, AffGProof{}, name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tss.DecodeBinary[AffGProof](mutated); err == nil {
				t.Fatal("AffGProof accepted non-canonical positive integer")
			}
		})
	}

	logX := big.NewInt(31)
	logC, logRho, err := sk.Encrypt(nil, logX)
	if err != nil {
		t.Fatal(err)
	}
	logStmt := LogStarStatement{
		PaillierN:   sk.PublicKey,
		C:           logC,
		X:           secp.ScalarBaseMult(secp.ScalarFromBigInt(logX)),
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: aux,
	}
	logProof, err := ProveLogStar(params, []byte("logstar canonical"), logStmt, LogStarWitness{
		X:   testSecpSecretScalar(t, logX),
		Rho: testSecretScalarFixed(t, logRho, modulusBytes(sk.N)),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLogStar(params, []byte("logstar canonical"), logStmt, logProof); err != nil {
		t.Fatal(err)
	}
	logRaw, err := logProof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"S", "A", "D", "Z2"} {
		t.Run(fmt.Sprintf("logstar field %s", name), func(t *testing.T) {
			mutated, err := prependZeroToWireField(logRaw, logStarProofType, LogStarProof{}, name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tss.DecodeBinary[LogStarProof](mutated); err == nil {
				t.Fatal("LogStarProof accepted non-canonical positive integer")
			}
		})
	}
}
