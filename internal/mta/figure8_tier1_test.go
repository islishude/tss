//go:build tier1

package mta

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestStartOpeningEncElgForVerifier(t *testing.T) {
	skA, _, rpA, _ := setupTestEnv(t)
	params := testSecurityParams()
	x := big.NewInt(17)
	exponentValue := big.NewInt(19)
	opening, err := Start(testutil.DeterministicReader(8101), testSecretScalar(t, x), skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	defer opening.Destroy()
	generator := secp.Clone(secp.G)
	base := secp.ScalarMult(generator, secp.ScalarFromUint64(7))
	exponent := secp.ScalarFromBigInt(exponentValue)
	exponentCommitment := secp.ScalarMult(generator, exponent)
	combined := secp.Add(
		secp.ScalarMult(base, exponent),
		secp.ScalarMult(generator, secp.ScalarFromBigInt(x)),
	)
	baseBytes, _ := secp.PointBytes(base)
	exponentBytes, _ := secp.PointBytes(exponentCommitment)
	combinedBytes, _ := secp.PointBytes(combined)
	proof, err := opening.ProveEncElgForVerifier(
		params,
		testutil.DeterministicReader(8102),
		[]byte("figure8-rid"),
		baseBytes,
		exponentBytes,
		combinedBytes,
		testSecretScalar(t, exponentValue),
		skA.PublicKey,
		rpA,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStartEncElg(
		params,
		[]byte("figure8-rid"),
		opening.Message,
		baseBytes,
		exponentBytes,
		combinedBytes,
		skA.PublicKey,
		rpA,
		proof,
	); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStartEncElg(
		params,
		[]byte("other-rid"),
		opening.Message,
		baseBytes,
		exponentBytes,
		combinedBytes,
		skA.PublicKey,
		rpA,
		proof,
	); err == nil {
		t.Fatal("enc-elg start proof verified under another RID")
	}
}

func TestRespondFigure8CompletenessAndCiphertextBinding(t *testing.T) {
	skA, skB, rpA, _ := setupTestEnv(t)
	params := testSecurityParams()
	a := big.NewInt(13)
	b := big.NewInt(37)
	start, err := Start(testutil.DeterministicReader(8201), testSecretScalar(t, a), skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	defer start.Destroy()
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, betaShare, err := RespondFigure8(
		params,
		testutil.DeterministicReader(8202),
		[]byte("figure8-response"),
		start.Message,
		testSecretScalar(t, b),
		bCommitment,
		skA.PublicKey,
		skB.PublicKey,
		rpA,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Destroy()
	defer betaShare.Destroy()
	if len(response.Ciphertext) == 0 || len(response.F) == 0 {
		t.Fatal("Figure 8 response omitted D or F")
	}
	alphaShare, err := Finish(
		params,
		[]byte("figure8-response"),
		start.Message,
		*response,
		bCommitment,
		skA,
		skB.PublicKey,
		rpA,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer alphaShare.Destroy()
	got := new(big.Int).Add(testSecretBig(t, alphaShare), testSecretBig(t, betaShare))
	got.Mod(got, secp.Order())
	want := new(big.Int).Mul(a, b)
	want.Mod(want, secp.Order())
	if got.Cmp(want) != 0 {
		t.Fatalf("Figure 8 MtA shares sum to %v, want %v", got, want)
	}

	badF := response.Clone()
	badF.F = bytes.Clone(response.Ciphertext)
	if err := VerifyResponse(params, []byte("figure8-response"), start.Message, badF, bCommitment, skA.PublicKey, skB.PublicKey, rpA); err == nil {
		t.Fatal("accepted response with mutated F")
	}
	badD := response.Clone()
	badD.Ciphertext = bytes.Clone(response.F)
	if err := VerifyResponse(params, []byte("figure8-response"), start.Message, badD, bCommitment, skA.PublicKey, skB.PublicKey, rpA); err == nil {
		t.Fatal("accepted response with mutated D")
	}
}
