package mta

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestMTAProductShares(t *testing.T) {
	t.Parallel()
	params := testSecurityParams()
	skA, skB, rpA, rpB := setupTestEnv(t)
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	startDomain := []byte("start")
	responseDomain := []byte("response")
	aSecret := testSecretScalar(t, a)
	bSecret := testSecretScalar(t, b)
	start, err := Start(nil, aSecret, &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(params, nil, startDomain, start, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStart(params, startDomain, start.Message, &skA.PublicKey, *rpB, startProof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStart(params, []byte("other-start"), start.Message, &skA.PublicKey, *rpB, startProof); err == nil {
		t.Fatal("start proof verified under wrong domain")
	}
	if err := VerifyStart(params, startDomain, start.Message, &skA.PublicKey, *rpA, startProof); err == nil {
		t.Fatal("start proof verified for wrong verifier aux")
	}
	response, betaShare, err := Respond(params, nil, startDomain, responseDomain, start.Message, startProof, bSecret, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Respond(params, nil, startDomain, responseDomain, start.Message, nil, bSecret, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA); err == nil {
		t.Fatal("missing start proof accepted")
	}
	if _, _, err := Respond(params, nil, startDomain, responseDomain, start.Message, startProof, bSecret, bCommit, &skA.PublicKey, &skB.PublicKey, *rpA, *rpA); err == nil {
		t.Fatal("start proof for different verifier accepted")
	}
	alphaShare, err := Finish(params, responseDomain, start.Message, *response, bCommit, skA, &skB.PublicKey, *rpA)
	if err != nil {
		t.Fatal(err)
	}
	alphaBig := testSecretBig(t, alphaShare)
	betaBig := testSecretBig(t, betaShare)
	got := new(big.Int).Add(alphaBig, betaBig)
	got.Mod(got, secp.Order())
	want := new(big.Int).Mul(a, b)
	want.Mod(want, secp.Order())
	if got.Cmp(want) != 0 {
		t.Fatalf("alpha+beta = %s, want %s", got, want)
	}
	startRaw, err := start.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	startRaw2, err := start.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(startRaw, startRaw2) {
		t.Fatal("MtA start encoding is not deterministic")
	}
	startDecoded, err := tss.DecodeBinary[StartMessage](startRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(startDecoded.Ciphertext, start.Message.Ciphertext) {
		t.Fatal("MtA start mismatch after round trip")
	}
	responseRaw, err := response.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	responseDecoded, err := tss.DecodeBinary[ResponseMessage](responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	decodedProofRaw, err := responseDecoded.Proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	responseProofRaw, err := response.Proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedProofRaw, responseProofRaw) {
		t.Fatal("MtA response mismatch after round trip")
	}
	if _, err := tss.DecodeBinary[StartMessage]([]byte(`{"ciphertext":"AQ=="}`)); err == nil {
		t.Fatal("JSON MtA start decoded")
	}
	if _, err := tss.DecodeBinary[ResponseMessage]([]byte(`{"ciphertext":"AQ=="}`)); err == nil {
		t.Fatal("JSON MtA response decoded")
	}
	response.Proof.TranscriptHash[0] ^= 1
	if _, err := Finish(params, responseDomain, start.Message, *response, bCommit, skA, &skB.PublicKey, *rpA); err == nil {
		t.Fatal("tampered response proof verified")
	}
}
