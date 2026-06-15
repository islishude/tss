package mta

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestMTAProductShares(t *testing.T) {
	t.Parallel()
	params := testSecurityParams()
	skA, err := pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	skB, err := pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// Generate verifier-specific Ring-Pedersen params for both sides.
	rpA, _, err := zkpai.GenerateRingPedersenParams(nil, skA)
	if err != nil {
		t.Fatal(err)
	}
	rpB, _, err := zkpai.GenerateRingPedersenParams(nil, skB)
	if err != nil {
		t.Fatal(err)
	}
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	startDomain := []byte("start")
	responseDomain := []byte("response")
	start, err := Start(nil, a, &skA.PublicKey)
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
	legacyProof, err := zkpai.ProveEncryption(nil, startDomain, &skA.PublicKey, new(big.Int).SetBytes(start.Message.Ciphertext), start.k, start.rho) //nolint:staticcheck // verifies legacy proof rejection
	if err != nil {
		t.Fatal(err)
	}
	legacyProofBytes, err := zkpai.Marshal(legacyProof)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStart(params, startDomain, start.Message, &skA.PublicKey, *rpB, legacyProofBytes); err == nil {
		t.Fatal("legacy encryption proof verified as EncProof")
	}
	response, betaShare, err := Respond(params, nil, startDomain, responseDomain, start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Respond(params, nil, startDomain, responseDomain, start.Message, nil, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA); err == nil {
		t.Fatal("missing start proof accepted")
	}
	if _, _, err := Respond(params, nil, startDomain, responseDomain, start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpA, *rpA); err == nil {
		t.Fatal("start proof for different verifier accepted")
	}
	alphaShare, err := Finish(params, responseDomain, start.Message, *response, bCommit, skA, &skB.PublicKey, *rpA)
	if err != nil {
		t.Fatal(err)
	}
	got := new(big.Int).Add(alphaShare, betaShare)
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
	startDecoded, err := UnmarshalStartMessage(startRaw)
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
	responseDecoded, err := UnmarshalResponseMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseDecoded.Proof, response.Proof) {
		t.Fatal("MtA response mismatch after round trip")
	}
	if _, err := UnmarshalStartMessage([]byte(`{"ciphertext":"AQ=="}`)); err == nil {
		t.Fatal("JSON MtA start decoded")
	}
	if _, err := UnmarshalResponseMessage([]byte(`{"ciphertext":"AQ=="}`)); err == nil {
		t.Fatal("JSON MtA response decoded")
	}
	response.Proof[0] ^= 1
	if _, err := Finish(params, responseDomain, start.Message, *response, bCommit, skA, &skB.PublicKey, *rpA); err == nil {
		t.Fatal("tampered response proof verified")
	}
}
