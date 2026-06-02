package mta

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestMTAProductShares(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(context.Background(), nil, 1024)
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
	start, err := Start(nil, startDomain, a, &sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	response, betaShare, err := Respond(nil, startDomain, responseDomain, *start, b, bCommit, &sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	alphaShare, err := Finish(startDomain, responseDomain, *start, *response, bCommit, sk)
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
	startRaw, err := start.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	startRaw2, err := start.MarshalBinary()
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
	if !bytes.Equal(startDecoded.Ciphertext, start.Ciphertext) {
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
	if _, err := Finish(startDomain, responseDomain, *start, *response, bCommit, sk); err == nil {
		t.Fatal("tampered response proof verified")
	}
}

func FuzzStartMessageUnmarshal(f *testing.F) {
	start, response := seedMessages(f)
	_ = response
	raw, err := start.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"ciphertext":"AQ=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalStartMessage(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, m, (*StartMessage).MarshalBinary, UnmarshalStartMessage)
	})
}

func FuzzResponseMessageUnmarshal(f *testing.F) {
	_, response := seedMessages(f)
	raw, err := response.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"ciphertext":"AQ=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalResponseMessage(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, m, (*ResponseMessage).MarshalBinary, UnmarshalResponseMessage)
	})
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
}

func seedMessages(tb testing.TB) (*StartMessage, *ResponseMessage) {
	tb.Helper()
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		tb.Fatal(err)
	}
	start, err := Start(nil, []byte("start"), a, &sk.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	response, _, err := Respond(nil, []byte("start"), []byte("response"), *start, b, bCommit, &sk.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	return start, response
}
