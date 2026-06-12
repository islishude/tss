//go:build tier1

package paillier

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestMTAResponseProofFieldTamper(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 1024)
	domain := []byte("mta tamper")
	a := big.NewInt(23)
	b := big.NewInt(29)
	beta := big.NewInt(31)
	encA, _, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, betaRandomness := mtaResponseForTest(t, sk, encA, b, beta)
	proof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*MTAResponseProof)
	}{
		{name: "transcript", mutate: func(p *MTAResponseProof) { p.TranscriptHash[0] ^= 1 }},
		{name: "beta commitment", mutate: func(p *MTAResponseProof) { p.BetaCommitment[0] ^= 1 }},
		{name: "cipher commitment", mutate: func(p *MTAResponseProof) { p.CipherCommitment[0] ^= 1 }},
		{name: "b commitment", mutate: func(p *MTAResponseProof) { p.BCommitment[0] ^= 1 }},
		{name: "beta nonce", mutate: func(p *MTAResponseProof) { p.BetaNonce[0] ^= 1 }},
		{name: "b response", mutate: func(p *MTAResponseProof) { p.BResponse[0] ^= 1 }},
		{name: "beta response", mutate: func(p *MTAResponseProof) { p.BetaResponse[0] ^= 1 }},
		{name: "randomness", mutate: func(p *MTAResponseProof) { p.Randomness[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := proof.Clone()
			tc.mutate(tampered)
			if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
				t.Fatal("tampered MtA response proof verified")
			}
		})
	}
}

func assertMTAResponseProofRoundTrip(t *testing.T, proof *MTAResponseProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalMTAResponseProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("MtA response proof encoding is not deterministic")
	}
	if _, err := UnmarshalMTAResponseProof(append(raw, 0)); err == nil {
		t.Fatal("MtA response proof accepted trailing bytes")
	}
}
