package paillier

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestEncryptedScalarProofTamper(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.PublicKey.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	encProof, rangeProof, err := ProveEncScalarAndRange(nil, []byte("domain"), &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncScalarAndRange([]byte("domain"), &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("proof did not verify")
	}
	encProof.Response[0] ^= 1
	if VerifyEncScalarAndRange([]byte("domain"), &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("tampered enc proof verified")
	}
	encProof.Response[0] ^= 1
	rangeProof.Digest[0] ^= 1
	if VerifyEncScalarAndRange([]byte("domain"), &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("tampered range proof verified")
	}
}

func TestModulusProofTamper(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(512)
	defer restore()
	sk, err := pai.GenerateKey(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveModulus([]byte("domain"), &sk.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyModulus([]byte("domain"), &sk.PublicKey, 1, proof) {
		t.Fatal("modulus proof did not verify")
	}
	if VerifyModulus([]byte("other"), &sk.PublicKey, 1, proof) {
		t.Fatal("modulus proof verified under wrong domain")
	}
	proof.Digest[0] ^= 1
	if VerifyModulus([]byte("domain"), &sk.PublicKey, 1, proof) {
		t.Fatal("tampered modulus proof verified")
	}
}

func TestProofMarshalCanonicalBinary(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("canonical proof domain")

	modProof, err := ProveModulus(domain, &sk.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertModulusProofRoundTrip(t, modProof)
	if _, err := UnmarshalModulusProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON modulus proof fallback was accepted")
	}
	if _, err := UnmarshalEncScalarProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON encrypted scalar proof fallback was accepted")
	}
	if _, err := UnmarshalEncRangeProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON encrypted range proof fallback was accepted")
	}
	if _, err := UnmarshalMTAResponseProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON MtA response proof fallback was accepted")
	}

	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.PublicKey.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	encProof, rangeProof, err := ProveEncScalarAndRange(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	assertEncScalarProofRoundTrip(t, encProof)
	assertEncRangeProofRoundTrip(t, rangeProof)

	b := big.NewInt(17)
	beta := big.NewInt(19)
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	encBeta, betaRandomness, err := sk.PublicKey.Encrypt(nil, beta)
	if err != nil {
		t.Fatal(err)
	}
	response := new(big.Int).Exp(ciphertext, b, sk.NSquared)
	response.Mul(response, encBeta)
	response.Mod(response, sk.NSquared)
	mtaProof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, ciphertext, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	assertMTAResponseProofRoundTrip(t, mtaProof)
	if !VerifyMTAResponse(domain, &sk.PublicKey, ciphertext, response, bCommitment, mtaProof) {
		t.Fatal("MtA response proof did not verify")
	}
}

func TestMTAResponseProofFieldTamper(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("mta tamper")
	a := big.NewInt(23)
	b := big.NewInt(29)
	beta := big.NewInt(31)
	encA, _, err := sk.PublicKey.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	encBeta, betaRandomness, err := sk.PublicKey.Encrypt(nil, beta)
	if err != nil {
		t.Fatal(err)
	}
	response := new(big.Int).Exp(encA, b, sk.NSquared)
	response.Mul(response, encBeta)
	response.Mod(response, sk.NSquared)
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
			tampered := cloneMTAResponseProof(proof)
			tc.mutate(tampered)
			if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
				t.Fatal("tampered MtA response proof verified")
			}
		})
	}
}

func assertModulusProofRoundTrip(t *testing.T, proof *ModulusProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("TSS1")) {
		t.Fatal("modulus proof was not binary TLV")
	}
	decoded, err := UnmarshalModulusProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("modulus proof encoding is not deterministic")
	}
	if _, err := UnmarshalModulusProof(append(raw, 0)); err == nil {
		t.Fatal("modulus proof accepted trailing bytes")
	}
}

func assertEncScalarProofRoundTrip(t *testing.T, proof *EncScalarProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEncScalarProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("encrypted scalar proof encoding is not deterministic")
	}
	if _, err := UnmarshalEncScalarProof(append(raw, 0)); err == nil {
		t.Fatal("encrypted scalar proof accepted trailing bytes")
	}
}

func assertEncRangeProofRoundTrip(t *testing.T, proof *EncRangeProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEncRangeProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("encrypted range proof encoding is not deterministic")
	}
	if _, err := UnmarshalEncRangeProof(append(raw, 0)); err == nil {
		t.Fatal("encrypted range proof accepted trailing bytes")
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

func cloneMTAResponseProof(in *MTAResponseProof) *MTAResponseProof {
	out := *in
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	out.BetaCommitment = append([]byte(nil), in.BetaCommitment...)
	out.CipherCommitment = append([]byte(nil), in.CipherCommitment...)
	out.BCommitment = append([]byte(nil), in.BCommitment...)
	out.BetaNonce = append([]byte(nil), in.BetaNonce...)
	out.BResponse = append([]byte(nil), in.BResponse...)
	out.BetaResponse = append([]byte(nil), in.BetaResponse...)
	out.Randomness = append([]byte(nil), in.Randomness...)
	return &out
}
