package paillier

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
)

func TestEncryptedScalarProofTamper(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
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
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
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
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
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

	encProofBytes, err := Marshal(encProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalEncRangeProof(encProofBytes); err == nil {
		t.Fatal("encrypted scalar proof decoded as range proof")
	}
	rangeProofBytes, err := Marshal(rangeProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalMTAResponseProof(rangeProofBytes); err == nil {
		t.Fatal("range proof decoded as MtA response proof")
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
	encA, _, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
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

func TestProofDomainSeparation(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("proof domain")
	otherDomain := []byte("other proof domain")

	modProof, err := ProveModulus(domain, &sk.PublicKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyModulus(domain, &sk.PublicKey, 7, modProof) {
		t.Fatal("modulus proof did not verify")
	}
	if VerifyModulus(otherDomain, &sk.PublicKey, 7, modProof) {
		t.Fatal("modulus proof verified under wrong domain")
	}
	if VerifyModulus(domain, &sk.PublicKey, 8, modProof) {
		t.Fatal("modulus proof verified under wrong party")
	}

	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	encProof, rangeProof, err := ProveEncScalarAndRange(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncScalarAndRange(domain, &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("encrypted scalar proof did not verify")
	}
	if VerifyEncScalarAndRange(otherDomain, &sk.PublicKey, ciphertext, encProof, rangeProof) {
		t.Fatal("encrypted scalar proof verified under wrong domain")
	}

	b := big.NewInt(17)
	beta := big.NewInt(19)
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
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
	if !VerifyMTAResponse(domain, &sk.PublicKey, ciphertext, response, bCommitment, mtaProof) {
		t.Fatal("MtA response proof did not verify")
	}
	if VerifyMTAResponse(otherDomain, &sk.PublicKey, ciphertext, response, bCommitment, mtaProof) {
		t.Fatal("MtA response proof verified under wrong domain")
	}
}

func TestProofRejectsNonMinimalIntegerEncodings(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("minimal integers")
	a := big.NewInt(23)
	b := big.NewInt(29)
	beta := big.NewInt(31)
	encA, randomness, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	encProof, rangeProof, err := ProveEncScalarAndRange(nil, domain, &sk.PublicKey, encA, a, randomness)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
	if err != nil {
		t.Fatal(err)
	}
	response := new(big.Int).Exp(encA, b, sk.NSquared)
	response.Mul(response, encBeta)
	response.Mod(response, sk.NSquared)
	mtaProof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("encrypted scalar", func(t *testing.T) {
		tampered := *encProof
		tampered.CipherCommitment = prependZero(tampered.CipherCommitment)
		if VerifyEncScalar(domain, &sk.PublicKey, encA, &tampered) {
			t.Fatal("non-minimal encrypted scalar proof verified")
		}
		if _, err := Marshal(&tampered); err == nil {
			t.Fatal("non-minimal encrypted scalar proof marshaled")
		}
		raw := mustWireProof(t, encScalarProofWireType, []wire.Field{
			{Tag: encScalarProofFieldScalarCommitment, Value: tampered.ScalarCommitment},
			{Tag: encScalarProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: encScalarProofFieldPointCommitment, Value: tampered.PointCommitment},
			{Tag: encScalarProofFieldResponse, Value: tampered.Response},
			{Tag: encScalarProofFieldRandomness, Value: tampered.Randomness},
			{Tag: encScalarProofFieldTranscriptHash, Value: tampered.TranscriptHash},
		})
		if _, err := UnmarshalEncScalarProof(raw); err == nil {
			t.Fatal("non-minimal encrypted scalar proof decoded")
		}
	})

	t.Run("encrypted range", func(t *testing.T) {
		tampered := *rangeProof
		tampered.Response = prependZero(tampered.Response)
		if VerifyEncScalarAndRange(domain, &sk.PublicKey, encA, encProof, &tampered) {
			t.Fatal("non-minimal range proof verified")
		}
		if _, err := Marshal(&tampered); err == nil {
			t.Fatal("non-minimal range proof marshaled")
		}
		raw := mustWireProof(t, encRangeProofWireType, []wire.Field{
			{Tag: encRangeProofFieldBound, Value: tampered.Bound},
			{Tag: encRangeProofFieldChallenge, Value: tampered.Challenge},
			{Tag: encRangeProofFieldResponse, Value: tampered.Response},
			{Tag: encRangeProofFieldTranscriptHash, Value: tampered.TranscriptHash},
			{Tag: encRangeProofFieldDigest, Value: tampered.Digest},
		})
		if _, err := UnmarshalEncRangeProof(raw); err == nil {
			t.Fatal("non-minimal range proof decoded")
		}
	})

	t.Run("mta response", func(t *testing.T) {
		tampered := cloneMTAResponseProof(mtaProof)
		tampered.BResponse = prependZero(tampered.BResponse)
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
			t.Fatal("non-minimal MtA response proof verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("non-minimal MtA response proof marshaled")
		}
		raw := mustWireProof(t, mtaResponseProofWireType, []wire.Field{
			{Tag: mtaResponseProofFieldTranscriptHash, Value: tampered.TranscriptHash},
			{Tag: mtaResponseProofFieldBetaCommitment, Value: tampered.BetaCommitment},
			{Tag: mtaResponseProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: mtaResponseProofFieldBCommitment, Value: tampered.BCommitment},
			{Tag: mtaResponseProofFieldBetaNonce, Value: tampered.BetaNonce},
			{Tag: mtaResponseProofFieldBResponse, Value: tampered.BResponse},
			{Tag: mtaResponseProofFieldBetaResponse, Value: tampered.BetaResponse},
			{Tag: mtaResponseProofFieldRandomness, Value: tampered.Randomness},
		})
		if _, err := UnmarshalMTAResponseProof(raw); err == nil {
			t.Fatal("non-minimal MtA response proof decoded")
		}
	})
}

func TestProofRejectsMalformedCurvePoints(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(1024)
	defer restore()
	sk, err := pai.GenerateKey(nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("malformed points")
	a := big.NewInt(23)
	b := big.NewInt(29)
	beta := big.NewInt(31)
	encA, randomness, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	encProof, _, err := ProveEncScalarAndRange(nil, domain, &sk.PublicKey, encA, a, randomness)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(b))
	if err != nil {
		t.Fatal(err)
	}
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
	if err != nil {
		t.Fatal(err)
	}
	response := new(big.Int).Exp(encA, b, sk.NSquared)
	response.Mul(response, encBeta)
	response.Mod(response, sk.NSquared)
	mtaProof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	malformedPoint := []byte{0x02}

	t.Run("encrypted scalar commitment", func(t *testing.T) {
		tampered := *encProof
		tampered.ScalarCommitment = malformedPoint
		if VerifyEncScalar(domain, &sk.PublicKey, encA, &tampered) {
			t.Fatal("malformed scalar commitment verified")
		}
		if _, err := Marshal(&tampered); err == nil {
			t.Fatal("malformed scalar commitment marshaled")
		}
		raw := mustWireProof(t, encScalarProofWireType, []wire.Field{
			{Tag: encScalarProofFieldScalarCommitment, Value: tampered.ScalarCommitment},
			{Tag: encScalarProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: encScalarProofFieldPointCommitment, Value: tampered.PointCommitment},
			{Tag: encScalarProofFieldResponse, Value: tampered.Response},
			{Tag: encScalarProofFieldRandomness, Value: tampered.Randomness},
			{Tag: encScalarProofFieldTranscriptHash, Value: tampered.TranscriptHash},
		})
		if _, err := UnmarshalEncScalarProof(raw); err == nil {
			t.Fatal("malformed scalar commitment decoded")
		}
	})

	t.Run("encrypted scalar nonce", func(t *testing.T) {
		tampered := *encProof
		tampered.PointCommitment = malformedPoint
		if VerifyEncScalar(domain, &sk.PublicKey, encA, &tampered) {
			t.Fatal("malformed point commitment verified")
		}
		if _, err := Marshal(&tampered); err == nil {
			t.Fatal("malformed point commitment marshaled")
		}
		raw := mustWireProof(t, encScalarProofWireType, []wire.Field{
			{Tag: encScalarProofFieldScalarCommitment, Value: tampered.ScalarCommitment},
			{Tag: encScalarProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: encScalarProofFieldPointCommitment, Value: tampered.PointCommitment},
			{Tag: encScalarProofFieldResponse, Value: tampered.Response},
			{Tag: encScalarProofFieldRandomness, Value: tampered.Randomness},
			{Tag: encScalarProofFieldTranscriptHash, Value: tampered.TranscriptHash},
		})
		if _, err := UnmarshalEncScalarProof(raw); err == nil {
			t.Fatal("malformed point commitment decoded")
		}
	})

	t.Run("mta beta commitment", func(t *testing.T) {
		tampered := cloneMTAResponseProof(mtaProof)
		tampered.BetaCommitment = malformedPoint
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
			t.Fatal("malformed beta commitment verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("malformed beta commitment marshaled")
		}
		raw := mustWireProof(t, mtaResponseProofWireType, []wire.Field{
			{Tag: mtaResponseProofFieldTranscriptHash, Value: tampered.TranscriptHash},
			{Tag: mtaResponseProofFieldBetaCommitment, Value: tampered.BetaCommitment},
			{Tag: mtaResponseProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: mtaResponseProofFieldBCommitment, Value: tampered.BCommitment},
			{Tag: mtaResponseProofFieldBetaNonce, Value: tampered.BetaNonce},
			{Tag: mtaResponseProofFieldBResponse, Value: tampered.BResponse},
			{Tag: mtaResponseProofFieldBetaResponse, Value: tampered.BetaResponse},
			{Tag: mtaResponseProofFieldRandomness, Value: tampered.Randomness},
		})
		if _, err := UnmarshalMTAResponseProof(raw); err == nil {
			t.Fatal("malformed beta commitment decoded")
		}
	})

	t.Run("mta b nonce", func(t *testing.T) {
		tampered := cloneMTAResponseProof(mtaProof)
		tampered.BCommitment = malformedPoint
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
			t.Fatal("malformed b nonce verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("malformed b nonce marshaled")
		}
		raw := mustWireProof(t, mtaResponseProofWireType, []wire.Field{
			{Tag: mtaResponseProofFieldTranscriptHash, Value: tampered.TranscriptHash},
			{Tag: mtaResponseProofFieldBetaCommitment, Value: tampered.BetaCommitment},
			{Tag: mtaResponseProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: mtaResponseProofFieldBCommitment, Value: tampered.BCommitment},
			{Tag: mtaResponseProofFieldBetaNonce, Value: tampered.BetaNonce},
			{Tag: mtaResponseProofFieldBResponse, Value: tampered.BResponse},
			{Tag: mtaResponseProofFieldBetaResponse, Value: tampered.BetaResponse},
			{Tag: mtaResponseProofFieldRandomness, Value: tampered.Randomness},
		})
		if _, err := UnmarshalMTAResponseProof(raw); err == nil {
			t.Fatal("malformed b nonce decoded")
		}
	})

	t.Run("mta beta nonce", func(t *testing.T) {
		tampered := cloneMTAResponseProof(mtaProof)
		tampered.BetaNonce = malformedPoint
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
			t.Fatal("malformed beta nonce verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("malformed beta nonce marshaled")
		}
		raw := mustWireProof(t, mtaResponseProofWireType, []wire.Field{
			{Tag: mtaResponseProofFieldTranscriptHash, Value: tampered.TranscriptHash},
			{Tag: mtaResponseProofFieldBetaCommitment, Value: tampered.BetaCommitment},
			{Tag: mtaResponseProofFieldCipherCommitment, Value: tampered.CipherCommitment},
			{Tag: mtaResponseProofFieldBCommitment, Value: tampered.BCommitment},
			{Tag: mtaResponseProofFieldBetaNonce, Value: tampered.BetaNonce},
			{Tag: mtaResponseProofFieldBResponse, Value: tampered.BResponse},
			{Tag: mtaResponseProofFieldBetaResponse, Value: tampered.BetaResponse},
			{Tag: mtaResponseProofFieldRandomness, Value: tampered.Randomness},
		})
		if _, err := UnmarshalMTAResponseProof(raw); err == nil {
			t.Fatal("malformed beta nonce decoded")
		}
	})
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

func prependZero(in []byte) []byte {
	out := make([]byte, 0, len(in)+1)
	out = append(out, 0)
	out = append(out, in...)
	return out
}

func mustWireProof(t *testing.T, typeID string, fields []wire.Field) []byte {
	t.Helper()
	raw, err := wire.Marshal(proofVersion, typeID, fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
