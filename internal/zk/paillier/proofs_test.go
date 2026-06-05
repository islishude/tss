package paillier

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/wire"
)

func TestEncryptionProofTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	domain := []byte("encryption proof")
	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveEncryption(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEncryption(domain, &sk.PublicKey, ciphertext, proof) {
		t.Fatal("encryption proof did not verify")
	}
	if VerifyEncryption([]byte("other domain"), &sk.PublicKey, ciphertext, proof) {
		t.Fatal("encryption proof verified under wrong domain")
	}
	tampered := cloneEncryptionProof(proof)
	tampered.Response[0] ^= 1
	if VerifyEncryption(domain, &sk.PublicKey, ciphertext, tampered) {
		t.Fatal("tampered encryption proof verified")
	}
	if VerifyEncryption(domain, &sk.PublicKey, sk.NSquared, proof) {
		t.Fatal("invalid ciphertext outside Z*_{N^2} verified")
	}
}

func TestModulusProofCGGMP24Checks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 512)
	domain := []byte("modulus proof")
	party := uint32(7)
	proof, err := ProveModulus(nil, domain, sk, party)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyModulus(domain, &sk.PublicKey, party, proof) {
		t.Fatal("modulus proof did not verify")
	}
	if VerifyModulus([]byte("other"), &sk.PublicKey, party, proof) {
		t.Fatal("modulus proof verified under wrong domain")
	}
	if VerifyModulus(domain, &sk.PublicKey, party+1, proof) {
		t.Fatal("modulus proof verified under wrong party")
	}

	nLen := modulusBytes(sk.N)
	t.Run("jacobi w", func(t *testing.T) {
		tampered := cloneModulusProof(proof)
		tampered.W = fixedModNBytes(big.NewInt(1), nLen)
		if VerifyModulus(domain, &sk.PublicKey, party, tampered) {
			t.Fatal("modulus proof with Jacobi(w,N) != -1 verified")
		}
	})
	t.Run("round count", func(t *testing.T) {
		tampered := cloneModulusProof(proof)
		tampered.X = tampered.X[:modulusProofRounds-1]
		if VerifyModulus(domain, &sk.PublicKey, party, tampered) {
			t.Fatal("modulus proof with wrong tuple count verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("modulus proof with wrong tuple count marshaled")
		}
	})
	t.Run("prover y field", func(t *testing.T) {
		raw := mustWireProof(t, modulusProofWireType, []wire.Field{
			{Tag: modulusProofFieldW, Value: proof.W},
			{Tag: modulusProofFieldTranscriptHash, Value: proof.TranscriptHash},
			{Tag: modulusProofFieldX, Value: wire.EncodeBytesList(proof.X)},
			{Tag: modulusProofFieldA, Value: proof.A},
			{Tag: modulusProofFieldB, Value: proof.B},
			{Tag: modulusProofFieldZ, Value: wire.EncodeBytesList(proof.Z)},
			{Tag: 99, Value: wire.EncodeBytesList(proof.Z)},
		})
		if _, err := UnmarshalModulusProof(raw); err == nil {
			t.Fatal("modulus proof accepted prover-supplied extra field")
		}
	})
	t.Run("w x z units", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*ModulusProof)
		}{
			{name: "w zero", mutate: func(p *ModulusProof) { p.W = make([]byte, nLen) }},
			{name: "x outside", mutate: func(p *ModulusProof) { p.X[0] = fixedModNBytes(sk.N, nLen) }},
			{name: "z outside", mutate: func(p *ModulusProof) { p.Z[0] = fixedModNBytes(sk.N, nLen) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tampered := cloneModulusProof(proof)
				tc.mutate(tampered)
				if VerifyModulus(domain, &sk.PublicKey, party, tampered) {
					t.Fatal("modulus proof with invalid Z_N* element verified")
				}
			})
		}
	})
	t.Run("equations", func(t *testing.T) {
		tamperedZ := cloneModulusProof(proof)
		tamperedZ.Z[0][len(tamperedZ.Z[0])-1] ^= 1
		if VerifyModulus(domain, &sk.PublicKey, party, tamperedZ) {
			t.Fatal("modulus proof with bad z^N equation verified")
		}
		tamperedX := cloneModulusProof(proof)
		tamperedX.X[0][len(tamperedX.X[0])-1] ^= 1
		if VerifyModulus(domain, &sk.PublicKey, party, tamperedX) {
			t.Fatal("modulus proof with bad x^4 equation verified")
		}
	})
}

func TestRingPedersenProofChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 512)
	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	paramsBytes, err := MarshalRingPedersenParams(params)
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("ring pedersen")
	party := uint32(3)
	proof, err := ProveRingPedersen(nil, domain, sk, params, lambda, party)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRingPedersen(domain, params, party, proof) {
		t.Fatal("Ring-Pedersen proof did not verify")
	}
	if VerifyRingPedersen([]byte("other"), params, party, proof) {
		t.Fatal("Ring-Pedersen proof verified under wrong domain")
	}
	if VerifyRingPedersen(domain, params, party+1, proof) {
		t.Fatal("Ring-Pedersen proof verified under wrong party")
	}
	decodedParams, err := UnmarshalRingPedersenParams(paramsBytes)
	if err != nil {
		t.Fatal(err)
	}
	if decodedParams.N.Cmp(params.N) != 0 || decodedParams.S.Cmp(params.S) != 0 || decodedParams.T.Cmp(params.T) != 0 {
		t.Fatal("Ring-Pedersen parameters did not round-trip")
	}

	nLen := modulusBytes(params.N)
	t.Run("invalid params", func(t *testing.T) {
		bad := &RingPedersenParams{N: params.N, S: big.NewInt(1), T: params.T}
		if ValidateRingPedersenParams(bad) == nil {
			t.Fatal("degenerate Ring-Pedersen parameters validated")
		}
		if VerifyRingPedersen(domain, bad, party, proof) {
			t.Fatal("Ring-Pedersen proof verified against invalid parameters")
		}
	})
	t.Run("out of range response", func(t *testing.T) {
		tampered := cloneRingPedersenProof(proof)
		tampered.Responses[0] = fixedModNBytes(params.N, nLen)
		if VerifyRingPedersen(domain, params, party, tampered) {
			t.Fatal("Ring-Pedersen proof with out-of-range response verified")
		}
	})
	t.Run("tamper", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*RingPedersenProof)
		}{
			{name: "commitment", mutate: func(p *RingPedersenProof) { p.Commitments[0][len(p.Commitments[0])-1] ^= 1 }},
			{name: "challenge", mutate: func(p *RingPedersenProof) { p.Challenges[0] ^= 1 }},
			{name: "response", mutate: func(p *RingPedersenProof) { p.Responses[0][len(p.Responses[0])-1] ^= 1 }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tampered := cloneRingPedersenProof(proof)
				tc.mutate(tampered)
				if VerifyRingPedersen(domain, params, party, tampered) {
					t.Fatal("tampered Ring-Pedersen proof verified")
				}
			})
		}
	})
}

func TestProofMarshalCanonicalBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	domain := []byte("canonical proof domain")

	modProof, err := ProveModulus(nil, domain, sk, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertModulusProofRoundTrip(t, modProof)
	if _, err := UnmarshalModulusProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON modulus proof fallback was accepted")
	}

	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	paramsBytes, err := MarshalRingPedersenParams(params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRingPedersenParams(paramsBytes); err != nil {
		t.Fatal(err)
	}
	rpProof, err := ProveRingPedersen(nil, domain, sk, params, lambda, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertRingPedersenProofRoundTrip(t, rpProof)
	if _, err := UnmarshalRingPedersenProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON Ring-Pedersen proof fallback was accepted")
	}

	scalar := big.NewInt(42)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	encProof, err := ProveEncryption(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness)
	if err != nil {
		t.Fatal(err)
	}
	assertEncryptionProofRoundTrip(t, encProof)
	if _, err := UnmarshalEncryptionProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON encryption proof fallback was accepted")
	}

	b := big.NewInt(17)
	beta := big.NewInt(19)
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, betaRandomness := mtaResponseForTest(t, sk, ciphertext, b, beta)
	mtaProof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, ciphertext, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}
	assertMTAResponseProofRoundTrip(t, mtaProof)
	if !VerifyMTAResponse(domain, &sk.PublicKey, ciphertext, response, bCommitment, mtaProof) {
		t.Fatal("MtA response proof did not verify")
	}
	if _, err := UnmarshalMTAResponseProof([]byte(`{"version":1}`)); err == nil {
		t.Fatal("JSON MtA response proof fallback was accepted")
	}
	if mtaBytes, err := Marshal(mtaProof); err != nil {
		t.Fatal(err)
	} else if _, err := UnmarshalEncryptionProof(mtaBytes); err == nil {
		t.Fatal("MtA response proof decoded as encryption proof")
	}
}

func TestMTAResponseProofFieldTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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
			tampered := cloneMTAResponseProof(proof)
			tc.mutate(tampered)
			if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
				t.Fatal("tampered MtA response proof verified")
			}
		})
	}
}

func TestProofRejectsNonCanonicalAndMalformedInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
	sk := testPaillierKey(t, 1024)
	domain := []byte("negative proof inputs")
	a := big.NewInt(23)
	b := big.NewInt(29)
	beta := big.NewInt(31)
	encA, randomness, err := sk.Encrypt(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	encProof, err := ProveEncryption(nil, domain, &sk.PublicKey, encA, a, randomness)
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, betaRandomness := mtaResponseForTest(t, sk, encA, b, beta)
	mtaProof, err := ProveMTAResponse(nil, domain, &sk.PublicKey, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("non canonical scalar response", func(t *testing.T) {
		tampered := cloneEncryptionProof(encProof)
		tampered.Response = prependZero(tampered.Response)
		if VerifyEncryption(domain, &sk.PublicKey, encA, tampered) {
			t.Fatal("non-canonical encryption response verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("non-canonical encryption response marshaled")
		}
	})
	t.Run("fixed width ciphertext", func(t *testing.T) {
		tampered := cloneEncryptionProof(encProof)
		tampered.CipherCommitment = prependZero(tampered.CipherCommitment)
		if VerifyEncryption(domain, &sk.PublicKey, encA, tampered) {
			t.Fatal("wrong-width encryption cipher commitment verified")
		}
	})
	t.Run("malformed curve point", func(t *testing.T) {
		tampered := cloneEncryptionProof(encProof)
		tampered.ScalarCommitment = []byte{0x02}
		if VerifyEncryption(domain, &sk.PublicKey, encA, tampered) {
			t.Fatal("malformed scalar commitment verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("malformed scalar commitment marshaled")
		}
	})
	t.Run("mta oversized response", func(t *testing.T) {
		tampered := cloneMTAResponseProof(mtaProof)
		tampered.BResponse = append([]byte{1}, make([]byte, mtaResponseScalarMaxBytes)...)
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
			t.Fatal("oversized MtA response verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("oversized MtA response marshaled")
		}
	})
	t.Run("mta malformed point", func(t *testing.T) {
		tampered := cloneMTAResponseProof(mtaProof)
		tampered.BCommitment = []byte{0x02}
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, response, bCommitment, tampered) {
			t.Fatal("malformed MtA point verified")
		}
		if _, err := Marshal(tampered); err == nil {
			t.Fatal("malformed MtA point marshaled")
		}
	})
	t.Run("mta invalid ciphertext", func(t *testing.T) {
		if VerifyMTAResponse(domain, &sk.PublicKey, big.NewInt(0), response, bCommitment, mtaProof) {
			t.Fatal("MtA proof verified with invalid input ciphertext")
		}
		if VerifyMTAResponse(domain, &sk.PublicKey, encA, sk.NSquared, bCommitment, mtaProof) {
			t.Fatal("MtA proof verified with invalid response ciphertext")
		}
	})
}

func TestNewProofUnmarshalRejectsNonCanonicalPositiveIntegers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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
		ProverPaillierN: &sk.PublicKey,
		CiphertextK:     ciphertextK,
		VerifierAux:     *aux,
	}
	encProof, err := ProveEnc(params, []byte("enc canonical"), encStmt, EncWitness{K: k, Rho: rhoK}, nil)
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
	for _, tag := range []uint16{encProofFieldS, encProofFieldA, encProofFieldC, encProofFieldZ2} {
		t.Run(fmt.Sprintf("enc field %d", tag), func(t *testing.T) {
			mutated, err := prependZeroToWireField(encRaw, encProofWireType, tag)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalEncProof(mutated); err == nil {
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
	xMulC, err := OMulCT(&sk.PublicKey, x, encX, signedPowerOfTwoBytes(params.Ell))
	if err != nil {
		t.Fatal(err)
	}
	responseD, err := OAdd(&sk.PublicKey, xMulC, encYReceiver)
	if err != nil {
		t.Fatal(err)
	}
	encYProver, rhoYProver, err := sk.Encrypt(nil, y)
	if err != nil {
		t.Fatal(err)
	}
	affGStmt := AffGStatement{
		ReceiverPaillierN: &sk.PublicKey,
		ProverPaillierN:   &sk.PublicKey,
		C:                 encX,
		D:                 responseD,
		Y:                 encYProver,
		X:                 secp.ScalarBaseMult(secp.ScalarFromBigInt(x)),
		VerifierAux:       *aux,
	}
	affGProof, err := ProveAffG(params, []byte("affg canonical"), affGStmt, AffGWitness{
		X: x, Y: y, Rho: rhoYReceiver, RhoY: rhoYProver,
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
	for _, tag := range []uint16{
		affGProofFieldA, affGProofFieldBy, affGProofFieldE, affGProofFieldS,
		affGProofFieldF, affGProofFieldT, affGProofFieldY, affGProofFieldW, affGProofFieldWY,
	} {
		t.Run(fmt.Sprintf("affg field %d", tag), func(t *testing.T) {
			mutated, err := prependZeroToWireField(affGRaw, affGProofWireType, tag)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalAffGProof(mutated); err == nil {
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
		PaillierN:   &sk.PublicKey,
		C:           logC,
		X:           secp.ScalarBaseMult(secp.ScalarFromBigInt(logX)),
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: *aux,
	}
	logProof, err := ProveLogStar(params, []byte("logstar canonical"), logStmt, LogStarWitness{X: logX, Rho: logRho}, nil)
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
	for _, tag := range []uint16{logStarProofFieldS, logStarProofFieldA, logStarProofFieldD, logStarProofFieldZ2} {
		t.Run(fmt.Sprintf("logstar field %d", tag), func(t *testing.T) {
			mutated, err := prependZeroToWireField(logRaw, logStarProofWireType, tag)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalLogStarProof(mutated); err == nil {
				t.Fatal("LogStarProof accepted non-canonical positive integer")
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

func assertRingPedersenProofRoundTrip(t *testing.T, proof *RingPedersenProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalRingPedersenProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("Ring-Pedersen proof encoding is not deterministic")
	}
	if _, err := UnmarshalRingPedersenProof(append(raw, 0)); err == nil {
		t.Fatal("Ring-Pedersen proof accepted trailing bytes")
	}
}

func assertEncryptionProofRoundTrip(t *testing.T, proof *EncryptionProof) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEncryptionProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("encryption proof encoding is not deterministic")
	}
	if _, err := UnmarshalEncryptionProof(append(raw, 0)); err == nil {
		t.Fatal("encryption proof accepted trailing bytes")
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

func testPaillierKey(t *testing.T, bits int) *pai.PrivateKey {
	t.Helper()
	restore := pai.SetMinimumModulusBitsForTesting(bits)
	t.Cleanup(restore)
	sk, err := pai.GenerateKey(context.Background(), nil, bits)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func mtaResponseForTest(t *testing.T, sk *pai.PrivateKey, encA, b, beta *big.Int) (*big.Int, *big.Int) {
	t.Helper()
	encBeta, betaRandomness, err := sk.Encrypt(nil, beta)
	if err != nil {
		t.Fatal(err)
	}
	nLen := modulusBytes(sk.N)
	nSquaredLen := 2 * nLen
	encPowBytes, err := paillierct.ExpCT(
		paillierct.FixedEncode(sk.NSquared, nSquaredLen),
		paillierct.FixedEncode(encA, nSquaredLen),
		secp.ScalarFromBigInt(b).Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	response := new(big.Int).SetBytes(encPowBytes)
	response.Mul(response, encBeta)
	response.Mod(response, sk.NSquared)
	return response, betaRandomness
}

func cloneModulusProof(in *ModulusProof) *ModulusProof {
	out := *in
	out.W = append([]byte(nil), in.W...)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	out.X = cloneByteSlices(in.X)
	out.A = append([]byte(nil), in.A...)
	out.B = append([]byte(nil), in.B...)
	out.Z = cloneByteSlices(in.Z)
	return &out
}

func cloneRingPedersenProof(in *RingPedersenProof) *RingPedersenProof {
	out := *in
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	out.Commitments = cloneByteSlices(in.Commitments)
	out.Challenges = append([]byte(nil), in.Challenges...)
	out.Responses = cloneByteSlices(in.Responses)
	return &out
}

func cloneEncryptionProof(in *EncryptionProof) *EncryptionProof {
	out := *in
	out.ScalarCommitment = append([]byte(nil), in.ScalarCommitment...)
	out.CipherCommitment = append([]byte(nil), in.CipherCommitment...)
	out.PointCommitment = append([]byte(nil), in.PointCommitment...)
	out.Bound = append([]byte(nil), in.Bound...)
	out.Response = append([]byte(nil), in.Response...)
	out.Randomness = append([]byte(nil), in.Randomness...)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	return &out
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

func cloneByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
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

func prependZeroToWireField(raw []byte, typeID string, tag uint16) ([]byte, error) {
	version, fields, err := wire.Unmarshal(raw, typeID)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Tag == tag {
			value := make([]byte, 0, len(fields[i].Value)+1)
			value = append(value, 0)
			value = append(value, fields[i].Value...)
			fields[i].Value = value
			return wire.Marshal(version, typeID, fields)
		}
	}
	return nil, fmt.Errorf("missing wire field %d", tag)
}
