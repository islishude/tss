package paillier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/paillier/paillierct"
	"github.com/islishude/tss/internal/wire"
)

var testPaillierKeyCache sync.Map

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

// --- Shared test helpers ---

func testPaillierKey(t *testing.T, bits int) *pai.PrivateKey {
	t.Helper()
	if sk, ok := testPaillierKeyCache.Load(bits); ok {
		return sk.(*pai.PrivateKey)
	}
	sk, err := pai.GenerateKey(context.Background(), nil, bits)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := testPaillierKeyCache.LoadOrStore(bits, sk)
	if actual != sk {
		return actual.(*pai.PrivateKey)
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
