//go:build tier1

package mta

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
)

func TestResponseOpeningVerifyBindsEveryWitnessAndPublicRelation(t *testing.T) {
	skA, skB, rpA, rpB := setupTestEnv(t)
	t.Cleanup(skA.Destroy)
	t.Cleanup(skB.Destroy)
	params := testSecurityParams()
	startDomain := []byte("response-opening-start")
	responseDomain := []byte("response-opening-response")
	a := big.NewInt(13)
	b := big.NewInt(37)
	aCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(a)))
	if err != nil {
		t.Fatal(err)
	}
	bCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	start, err := Start(nil, testSecretScalar(t, a), skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(start.Destroy)
	startProof, err := ProveStartForVerifier(params, nil, startDomain, start, aCommitment, skA.PublicKey, rpB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(startProof.Destroy)
	response, betaShare, opening, err := RespondWithOpening(
		params, nil, startDomain, responseDomain,
		start.Message, startProof, aCommitment,
		testSecretScalar(t, b), bCommitment,
		skA.PublicKey, skB.PublicKey, rpB, rpA,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(response.Destroy)
	t.Cleanup(betaShare.Destroy)
	t.Cleanup(opening.Destroy)

	if err := opening.Verify(params, start.Message, *response, aCommitment, bCommitment, skA.PublicKey, skB.PublicKey); err != nil {
		t.Fatalf("valid response opening rejected: %v", err)
	}

	t.Run("alternate-y-representative", func(t *testing.T) {
		originalY, err := responseOpeningSignedValue(opening.y)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.ClearBigInt(originalY)
		period := new(big.Int).Mul(secp.Order(), skA.N)
		period.Mul(period, skB.N)
		defer secret.ClearBigInt(period)
		alternateY := new(big.Int).Add(originalY, period)
		defer secret.ClearBigInt(alternateY)
		encodedY := alternateY.Bytes()
		candidateY, err := secret.NewSignedInt(false, encodedY, len(encodedY))
		clear(encodedY)
		if err != nil {
			t.Fatal(err)
		}
		candidate := opening.Clone()
		defer candidate.Destroy()
		candidate.y.Destroy()
		candidate.y = candidateY
		encoded, err := candidate.MarshalPrivateBinary()
		if err != nil {
			t.Fatalf("alternate representative did not encode: %v", err)
		}
		defer clear(encoded)
		var decoded ResponseOpening
		if err := decoded.UnmarshalPrivateBinary(encoded); err != nil {
			t.Fatalf("alternate representative did not decode: %v", err)
		}
		defer decoded.Destroy()
		err = decoded.Verify(params, start.Message, *response, aCommitment, bCommitment, skA.PublicKey, skB.PublicKey)
		if err == nil {
			t.Fatal("out-of-range alternate y representative was accepted")
		}
		if !strings.Contains(err.Error(), "invalid width") && !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("alternate representative failed at wrong boundary: %v", err)
		}
	})

	witnessTests := []struct {
		name   string
		want   string
		mutate func(*testing.T, *ResponseOpening)
	}{
		{
			name: "x",
			want: "x does not open b commitment",
			mutate: func(t *testing.T, candidate *ResponseOpening) {
				candidate.x.Destroy()
				candidate.x = responseOpeningTestScalar(t, big.NewInt(38), secp.ScalarSize)
			},
		},
		{
			name: "y",
			want: "y does not open proof YPoint",
			mutate: func(t *testing.T, candidate *ResponseOpening) {
				candidate.y.Destroy()
				candidate.y = differentResponseOpeningSignedInt(t, opening.y)
			},
		},
		{
			name: "rho",
			want: "does not reproduce response ciphertext",
			mutate: func(t *testing.T, candidate *ResponseOpening) {
				candidate.rho.Destroy()
				candidate.rho = differentResponseOpeningScalar(t, opening.rho)
			},
		},
		{
			name: "rhoY",
			want: "does not reproduce proof Y ciphertext",
			mutate: func(t *testing.T, candidate *ResponseOpening) {
				candidate.rhoY.Destroy()
				candidate.rhoY = differentResponseOpeningScalar(t, opening.rhoY)
			},
		},
	}
	for _, tc := range witnessTests {
		t.Run("tampered-witness-"+tc.name, func(t *testing.T) {
			candidate := opening.Clone()
			defer candidate.Destroy()
			tc.mutate(t, candidate)
			encoded, err := candidate.MarshalPrivateBinary()
			if err != nil {
				t.Fatalf("structurally valid witness mutation did not encode: %v", err)
			}
			defer clear(encoded)
			var decoded ResponseOpening
			if err := decoded.UnmarshalPrivateBinary(encoded); err != nil {
				t.Fatalf("structurally valid witness mutation did not decode: %v", err)
			}
			defer decoded.Destroy()
			err = decoded.Verify(params, start.Message, *response, aCommitment, bCommitment, skA.PublicKey, skB.PublicKey)
			if err == nil {
				t.Fatal("structurally valid witness mutation was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("witness mutation failed at wrong relation: got %q, want %q", err, tc.want)
			}
		})
	}

	otherResponseA := differentResponseOpeningCiphertext(t, skA.PublicKey, response.Ciphertext)
	otherResponseY := differentResponseOpeningCiphertext(t, skB.PublicKey, response.Proof.Y.Bytes())
	otherACommitment := differentResponseOpeningPoint(t, aCommitment)
	otherBCommitment := differentResponseOpeningPoint(t, bCommitment)
	otherYPoint := differentResponseOpeningPoint(t, response.Proof.YPoint)
	otherAlphaPoint := differentResponseOpeningPoint(t, response.Proof.AlphaPoint)
	publicTests := []struct {
		name   string
		want   string
		mutate func(*ResponseMessage, *[]byte, *[]byte)
	}{
		{
			name: "D",
			want: "does not reproduce response ciphertext",
			mutate: func(candidate *ResponseMessage, _, _ *[]byte) {
				clear(candidate.Ciphertext)
				candidate.Ciphertext = bytes.Clone(otherResponseA)
			},
		},
		{
			name: "proof-Y",
			want: "does not reproduce proof Y ciphertext",
			mutate: func(candidate *ResponseMessage, _, _ *[]byte) {
				secret.ClearBigInt(candidate.Proof.Y)
				candidate.Proof.Y = new(big.Int).SetBytes(otherResponseY)
			},
		},
		{
			name: "b-commitment",
			want: "x does not open b commitment",
			mutate: func(_ *ResponseMessage, _, candidateB *[]byte) {
				*candidateB = bytes.Clone(otherBCommitment)
			},
		},
		{
			name: "proof-YPoint",
			want: "y does not open proof YPoint",
			mutate: func(candidate *ResponseMessage, _, _ *[]byte) {
				clear(candidate.Proof.YPoint)
				candidate.Proof.YPoint = bytes.Clone(otherYPoint)
			},
		},
		{
			name: "a-commitment",
			want: "does not open proof AlphaPoint",
			mutate: func(_ *ResponseMessage, candidateA, _ *[]byte) {
				*candidateA = bytes.Clone(otherACommitment)
			},
		},
		{
			name: "proof-AlphaPoint",
			want: "does not open proof AlphaPoint",
			mutate: func(candidate *ResponseMessage, _, _ *[]byte) {
				clear(candidate.Proof.AlphaPoint)
				candidate.Proof.AlphaPoint = bytes.Clone(otherAlphaPoint)
			},
		},
	}
	for _, tc := range publicTests {
		t.Run("tampered-public-"+tc.name, func(t *testing.T) {
			candidateResponse := response.Clone()
			defer candidateResponse.Destroy()
			candidateA := bytes.Clone(aCommitment)
			candidateB := bytes.Clone(bCommitment)
			tc.mutate(&candidateResponse, &candidateA, &candidateB)
			err := opening.Verify(params, start.Message, candidateResponse, candidateA, candidateB, skA.PublicKey, skB.PublicKey)
			if err == nil {
				t.Fatal("structurally valid public relation mutation was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("public mutation failed at wrong relation: got %q, want %q", err, tc.want)
			}
		})
	}
}

func responseOpeningTestScalar(t *testing.T, value *big.Int, fixedLen int) *secret.Scalar {
	t.Helper()
	encoded := value.FillBytes(make([]byte, fixedLen))
	defer clear(encoded)
	out, err := secret.NewScalar(encoded, fixedLen)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func differentResponseOpeningScalar(t *testing.T, current *secret.Scalar) *secret.Scalar {
	t.Helper()
	for _, value := range []int64{2, 3} {
		candidate := responseOpeningTestScalar(t, big.NewInt(value), current.FixedLen())
		if !candidate.Equal(current) {
			return candidate
		}
		candidate.Destroy()
	}
	t.Fatal("failed to construct distinct response opening scalar")
	return nil
}

func differentResponseOpeningSignedInt(t *testing.T, current *secret.SignedInt) *secret.SignedInt {
	t.Helper()
	for _, value := range []byte{1, 2} {
		magnitude := make([]byte, current.FixedLen())
		magnitude[len(magnitude)-1] = value
		candidate, err := secret.NewSignedInt(false, magnitude, len(magnitude))
		clear(magnitude)
		if err != nil {
			t.Fatal(err)
		}
		if !candidate.Equal(current) {
			return candidate
		}
		candidate.Destroy()
	}
	t.Fatal("failed to construct distinct response opening signed integer")
	return nil
}

func differentResponseOpeningCiphertext(t *testing.T, pk *pai.PublicKey, current []byte) []byte {
	t.Helper()
	currentValue := new(big.Int).SetBytes(current)
	for _, message := range []int64{1, 2} {
		candidate, err := pk.EncryptWithRandomness(big.NewInt(message), big.NewInt(1))
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Cmp(currentValue) != 0 {
			return candidate.Bytes()
		}
		secret.ClearBigInt(candidate)
	}
	t.Fatal("failed to construct distinct Paillier ciphertext")
	return nil
}

func differentResponseOpeningPoint(t *testing.T, current []byte) []byte {
	t.Helper()
	for _, scalar := range []int64{1, 2} {
		candidate, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(scalar))))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(candidate, current) {
			return candidate
		}
		clear(candidate)
	}
	t.Fatal("failed to construct distinct secp256k1 point")
	return nil
}
