//go:build tier1

package mta

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// Tier 1: Finish error paths (needs crypto keygen).

func TestFinishErrors(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, rpB := setupTestEnv(t)
	params := testSecurityParams()

	a := big.NewInt(13)
	b := big.NewInt(37)
	start, err := Start(nil, testSecretScalar(t, a), skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	aCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(a)))
	if err != nil {
		t.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(params, nil, []byte("start"), start, aCommit, skA.PublicKey, rpB)
	if err != nil {
		t.Fatal(err)
	}
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := Respond(params, nil, []byte("start"), []byte("response"), start.Message, startProof, aCommit, testSecretScalar(t, b), bCommit, skA.PublicKey, skB.PublicKey, rpB, rpA)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil skA", func(t *testing.T) {
		_, err := Finish(params, []byte("response"), start.Message, *response, aCommit, bCommit, nil, skB.PublicKey, rpA)
		if err == nil {
			t.Fatal("expected error for nil Paillier private key")
		}
	})

	t.Run("invalid start message", func(t *testing.T) {
		badStart := StartMessage{Ciphertext: nil}
		_, err := Finish(params, []byte("response"), badStart, *response, aCommit, bCommit, skA, skB.PublicKey, rpA)
		if err == nil {
			t.Fatal("expected error for invalid start message")
		}
	})

	t.Run("invalid b commitment", func(t *testing.T) {
		_, err := Finish(params, []byte("response"), start.Message, *response, aCommit, []byte{0x00, 0x01}, skA, skB.PublicKey, rpA)
		if err == nil {
			t.Fatal("expected error for invalid b commitment")
		}
	})

	t.Run("empty b commitment", func(t *testing.T) {
		_, err := Finish(params, []byte("response"), start.Message, *response, aCommit, nil, skA, skB.PublicKey, rpA)
		if err == nil {
			t.Fatal("expected error for empty b commitment")
		}
	})

	t.Run("invalid response proof", func(t *testing.T) {
		badResponse := *response
		badResponse.Proof.A = new(big.Int)
		_, err := Finish(params, []byte("response"), start.Message, badResponse, aCommit, bCommit, skA, skB.PublicKey, rpA)
		if err == nil {
			t.Fatal("expected error for invalid response proof")
		}
	})

	t.Run("wrong response domain", func(t *testing.T) {
		_, err := Finish(params, []byte("wrong-domain"), start.Message, *response, aCommit, bCommit, skA, skB.PublicKey, rpA)
		if err == nil {
			t.Fatal("expected error for wrong response domain")
		}
	})
}

func TestFinishMultipleValues(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, rpB := setupTestEnv(t)
	params := testSecurityParams()
	startDomain := []byte("start")
	responseDomain := []byte("response")

	pairs := []struct{ a, b int64 }{
		{1, 1},
		{2, 3},
		{7, 11},
		{42, 99},
		{1 << 20, 1 << 20},
	}
	for _, p := range pairs {
		a := big.NewInt(p.a)
		b := big.NewInt(p.b)
		aCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(a)))
		if err != nil {
			t.Fatal(err)
		}
		bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
		if err != nil {
			t.Fatal(err)
		}
		start, err := Start(nil, testSecretScalar(t, a), skA.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		startProof, err := ProveStartForVerifier(params, nil, startDomain, start, aCommit, skA.PublicKey, rpB)
		if err != nil {
			t.Fatal(err)
		}
		response, betaShare, err := Respond(params, nil, startDomain, responseDomain, start.Message, startProof, aCommit, testSecretScalar(t, b), bCommit, skA.PublicKey, skB.PublicKey, rpB, rpA)
		if err != nil {
			t.Fatal(err)
		}
		alphaShare, err := Finish(params, responseDomain, start.Message, *response, aCommit, bCommit, skA, skB.PublicKey, rpA)
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
			t.Fatalf("a=%d b=%d: alpha+beta = %s mod q, want %s", p.a, p.b, got, want)
		}
	}
}

func TestFinishCenteredSignedPlaintextPreservesDeltaAndSigmaRelations(t *testing.T) {
	t.Parallel()
	skA, skB, rpA, _ := setupTestEnv(t)
	params := testSecurityParams()

	tests := []struct {
		name   string
		domain []byte
		a      int64
		b      int64
		mask   int64
	}{
		{name: "delta", domain: []byte("negative-delta-response"), a: 3, b: 5, mask: 19},
		{name: "sigma", domain: []byte("negative-sigma-response"), a: 7, b: 11, mask: 83},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := big.NewInt(tc.a)
			b := big.NewInt(tc.b)
			aSecret := testSecretScalar(t, a)
			bSecret := testSecretScalar(t, b)
			start, err := Start(nil, aSecret, skA.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			aCommitment, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(a)))
			if err != nil {
				t.Fatal(err)
			}
			bPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(b))
			bCommitment, err := secp.PointBytes(bPoint)
			if err != nil {
				t.Fatal(err)
			}

			maskBytes := big.NewInt(tc.mask).FillBytes(make([]byte, int((params.EllPrime+8)/8)))
			mask, err := secret.NewSignedInt(true, maskBytes, len(maskBytes))
			clear(maskBytes)
			if err != nil {
				t.Fatal(err)
			}
			defer mask.Destroy()
			encMaskA, rho, err := skA.EncryptSignedSecret(nil, mask)
			if err != nil {
				t.Fatal(err)
			}
			defer rho.Destroy()
			product, err := skA.MulPlaintext(new(big.Int).SetBytes(start.Message.Ciphertext), b)
			if err != nil {
				t.Fatal(err)
			}
			responseCiphertext, err := skA.AddCiphertexts(product, encMaskA)
			if err != nil {
				t.Fatal(err)
			}
			encMaskB, rhoY, err := skB.EncryptSignedSecret(nil, mask)
			if err != nil {
				t.Fatal(err)
			}
			defer rhoY.Destroy()
			aPoint, err := secp.PointFromBytes(aCommitment)
			if err != nil {
				t.Fatal(err)
			}
			statement := zkpai.AffGStatement{
				ReceiverPaillierN: skA.PublicKey,
				ProverPaillierN:   skB.PublicKey,
				C:                 new(big.Int).SetBytes(start.Message.Ciphertext),
				D:                 responseCiphertext,
				Y:                 encMaskB,
				X:                 bPoint,
				K:                 aPoint,
				VerifierAux:       rpA,
			}
			proof, err := zkpai.ProveAffG(params, tc.domain, statement, zkpai.AffGWitness{
				X: bSecret, Y: mask, Rho: rho, RhoY: rhoY,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			response := ResponseMessage{Ciphertext: responseCiphertext.Bytes(), Proof: *proof}
			alphaShare, err := Finish(params, tc.domain, start.Message, response, aCommitment, bCommitment, skA, skB.PublicKey, rpA)
			if err != nil {
				t.Fatal(err)
			}
			defer alphaShare.Destroy()
			maskScalar, err := signedSecretScalarModOrder(mask)
			if err != nil {
				t.Fatal(err)
			}
			betaShare := secp.ScalarNeg(maskScalar)
			alphaScalar, err := secpScalarFromSecret(alphaShare)
			if err != nil {
				t.Fatal(err)
			}
			got := secp.ScalarAdd(alphaScalar, betaShare)
			want := secp.ScalarMul(secp.ScalarFromBigInt(a), secp.ScalarFromBigInt(b))
			if !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Fatal("centered signed MtA shares did not preserve the product relation")
			}
		})
	}
}
