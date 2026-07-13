//go:build tier1

package paillier

import (
	"context"
	"math/big"
	"testing"

	pai "github.com/islishude/tss/internal/paillier"
)

func TestFactorProofRoundTripAndContextBinding(t *testing.T) {
	sk := testPaillierKey(t, 1024)
	params := SecurityParams{Ell: 256, EllPrime: 512, Epsilon: 128, ChallengeBits: 128, MinPaillierBits: 1024}
	aux, lambda, err := testIndependentRingPedersenParams(t, nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	defer lambda.Destroy()
	state := []byte("factor-proof/session/prover-1/verifier-2")
	proof, err := ProveFactor(params, state, sk, aux, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt := FactorStatement{ProverPaillierN: sk.PublicKey, VerifierAux: aux}
	if err := VerifyFactor(params, state, stmt, proof); err != nil {
		t.Fatal(err)
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded FactorProof
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFactor(params, state, stmt, &decoded); err != nil {
		t.Fatalf("decoded proof failed: %v", err)
	}
	if err := VerifyFactor(params, []byte("wrong-state"), stmt, proof); err == nil {
		t.Fatal("factor proof verified across domains")
	}

	otherSK, err := pai.GenerateKeyForTest(context.Background(), nil, 1024)
	if err != nil {
		t.Fatal(err)
	}
	otherAux, otherLambda, err := GenerateRingPedersenParams(nil, otherSK)
	if err != nil {
		t.Fatal(err)
	}
	defer otherLambda.Destroy()
	if err := VerifyFactor(params, state, FactorStatement{ProverPaillierN: otherSK.PublicKey, VerifierAux: aux}, proof); err == nil {
		t.Fatal("factor proof verified for another prover modulus")
	}
	if err := VerifyFactor(params, state, FactorStatement{ProverPaillierN: sk.PublicKey, VerifierAux: otherAux}, proof); err == nil {
		t.Fatal("factor proof verified for another verifier auxiliary key")
	}
	changedParams := params
	changedParams.Epsilon++
	if err := VerifyFactor(changedParams, state, stmt, proof); err == nil {
		t.Fatal("factor proof verified under another security profile")
	}

	mutations := map[string]func(*FactorProof){
		"P":          func(p *FactorProof) { p.P.Add(p.P, big.NewInt(1)) },
		"Q":          func(p *FactorProof) { p.Q.Add(p.Q, big.NewInt(1)) },
		"A":          func(p *FactorProof) { p.A.Add(p.A, big.NewInt(1)) },
		"B":          func(p *FactorProof) { p.B.Add(p.B, big.NewInt(1)) },
		"T":          func(p *FactorProof) { p.T.Add(p.T, big.NewInt(1)) },
		"sigma":      func(p *FactorProof) { p.Sigma.Add(p.Sigma, big.NewInt(1)) },
		"z1":         func(p *FactorProof) { p.Z1.Add(p.Z1, big.NewInt(1)) },
		"z2":         func(p *FactorProof) { p.Z2.Add(p.Z2, big.NewInt(1)) },
		"w1":         func(p *FactorProof) { p.W1.Add(p.W1, big.NewInt(1)) },
		"w2":         func(p *FactorProof) { p.W2.Add(p.W2, big.NewInt(1)) },
		"v":          func(p *FactorProof) { p.V.Add(p.V, big.NewInt(1)) },
		"transcript": func(p *FactorProof) { p.TranscriptHash[0] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := proof.Clone()
			mutate(mutated)
			if err := VerifyFactor(params, state, stmt, mutated); err == nil {
				t.Fatal("mutated factor proof verified")
			}
		})
	}

	t.Run("oversized commitment response", func(t *testing.T) {
		mutated := proof.Clone()
		mutated.W1 = new(big.Int).Lsh(big.NewInt(1), uint(int(params.Ell+max(params.Epsilon, params.ChallengeBits))+aux.N.BitLen()+2))
		if err := VerifyFactor(params, state, stmt, mutated); err == nil {
			t.Fatal("oversized factor commitment response verified")
		}
	})
	t.Run("oversized product response", func(t *testing.T) {
		mutated := proof.Clone()
		mutated.V = new(big.Int).Lsh(big.NewInt(1), uint(int(params.Ell+max(params.Epsilon, params.ChallengeBits))+sk.N.BitLen()+aux.N.BitLen()+3))
		if err := VerifyFactor(params, state, stmt, mutated); err == nil {
			t.Fatal("oversized factor product response verified")
		}
	})
}

func TestGeneratedRingPedersenBasesAreQuadraticResidues(t *testing.T) {
	sk := testPaillierKey(t, 1024)
	params, lambda, err := GenerateRingPedersenParams(nil, sk)
	if err != nil {
		t.Fatal(err)
	}
	defer lambda.Destroy()
	p, q, err := paillierFactors(sk)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]*big.Int{"S": params.S, "T": params.T} {
		if big.Jacobi(value, p) != 1 || big.Jacobi(value, q) != 1 {
			t.Fatalf("%s is not a quadratic residue modulo both factors", name)
		}
	}
}

func TestFactorWitnessRejectsSmallOrUnbalancedFactor(t *testing.T) {
	params := SecurityParams{Ell: 256, EllPrime: 512, Epsilon: 128, ChallengeBits: 128, MinPaillierBits: 1024}
	p := big.NewInt(7)
	q := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1021), big.NewInt(1))
	n := new(big.Int).Mul(new(big.Int).Set(p), q)
	if err := validateFactorWitness(params, n, p, q); err == nil {
		t.Fatal("small-factor witness passed Pi-fac bounds")
	}
}

func TestFactorWitnessBoundsAreStrict(t *testing.T) {
	params := SecurityParams{Ell: 8, EllPrime: 32, Epsilon: 8, ChallengeBits: 8, MinPaillierBits: 16}
	p := big.NewInt(257)
	q := big.NewInt(263)
	n := new(big.Int).Mul(new(big.Int).Set(p), q)
	if err := validateFactorWitness(params, n, p, q); err != nil {
		t.Fatalf("factors immediately above the lower bound failed: %v", err)
	}
	lower := new(big.Int).Lsh(big.NewInt(1), uint(params.Ell))
	n = new(big.Int).Mul(new(big.Int).Set(lower), q)
	if err := validateFactorWitness(params, n, lower, q); err == nil {
		t.Fatal("factor equal to the lower bound was accepted")
	}
	upperFactor := new(big.Int).Lsh(big.NewInt(1), 16)
	one := big.NewInt(1)
	n = new(big.Int).Mul(new(big.Int).Set(upperFactor), one)
	if err := validateFactorWitness(params, n, upperFactor, one); err == nil {
		t.Fatal("factor at the derived upper bound was accepted")
	}
}
