//go:build tier1

package paillier

import (
	"math/big"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestModulusProofCGGMP24Checks(t *testing.T) {
	t.Parallel()
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
		tampered := proof.Clone()
		tampered.W = fixedModNBytes(big.NewInt(1), nLen)
		if VerifyModulus(domain, &sk.PublicKey, party, tampered) {
			t.Fatal("modulus proof with Jacobi(w,N) != -1 verified")
		}
	})
	t.Run("round count", func(t *testing.T) {
		tampered := proof.Clone()
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
			{Tag: testutil.MustFieldTag(ModulusProof{}, "W"), Value: proof.W},
			{Tag: testutil.MustFieldTag(ModulusProof{}, "TranscriptHash"), Value: proof.TranscriptHash},
			{Tag: testutil.MustFieldTag(ModulusProof{}, "X"), Value: wire.EncodeBytesList(proof.X)},
			{Tag: testutil.MustFieldTag(ModulusProof{}, "A"), Value: proof.A},
			{Tag: testutil.MustFieldTag(ModulusProof{}, "B"), Value: proof.B},
			{Tag: testutil.MustFieldTag(ModulusProof{}, "Z"), Value: wire.EncodeBytesList(proof.Z)},
			{Tag: 99, Value: wire.EncodeBytesList(proof.Z)},
		})
		if _, err := tss.DecodeBinary[ModulusProof](raw); err == nil {
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
				tampered := proof.Clone()
				tc.mutate(tampered)
				if VerifyModulus(domain, &sk.PublicKey, party, tampered) {
					t.Fatal("modulus proof with invalid Z_N* element verified")
				}
			})
		}
	})
	t.Run("equations", func(t *testing.T) {
		tamperedZ := proof.Clone()
		tamperedZ.Z[0][len(tamperedZ.Z[0])-1] ^= 1
		if VerifyModulus(domain, &sk.PublicKey, party, tamperedZ) {
			t.Fatal("modulus proof with bad z^N equation verified")
		}
		tamperedX := proof.Clone()
		tamperedX.X[0][len(tamperedX.X[0])-1] ^= 1
		if VerifyModulus(domain, &sk.PublicKey, party, tamperedX) {
			t.Fatal("modulus proof with bad x^4 equation verified")
		}
	})
}
