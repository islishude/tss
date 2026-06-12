//go:build tier1

package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestLegacyLogProofTamper(t *testing.T) {
	t.Parallel()
	sk := testPaillierKey(t, 1024)
	domain := []byte("legacy log proof")
	scalar := big.NewInt(99)
	ciphertext, randomness, err := sk.Encrypt(nil, scalar)
	if err != nil {
		t.Fatal(err)
	}
	pointBytes, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(scalar)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveLog(nil, domain, &sk.PublicKey, ciphertext, scalar, randomness, pointBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyLog(domain, &sk.PublicKey, ciphertext, proof) {
		t.Fatal("legacy log proof did not verify")
	}
	if VerifyLog([]byte("other domain"), &sk.PublicKey, ciphertext, proof) {
		t.Fatal("legacy log proof verified under wrong domain")
	}
	if VerifyLog(domain, &sk.PublicKey, sk.NSquared, proof) {
		t.Fatal("legacy log proof verified with invalid ciphertext")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*LogProof)
	}{
		{name: "point", mutate: func(p *LogProof) { p.Point[0] ^= 1 }},
		{name: "cipher commitment", mutate: func(p *LogProof) { p.CipherCommitment[0] ^= 1 }},
		{name: "point commitment", mutate: func(p *LogProof) { p.PointCommitment[0] ^= 1 }},
		{name: "response", mutate: func(p *LogProof) { p.Response[0] ^= 1 }},
		{name: "randomness", mutate: func(p *LogProof) { p.Randomness[0] ^= 1 }},
		{name: "transcript", mutate: func(p *LogProof) { p.TranscriptHash[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := proof.Clone()
			tc.mutate(tampered)
			if VerifyLog(domain, &sk.PublicKey, ciphertext, tampered) {
				t.Fatal("tampered legacy log proof verified")
			}
		})
	}
}
