package paillier

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestLegacyLogProofTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crypto proof test in short mode")
	}
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
			tampered := cloneLogProof(proof)
			tc.mutate(tampered)
			if VerifyLog(domain, &sk.PublicKey, ciphertext, tampered) {
				t.Fatal("tampered legacy log proof verified")
			}
		})
	}
}

func TestLegacyProofWireTypesAreSeparated(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		raw       []byte
		unmarshal func([]byte) error
	}{
		{
			name: "log as encryption",
			raw:  mustMarshalProof(t, seedLogProof(t)),
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalEncryptionProof(raw)
				return err
			},
		},
		{
			name: "encryption as mta",
			raw:  mustMarshalProof(t, seedEncryptionProof(t)),
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalMTAResponseProof(raw)
				return err
			},
		},
		{
			name: "mta as log",
			raw:  mustMarshalProof(t, seedMTAResponseProof(t)),
			unmarshal: func(raw []byte) error {
				_, err := UnmarshalLogProof(raw)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.unmarshal(tc.raw); err == nil {
				t.Fatal("proof decoded under wrong wire type")
			}
		})
	}
}

func cloneLogProof(in *LogProof) *LogProof {
	out := *in
	out.Point = append([]byte(nil), in.Point...)
	out.CipherCommitment = append([]byte(nil), in.CipherCommitment...)
	out.PointCommitment = append([]byte(nil), in.PointCommitment...)
	out.Response = append([]byte(nil), in.Response...)
	out.Randomness = append([]byte(nil), in.Randomness...)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	return &out
}
