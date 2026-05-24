package paillier

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

type proofFataler interface {
	Helper()
	Fatal(args ...any)
}

func seedModulusProof() *ModulusProof {
	return &ModulusProof{
		Version:          proofVersion,
		NBits:            2048,
		SmallFactorCheck: proofSeedHash(1),
		TranscriptHash:   proofSeedHash(2),
		Digest:           proofSeedHash(3),
	}
}

func seedEncScalarProof(tb proofFataler) *EncScalarProof {
	tb.Helper()
	return &EncScalarProof{
		Version:          proofVersion,
		ScalarCommitment: seedPoint(tb, 1),
		CipherCommitment: []byte{2},
		PointCommitment:  seedPoint(tb, 3),
		Response:         []byte{4},
		Randomness:       []byte{5},
		TranscriptHash:   proofSeedHash(6),
	}
}

func seedEncRangeProof() *EncRangeProof {
	proof := &EncRangeProof{
		Version:        proofVersion,
		Bound:          secp.Order().Bytes(),
		Challenge:      []byte{7},
		Response:       []byte{8},
		TranscriptHash: proofSeedHash(9),
	}
	proof.Digest = encRangeDigest(proof)
	return proof
}

func seedMTAResponseProof(tb proofFataler) *MTAResponseProof {
	tb.Helper()
	return &MTAResponseProof{
		Version:          proofVersion,
		TranscriptHash:   proofSeedHash(10),
		BetaCommitment:   seedPoint(tb, 11),
		CipherCommitment: []byte{12},
		BCommitment:      seedPoint(tb, 13),
		BetaNonce:        seedPoint(tb, 14),
		BResponse:        []byte{15},
		BetaResponse:     []byte{16},
		Randomness:       []byte{17},
	}
}

func proofSeedHash(b byte) []byte {
	return bytes.Repeat([]byte{b}, sha256.Size)
}

func seedPoint(tb proofFataler, scalar int64) []byte {
	tb.Helper()
	out, err := secp.PointBytes(secp.ScalarBaseMult(big.NewInt(scalar)))
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

func mustMarshalProof(tb proofFataler, proof any) []byte {
	tb.Helper()
	out, err := Marshal(proof)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}
