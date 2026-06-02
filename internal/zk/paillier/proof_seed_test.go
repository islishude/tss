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
	xs := make([][]byte, modulusProofRounds)
	zs := make([][]byte, modulusProofRounds)
	for i := range modulusProofRounds {
		xs[i] = []byte{byte(i + 1)}
		zs[i] = []byte{byte(i + 2)}
	}
	return &ModulusProof{
		Version:        proofVersion,
		W:              []byte{1},
		TranscriptHash: proofSeedHash(2),
		X:              xs,
		A:              make([]byte, modulusProofRounds),
		B:              make([]byte, modulusProofRounds),
		Z:              zs,
	}
}

func seedRingPedersenProof() *RingPedersenProof {
	commitments := make([][]byte, ringPedersenProofRounds)
	responses := make([][]byte, ringPedersenProofRounds)
	for i := range ringPedersenProofRounds {
		commitments[i] = []byte{byte(i + 1)}
		responses[i] = []byte{byte(i + 2)}
	}
	return &RingPedersenProof{
		Version:        proofVersion,
		TranscriptHash: proofSeedHash(3),
		Commitments:    commitments,
		Challenges:     make([]byte, ringPedersenProofRounds),
		Responses:      responses,
	}
}

func seedEncryptionProof(tb proofFataler) *EncryptionProof {
	tb.Helper()
	return &EncryptionProof{
		Version:          proofVersion,
		ScalarCommitment: seedPoint(tb, 1),
		CipherCommitment: []byte{2},
		PointCommitment:  seedPoint(tb, 3),
		Bound:            secp.Order().Bytes(),
		Response:         []byte{4},
		Randomness:       []byte{5},
		TranscriptHash:   proofSeedHash(6),
	}
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
	out, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(scalar))))
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
