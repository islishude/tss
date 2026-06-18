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

func seedEncProof() *EncProof {
	return &EncProof{
		Version:        encProofVersion,
		S:              big.NewInt(31),
		A:              big.NewInt(32),
		C:              big.NewInt(33),
		Z1:             big.NewInt(-34),
		Z2:             big.NewInt(35),
		Z3:             big.NewInt(36),
		TranscriptHash: proofSeedHash(37),
	}
}

func seedAffGProof(tb proofFataler) *AffGProof {
	tb.Helper()
	return &AffGProof{
		Version:        affGProofVersion,
		A:              big.NewInt(41),
		Bx:             seedCurvePoint(42),
		By:             big.NewInt(43),
		E:              big.NewInt(44),
		S:              big.NewInt(45),
		F:              big.NewInt(46),
		T:              big.NewInt(47),
		Y:              big.NewInt(48),
		Z1:             big.NewInt(-49),
		Z2:             big.NewInt(50),
		Z3:             big.NewInt(-51),
		Z4:             big.NewInt(52),
		W:              big.NewInt(53),
		WY:             big.NewInt(54),
		TranscriptHash: proofSeedHash(55),
	}
}

func seedLogStarProof() *LogStarProof {
	return &LogStarProof{
		Version:        logStarProofVersion,
		S:              big.NewInt(61),
		A:              big.NewInt(62),
		Y:              seedCurvePoint(63),
		D:              big.NewInt(64),
		Z1:             big.NewInt(-65),
		Z2:             big.NewInt(66),
		Z3:             big.NewInt(67),
		TranscriptHash: proofSeedHash(68),
	}
}

func proofSeedHash(b byte) []byte {
	return bytes.Repeat([]byte{b}, sha256.Size)
}

func seedCurvePoint(scalar int64) *secp.Point {
	return secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(scalar)))
}

func mustMarshalProof(tb proofFataler, proof any) []byte {
	tb.Helper()
	out, err := Marshal(proof)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

type binaryProof interface {
	MarshalBinary() ([]byte, error)
}

func mustMarshalBinary(tb proofFataler, proof binaryProof) []byte {
	tb.Helper()
	out, err := proof.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	return out
}
