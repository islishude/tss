package paillier

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestFactorProofRejectsNonCanonicalWire(t *testing.T) {
	t.Parallel()
	proof := seedFactorProof()
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := new(FactorProof).UnmarshalBinary(append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("factor proof accepted trailing bytes")
	}

	fields := factorProofWireFields(t, proof)
	missing, err := wire.MarshalFields(factorProofWireVersion, factorProofWireType, fields[1:])
	if err != nil {
		t.Fatal(err)
	}
	if err := new(FactorProof).UnmarshalBinary(missing); err == nil {
		t.Fatal("factor proof accepted a missing field")
	}

	duplicate := bytes.Clone(raw)
	fieldCountOffset := 4 + 2 + len(factorProofWireType) + 2
	binary.BigEndian.PutUint16(duplicate[fieldCountOffset:], 13)
	duplicate = wire.AppendUint16(duplicate, 12)
	duplicate = wire.AppendUint32(duplicate, uint32(len(proof.TranscriptHash)))
	duplicate = append(duplicate, proof.TranscriptHash...)
	if err := new(FactorProof).UnmarshalBinary(duplicate); err == nil {
		t.Fatal("factor proof accepted a duplicate tag")
	}

	nonMinimalFields := bytesFieldsClone(fields)
	nonMinimalFields[0].Value = append([]byte{0}, nonMinimalFields[0].Value...)
	nonMinimal, err := wire.MarshalFields(factorProofWireVersion, factorProofWireType, nonMinimalFields)
	if err != nil {
		t.Fatal(err)
	}
	if err := new(FactorProof).UnmarshalBinary(nonMinimal); err == nil {
		t.Fatal("factor proof accepted a non-minimal integer")
	}
}

func factorProofWireFields(t *testing.T, proof *FactorProof) []wire.Field {
	t.Helper()
	positive := []*big.Int{proof.P, proof.Q, proof.A, proof.B, proof.T}
	signed := []*big.Int{proof.Sigma, proof.Z1, proof.Z2, proof.W1, proof.W2, proof.V}
	fields := make([]wire.Field, 0, 12)
	for i, value := range positive {
		encoded, err := wire.EncodeBigPos(value)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, wire.Field{Tag: uint16(i + 1), Value: encoded})
	}
	for i, value := range signed {
		encoded, err := wire.EncodeBigInt(value)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, wire.Field{Tag: uint16(i + 6), Value: encoded})
	}
	fields = append(fields, wire.Field{Tag: 12, Value: bytes.Clone(proof.TranscriptHash)})
	return fields
}

func bytesFieldsClone(in []wire.Field) []wire.Field {
	out := make([]wire.Field, len(in))
	for i := range in {
		out[i] = wire.Field{Tag: in[i].Tag, Value: bytes.Clone(in[i].Value)}
	}
	return out
}
