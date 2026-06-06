package paillier

import (
	"bytes"
	"testing"
)

func FuzzModulusProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalProof(f, seedModulusProof()))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalModulusProof(data)
		if err != nil {
			return
		}
		assertProofRemarshals(t, proof, UnmarshalModulusProof)
	})
}

func FuzzRingPedersenProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalProof(f, seedRingPedersenProof()))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalRingPedersenProof(data)
		if err != nil {
			return
		}
		assertProofRemarshals(t, proof, UnmarshalRingPedersenProof)
	})
}

func FuzzRingPedersenParamsUnmarshal(f *testing.F) {
	paramsRaw, err := MarshalRingPedersenParams(seedRingPedersenParams())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(paramsRaw)
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		params, err := UnmarshalRingPedersenParams(data)
		if err != nil {
			return
		}
		raw, err := MarshalRingPedersenParams(params)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := UnmarshalRingPedersenParams(raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := MarshalRingPedersenParams(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, again) {
			t.Fatal("Ring-Pedersen params did not remarshal deterministically")
		}
	})
}

func FuzzEncryptionProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalProof(f, seedEncryptionProof(f)))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalEncryptionProof(data)
		if err != nil {
			return
		}
		assertProofRemarshals(t, proof, UnmarshalEncryptionProof)
	})
}

func FuzzMTAResponseProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalProof(f, seedMTAResponseProof(f)))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalMTAResponseProof(data)
		if err != nil {
			return
		}
		assertProofRemarshals(t, proof, UnmarshalMTAResponseProof)
	})
}

func FuzzLogProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalProof(f, seedLogProof(f)))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalLogProof(data)
		if err != nil {
			return
		}
		assertProofRemarshals(t, proof, UnmarshalLogProof)
	})
}

func FuzzEncProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalBinary(f, seedEncProof()))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalEncProof(data)
		if err != nil {
			return
		}
		assertBinaryProofRemarshals(t, proof, UnmarshalEncProof)
	})
}

func FuzzAffGProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalBinary(f, seedAffGProof(f)))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalAffGProof(data)
		if err != nil {
			return
		}
		assertBinaryProofRemarshals(t, proof, UnmarshalAffGProof)
	})
}

func FuzzLogStarProofUnmarshal(f *testing.F) {
	f.Add(mustMarshalBinary(f, seedLogStarProof()))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte("TSS1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := UnmarshalLogStarProof(data)
		if err != nil {
			return
		}
		assertBinaryProofRemarshals(t, proof, UnmarshalLogStarProof)
	})
}

func assertProofRemarshals[P any](t *testing.T, proof P, unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("proof did not remarshal deterministically")
	}
}

type binaryProof interface {
	MarshalBinary() ([]byte, error)
}

func assertBinaryProofRemarshals[P binaryProof](t *testing.T, proof P, unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("proof did not remarshal deterministically")
	}
}

func mustMarshalBinary(tb proofFataler, proof binaryProof) []byte {
	tb.Helper()
	out, err := proof.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	return out
}
