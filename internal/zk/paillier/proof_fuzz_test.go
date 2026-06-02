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
