package paillier

import (
	"testing"
)

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
