package paillier

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONProofMigrationHelpers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		proof   any
		migrate func([]byte) ([]byte, error)
		decode  func([]byte) error
	}{
		{
			name:    "modulus",
			proof:   seedModulusProof(),
			migrate: MigrateJSONModulusProof,
			decode: func(in []byte) error {
				_, err := UnmarshalModulusProof(in)
				return err
			},
		},
		{
			name:    "encrypted scalar",
			proof:   seedEncScalarProof(t),
			migrate: MigrateJSONEncScalarProof,
			decode: func(in []byte) error {
				_, err := UnmarshalEncScalarProof(in)
				return err
			},
		},
		{
			name:    "encrypted range",
			proof:   seedEncRangeProof(),
			migrate: MigrateJSONEncRangeProof,
			decode: func(in []byte) error {
				_, err := UnmarshalEncRangeProof(in)
				return err
			},
		},
		{
			name:    "mta response",
			proof:   seedMTAResponseProof(t),
			migrate: MigrateJSONMTAResponseProof,
			decode: func(in []byte) error {
				_, err := UnmarshalMTAResponseProof(in)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := mustMarshalProof(t, tc.proof)
			legacy, err := json.Marshal(tc.proof)
			if err != nil {
				t.Fatal(err)
			}
			migrated, err := tc.migrate(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(migrated, expected) {
				t.Fatal("migrated proof did not match canonical TLV")
			}
			if err := tc.decode(migrated); err != nil {
				t.Fatalf("migrated TLV did not decode: %v", err)
			}
			if err := tc.decode(legacy); err == nil {
				t.Fatal("legacy JSON decoded through the production proof decoder")
			}
		})
	}
}

func TestJSONProofMigrationRejectsUnsafeInputs(t *testing.T) {
	if _, err := MigrateJSONModulusProof([]byte(`{"version":1,"unknown":true}`)); err == nil {
		t.Fatal("legacy JSON proof with unknown field migrated")
	}

	legacy, err := json.Marshal(seedModulusProof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateJSONModulusProof(append(legacy, []byte(` {}`)...)); err == nil {
		t.Fatal("legacy JSON proof with trailing data migrated")
	}

	rangeProof := seedEncRangeProof()
	rangeProof.Response = prependZero(rangeProof.Response)
	legacy, err = json.Marshal(rangeProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateJSONEncRangeProof(legacy); err == nil {
		t.Fatal("legacy JSON proof with non-minimal integer migrated")
	}

	mtaProof := seedMTAResponseProof(t)
	mtaProof.BetaCommitment = []byte{0x02}
	legacy, err = json.Marshal(mtaProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateJSONMTAResponseProof(legacy); err == nil {
		t.Fatal("legacy JSON proof with malformed point migrated")
	}
}
