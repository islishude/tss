package paillier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// MigrateJSONModulusProof converts a legacy JSON modulus proof to canonical TLV.
func MigrateJSONModulusProof(in []byte) ([]byte, error) {
	var proof ModulusProof
	if err := decodeLegacyJSONProof(in, "modulus proof", &proof); err != nil {
		return nil, err
	}
	return Marshal(&proof)
}

// MigrateJSONEncScalarProof converts a legacy JSON encrypted scalar proof to canonical TLV.
func MigrateJSONEncScalarProof(in []byte) ([]byte, error) {
	var proof EncScalarProof
	if err := decodeLegacyJSONProof(in, "encrypted scalar proof", &proof); err != nil {
		return nil, err
	}
	return Marshal(&proof)
}

// MigrateJSONEncRangeProof converts a legacy JSON encrypted range proof to canonical TLV.
func MigrateJSONEncRangeProof(in []byte) ([]byte, error) {
	var proof EncRangeProof
	if err := decodeLegacyJSONProof(in, "encrypted range proof", &proof); err != nil {
		return nil, err
	}
	return Marshal(&proof)
}

// MigrateJSONMTAResponseProof converts a legacy JSON MtA response proof to canonical TLV.
func MigrateJSONMTAResponseProof(in []byte) ([]byte, error) {
	var proof MTAResponseProof
	if err := decodeLegacyJSONProof(in, "MtA response proof", &proof); err != nil {
		return nil, err
	}
	return Marshal(&proof)
}

func decodeLegacyJSONProof(in []byte, name string, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(in))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode legacy JSON %s: %w", name, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode legacy JSON %s: trailing data", name)
	}
	return nil
}
