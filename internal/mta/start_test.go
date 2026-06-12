package mta

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

// Tier 0: StartMessage validation and wire error paths (no crypto keygen).

func TestStartMessageValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    bool
	}{
		{name: "valid", ciphertext: []byte{0x01}, wantErr: false},
		{name: "empty", ciphertext: nil, wantErr: true},
		{name: "zero len", ciphertext: []byte{}, wantErr: true},
		{name: "leading zero", ciphertext: []byte{0x00, 0x05}, wantErr: true},
		{name: "all zeros", ciphertext: []byte{0x00}, wantErr: true},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := StartMessage{Ciphertext: tc.ciphertext}
			err := m.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestStartMessageMarshalBinaryInvalid(t *testing.T) {
	t.Parallel()

	// MarshalBinary calls Validate first — an invalid message should not marshal.
	m := StartMessage{Ciphertext: nil}
	_, err := m.MarshalBinary()
	if err == nil {
		t.Fatal("expected error marshaling invalid start message")
	}
}

func TestUnmarshalStartMessageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name: "empty",
			data: nil,
		},
		{
			name: "truncated TLV",
			data: []byte{0x00, 0x01},
		},
		{
			name: "wrong wire type",
			data: func() []byte {
				b, _ := wire.MarshalFields(messageVersion, "mta.response-message", []wire.Field{
					{Tag: responseMessageFieldCiphertext, Value: []byte{0x01}},
					{Tag: responseMessageFieldProof, Value: []byte{0x02}},
				})
				return b
			}(),
		},
		{
			name:    "wrong version",
			data:    mustMarshalStartAtVersion(t, 99, []byte{0x01}),
			wantErr: "wire StartMessage: got version 99, want 1",
		},
		{
			name: "extra fields",
			data: func() []byte {
				b, _ := wire.MarshalFields(messageVersion, startMessageWireType, []wire.Field{
					{Tag: startMessageFieldCiphertext, Value: []byte{0x01}},
					{Tag: 99, Value: []byte{0x02}},
				})
				return b
			}(),
		},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := UnmarshalStartMessage(tc.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantErr != "" && err.Error() != tc.wantErr {
				t.Fatalf("got error %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// mustMarshalStartAtVersion marshals a StartMessage with an overridden version.
func mustMarshalStartAtVersion(t *testing.T, version uint16, ciphertext []byte) []byte {
	t.Helper()
	b, err := wire.MarshalFields(version, startMessageWireType, []wire.Field{
		{Tag: startMessageFieldCiphertext, Value: ciphertext},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStartOpeningDestroy(t *testing.T) {
	t.Parallel()

	ciphertext := []byte{0x0a, 0x0b, 0x0c}
	opening := &StartOpening{
		Message: StartMessage{Ciphertext: ciphertext},
		k:       big.NewInt(42),
		rho:     big.NewInt(99),
	}
	opening.Destroy()
	if opening.k != nil {
		t.Fatal("k not cleared")
	}
	if opening.rho != nil {
		t.Fatal("rho not cleared")
	}
	for _, b := range opening.Message.Ciphertext {
		if b != 0 {
			t.Fatal("ciphertext not zeroed")
		}
	}
}

func TestStartOpeningDestroyNil(t *testing.T) {
	t.Parallel()

	var opening *StartOpening
	opening.Destroy() // must not panic
}

func TestStartOpeningString(t *testing.T) {
	t.Parallel()

	var nilOpening *StartOpening
	if s := nilOpening.String(); s != "<nil>" {
		t.Fatalf("got %q, want \"<nil>\"", s)
	}
	if s := nilOpening.GoString(); s != "<nil>" {
		t.Fatalf("got %q, want \"<nil>\"", s)
	}
	opening := &StartOpening{
		Message: StartMessage{Ciphertext: []byte{0x01}},
		k:       big.NewInt(42),
	}
	s := opening.String()
	if s == "" || s == "<nil>" {
		t.Fatalf("unexpected string: %q", s)
	}
	if bytes.Contains([]byte(s), []byte("42")) {
		t.Fatalf("StartOpening string leaked witness: %q", s)
	}
}

// Tier 1: Start phase error paths (needs crypto keygen).
