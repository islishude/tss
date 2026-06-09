package mta

import (
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

func FuzzStartMessageUnmarshal(f *testing.F) {
	start, response := seedMessages(f)
	_ = response
	raw, err := start.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"ciphertext":"AQ=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalStartMessage(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, m, (*StartMessage).MarshalBinary, UnmarshalStartMessage)
	})
}

// Tier 0: StartMessage validation and wire error paths (no crypto keygen).

func TestStartMessageValidate(t *testing.T) {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := StartMessage{Ciphertext: tt.ciphertext}
			err := m.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestStartMessageMarshalBinaryInvalid(t *testing.T) {
	// MarshalBinary calls Validate first — an invalid message should not marshal.
	m := StartMessage{Ciphertext: nil}
	_, err := m.MarshalBinary()
	if err == nil {
		t.Fatal("expected error marshaling invalid start message")
	}
}

func TestUnmarshalStartMessageErrors(t *testing.T) {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalStartMessage(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Fatalf("got error %q, want %q", err.Error(), tt.wantErr)
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
	var opening *StartOpening
	opening.Destroy() // must not panic
}

func TestStartOpeningString(t *testing.T) {
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
	if opening.k.String() != "" {
		t.Log("k is still readable via String()")
	}
}

// Tier 1: Start phase error paths (needs crypto keygen).

func TestStartErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Tier 1 test in short mode")
	}
	skA, _, _, _ := setupTestEnv(t)

	tests := []struct {
		name string
		a    *big.Int
	}{
		{name: "nil a", a: nil},
		{name: "zero a", a: big.NewInt(0)},
		{name: "negative a", a: big.NewInt(-5)},
		{name: "a at order", a: new(big.Int).Set(secp.Order())},
		{name: "a above order", a: new(big.Int).Add(secp.Order(), big.NewInt(1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Start(nil, tt.a, &skA.PublicKey)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestStartBoundaryValues(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Tier 1 test in short mode")
	}
	skA, _, _, _ := setupTestEnv(t)

	orderMinus1 := new(big.Int).Sub(secp.Order(), big.NewInt(1))
	tests := []struct {
		name string
		a    *big.Int
	}{
		{name: "a=1", a: big.NewInt(1)},
		{name: "a=order-1", a: orderMinus1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opening, err := Start(nil, tt.a, &skA.PublicKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opening == nil {
				t.Fatal("nil opening")
			}
		})
	}
}

func TestProveStartForVerifierErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Tier 1 test in short mode")
	}
	skA, _, _, rpB := setupTestEnv(t)

	t.Run("nil opening", func(t *testing.T) {
		_, err := ProveStartForVerifier(nil, nil, nil, &skA.PublicKey, *rpB)
		if err == nil {
			t.Fatal("expected error for nil opening")
		}
		if err.Error() != "nil MtA start opening" {
			t.Fatalf("got %q, want %q", err.Error(), "nil MtA start opening")
		}
	})

	t.Run("opening with invalid ciphertext", func(t *testing.T) {
		opening := &StartOpening{
			Message: StartMessage{Ciphertext: nil},
			k:       big.NewInt(13),
			rho:     big.NewInt(37),
		}
		_, err := ProveStartForVerifier(nil, nil, opening, &skA.PublicKey, *rpB)
		if err == nil {
			t.Fatal("expected error for opening with invalid message")
		}
	})
}

func TestVerifyStartErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Tier 1 test in short mode")
	}
	skA, _, _, rpB := setupTestEnv(t)

	a := big.NewInt(42)
	opening, err := Start(nil, a, &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveStartForVerifier(nil, []byte("domain"), opening, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("empty proof", func(t *testing.T) {
		err := VerifyStart([]byte("domain"), opening.Message, &skA.PublicKey, *rpB, nil)
		if err == nil {
			t.Fatal("expected error for empty proof")
		}
	})

	t.Run("truncated proof", func(t *testing.T) {
		err := VerifyStart([]byte("domain"), opening.Message, &skA.PublicKey, *rpB, proof[:4])
		if err == nil {
			t.Fatal("expected error for truncated proof")
		}
	})

	t.Run("garbled proof", func(t *testing.T) {
		garbled := make([]byte, len(proof))
		copy(garbled, proof)
		for i := range garbled {
			garbled[i] ^= 0xFF
		}
		err := VerifyStart([]byte("domain"), opening.Message, &skA.PublicKey, *rpB, garbled)
		if err == nil {
			t.Fatal("expected error for garbled proof")
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		err := VerifyStart([]byte("other-domain"), opening.Message, &skA.PublicKey, *rpB, proof)
		if err == nil {
			t.Fatal("expected error for wrong domain")
		}
	})
}
