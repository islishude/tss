package mta

import (
	"bytes"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
)

func FuzzResponseMessageUnmarshal(f *testing.F) {
	_, response := seedMessages(f)
	raw, err := response.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"ciphertext":"AQ=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalResponseMessage(data)
		if err != nil {
			return
		}
		assertPayloadRemarshals(t, m, (*ResponseMessage).MarshalBinary, UnmarshalResponseMessage)
	})
}

// Tier 0: ResponseMessage validation and wire error paths (no crypto keygen).

func TestResponseMessageValidate(t *testing.T) {
	// A valid ResponseMessage needs a valid AffGProof. Construct a minimal one via
	// the seedMessages helper and validate it.
	_, validResponse := seedMessages(t)

	tests := []struct {
		name       string
		ciphertext []byte
		proof      []byte
		wantErr    bool
	}{
		{name: "valid", ciphertext: validResponse.Ciphertext, proof: validResponse.Proof, wantErr: false},
		{name: "empty ciphertext", ciphertext: nil, proof: validResponse.Proof, wantErr: true},
		{name: "empty proof", ciphertext: validResponse.Ciphertext, proof: nil, wantErr: true},
		{name: "leading zero ciphertext", ciphertext: []byte{0x00, 0x01}, proof: validResponse.Proof, wantErr: true},
		{name: "garbled proof", ciphertext: validResponse.Ciphertext, proof: []byte{0xFF, 0xFE}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ResponseMessage{Ciphertext: tt.ciphertext, Proof: tt.proof}
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

func TestResponseMessageMarshalBinaryInvalid(t *testing.T) {
	m := ResponseMessage{Ciphertext: nil, Proof: nil}
	_, err := m.MarshalBinary()
	if err == nil {
		t.Fatal("expected error marshaling invalid response message")
	}
}

func TestUnmarshalResponseMessageErrors(t *testing.T) {
	_, validResponse := seedMessages(t)
	validRaw, err := validResponse.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

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
			name: "wrong wire type",
			data: func() []byte {
				b, _ := wire.MarshalFields(messageVersion, startMessageWireType, []wire.Field{
					{Tag: startMessageFieldCiphertext, Value: []byte{0x01}},
				})
				return b
			}(),
		},
		{
			name:    "wrong version",
			data:    mustMarshalResponseAtVersion(t, 99, validResponse.Ciphertext, validResponse.Proof),
			wantErr: "wire ResponseMessage: got version 99, want 1",
		},
		{
			name: "missing proof field",
			data: func() []byte {
				b, _ := wire.MarshalFields(messageVersion, responseMessageWireType, []wire.Field{
					{Tag: responseMessageFieldCiphertext, Value: validResponse.Ciphertext},
				})
				return b
			}(),
		},
		{
			name: "extra field",
			data: func() []byte {
				b, _ := wire.MarshalFields(messageVersion, responseMessageWireType, []wire.Field{
					{Tag: responseMessageFieldCiphertext, Value: validResponse.Ciphertext},
					{Tag: responseMessageFieldProof, Value: validResponse.Proof},
					{Tag: 99, Value: []byte{0x01}},
				})
				return b
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalResponseMessage(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Fatalf("got error %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}

	// Decoding a valid message should succeed.
	_, err = UnmarshalResponseMessage(validRaw)
	if err != nil {
		t.Fatalf("valid response message not decoded: %v", err)
	}
}

// mustMarshalResponseAtVersion marshals a ResponseMessage with an overridden version.
func mustMarshalResponseAtVersion(t *testing.T, version uint16, ciphertext, proof []byte) []byte {
	t.Helper()
	b, err := wire.MarshalFields(version, responseMessageWireType, []wire.Field{
		{Tag: responseMessageFieldCiphertext, Value: ciphertext},
		{Tag: responseMessageFieldProof, Value: proof},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Tier 1: Respond error paths (needs crypto keygen).

func TestRespondErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Tier 1 test in short mode")
	}
	skA, skB, rpA, rpB := setupTestEnv(t)

	a := big.NewInt(13)
	b := big.NewInt(37)
	start, err := Start(nil, a, &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(nil, []byte("start"), start, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil b", func(t *testing.T) {
		_, _, err := Respond(nil, []byte("start"), []byte("response"), start.Message, startProof, nil, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for nil b")
		}
	})
	t.Run("zero b", func(t *testing.T) {
		_, _, err := Respond(nil, []byte("start"), []byte("response"), start.Message, startProof, big.NewInt(0), bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for zero b")
		}
	})
	t.Run("negative b", func(t *testing.T) {
		_, _, err := Respond(nil, []byte("start"), []byte("response"), start.Message, startProof, big.NewInt(-5), bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for negative b")
		}
	})
	t.Run("b at order", func(t *testing.T) {
		_, _, err := Respond(nil, []byte("start"), []byte("response"), start.Message, startProof, new(big.Int).Set(secp.Order()), bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for b at order")
		}
	})
	t.Run("invalid start message", func(t *testing.T) {
		badStart := StartMessage{Ciphertext: nil}
		_, _, err := Respond(nil, []byte("start"), []byte("response"), badStart, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for invalid start message")
		}
	})
	t.Run("wrong start proof domain", func(t *testing.T) {
		_, _, err := Respond(nil, []byte("wrong-domain"), []byte("response"), start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
		if err == nil {
			t.Fatal("expected error for wrong start proof domain")
		}
	})
}

func TestRespondBoundaryValues(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Tier 1 test in short mode")
	}
	skA, skB, rpA, rpB := setupTestEnv(t)
	startProofDomain := []byte("start")
	responseDomain := []byte("response")

	a := big.NewInt(13)
	start, err := Start(nil, a, &skA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(nil, startProofDomain, start, &skA.PublicKey, *rpB)
	if err != nil {
		t.Fatal(err)
	}

	orderMinus1 := new(big.Int).Sub(secp.Order(), big.NewInt(1))
	bValues := []struct {
		name string
		b    *big.Int
	}{
		{name: "b=1", b: big.NewInt(1)},
		{name: "b=order-1", b: orderMinus1},
	}
	for _, bv := range bValues {
		t.Run(bv.name, func(t *testing.T) {
			bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(bv.b)))
			if err != nil {
				t.Fatal(err)
			}
			response, betaShare, err := Respond(nil, startProofDomain, responseDomain, start.Message, startProof, bv.b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if response == nil {
				t.Fatal("nil response")
			}
			if betaShare == nil {
				t.Fatal("nil beta share")
			}
		})
	}
}

func TestResponseMessageBinaryRoundTrip(t *testing.T) {
	_, validResponse := seedMessages(t)

	raw1, err := validResponse.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := validResponse.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("ResponseMessage encoding is not deterministic")
	}

	decoded, err := UnmarshalResponseMessage(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Ciphertext, validResponse.Ciphertext) {
		t.Fatal("ciphertext mismatch after round trip")
	}
	if !bytes.Equal(decoded.Proof, validResponse.Proof) {
		t.Fatal("proof mismatch after round trip")
	}
}
