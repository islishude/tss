package mta

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// Tier 0: ResponseMessage validation and wire error paths (no crypto keygen).

func TestResponseMessageValidate(t *testing.T) {
	t.Parallel()
	// A valid ResponseMessage needs a valid AffGProof. Construct a minimal one via
	// the seedMessages helper and validate it.
	_, validResponse := seedMessages(t)
	badProof := validResponse.Proof
	badProof.A = nil // garble the proof

	tests := []struct {
		name       string
		ciphertext []byte
		f          []byte
		proof      zkpai.AffGProof
		wantErr    bool
	}{
		{name: "valid", ciphertext: validResponse.Ciphertext, f: validResponse.F, proof: validResponse.Proof, wantErr: false},
		{name: "empty ciphertext", ciphertext: nil, f: validResponse.F, proof: validResponse.Proof, wantErr: true},
		{name: "empty F", ciphertext: validResponse.Ciphertext, proof: validResponse.Proof, wantErr: true},
		{name: "empty proof", ciphertext: validResponse.Ciphertext, f: validResponse.F, proof: zkpai.AffGProof{}, wantErr: true},
		{name: "leading zero ciphertext", ciphertext: []byte{0x00, 0x01}, f: validResponse.F, proof: validResponse.Proof, wantErr: true},
		{name: "leading zero F", ciphertext: validResponse.Ciphertext, f: []byte{0x00, 0x01}, proof: validResponse.Proof, wantErr: true},
		{name: "garbled proof", ciphertext: validResponse.Ciphertext, f: validResponse.F, proof: badProof, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ResponseMessage{Ciphertext: tt.ciphertext, F: tt.f, Proof: tt.proof}
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
	t.Parallel()

	m := ResponseMessage{Ciphertext: nil, Proof: zkpai.AffGProof{}}
	_, err := m.MarshalBinary()
	if err == nil {
		t.Fatal("expected error marshaling invalid response message")
	}
}

func TestUnmarshalResponseMessageErrors(t *testing.T) {
	t.Parallel()
	_, validResponse := seedMessages(t)
	validProofRaw := mustMarshalAffGProof(t, validResponse.Proof)
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
				b, _ := wire.MarshalFields(responseMessageWireVersion, startMessageWireType, []wire.Field{
					{Tag: testutil.MustFieldTag(StartMessage{}, "Ciphertext"), Value: []byte{0x01}},
				})
				return b
			}(),
		},
		{
			name:    "wrong version",
			data:    mustMarshalResponseAtVersion(t, 99, validResponse.Ciphertext, validResponse.F, validResponse.Proof),
			wantErr: "wire ResponseMessage: got version 99, want 1",
		},
		{
			name: "missing proof field",
			data: func() []byte {
				b, _ := wire.MarshalFields(responseMessageWireVersion, responseMessageWireType, []wire.Field{
					{Tag: testutil.MustFieldTag(ResponseMessage{}, "Ciphertext"), Value: validResponse.Ciphertext},
					{Tag: testutil.MustFieldTag(ResponseMessage{}, "F"), Value: validResponse.F},
				})
				return b
			}(),
		},
		{
			name: "extra field",
			data: func() []byte {
				b, _ := wire.MarshalFields(responseMessageWireVersion, responseMessageWireType, []wire.Field{
					{Tag: testutil.MustFieldTag(ResponseMessage{}, "Ciphertext"), Value: validResponse.Ciphertext},
					{Tag: testutil.MustFieldTag(ResponseMessage{}, "F"), Value: validResponse.F},
					{Tag: testutil.MustFieldTag(ResponseMessage{}, "Proof"), Value: validProofRaw},
					{Tag: 99, Value: []byte{0x01}},
				})
				return b
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tss.DecodeBinary[ResponseMessage](tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Fatalf("got error %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}

	// Decoding a valid message should succeed.
	_, err = tss.DecodeBinary[ResponseMessage](validRaw)
	if err != nil {
		t.Fatalf("valid response message not decoded: %v", err)
	}
}

// mustMarshalResponseAtVersion marshals a ResponseMessage with an overridden version.
func mustMarshalResponseAtVersion(t *testing.T, version uint16, ciphertext, f []byte, proof zkpai.AffGProof) []byte {
	t.Helper()
	b, err := wire.MarshalFields(version, responseMessageWireType, []wire.Field{
		{Tag: testutil.MustFieldTag(ResponseMessage{}, "Ciphertext"), Value: ciphertext},
		{Tag: testutil.MustFieldTag(ResponseMessage{}, "F"), Value: f},
		{Tag: testutil.MustFieldTag(ResponseMessage{}, "Proof"), Value: mustMarshalAffGProof(t, proof)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustMarshalAffGProof(t *testing.T, proof zkpai.AffGProof) []byte {
	t.Helper()
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Tier 1: Respond error paths (needs crypto keygen).

func TestResponseMessageBinaryRoundTrip(t *testing.T) {
	t.Parallel()
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

	decoded, err := tss.DecodeBinary[ResponseMessage](raw1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Ciphertext, validResponse.Ciphertext) {
		t.Fatal("ciphertext mismatch after round trip")
	}
	if !bytes.Equal(decoded.F, validResponse.F) {
		t.Fatal("F mismatch after round trip")
	}
	if !bytes.Equal(mustMarshalAffGProof(t, decoded.Proof), mustMarshalAffGProof(t, validResponse.Proof)) {
		t.Fatal("proof mismatch after round trip")
	}
}
