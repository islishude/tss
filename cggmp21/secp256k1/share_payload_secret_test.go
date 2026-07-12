package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss/internal/wire"
)

func TestDKGEncryptedSharePayloadsRejectRetiredPlaintextShapes(t *testing.T) {
	t.Parallel()
	planHash := bytes.Repeat([]byte{0x52}, 32)
	commitHash := bytes.Repeat([]byte{0x25}, 32)
	tests := []struct {
		name     string
		wireType string
		fields   []wire.Field
		decode   func([]byte) error
	}{
		{
			name:     "keygen",
			wireType: keygenSharePayloadWireType,
			fields:   []wire.Field{{Tag: 1, Value: []byte{0x01}}, {Tag: 2, Value: planHash}},
			decode: func(raw []byte) error {
				_, err := unmarshalKeygenSharePayload(raw)
				return err
			},
		},
		{
			name:     "refresh",
			wireType: refreshSharePayloadWireType,
			fields:   []wire.Field{{Tag: 1, Value: []byte{0x01}}, {Tag: 2, Value: planHash}},
			decode: func(raw []byte) error {
				_, err := unmarshalRefreshSharePayload(raw)
				return err
			},
		},
		{
			name:     "reshare",
			wireType: reshareSharePayloadWireType,
			fields: []wire.Field{
				{Tag: 1, Value: wire.Uint32(1)},
				{Tag: 2, Value: wire.Uint32(2)},
				{Tag: 3, Value: bytes.Repeat([]byte{0x01}, 32)},
				{Tag: 4, Value: commitHash},
				{Tag: 5, Value: planHash},
			},
			decode: func(raw []byte) error {
				_, err := unmarshalReshareSharePayload(raw)
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := wire.MarshalFields(1, tc.wireType, tc.fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.decode(raw); err == nil {
				t.Fatal("accepted retired plaintext share encoding")
			}
		})
	}
}

func TestReshareEncryptedSharePayloadRoundTrip(t *testing.T) {
	t.Parallel()
	proof := testEncProof(17)
	proof.TranscriptHash = bytes.Repeat([]byte{0x71}, 32)
	payload := reshareSharePayload{
		Dealer:               1,
		Receiver:             2,
		Ciphertext:           []byte{0x01, 0x02},
		Proof:                proof,
		DealerCommitmentHash: bytes.Repeat([]byte{0x72}, 32),
		PlanHash:             bytes.Repeat([]byte{0x73}, 32),
	}
	raw, err := marshalReshareSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalReshareSharePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalReshareSharePayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatal("reshare encrypted share re-encoded differently")
	}
}
