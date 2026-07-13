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
			name:     "figure7-auxinfo",
			wireType: auxInfoDirectPayloadWireType,
			fields:   []wire.Field{{Tag: 1, Value: []byte{0x01}}, {Tag: 2, Value: planHash}},
			decode: func(raw []byte) error {
				var payload auxInfoDirectPayload
				return payload.UnmarshalBinaryWithLimits(raw, testLimits())
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
