package paillier

import (
	"bytes"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

func TestStandaloneProofDecodersEnforceObjectByteCaps(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		maxBytes int
		decode   func([]byte) error
	}{
		"modulus": {
			maxBytes: tss.DefaultMaxPaillierProofBytes,
			decode: func(in []byte) error {
				var proof ModulusProof
				return proof.UnmarshalBinary(in)
			},
		},
		"ring-pedersen": {
			maxBytes: tss.DefaultMaxPaillierProofBytes,
			decode: func(in []byte) error {
				var proof RingPedersenProof
				return proof.UnmarshalBinary(in)
			},
		},
		"enc": {
			maxBytes: tss.DefaultMaxZKProofBytes,
			decode: func(in []byte) error {
				var proof EncProof
				return proof.UnmarshalBinary(in)
			},
		},
		"affg": {
			maxBytes: tss.DefaultMaxZKProofBytes,
			decode: func(in []byte) error {
				var proof AffGProof
				return proof.UnmarshalBinary(in)
			},
		},
		"logstar": {
			maxBytes: tss.DefaultMaxZKProofBytes,
			decode: func(in []byte) error {
				var proof LogStarProof
				return proof.UnmarshalBinary(in)
			},
		},
	} {
		err := tc.decode(make([]byte, tc.maxBytes+1))
		if err == nil || !strings.Contains(err.Error(), "wire input too large") {
			t.Errorf("%s oversized decode got %v, want wire frame rejection", name, err)
		}
	}
}

func TestModulusProofDecoderCapsListItems(t *testing.T) {
	t.Parallel()

	raw, err := wire.MarshalFields(modulusProofWireVersion, modulusProofWireType, []wire.Field{
		{Tag: 1, Value: []byte{1}},
		{Tag: 2, Value: make([]byte, 32)},
		{Tag: 3, Value: wire.EncodeBytesList([][]byte{bytes.Repeat([]byte{1}, zkFieldLimits()["paillier_modulus"]+1)})},
		{Tag: 4, Value: make([]byte, modulusProofRounds)},
		{Tag: 5, Value: make([]byte, modulusProofRounds)},
		{Tag: 6, Value: wire.EncodeBytesList([][]byte{{1}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	var proof ModulusProof
	err = proof.UnmarshalBinary(raw)
	if err == nil || !strings.Contains(err.Error(), "byte field too large") {
		t.Fatalf("oversized modulus proof item got %v, want semantic field rejection", err)
	}
}
