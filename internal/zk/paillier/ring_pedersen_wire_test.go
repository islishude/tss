package paillier

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

type ringPedersenParamsNestedMessage struct {
	Params RingPedersenParams `wire:"1,nested,max_bytes=ring_pedersen_params"`
}

func (ringPedersenParamsNestedMessage) WireType() string { return "zk.paillier.test.rp-nested" }

func (ringPedersenParamsNestedMessage) WireVersion() uint16 { return 1 }

func ringPedersenParamsTestLimits() wire.FieldLimits {
	return wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
		"ring_pedersen_params":  1024,
	}
}

func TestRingPedersenParamsWireRoundTrip(t *testing.T) {
	t.Parallel()

	params := seedRingPedersenParams()
	raw, err := wire.Marshal(params, wire.WithFieldLimitsForMarshal(ringPedersenParamsTestLimits()))
	if err != nil {
		t.Fatal(err)
	}

	var decoded RingPedersenParams
	if err := wire.Unmarshal(raw, &decoded, wire.WithFieldLimits(ringPedersenParamsTestLimits())); err != nil {
		t.Fatal(err)
	}
	if decoded.N.Cmp(params.N) != 0 || decoded.S.Cmp(params.S) != 0 || decoded.T.Cmp(params.T) != 0 {
		t.Fatal("Ring-Pedersen params did not round-trip")
	}

	again, err := wire.Marshal(&decoded, wire.WithFieldLimitsForMarshal(ringPedersenParamsTestLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("Ring-Pedersen params wire encoding is not deterministic")
	}
}

func TestRingPedersenParamsWireRejectsNilFields(t *testing.T) {
	t.Parallel()

	_, err := wire.Marshal(&RingPedersenParams{
		N: nil,
		S: big.NewInt(2),
		T: big.NewInt(4),
	}, wire.WithFieldLimitsForMarshal(ringPedersenParamsTestLimits()))
	if err == nil {
		t.Fatal("expected nil Ring-Pedersen field rejection")
	}
}

func TestRingPedersenParamsWireRejectsInvalidN(t *testing.T) {
	t.Parallel()

	_, err := wire.Marshal(&RingPedersenParams{
		N: big.NewInt(17),
		S: big.NewInt(2),
		T: big.NewInt(3),
	}, wire.WithFieldLimitsForMarshal(ringPedersenParamsTestLimits()))
	if err == nil {
		t.Fatal("expected invalid Ring-Pedersen modulus rejection")
	}
}

func TestRingPedersenParamsWireRejectsOversizedModulus(t *testing.T) {
	t.Parallel()

	params := seedRingPedersenParams()
	_, err := wire.Marshal(params, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": 7,
	}))
	if err == nil {
		t.Fatal("expected oversized modulus rejection during marshal")
	}

	raw, err := wire.MarshalFields(ringPedersenParamsWireVersion, ringPedersenParamsWireType, []wire.Field{
		{Tag: 1, Value: []byte{0x01, 0x00}},
		{Tag: 2, Value: []byte{0x00, 0x02}},
		{Tag: 3, Value: []byte{0x00, 0x04}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded RingPedersenParams
	err = wire.Unmarshal(raw, &decoded, wire.WithFieldLimits(wire.FieldLimits{
		"paillier_modulus_bits": 8,
	}))
	if err == nil {
		t.Fatal("expected oversized modulus rejection during unmarshal")
	}
}

func TestRingPedersenParamsNestedLimits(t *testing.T) {
	t.Parallel()

	params := seedRingPedersenParams()
	innerRaw, err := wire.Marshal(params, wire.WithFieldLimitsForMarshal(ringPedersenParamsTestLimits()))
	if err != nil {
		t.Fatal(err)
	}
	nested := ringPedersenParamsNestedMessage{Params: *params}

	if _, err := wire.Marshal(nested, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
	})); err == nil {
		t.Fatal("expected missing nested ring_pedersen_params limit")
	}

	if _, err := wire.Marshal(nested, wire.WithFieldLimitsForMarshal(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
		"ring_pedersen_params":  len(innerRaw) - 1,
	})); err == nil {
		t.Fatal("expected nested max_bytes rejection during marshal")
	}

	raw, err := wire.Marshal(nested, wire.WithFieldLimitsForMarshal(ringPedersenParamsTestLimits()))
	if err != nil {
		t.Fatal(err)
	}
	var decoded ringPedersenParamsNestedMessage
	if err := wire.Unmarshal(raw, &decoded, wire.WithFieldLimits(wire.FieldLimits{
		"paillier_modulus_bits": tss.DefaultMaxPaillierModulusBits,
		"ring_pedersen_params":  len(innerRaw) - 1,
	})); err == nil {
		t.Fatal("expected nested max_bytes rejection during unmarshal")
	}
}
