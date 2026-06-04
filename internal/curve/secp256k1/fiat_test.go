package secp256k1

import (
	"fmt"
	"math/big"
	"testing"
)

func mustModulus(hex string) [32]byte {
	x, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("invalid hex constant")
	}
	b := x.Bytes()
	var out [32]byte
	for i := range b {
		out[31-i] = b[len(b)-1-i]
	}
	return out
}

func scalarFromHex(s string) Scalar {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex constant")
	}
	pad := x.FillBytes(make([]byte, 32))
	out, err := ScalarFromBytes(pad)
	if err != nil {
		panic(fmt.Sprintf("invalid scalar constant %s: %v", s, err))
	}
	return out
}

func TestPrecomputedValues(t *testing.T) {
	var (
		wantScalarModulus = mustModulus("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
		wantFieldModulus  = mustModulus("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	)
	if scalarModulus != wantScalarModulus {
		t.Errorf("scalarModulus = %x, want %x", scalarModulus, wantScalarModulus)
	}
	if fieldModulus != wantFieldModulus {
		t.Errorf("fieldModulus = %x, want %x", fieldModulus, wantFieldModulus)
	}

	wantHalfOrder := scalarFromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
	if got := halfOrder; got != wantHalfOrder {
		t.Errorf("halfOrder = %v, want %v", got, wantHalfOrder)
	}

	var (
		wantFieldTwo   = FieldAdd(FieldOne(), FieldOne())
		wantFieldThree = FieldAdd(wantFieldTwo, FieldOne())
		wantFieldB     = FieldAdd(
			FieldAdd(
				FieldAdd(
					FieldAdd(
						FieldAdd(FieldOne(), FieldOne()),
						FieldOne(),
					),
					FieldOne(),
				),
				FieldOne(),
			),
			FieldAdd(FieldOne(), FieldOne()),
		)
	)

	if fieldTwo != wantFieldTwo {
		t.Errorf("fieldTwo = %v, want %v", fieldTwo, wantFieldTwo)
	}

	if fieldThree != wantFieldThree {
		t.Errorf("fieldThree = %v, want %v", fieldThree, wantFieldThree)
	}

	if fieldB != wantFieldB {
		t.Errorf("fieldB = %v, want %v", fieldB, wantFieldB)
	}
}
