package secret

import (
	"math/big"
	"testing"
)

func TestClearBigIntClearsBackingWords(t *testing.T) {
	words := make([]big.Word, 2, 4)
	for i := range words[:cap(words)] {
		words[:cap(words)][i] = big.Word(i + 1)
	}
	x := new(big.Int).SetBits(words)

	ClearBigInt(x)

	if x.Sign() != 0 {
		t.Fatal("big.Int was not reset to zero")
	}
	if len(x.Bits()) != 0 {
		t.Fatal("big.Int still has backing words")
	}
	for i, word := range words[:cap(words)] {
		if word != 0 {
			t.Fatalf("word %d was not cleared", i)
		}
	}
	var nilX *big.Int
	ClearBigInt(nilX)
}
