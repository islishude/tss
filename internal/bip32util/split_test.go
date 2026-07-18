package bip32util

import (
	"bytes"
	"io"
	"testing"

	"github.com/islishude/tss"
)

func TestSplitChainCodeAggregatesToTarget(t *testing.T) {
	t.Parallel()
	target := bytes.Repeat([]byte{0xa5}, ChainCodeSize)
	parties := tss.NewPartySet(1, 2, 3)
	random := append(bytes.Repeat([]byte{0x11}, ChainCodeSize), bytes.Repeat([]byte{0x22}, ChainCodeSize)...)

	shares, err := SplitChainCode(bytes.NewReader(random), target, parties)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, share := range shares {
			clear(share)
		}
	}()
	aggregate, err := AggregateChainCode(parties, shares)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aggregate, target) {
		t.Fatal("split chain code did not aggregate to the target")
	}
	if bytes.Equal(shares[1], shares[2]) {
		t.Fatal("distinct reader blocks produced equal chain-code shares")
	}
}

func TestSplitChainCodeRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	validTarget := make([]byte, ChainCodeSize)
	tests := []struct {
		name    string
		reader  io.Reader
		target  []byte
		parties tss.PartySet
	}{
		{name: "nil reader", target: validTarget, parties: tss.NewPartySet(1)},
		{name: "short target", reader: bytes.NewReader(nil), target: make([]byte, ChainCodeSize-1), parties: tss.NewPartySet(1)},
		{name: "empty parties", reader: bytes.NewReader(nil), target: validTarget},
		{name: "zero party", reader: bytes.NewReader(nil), target: validTarget, parties: tss.NewPartySet(0)},
		{name: "duplicate party", reader: bytes.NewReader(nil), target: validTarget, parties: tss.NewPartySet(1, 1)},
		{name: "short randomness", reader: bytes.NewReader(nil), target: validTarget, parties: tss.NewPartySet(1, 2)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := SplitChainCode(test.reader, test.target, test.parties); err == nil {
				t.Fatal("SplitChainCode accepted invalid input")
			}
		})
	}
}
