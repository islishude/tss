package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestPaillierPublicSharesHashHandlesFullPartyIDRange(t *testing.T) {
	t.Parallel()
	shares := []PaillierPublicShare{
		{Party: ^tss.PartyID(0), PublicKey: []byte("max"), Proof: []byte("max-proof")},
		{Party: 1, PublicKey: []byte("one"), Proof: []byte("one-proof")},
	}
	want := paillierPublicSharesHash([]PaillierPublicShare{shares[1], shares[0]})
	if got := paillierPublicSharesHash(shares); !bytes.Equal(got, want) {
		t.Fatalf("hash depends on full-range PartyID input order: got %x want %x", got, want)
	}
}
