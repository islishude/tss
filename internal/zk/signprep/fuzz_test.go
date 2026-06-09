package signprep

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func FuzzProofUnmarshal(f *testing.F) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{1},
		Party:                1,
		Signers:              []tss.PartyID{1},
		ContextHash:          bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:            kPoint,
		KeygenTranscriptHash: bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:          bytes.Repeat([]byte{0xcc}, 32),
		EncK:                 make([]byte, 256),
		PaillierPublicKey:    make([]byte, 256),
		Gamma:                kPoint,
		Delta:                scalarFixedBytes(one),
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
	}
	wit := Witness{KShare: one, MTASum: one, ChiShare: two}
	proof, err := Prove(testutil.DeterministicReader(1), stmt, wit)
	if err != nil {
		f.Fatal(err)
	}
	seed, err := proof.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte(`{"not":"proof"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// UnmarshalProof must never panic.
		p, err := UnmarshalProof(data)
		if err != nil {
			return // expected for fuzz inputs
		}
		// Successful decode must produce a valid proof.
		if err := p.Validate(); err != nil {
			t.Fatalf("UnmarshalProof succeeded but Validate failed: %v", err)
		}
		// Re-marshal must be deterministic.
		reEncoded, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("re-MarshalBinary failed: %v", err)
		}
		reDecoded, err := UnmarshalProof(reEncoded)
		if err != nil {
			t.Fatalf("re-UnmarshalProof failed: %v", err)
		}
		reReEncoded, err := reDecoded.MarshalBinary()
		if err != nil {
			t.Fatalf("re-re-MarshalBinary failed: %v", err)
		}
		if !bytes.Equal(reEncoded, reReEncoded) {
			t.Fatal("proof re-encoding is not deterministic")
		}
	})
}
