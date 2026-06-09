package signprep

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestGoldenProof(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	if err != nil {
		t.Fatal(err)
	}
	chiPoint, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	if err != nil {
		t.Fatal(err)
	}
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{1},
		Party:                1,
		Signers:              []tss.PartyID{1, 2, 3},
		ContextHash:          bytes.Repeat([]byte{0xaa}, 32),
		AdditiveShift:        nil,
		PublicKey:            kPoint,
		KeygenTranscriptHash: bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:          bytes.Repeat([]byte{0xcc}, 32),
		EncK:                 make([]byte, 256),
		PaillierPublicKey:    make([]byte, 256),
		Round1Echo:           bytes.Repeat([]byte{0xdd}, 32),
		Gamma:                kPoint,
		Delta:                scalarFixedBytes(one),
		LittleR:              scalarFixedBytes(one),
		R:                    kPoint,
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
	}
	wit := Witness{KShare: one, MTASum: one, ChiShare: two}

	proof, err := Prove(testutil.DeterministicReader(42), stmt, wit)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the proof.
	if err := Verify(stmt, proof); err != nil {
		t.Fatal(err)
	}

	// Round-trip through MarshalBinary/UnmarshalProof.
	decoded, err := UnmarshalProof(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reEncoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatal("golden deterministic round-trip failed")
	}

	// Re-generated with the deterministic reader must be byte-identical.
	proof2, err := Prove(testutil.DeterministicReader(42), stmt, wit)
	if err != nil {
		t.Fatal(err)
	}
	encoded2, err := proof2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, encoded2) {
		t.Fatal("deterministic proof generation is not stable")
	}
}
