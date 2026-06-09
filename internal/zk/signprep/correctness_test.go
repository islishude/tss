package signprep

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func TestSignPrepProveAndVerify(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
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
	wit := Witness{
		KShare:   one,
		MTASum:   one,
		ChiShare: two,
	}

	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := Verify(stmt, proof); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignPrepProofWithAdditiveShift(t *testing.T) {
	one := big.NewInt(1)
	// k=1, xbar=1, shift=1, M=3: chi = 1*(1+1) + 3 = 5. KPoint=1G, ChiPoint=5G.
	five := big.NewInt(5)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(five)))
	xBarPoint := kPoint
	shift := scalarFixedBytes(one)
	three := big.NewInt(3)

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{2},
		Party:                2,
		Signers:              []tss.PartyID{2, 3},
		ContextHash:          bytes.Repeat([]byte{0x11}, 32),
		AdditiveShift:        shift,
		PublicKey:            kPoint,
		KeygenTranscriptHash: bytes.Repeat([]byte{0x22}, 32),
		PartiesHash:          bytes.Repeat([]byte{0x33}, 32),
		EncK:                 make([]byte, 256),
		PaillierPublicKey:    make([]byte, 256),
		Gamma:                kPoint,
		Delta:                scalarFixedBytes(one),
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
	}
	wit := Witness{
		KShare:   one,
		MTASum:   three,
		ChiShare: five,
	}

	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove with shift: %v", err)
	}
	if err := Verify(stmt, proof); err != nil {
		t.Fatalf("Verify with shift: %v", err)
	}
}

func TestSignPrepProofRejectsWrongKPoint(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{3},
		Party:                3,
		Signers:              []tss.PartyID{3},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Tamper with KPoint.
	wrongK, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	tampered := stmt
	tampered.KPoint = wrongK
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong KPoint")
	}
}

func TestSignPrepProofRejectsWrongChiPoint(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{4},
		Party:                4,
		Signers:              []tss.PartyID{4},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	wrongChi, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(three)))
	tampered := stmt
	tampered.ChiPoint = wrongChi
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong ChiPoint")
	}
}

func TestSignPrepProofRejectsWrongContextHash(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{5},
		Party:                5,
		Signers:              []tss.PartyID{5},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	tampered := stmt
	tampered.ContextHash = bytes.Repeat([]byte{0xff}, 32)
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong context hash")
	}
}

func TestSignPrepProofRejectsWrongSessionID(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{6},
		Party:                6,
		Signers:              []tss.PartyID{6},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	tampered := stmt
	tampered.SessionID = tss.SessionID{99}
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong session ID (cross-session replay)")
	}
}

func TestSignPrepProofRejectsWrongParty(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{7},
		Party:                7,
		Signers:              []tss.PartyID{7},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	tampered := stmt
	tampered.Party = 99
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong party (cross-signer replay)")
	}
}

func TestSignPrepProofRejectsWrongSignerSet(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{8},
		Party:                8,
		Signers:              []tss.PartyID{8, 9},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	tampered := stmt
	tampered.Signers = []tss.PartyID{8, 10}
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong signer set")
	}
}

func TestSignPrepProofRejectsWrongKeygenTranscriptHash(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{9},
		Party:                9,
		Signers:              []tss.PartyID{9},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	tampered := stmt
	tampered.KeygenTranscriptHash = bytes.Repeat([]byte{0xff}, 32)
	if err := Verify(tampered, proof); err == nil {
		t.Fatal("expected failure with wrong keygen transcript hash")
	}
}

func TestSignPrepProofEncodingRoundTrip(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{10},
		Party:                10,
		Signers:              []tss.PartyID{10},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	encoded, err := proof.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	decoded, err := UnmarshalProof(encoded)
	if err != nil {
		t.Fatalf("UnmarshalProof: %v", err)
	}

	reEncoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary (2): %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatal("round-trip produced different encoding")
	}

	if err := Verify(stmt, decoded); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}

func TestSignPrepProofRejectsNilProof(t *testing.T) {
	one := big.NewInt(1)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{11},
		Party:                11,
		Signers:              []tss.PartyID{11},
		ContextHash:          bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:            kPoint,
		KeygenTranscriptHash: bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:          bytes.Repeat([]byte{0xcc}, 32),
		EncK:                 make([]byte, 256),
		PaillierPublicKey:    make([]byte, 256),
		Gamma:                kPoint,
		Delta:                scalarFixedBytes(one),
		KPoint:               kPoint,
		ChiPoint:             kPoint,
		XBarPoint:            kPoint,
	}
	if err := Verify(stmt, nil); err == nil {
		t.Fatal("expected failure with nil proof")
	}
}

func TestSignPrepProofRejectsEmptyProofBytes(t *testing.T) {
	if _, err := UnmarshalProof(nil); err == nil {
		t.Fatal("expected failure with nil bytes")
	}
	if _, err := UnmarshalProof([]byte{}); err == nil {
		t.Fatal("expected failure with empty bytes")
	}
}

func TestSignPrepProofRejectsWrongWireType(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{12},
		Party:                12,
		Signers:              []tss.PartyID{12},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	encoded, err := proof.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Mutate the wire type bytes.
	wrongType := bytes.Replace(encoded, []byte(proofWireType), []byte("wrong.type.here"), 1)
	if _, err := UnmarshalProof(wrongType); err == nil {
		t.Fatal("expected failure with wrong wire type")
	}
}

func TestSignPrepProofMalformedInputsDontPanic(t *testing.T) {
	malformed := [][]byte{
		{0x00, 0x01, 0x02},
		bytes.Repeat([]byte{0xff}, 100),
		[]byte("not a valid proof"),
	}
	for i, data := range malformed {
		if _, err := UnmarshalProof(data); err == nil {
			t.Errorf("case %d: expected error for malformed input", i)
		}
	}
}

// TestSignPrepProofRejectsCrossSessionReplay verifies proof cannot be
// replayed across sessions.
func TestSignPrepProofRejectsCrossSessionReplay(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{100},
		Party:                100,
		Signers:              []tss.PartyID{100},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Verify with original statement.
	if err := Verify(stmt, proof); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Replay into different session ID.
	replay := stmt
	replay.SessionID = tss.SessionID{200}
	if err := Verify(replay, proof); err == nil {
		t.Fatal("expected failure: proof replayed to wrong session")
	}
}

// TestSignPrepProofRejectsCrossSignerReplay verifies proof cannot be
// replayed by a different signer.
func TestSignPrepProofRejectsCrossSignerReplay(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{101},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Replay as a different signer.
	replay := stmt
	replay.Party = 999
	if err := Verify(replay, proof); err == nil {
		t.Fatal("expected failure: proof replayed by different signer")
	}
}

// TestSignPrepProofRejectsCrossKeygenTranscriptReplay verifies proof
// cannot be replayed with a different keygen transcript.
func TestSignPrepProofRejectsCrossKeygenTranscriptReplay(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{102},
		Party:                102,
		Signers:              []tss.PartyID{102},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	replay := stmt
	replay.KeygenTranscriptHash = bytes.Repeat([]byte{0xff}, 32)
	if err := Verify(replay, proof); err == nil {
		t.Fatal("expected failure: proof replayed with different keygen transcript")
	}
}

// TestSignPrepProofRejectsCrossAdditiveShiftReplay verifies proof
// cannot be replayed with a different additive shift.
func TestSignPrepProofRejectsCrossAdditiveShiftReplay(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{103},
		Party:                103,
		Signers:              []tss.PartyID{103},
		ContextHash:          bytes.Repeat([]byte{0xaa}, 32),
		AdditiveShift:        scalarFixedBytes(one), // shift = 1
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Replay with different additive shift.
	replay := stmt
	replay.AdditiveShift = scalarFixedBytes(three) // shift = 3, not 1
	if err := Verify(replay, proof); err == nil {
		t.Fatal("expected failure: proof replayed with different additive shift")
	}
}

// TestSignPrepProofRejectsCrossContextReplay verifies proof cannot be
// replayed with a different presign context.
func TestSignPrepProofRejectsCrossContextReplay(t *testing.T) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:             "cggmp21-secp256k1",
		SessionID:            tss.SessionID{104},
		Party:                104,
		Signers:              []tss.PartyID{104},
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
	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	replay := stmt
	replay.ContextHash = bytes.Repeat([]byte{0xff}, 32)
	if err := Verify(replay, proof); err == nil {
		t.Fatal("expected failure: proof replayed with different presign context")
	}
}
