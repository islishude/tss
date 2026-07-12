package signprep

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
)

// mustNewSecretScalar is a test helper that panics on invalid test data.
func mustNewSecretScalar(data []byte) *secret.Scalar {
	s, err := newProofScalar(data)
	if err != nil {
		panic("signprep test: invalid scalar: " + err.Error())
	}
	return s
}

// TestSignPrepProofZeroKnowledge verifies that two proofs generated with the
// same witness but different nonces produce different encodings, confirming
// the proof does not deterministically leak the witness.
func TestSignPrepProofZeroKnowledge(t *testing.T) {
	t.Parallel()

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
		Protocol:              "cggmp21-secp256k1",
		SessionID:             tss.SessionID{200},
		Party:                 200,
		Signers:               tss.NewPartySet(200),
		PlanHash:              bytes.Repeat([]byte{0x99}, 32),
		ContextHash:           bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:             kPoint,
		KeygenTranscriptHash:  bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:           bytes.Repeat([]byte{0xcc}, 32),
		Round2CommitmentsHash: bytes.Repeat([]byte{0xcd}, 32),
		MTAContributionsHash:  bytes.Repeat([]byte{0xce}, 32),
		MTABasePoint:          kPoint,
		DeltaBasePoint:        kPoint,
		EncK:                  make([]byte, 256),
		PaillierPublicKey:     make([]byte, 256),
		Gamma:                 kPoint,
		Delta:                 scalarFixedBytes(one),
		KPoint:                kPoint,
		ChiPoint:              chiPoint,
		XBarPoint:             xBarPoint,
	}
	wit := Witness{
		KShare:   witnessScalarForTest(one),
		MTASum:   witnessScalarForTest(one),
		ChiShare: witnessScalarForTest(two),
	}

	proof1, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove 1: %v", err)
	}
	proof2, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove 2: %v", err)
	}

	enc1, _ := proof1.MarshalBinary()
	enc2, _ := proof2.MarshalBinary()

	// Different nonces must produce different commitments and responses.
	if bytes.Equal(enc1, enc2) {
		t.Fatal("two proofs with different nonces produced identical encodings — proof may be deterministic and leak witness")
	}

	// Both proofs must verify.
	if err := Verify(stmt, proof1); err != nil {
		t.Fatalf("Verify 1: %v", err)
	}
	if err := Verify(stmt, proof2); err != nil {
		t.Fatalf("Verify 2: %v", err)
	}
}

// TestSignPrepProofDoesNotContainWitness verifies that the proof bytes do not
// contain the secret witness values (k_i, chi_i, M_i) in plaintext.
func TestSignPrepProofDoesNotContainWitness(t *testing.T) {
	t.Parallel()

	one := big.NewInt(1)
	two := big.NewInt(2)
	// Use large secret values to avoid coincidental byte matches.
	secretK, _ := new(big.Int).SetString("deadbeefcafe0001", 16)
	secretM, _ := new(big.Int).SetString("c0ffee1234560002", 16)
	// chi = k*xbar + M = k*2 + M
	secretChi := new(big.Int).Mul(secretK, two)
	secretChi.Add(secretChi, secretM)
	secretChi.Mod(secretChi, secp.Order())

	xBarPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(two)))
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(secretK)))
	mPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(secretM)))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(secretChi)))

	stmt := Statement{
		Protocol:              "cggmp21-secp256k1",
		SessionID:             tss.SessionID{201},
		Party:                 201,
		Signers:               tss.NewPartySet(201),
		PlanHash:              bytes.Repeat([]byte{0x99}, 32),
		ContextHash:           bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:             kPoint,
		KeygenTranscriptHash:  bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:           bytes.Repeat([]byte{0xcc}, 32),
		Round2CommitmentsHash: bytes.Repeat([]byte{0xcd}, 32),
		MTAContributionsHash:  bytes.Repeat([]byte{0xce}, 32),
		MTAOffsetPoint:        mPoint,
		DeltaOffsetPoint:      signPrepPointBytes(one),
		EncK:                  make([]byte, 256),
		PaillierPublicKey:     make([]byte, 256),
		Gamma:                 kPoint,
		Delta:                 scalarFixedBytes(one),
		KPoint:                kPoint,
		ChiPoint:              chiPoint,
		XBarPoint:             xBarPoint,
	}
	wit := Witness{
		KShare:   witnessScalarForTest(secretK),
		MTASum:   witnessScalarForTest(secretM),
		ChiShare: witnessScalarForTest(secretChi),
	}

	proof, err := Prove(nil, stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Verify the proof.
	if err := Verify(stmt, proof); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The proof must reveal MPoint but NOT k_i or chi_i or M_i in plaintext.
	enc, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Check that k_i, chi_i, and M_i scalars are not present in plaintext.
	kBytes := secp.ScalarFromBigInt(secretK).Bytes()
	chiBytes := secp.ScalarFromBigInt(secretChi).Bytes()
	mBytes := secp.ScalarFromBigInt(secretM).Bytes()
	if bytes.Contains(enc, kBytes) {
		t.Error("proof encoding contains k_i scalar in plaintext")
	}
	if bytes.Contains(enc, chiBytes) {
		t.Error("proof encoding contains chi_i scalar in plaintext")
	}
	if bytes.Contains(enc, mBytes) {
		t.Error("proof encoding contains M_i scalar in plaintext")
	}

	// MPoint must be in the proof (it's a public commitment, not secret).
	if !bytes.Contains(enc, mPoint) {
		t.Error("proof encoding does not contain MPoint (expected public commitment)")
	}
}

// TestSignPrepProofFuzzVerify fuzzes the Verify function with random proof
// bytes to ensure it never panics.
func TestSignPrepProofFuzzVerify(t *testing.T) {
	t.Parallel()

	one := big.NewInt(1)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	xBarPoint := kPoint

	stmt := Statement{
		Protocol:              "cggmp21-secp256k1",
		SessionID:             tss.SessionID{202},
		Party:                 202,
		Signers:               tss.NewPartySet(202),
		PlanHash:              bytes.Repeat([]byte{0x99}, 32),
		ContextHash:           bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:             kPoint,
		KeygenTranscriptHash:  bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:           bytes.Repeat([]byte{0xcc}, 32),
		Round2CommitmentsHash: bytes.Repeat([]byte{0xcd}, 32),
		MTAContributionsHash:  bytes.Repeat([]byte{0xce}, 32),
		MTABasePoint:          kPoint,
		DeltaBasePoint:        kPoint,
		EncK:                  make([]byte, 256),
		PaillierPublicKey:     make([]byte, 256),
		Gamma:                 kPoint,
		Delta:                 scalarFixedBytes(one),
		KPoint:                kPoint,
		ChiPoint:              kPoint,
		XBarPoint:             xBarPoint,
	}

	// Generate random-looking proofs and call Verify — must never panic.
	randomProofs := []*Proof{
		nil,
		{},
		{MPoint: []byte{0x00}},
		{MPoint: kPoint}, // valid point but no commitments
		{
			MPoint: kPoint, KCommitment: kPoint, MCommitment: kPoint,
			DLEQA1: kPoint, DLEQA2: kPoint,
			KResponse: mustNewSecretScalar(one.Bytes()), MResponse: scalarFixedBytes(one),
			DLEQResponse: mustNewSecretScalar(one.Bytes()),
		}, // structurally valid but semantically wrong
		{
			MPoint: make([]byte, 33), KCommitment: kPoint, MCommitment: kPoint,
			DLEQA1: kPoint, DLEQA2: kPoint,
			KResponse: mustNewSecretScalar([]byte{0x00}), MResponse: scalarFixedBytes(one),
			DLEQResponse: mustNewSecretScalar(one.Bytes()),
		}, // invalid response
	}
	for i, p := range randomProofs {
		// Verify should return an error, not panic.
		_ = Verify(stmt, p)
		// Also verify that unmarshal → verify doesn't panic.
		if p != nil {
			enc, err := p.MarshalBinary()
			if err == nil {
				decoded, _ := tss.DecodeBinary[Proof](enc)
				if decoded != nil {
					_ = Verify(stmt, decoded)
				}
			}
		}
		_ = i
	}
}
