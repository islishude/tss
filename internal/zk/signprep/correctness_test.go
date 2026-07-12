package signprep

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

type signPrepProofFixture struct {
	stmt  Statement
	wit   Witness
	proof *Proof
}

type signPrepFixtureOption func(*Statement, *Witness)

func TestSignPrepProofAcceptsValidStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []signPrepFixtureOption
	}{
		{
			name: "base statement",
			opts: []signPrepFixtureOption{
				withSignPrepParty(1, tss.NewPartySet(1, 2, 3)),
			},
		},
		{
			name: "additive shift",
			opts: []signPrepFixtureOption{
				withSignPrepParty(2, tss.NewPartySet(2, 3)),
				withSignPrepAdditiveShift(),
				func(stmt *Statement, _ *Witness) {
					stmt.ContextHash = bytes.Repeat([]byte{0x11}, 32)
					stmt.KeygenTranscriptHash = bytes.Repeat([]byte{0x22}, 32)
					stmt.PartiesHash = bytes.Repeat([]byte{0x33}, 32)
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fx := newSignPrepProofFixture(t, int64(i+1), tc.opts...)
			if err := Verify(fx.stmt, fx.proof); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestSignPrepProofRejectsStatementMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		opts   []signPrepFixtureOption
		mutate func(*Statement)
	}{
		{
			name: "wrong K point",
			mutate: func(stmt *Statement) {
				stmt.KPoint = signPrepPointBytes(big.NewInt(2))
			},
		},
		{
			name: "wrong chi point",
			mutate: func(stmt *Statement) {
				stmt.ChiPoint = signPrepPointBytes(big.NewInt(3))
			},
		},
		{
			name: "wrong context hash",
			mutate: func(stmt *Statement) {
				stmt.ContextHash = bytes.Repeat([]byte{0xff}, 32)
			},
		},
		{
			name: "cross-session replay",
			mutate: func(stmt *Statement) {
				stmt.SessionID = tss.SessionID{99}
			},
		},
		{
			name: "cross-signer replay",
			mutate: func(stmt *Statement) {
				stmt.Party = 99
			},
		},
		{
			name: "wrong signer set",
			opts: []signPrepFixtureOption{
				withSignPrepParty(8, tss.NewPartySet(8, 9)),
			},
			mutate: func(stmt *Statement) {
				stmt.Signers = tss.NewPartySet(8, 10)
			},
		},
		{
			name: "wrong keygen transcript hash",
			mutate: func(stmt *Statement) {
				stmt.KeygenTranscriptHash = bytes.Repeat([]byte{0xff}, 32)
			},
		},
		{
			name: "cross-additive-shift replay",
			opts: []signPrepFixtureOption{
				withSignPrepAdditiveShift(),
			},
			mutate: func(stmt *Statement) {
				stmt.AdditiveShift = scalarFixedBytes(big.NewInt(3))
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fx := newSignPrepProofFixture(t, int64(20+i), tc.opts...)
			if err := Verify(fx.stmt, fx.proof); err != nil {
				t.Fatalf("Verify original statement: %v", err)
			}

			tampered := fx.stmt.Clone()
			tc.mutate(&tampered)
			if err := Verify(tampered, fx.proof); err == nil {
				t.Fatal("expected mutated statement to reject")
			}
		})
	}
}

func TestSignPrepProofRejectsUnderboundStatements(t *testing.T) {
	t.Parallel()

	fx := newSignPrepProofFixture(t, 80, withSignPrepParty(1, tss.NewPartySet(1, 2, 3)))
	for name, mutate := range map[string]func(*Statement){
		"missing plan hash": func(stmt *Statement) { stmt.PlanHash = nil },
		"unsorted signers":  func(stmt *Statement) { stmt.Signers = tss.PartySet{2, 1, 3} },
		"duplicate signers": func(stmt *Statement) { stmt.Signers = tss.PartySet{1, 2, 2} },
		"party not signer":  func(stmt *Statement) { stmt.Signers = tss.NewPartySet(2, 3) },
	} {
		stmt := fx.stmt.Clone()
		mutate(&stmt)
		if _, err := Prove(testutil.DeterministicReader(81), stmt, fx.wit); err == nil {
			t.Errorf("Prove accepted %s", name)
		}
		if err := Verify(stmt, fx.proof); err == nil {
			t.Errorf("Verify accepted %s", name)
		}
	}
}

func TestSignPrepProofEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	fx := newSignPrepProofFixture(t, 10, withSignPrepParty(10, tss.NewPartySet(10)))
	encoded, err := fx.proof.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	decoded, err := tss.DecodeBinary[Proof](encoded)
	if err != nil {
		t.Fatalf("tss.DecodeBinary[Proof]: %v", err)
	}

	reEncoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary (2): %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatal("round-trip produced different encoding")
	}

	if err := Verify(fx.stmt, decoded); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}

func TestSignPrepProofRejectsInvalidProofEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input func(t *testing.T) []byte
	}{
		{
			name: "nil bytes",
			input: func(t *testing.T) []byte {
				t.Helper()
				return nil
			},
		},
		{
			name: "empty bytes",
			input: func(t *testing.T) []byte {
				t.Helper()
				return []byte{}
			},
		},
		{
			name: "wrong wire type",
			input: func(t *testing.T) []byte {
				t.Helper()

				fx := newSignPrepProofFixture(t, 12, withSignPrepParty(12, tss.NewPartySet(12)))
				encoded, err := fx.proof.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return bytes.Replace(encoded, []byte(proofWireType), []byte("wrong.type.here"), 1)
			},
		},
		{
			name: "short malformed bytes",
			input: func(t *testing.T) []byte {
				t.Helper()
				return []byte{0x00, 0x01, 0x02}
			},
		},
		{
			name: "all-ones malformed bytes",
			input: func(t *testing.T) []byte {
				t.Helper()
				return bytes.Repeat([]byte{0xff}, 100)
			},
		},
		{
			name: "text malformed bytes",
			input: func(t *testing.T) []byte {
				t.Helper()
				return []byte("not a valid proof")
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tss.DecodeBinary[Proof](tc.input(t)); err == nil {
				t.Fatal("expected invalid proof encoding to reject")
			}
		})
	}
}

func TestSignPrepProofRejectsNilProof(t *testing.T) {
	t.Parallel()

	fx := newSignPrepProofFixture(t, 11, withSignPrepParty(11, tss.NewPartySet(11)))
	if err := Verify(fx.stmt, nil); err == nil {
		t.Fatal("expected failure with nil proof")
	}
}

func TestSignPrepProofRejectsUnusedZeroMFields(t *testing.T) {
	t.Parallel()

	fx := newSignPrepProofFixture(t, 12, withSignPrepParty(12, tss.NewPartySet(12)))
	proof := fx.proof.Clone()
	proof.MPoint = nil
	if err := proof.Validate(); err == nil || !strings.Contains(err.Error(), "zero MPoint") {
		t.Fatalf("zero-M proof with unused fields got %v, want semantic rejection", err)
	}
	if _, err := proof.MarshalBinary(); err == nil || !strings.Contains(err.Error(), "zero MPoint") {
		t.Fatalf("zero-M proof with unused fields marshaled: %v", err)
	}
}

func TestSignPrepProofDecoderRejectsOversizedFieldAtWireBoundary(t *testing.T) {
	t.Parallel()

	raw, err := wire.MarshalFields(proofWireVersion, proofWireType, []wire.Field{
		{Tag: 1, Value: make([]byte, proofMaxPointBytes+1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var proof Proof
	err = proof.UnmarshalBinary(raw)
	if err == nil || !strings.Contains(err.Error(), "wire field 1 too large") {
		t.Fatalf("oversized signprep point got %v, want wire field rejection", err)
	}
}

func newSignPrepProofFixture(t *testing.T, seed int64, opts ...signPrepFixtureOption) signPrepProofFixture {
	t.Helper()

	one := big.NewInt(1)
	two := big.NewInt(2)
	kPoint := signPrepPointBytes(one)
	chiPoint := signPrepPointBytes(two)

	stmt := Statement{
		Protocol:              "cggmp21-secp256k1",
		SessionID:             tss.SessionID{byte(seed)},
		Party:                 tss.PartyID(seed),
		Signers:               tss.NewPartySet(tss.PartyID(seed)),
		PlanHash:              bytes.Repeat([]byte{0x99}, 32),
		ContextHash:           bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:             kPoint,
		KeygenTranscriptHash:  bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:           bytes.Repeat([]byte{0xcc}, 32),
		EncK:                  make([]byte, 256),
		PaillierPublicKey:     make([]byte, 256),
		Round1Echo:            bytes.Repeat([]byte{0xdd}, 32),
		Round2CommitmentsHash: bytes.Repeat([]byte{0xde}, 32),
		MTAContributionsHash:  bytes.Repeat([]byte{0xdf}, 32),
		MTABasePoint:          kPoint,
		DeltaBasePoint:        kPoint,
		Gamma:                 kPoint,
		Delta:                 scalarFixedBytes(one),
		LittleR:               scalarFixedBytes(one),
		R:                     kPoint,
		KPoint:                kPoint,
		ChiPoint:              chiPoint,
		XBarPoint:             kPoint,
	}
	wit := Witness{
		KShare:   witnessScalarForTest(one),
		MTASum:   witnessScalarForTest(one),
		ChiShare: witnessScalarForTest(two),
	}

	for _, opt := range opts {
		opt(&stmt, &wit)
	}

	stmt, wit = stmt.Clone(), wit.Clone()
	proof, err := Prove(testutil.DeterministicReader(seed), stmt, wit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	return signPrepProofFixture{stmt: stmt, wit: wit, proof: proof}
}

func TestSignPrepProveRejectsWitnessPointMismatch(t *testing.T) {
	t.Parallel()

	fixture := newSignPrepProofFixture(t, 91)
	badK := fixture.wit.Clone()
	badK.KShare.Destroy()
	badK.KShare = witnessScalarForTest(big.NewInt(2))
	if _, err := Prove(testutil.DeterministicReader(92), fixture.stmt, badK); err == nil {
		t.Fatal("signprep accepted a KShare that did not match KPoint")
	}
	badK.KShare.Destroy()
	badChi := fixture.wit.Clone()
	badChi.ChiShare.Destroy()
	badChi.ChiShare = witnessScalarForTest(big.NewInt(3))
	if _, err := Prove(testutil.DeterministicReader(93), fixture.stmt, badChi); err == nil {
		t.Fatal("signprep accepted a ChiShare that did not match ChiPoint")
	}
	badChi.ChiShare.Destroy()
	badMTA := fixture.wit.Clone()
	badMTA.MTASum.Destroy()
	badMTA.MTASum = witnessScalarForTest(big.NewInt(2))
	if _, err := Prove(testutil.DeterministicReader(94), fixture.stmt, badMTA); err == nil {
		t.Fatal("signprep accepted an MTA sum unrelated to the bound contributions")
	}
	badMTA.MTASum.Destroy()
	badDelta := fixture.stmt.Clone()
	badDelta.Delta = scalarFixedBytes(big.NewInt(2))
	if _, err := Prove(testutil.DeterministicReader(95), badDelta, fixture.wit); err == nil {
		t.Fatal("signprep accepted a delta share unrelated to the bound MtA contributions")
	}
}

func withSignPrepParty(party tss.PartyID, signers tss.PartySet) signPrepFixtureOption {
	return func(stmt *Statement, _ *Witness) {
		stmt.SessionID = tss.SessionID{byte(party)}
		stmt.Party = party
		stmt.Signers = signers.Clone()
	}
}

func withSignPrepAdditiveShift() signPrepFixtureOption {
	return func(stmt *Statement, wit *Witness) {
		one := big.NewInt(1)
		three := big.NewInt(3)
		five := big.NewInt(5)

		stmt.AdditiveShift = scalarFixedBytes(one)
		stmt.ChiPoint = signPrepPointBytes(five)
		stmt.MTABasePoint = signPrepPointBytes(three)
		wit.MTASum = witnessScalarForTest(three)
		wit.ChiShare = witnessScalarForTest(five)
	}
}

func scalarFixedBytes(x *big.Int) []byte {
	return secp.ScalarFromBigInt(x).Bytes()
}

func witnessScalarForTest(x *big.Int) *secret.Scalar {
	s, err := secret.NewScalar(scalarFixedBytes(x), secp.ScalarSize)
	if err != nil {
		panic("signprep test witness scalar: " + err.Error())
	}
	return s
}

func signPrepPointBytes(x *big.Int) []byte {
	point, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(x)))
	if err != nil {
		panic("signprep test point: " + err.Error())
	}
	return point
}
