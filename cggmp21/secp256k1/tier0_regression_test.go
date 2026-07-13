package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestFastStaticRetiredSigningPathsDoNotReturn(t *testing.T) {
	sourceFS := os.DirFS(".")
	entries, err := fs.ReadDir(sourceFS, ".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"LogCiphertext",
		"LogProof",
		"payloadPresignIdentification",
		"presignIdentificationRound",
		"payloadSignIdentification",
		"signIdentificationRound",
		"signprep",
		"KPoint",
		"ChiPoint",
		"DeltaAggregate",
		".BigInt()",
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := fs.ReadFile(sourceFS, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range forbidden {
			if strings.Contains(string(body), marker) {
				t.Fatalf("%s contains retired or unsafe marker %q", name, marker)
			}
		}
	}
}

func TestFastKeyShareWireSchemaHasNoRetiredFigure9Fields(t *testing.T) {
	want := []struct {
		name string
		tag  string
	}{
		{name: "Party", tag: "1"},
		{name: "Threshold", tag: "2"},
		{name: "Parties", tag: "3"},
		{name: "PublicKey", tag: "4"},
		{name: "ChainCode", tag: "5"},
		{name: "Secret", tag: "6"},
		{name: "GroupCommitments", tag: "7"},
		{name: "PartyData", tag: "8"},
		{name: "PaillierPrivateKey", tag: "9"},
		{name: "ShareProof", tag: "10"},
		{name: "KeygenTranscriptHash", tag: "11"},
		{name: "PaillierProofSessionID", tag: "12"},
		{name: "PaillierProofDomain", tag: "13"},
		{name: "ResharePlanHash", tag: "14"},
		{name: "PlanHash", tag: "15"},
		{name: "SecurityParams", tag: "16"},
		{name: "Epoch", tag: "17"},
	}
	typ := reflect.TypeFor[keyShareState]()
	if typ.NumField() != len(want) {
		t.Fatalf("key share wire state has %d fields, want exactly %d", typ.NumField(), len(want))
	}
	for i, expected := range want {
		field := typ.Field(i)
		tag, _, _ := strings.Cut(field.Tag.Get("wire"), ",")
		if field.Name != expected.name || tag != expected.tag {
			t.Fatalf("key share wire field %d = %s tag %q, want %s tag %q", i, field.Name, tag, expected.name, expected.tag)
		}
	}
}

func TestFastSecretScalarWireBoundaries(t *testing.T) {
	secretScalarType := reflect.TypeFor[*secret.Scalar]()
	for _, tc := range []struct {
		owner reflect.Type
		field string
	}{
		{owner: reflect.TypeFor[signPartialPayload](), field: "S"},
		{owner: reflect.TypeFor[presignRound3Payload](), field: "Delta"},
	} {
		field, ok := tc.owner.FieldByName(tc.field)
		if !ok || field.Type != secretScalarType {
			t.Fatalf("%v.%s is %v, want *secret.Scalar", tc.owner, tc.field, field.Type)
		}
	}
	partials, ok := reflect.TypeFor[SignSession]().FieldByName("partials")
	if !ok || partials.Type.Kind() != reflect.Map || partials.Type.Elem() != reflect.TypeFor[secp.Scalar]() {
		t.Fatalf("SignSession.partials has unsafe type %v", partials.Type)
	}
}

func TestFastNormalizedPresignValidationMatrix(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Presign)
	}{
		{name: "missing presign id", mutate: func(p *Presign) { p.state.PresignID = nil }},
		{name: "missing epoch id", mutate: func(p *Presign) { p.state.EpochID = nil }},
		{name: "zero little r", mutate: func(p *Presign) { p.state.LittleR = secp.ScalarZero() }},
		{name: "wrong commitment order", mutate: func(p *Presign) { p.state.Commitments[1].Party = 1 }},
		{name: "aggregate delta mismatch", mutate: func(p *Presign) { p.state.Commitments[1].DeltaTilde = testCurvePointBytes(t, 1) }},
		{name: "aggregate chi mismatch", mutate: func(p *Presign) { p.state.Commitments[1].STilde = testCurvePointBytes(t, 1) }},
		{name: "request-time path", mutate: func(p *Presign) { p.state.Context.Derivation.Path = []uint32{1} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := minimalCGGMP21Presign(t)
			defer p.Destroy()
			tc.mutate(p)
			if err := p.ValidateWithLimits(testLimits()); err == nil {
				t.Fatal("invalid normalized presign was accepted")
			}
		})
	}
}

func TestFastSignPartialPayloadRequiresEpochAndPresignBindings(t *testing.T) {
	zero, err := secpSecretScalarFromScalarAllowZero(secp.ScalarZero())
	if err != nil {
		t.Fatal(err)
	}
	base := signPartialPayload{
		S:                   zero,
		PresignID:           bytes.Repeat([]byte{1}, sha256.Size),
		EpochID:             bytes.Repeat([]byte{2}, sha256.Size),
		PresignTranscript:   bytes.Repeat([]byte{3}, sha256.Size),
		PresignContext:      bytes.Repeat([]byte{4}, sha256.Size),
		DigestHash:          bytes.Repeat([]byte{5}, sha256.Size),
		PartialEquationHash: bytes.Repeat([]byte{6}, sha256.Size),
		PlanHash:            bytes.Repeat([]byte{7}, sha256.Size),
	}
	defer base.S.Destroy()
	for _, mutate := range []func(*signPartialPayload){
		func(p *signPartialPayload) { p.PresignID = nil },
		func(p *signPartialPayload) { p.EpochID = nil },
		func(p *signPartialPayload) { p.DigestHash = nil },
		func(p *signPartialPayload) { p.PartialEquationHash = nil },
	} {
		p := base
		mutate(&p)
		if _, err := p.MarshalBinaryWithLimits(testLimits()); err == nil {
			t.Fatal("sign partial missing a required binding was accepted")
		}
	}
}

func TestFastPresignRound3PayloadRejectsMissingBindings(t *testing.T) {
	g, err := secp.PointBytes(secp.G)
	if err != nil {
		t.Fatal(err)
	}
	zero := secp.ScalarZero().Bytes()
	proof := zkpai.ElogProof{
		A: bytes.Clone(g), N: bytes.Clone(g), B: bytes.Clone(g),
		Z: bytes.Clone(zero), U: bytes.Clone(zero), TranscriptHash: bytes.Repeat([]byte{8}, sha256.Size),
	}
	delta, err := secpSecretScalarFromScalarAllowZero(secp.ScalarZero())
	if err != nil {
		t.Fatal(err)
	}
	p := presignRound3Payload{
		Delta: delta, S: g, DeltaPoint: bytes.Clone(g), Proof: proof,
		PlanHash: bytes.Repeat([]byte{1}, sha256.Size),
		EpochID:  bytes.Repeat([]byte{2}, sha256.Size), PresignID: bytes.Repeat([]byte{3}, sha256.Size),
	}
	defer p.Delta.Destroy()
	p.EpochID = nil
	if _, err := p.MarshalBinaryWithLimits(testLimits()); err == nil {
		t.Fatal("round3 payload without EpochID was accepted")
	}
}
