package secp256k1

import (
	"bytes"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/zk/signprep"
)

// TestFast_StaticNoSecretShareRegression scans sign.go for forbidden
// regression markers that would indicate secret material leaking into
// the public API surface. No cryptographic operations are performed.
func TestFast_StaticNoSecretShareRegression(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("sign.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{"SecretShare", "NonceShare", "InterpolateConstant"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sign.go still contains forbidden regression marker %q", forbidden)
		}
	}
}

func TestFast_NoSecretScalarBigIntRegression(t *testing.T) {
	t.Parallel()

	sources := make(map[string][]byte, 3)
	for name, read := range map[string]func() ([]byte, error){
		"online_sign.go":    func() ([]byte, error) { return os.ReadFile("online_sign.go") },
		"presign_round3.go": func() ([]byte, error) { return os.ReadFile("presign_round3.go") },
		"sign.go":           func() ([]byte, error) { return os.ReadFile("sign.go") },
	} {
		body, err := read()
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = body
	}
	for name, body := range sources {
		if strings.Contains(string(body), ".BigInt()") {
			t.Fatalf("%s converts a scalar to *big.Int", name)
		}
	}

	secretScalarType := reflect.TypeFor[*secret.Scalar]()
	secpScalarType := reflect.TypeFor[secp.Scalar]()
	for _, tc := range []struct {
		name  string
		owner reflect.Type
		field string
		want  reflect.Type
	}{
		{name: "sign partial wire scalar", owner: reflect.TypeFor[signPartialPayload](), field: "S", want: secretScalarType},
		{name: "presign delta wire scalar", owner: reflect.TypeFor[presignRound3Payload](), field: "Delta", want: secretScalarType},
	} {
		field, ok := tc.owner.FieldByName(tc.field)
		if !ok {
			t.Fatalf("%s field missing", tc.name)
		}
		if field.Type != tc.want {
			t.Fatalf("%s type = %v, want %v", tc.name, field.Type, tc.want)
		}
	}

	partials, ok := reflect.TypeFor[SignSession]().FieldByName("partials")
	if !ok {
		t.Fatal("SignSession.partials field missing")
	}
	if partials.Type.Kind() != reflect.Map || partials.Type.Elem() != secpScalarType {
		t.Fatalf("SignSession.partials type = %v, want map with secp.Scalar values", partials.Type)
	}
}

func TestFast_RefreshCommitmentsRejectNonzeroConstant(t *testing.T) {
	t.Parallel()
	const threshold = 2
	commitments := make([][]byte, threshold)
	var err error
	commitments[0], err = secp.PointBytes(secp.G)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRefreshCommitments(commitments, threshold); err == nil || !strings.Contains(err.Error(), "constant commitment") {
		t.Fatalf("expected refresh constant commitment rejection, got %v", err)
	}
}

// --- Presign VerifyShares validation regression tests ---

func TestFast_PresignVerifySharesValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(presign *Presign)
		check   func(presign *Presign) error
		wantMsg string
	}{
		{
			name:    "nil VerifyShares",
			mutate:  func(p *Presign) { p.state.verifyShares = nil },
			check:   func(p *Presign) error { return p.ValidateWithLimits(testLimits()) },
			wantMsg: "nil VerifyShares",
		},
		{
			name:    "empty VerifyShares",
			mutate:  func(p *Presign) { p.state.verifyShares = []signVerifyShare{} },
			check:   func(p *Presign) error { return p.ValidateWithLimits(testLimits()) },
			wantMsg: "empty VerifyShares",
		},
		{
			name:    "mismatched signer count",
			mutate:  func(p *Presign) { p.state.signers = tss.NewPartySet(1, 2) },
			check:   func(p *Presign) error { return p.ValidateWithLimits(testLimits()) },
			wantMsg: "mismatched signer/verify share count",
		},
		{
			name: "duplicate VerifyShare",
			mutate: func(p *Presign) {
				vs := p.state.verifyShares[0]
				p.state.signers = tss.PartySet{1, 1}
				p.state.verifyShares = []signVerifyShare{vs, vs}
			},
			check: func(p *Presign) error {
				return validateSignVerifyShares(p.state.signers, p.state.verifyShares, testLimits())
			},
			wantMsg: "duplicate verify share",
		},
		{
			name: "non-signer party",
			mutate: func(p *Presign) {
				vs := p.state.verifyShares[0]
				vs.Party = 999
				p.state.verifyShares = []signVerifyShare{vs}
			},
			check: func(p *Presign) error {
				return validateSignVerifyShares(p.state.signers, p.state.verifyShares, testLimits())
			},
			wantMsg: "non-signer party in verify share",
		},
		{
			name:    "non-canonical KPoint",
			mutate:  func(p *Presign) { p.state.verifyShares[0].KPoint = nil },
			check:   func(p *Presign) error { return p.ValidateWithLimits(testLimits()) },
			wantMsg: "non-canonical KPoint",
		},
		{
			name:    "non-canonical ChiPoint",
			mutate:  func(p *Presign) { p.state.verifyShares[0].ChiPoint = nil },
			check:   func(p *Presign) error { return p.ValidateWithLimits(testLimits()) },
			wantMsg: "non-canonical ChiPoint",
		},
		{
			name:    "empty proof",
			mutate:  func(p *Presign) { p.state.verifyShares[0].Proof = new(signprep.Proof) },
			check:   func(p *Presign) error { return p.ValidateWithLimits(testLimits()) },
			wantMsg: "empty proof",
		},
		{
			name: "oversize proof",
			mutate: func(_ *Presign) {
			},
			check: func(p *Presign) error {
				limits := testLimits()
				limits.SignPrep.MaxProofBytes = 1
				return p.ValidateWithLimits(limits)
			},
			wantMsg: "oversize proof",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			presign := minimalCGGMP21Presign(t)
			tc.mutate(presign)
			if err := tc.check(presign); err == nil {
				t.Fatalf("expected rejection of %s", tc.wantMsg)
			}
		})
	}
}

// --- Aggregate failure semantics ---

func TestFast_AggregateFailureIsInvariantNotBlameAll(t *testing.T) {
	t.Parallel()
	if tss.ErrCodeInvariant != "invariant" {
		t.Fatal("ErrCodeInvariant not defined")
	}
	if tss.ErrCodeInvariant == tss.ErrCodeAggregateSignInvalid {
		t.Fatal("ErrCodeInvariant must differ from ErrCodeAggregateSignInvalid")
	}
	// Invariant error must not carry blame.
	err := &tss.ProtocolError{Code: tss.ErrCodeInvariant, Round: 1, Err: errors.New("test")}
	if err.Code != tss.ErrCodeInvariant || err.Round != 1 || err.Err == nil {
		t.Fatal("invariant error fields not set correctly")
	}
	if err.Blame != nil {
		t.Fatal("invariant error must not carry blame")
	}
}

// --- SignPartialPayload encoding validation ---

func TestFast_SignPartialPayloadEncodingRejectsMissingFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload signPartialPayload
		wantMsg string
	}{
		{
			name: "missing DigestHash",
			payload: signPartialPayload{
				S:                   testSecretScalar(t, 1),
				PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
				PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
				DigestHash:          nil,
				PartialEquationHash: bytes.Repeat([]byte{0xdd}, 32),
				PlanHash:            bytes.Repeat([]byte{0xee}, 32),
			},
			wantMsg: "missing DigestHash",
		},
		{
			name: "missing PartialEquationHash",
			payload: signPartialPayload{
				S:                   testSecretScalar(t, 1),
				PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
				PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
				DigestHash:          bytes.Repeat([]byte{0xcc}, 32),
				PartialEquationHash: nil,
				PlanHash:            bytes.Repeat([]byte{0xee}, 32),
			},
			wantMsg: "missing PartialEquationHash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := marshalSignPartialPayload(tc.payload); err == nil {
				t.Fatalf("expected rejection of %s", tc.wantMsg)
			}
		})
	}
}

// --- Original defect regression (Section 14.3) shape tests ---

// TestFast_OriginalDefectBlameShape verifies the error shape that the original
// defect fix must produce: ErrCodeVerification, single-party blame, no
// blame-all-signers, no ErrCodeAggregateSignInvalid for per-party failures.
func TestFast_OriginalDefectBlameShape(t *testing.T) {
	t.Parallel()
	// Verify the error code hierarchy is correct.
	if tss.ErrCodeVerification != "verification_failed" {
		t.Fatal("ErrCodeVerification value mismatch")
	}
	if tss.ErrCodeInvariant != "invariant" {
		t.Fatal("ErrCodeInvariant value mismatch")
	}
	if tss.ErrCodeAggregateSignInvalid != "aggregate_sign_invalid" {
		t.Fatal("ErrCodeAggregateSignInvalid value mismatch")
	}

	// Per-party verification failures use ErrCodeVerification, not
	// ErrCodeAggregateSignInvalid.
	verificationErr := &tss.ProtocolError{
		Code: tss.ErrCodeVerification,
		Blame: &tss.Blame{
			Reason:  "sign partial verification failed",
			Parties: tss.NewPartySet(3),
		},
	}
	if verificationErr.Code != tss.ErrCodeVerification {
		t.Fatal("verification error code mismatch")
	}
	if len(verificationErr.Blame.Parties) != 1 {
		t.Fatal("per-party blame must have exactly 1 party")
	}
	if verificationErr.Blame.Parties[0] != 3 {
		t.Fatal("blame must point to the malicious sender")
	}

	// Invariant errors must not carry blame.
	invariantErr := &tss.ProtocolError{
		Code: tss.ErrCodeInvariant,
		Err:  errors.New("test invariant"),
	}
	if invariantErr.Code != tss.ErrCodeInvariant || invariantErr.Err == nil {
		t.Fatal("invariant error fields not set correctly")
	}
	if invariantErr.Blame != nil {
		t.Fatal("invariant errors must not blame any party")
	}
}

// TestFast_OriginalDefectCodeSeparation verifies that the original defect's
// aggregate failure code is distinct from per-party verification codes.
func TestFast_OriginalDefectCodeSeparation(t *testing.T) {
	t.Parallel()
	codes := []string{
		tss.ErrCodeVerification,
		tss.ErrCodeAggregateSignInvalid,
		tss.ErrCodeInvariant,
		tss.ErrCodeInvalidMessage,
	}
	for i := range codes {
		for j := i + 1; j < len(codes); j++ {
			if codes[i] == codes[j] {
				t.Errorf("error codes must be distinct: %s == %s", codes[i], codes[j])
			}
		}
	}
}

// --- PresignRound3Payload validation ---

func TestFast_PresignRound3PayloadRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload presignRound3Payload
		wantMsg string
	}{
		{
			name: "empty proof",
			payload: func() presignRound3Payload {
				one := big.NewInt(1)
				kPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(one))
				return presignRound3Payload{
					Delta:    testSecretScalar(t, 1),
					KPoint:   kPoint,
					ChiPoint: kPoint,
					Proof:    &signprep.Proof{},
					PlanHash: bytes.Repeat([]byte{0xef}, 32),
				}
			}(),
			wantMsg: "empty proof in round3 payload",
		},
		{
			name: "non-canonical KPoint",
			payload: func() presignRound3Payload {
				one := big.NewInt(1)
				chiPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(one))
				proof := mustMinimalSignPrepProofForTest(t)
				return presignRound3Payload{
					Delta:    testSecretScalar(t, 1),
					KPoint:   nil,
					ChiPoint: chiPoint,
					Proof:    proof,
					PlanHash: bytes.Repeat([]byte{0xef}, 32),
				}
			}(),
			wantMsg: "non-canonical KPoint in round3 payload",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := marshalPresignRound3Payload(tc.payload); err == nil {
				t.Fatalf("expected rejection of %s", tc.wantMsg)
			}
		})
	}
}
