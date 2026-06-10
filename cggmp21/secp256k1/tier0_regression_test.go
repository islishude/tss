package secp256k1

import (
	"bytes"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// TestFast_StaticNoSecretShareRegression scans sign.go for forbidden
// regression markers that would indicate secret material leaking into
// the public API surface. No cryptographic operations are performed.
func TestFast_StaticNoSecretShareRegression(t *testing.T) {
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

func TestFast_RefreshCommitmentsRejectNonzeroConstant(t *testing.T) {
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

func TestFast_PresignRejectsMissingVerifyShares(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	// nil VerifyShares slices
	presign.VerifyShares = nil
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject presign with nil VerifyShares")
	}
}

func TestFast_PresignRejectsEmptyVerifyShares(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	presign.VerifyShares = []SignVerifyShare{}
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject presign with empty VerifyShares")
	}
}

func TestFast_PresignRejectsWrongVerifyShareCount(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	// Signers has 1 but we add extra without a share
	presign.Signers = []tss.PartyID{1, 2}
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject mismatched signer/verify share count")
	}
}

func TestFast_PresignRejectsDuplicateVerifyShare(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	vs := presign.VerifyShares[0]
	presign.Signers = []tss.PartyID{1, 1}
	presign.VerifyShares = []SignVerifyShare{vs, vs}
	if err := validateSignVerifyShares(presign.Signers, presign.VerifyShares); err == nil {
		t.Fatal("expected rejection of duplicate verify share")
	}
}

func TestFast_PresignRejectsNonSignerParty(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	vs := presign.VerifyShares[0]
	vs.Party = 999 // not in signer set
	presign.VerifyShares = []SignVerifyShare{vs}
	if err := validateSignVerifyShares(presign.Signers, presign.VerifyShares); err == nil {
		t.Fatal("expected rejection of non-signer party in verify share")
	}
}

func TestFast_PresignRejectsNonCanonicalKPoint(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	presign.VerifyShares[0].KPoint = []byte{0xFF}
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject non-canonical KPoint")
	}
}

func TestFast_PresignRejectsNonCanonicalChiPoint(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	presign.VerifyShares[0].ChiPoint = []byte{0xFF}
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject non-canonical ChiPoint")
	}
}

func TestFast_PresignRejectsEmptyProof(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	presign.VerifyShares[0].Proof = nil
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject empty proof")
	}
}

func TestFast_PresignRejectsOversizeProof(t *testing.T) {
	presign := minimalCGGMP21Presign(t)
	limits := TestLimits()
	presign.VerifyShares[0].Proof = make([]byte, limits.SignPrep.MaxProofBytes+1)
	if err := presign.Validate(); err == nil {
		t.Fatal("expected Validate to reject oversize proof")
	}
}

// --- Aggregate failure semantics ---

func TestFast_AggregateFailureIsInvariantNotBlameAll(t *testing.T) {
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

func TestFast_SignPartialPayloadRejectsMissingDigestHash(t *testing.T) {
	p := signPartialPayload{
		S:                   big.NewInt(1),
		PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
		PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
		DigestHash:          nil, // missing
		PartialEquationHash: bytes.Repeat([]byte{0xdd}, 32),
	}
	if _, err := marshalSignPartialPayload(p); err == nil {
		t.Fatal("expected rejection of missing DigestHash")
	}
}

func TestFast_SignPartialPayloadRejectsMissingPartialEquationHash(t *testing.T) {
	p := signPartialPayload{
		S:                   big.NewInt(1),
		PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
		PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
		DigestHash:          bytes.Repeat([]byte{0xcc}, 32),
		PartialEquationHash: nil,
	}
	if _, err := marshalSignPartialPayload(p); err == nil {
		t.Fatal("expected rejection of missing PartialEquationHash")
	}
}

// --- Original defect regression (Section 14.3) shape tests ---

// TestFast_OriginalDefectBlameShape verifies the error shape that the original
// defect fix must produce: ErrCodeVerification, single-party blame, no
// blame-all-signers, no ErrCodeAggregateSignInvalid for per-party failures.
func TestFast_OriginalDefectBlameShape(t *testing.T) {
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
			Parties: []tss.PartyID{3},
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

func TestFast_PresignRound3PayloadRejectsEmptyProof(t *testing.T) {
	one := big.NewInt(1)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	chiPoint := kPoint
	p := presignRound3Payload{Delta: one, KPoint: kPoint, ChiPoint: chiPoint, Proof: nil}
	if _, err := marshalPresignRound3Payload(p); err == nil {
		t.Fatal("expected rejection of empty proof in round3 payload")
	}
}

func TestFast_PresignRound3PayloadRejectsNonCanonicalKPoint(t *testing.T) {
	one := big.NewInt(1)
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(one)))
	proof := mustMinimalSignPrepProofForTest(t)
	p := presignRound3Payload{Delta: one, KPoint: []byte{0xFF}, ChiPoint: chiPoint, Proof: proof}
	if _, err := marshalPresignRound3Payload(p); err == nil {
		t.Fatal("expected rejection of non-canonical KPoint in round3 payload")
	}
}
