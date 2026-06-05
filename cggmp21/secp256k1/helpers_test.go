package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"testing"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

// --- PresignContext factory ---

func testPresignContext() PresignContext {
	return PresignContext{
		KeyID:         "test-key",
		ChainID:       "test-chain",
		PolicyDomain:  "test-policy",
		MessageDomain: "test-message",
	}
}

// --- Convenience wrappers ---

// StartPresign is a convenience wrapper around StartPresignWithContext that
// uses testPresignContext(). Only for use in tests.
func StartPresign(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID) (*PresignSession, []tss.Envelope, error) {
	return StartPresignWithContext(key, sessionID, signers, testPresignContext())
}

// StartSignDigest is a convenience wrapper around startSignDigestBound for tests.
func StartSignDigest(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte) (*SignSession, []tss.Envelope, error) {
	if presign == nil {
		return nil, nil, errNilPresign
	}
	return startSignDigestBound(key, presign, sessionID, digest32, presign.ContextHash, true)
}

// errNilPresign is a sentinel error for nil presign in test helpers.
var errNilPresign = errNilPresignError{}

type errNilPresignError struct{}

func (errNilPresignError) Error() string { return "nil presign" }

// SignDigest is a convenience wrapper around SignDigestInteractive for tests.
func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	return SignDigestInteractive(digest32, signers, testPresignContext())
}

// --- Clone helpers ---

// cloneKeyShare returns a deep copy of a KeyShare for mutation testing.
// Used by integration-tagged test files.
//
//nolint:unused
func cloneKeyShare(in *KeyShare) *KeyShare {
	if in == nil {
		return nil
	}
	out := *in
	out.Parties = append([]tss.PartyID(nil), in.Parties...)
	out.PublicKey = append([]byte(nil), in.PublicKey...)
	out.ChainCode = append([]byte(nil), in.ChainCode...)
	out.secret = append([]byte(nil), in.secret...)
	out.GroupCommitments = cloneByteSlices(in.GroupCommitments)
	out.VerificationShares = append([]VerificationShare(nil), in.VerificationShares...)
	for i := range out.VerificationShares {
		out.VerificationShares[i].PublicKey = append([]byte(nil), in.VerificationShares[i].PublicKey...)
	}
	out.PaillierPublicKey = append([]byte(nil), in.PaillierPublicKey...)
	out.paillierPrivateKey = append([]byte(nil), in.paillierPrivateKey...)
	out.PaillierProof = append([]byte(nil), in.PaillierProof...)
	out.PaillierPublicKeys = append([]PaillierPublicShare(nil), in.PaillierPublicKeys...)
	for i := range out.PaillierPublicKeys {
		out.PaillierPublicKeys[i].PublicKey = append([]byte(nil), in.PaillierPublicKeys[i].PublicKey...)
		out.PaillierPublicKeys[i].Proof = append([]byte(nil), in.PaillierPublicKeys[i].Proof...)
	}
	out.RingPedersenParams = append([]byte(nil), in.RingPedersenParams...)
	out.RingPedersenProof = append([]byte(nil), in.RingPedersenProof...)
	out.RingPedersenPublic = append([]RingPedersenPublicShare(nil), in.RingPedersenPublic...)
	for i := range out.RingPedersenPublic {
		out.RingPedersenPublic[i].Params = append([]byte(nil), in.RingPedersenPublic[i].Params...)
		out.RingPedersenPublic[i].Proof = append([]byte(nil), in.RingPedersenPublic[i].Proof...)
	}
	out.PaillierProofSessionID = in.PaillierProofSessionID
	out.PaillierProofDomain = in.PaillierProofDomain
	out.ShareProof = append([]byte(nil), in.ShareProof...)
	out.KeygenTranscriptHash = append([]byte(nil), in.KeygenTranscriptHash...)
	return &out
}

// clonePresign returns a deep copy of a Presign for mutation testing.
// Used by integration-tagged test files.
//
//nolint:unused
func clonePresign(in *Presign) *Presign {
	if in == nil {
		return nil
	}
	out := *in
	out.Signers = append([]tss.PartyID(nil), in.Signers...)
	out.R = append([]byte(nil), in.R...)
	out.LittleR = append([]byte(nil), in.LittleR...)
	out.KShare = append([]byte(nil), in.KShare...)
	out.ChiShare = append([]byte(nil), in.ChiShare...)
	out.Delta = append([]byte(nil), in.Delta...)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	out.Context.DerivationPath = append([]uint32(nil), in.Context.DerivationPath...)
	out.ContextHash = append([]byte(nil), in.ContextHash...)
	out.AdditiveShift = append([]byte(nil), in.AdditiveShift...)
	out.Consumed = false
	return &out
}

// cloneByteSlices returns a deep copy of a [][]byte slice.
// Used by integration-tagged test files.
//
//nolint:unused
func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

// --- Minimal presign fixture ---

// minimalCGGMP21Presign creates a Presign with minimal valid fields for
// wire-format testing. No keygen or Paillier crypto is performed.
func minimalCGGMP21Presign(tb interface{ Fatal(...any) }) *Presign {
	one := big.NewInt(1)
	RPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(one))
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		tb.Fatal("PointBytes: " + err.Error())
	}
	littleR := new(big.Int).Mod(RPoint.X.BigInt(), secp.Order())
	transcript := sha256.Sum256([]byte("minimal presign"))
	ctx := testPresignContext()
	contextHash := presignContextHash(ctx)
	return &Presign{
		Version:        tss.Version,
		Party:          1,
		Threshold:      1,
		Signers:        []tss.PartyID{1},
		R:              R,
		LittleR:        scalarBytes(littleR),
		KShare:         scalarBytes(one),
		ChiShare:       scalarBytes(one),
		Delta:          scalarBytes(one),
		TranscriptHash: transcript[:],
		Context:        ctx,
		ContextHash:    contextHash,
	}
}

// checkGolden compares raw bytes against a golden file. When the environment
// variable UPDATE_GOLDEN=1 is set, it writes the golden file. No crypto.
func checkGolden(t *testing.T, golden string, raw []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatalf("reading golden %s: %v (run with UPDATE_GOLDEN=1 to generate)", golden, err)
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		t.Errorf("golden mismatch:\n  got:  %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}
}
