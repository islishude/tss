package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire/wireutil"
	"github.com/islishude/tss/internal/zk/signprep"
)

// testCGGMP21Guard is a helper that creates an EnvelopeGuard for CGGMP21 protocol tests.
// It uses the production policy set but relaxes broadcast consistency requirements
// since test harnesses don't coordinate BroadcastCertificates.
func testCGGMP21Guard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) *tss.EnvelopeGuard {
	return tss.NewTestEnvelopeGuard(self, parties, protocol, sessionID, testCGGMP21Policies())
}

// testCGGMP21Policies returns the production CGGMP21 policy set with broadcast
// consistency relaxed to None for all payload types. Tests that specifically
// exercise broadcast consistency should use CGGMP21Policies directly.
func testCGGMP21Policies() tss.PolicySet {
	entries := CGGMP21Policies.Entries()
	relaxed := make([]tss.DeliveryPolicy, len(entries))
	for i, p := range entries {
		relaxed[i] = p
		relaxed[i].BroadcastConsistency = tss.BroadcastConsistencyNone
	}
	ps, err := tss.NewPolicySet(relaxed...)
	if err != nil {
		panic(err)
	}
	return ps
}

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
	return startSignDigestBound(key, presign, sessionID, digest32, presign.ContextHash, true, nil)
}

// errNilPresign is a sentinel error for nil presign in test helpers.
var errNilPresign = errNilPresignError{}

type errNilPresignError struct{}

func (errNilPresignError) Error() string { return "nil presign" }

// SignDigest is a convenience wrapper around SignDigestInteractive for tests.
func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	return SignDigestInteractive(digest32, signers, testPresignContext())
}

func deliverKeygenMessages(t testing.TB, sessions map[tss.PartyID]*KeygenSession, parties []tss.PartyID, messages []tss.Envelope) {
	t.Helper()
	// Attach test guards to sessions that don't already have one. Authenticated
	// transport delivery requires a guard from v1 onwards.
	ps := tss.PartySet(parties)
	for _, id := range parties {
		s := sessions[id]
		if s.Guard() == nil {
			s.SetGuard(testCGGMP21Guard(id, ps, s.cfg.SessionID))
		}
	}
	queue := append([]tss.Envelope(nil), messages...)
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			// Simulate authenticated, optionally confidential transport delivery.
			delivered := env
			delivered.Security.Authenticated = true
			delivered.Security.AuthenticatedParty = env.From
			if env.To != 0 {
				delivered.Security.Confidential = true
			}
			out, err := sessions[id].HandleKeygenMessage(delivered)
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
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
	minimalProof := mustMinimalSignPrepProofForTest(tb)
	littleR := new(big.Int).Mod(RPoint.X.BigInt(), secp.Order())
	transcript := sha256.Sum256([]byte("minimal presign"))
	ctx := testPresignContext()
	contextHash := presignContextHash(ctx)
	kShare, err := secpSecretScalarFromBig(one)
	if err != nil {
		tb.Fatal("k share: " + err.Error())
	}
	chiShare, err := secpSecretScalarFromBig(one)
	if err != nil {
		tb.Fatal("chi share: " + err.Error())
	}
	delta, err := secpSecretScalarFromBig(one)
	if err != nil {
		tb.Fatal("delta: " + err.Error())
	}
	return &Presign{
		mu:                   new(sync.Mutex),
		Version:              tss.Version,
		Party:                1,
		Threshold:            1,
		Signers:              []tss.PartyID{1},
		R:                    R,
		LittleR:              scalarBytes(littleR),
		TranscriptHash:       transcript[:],
		Context:              ctx,
		ContextHash:          contextHash,
		PublicKey:            R,
		KeygenTranscriptHash: transcript[:],
		PartiesHash:          wireutil.PartySetHash([]tss.PartyID{1}, partySetHashLabel),
		VerifyShares: []SignVerifyShare{{
			Party:    1,
			KPoint:   R,
			ChiPoint: R,
			Proof:    minimalProof,
		}},
		kShare:   kShare,
		chiShare: chiShare,
		delta:    delta,
	}
}

func mustMinimalSignPrepProofForTest(tb interface{ Fatal(...any) }) []byte {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kScalar := secp.ScalarFromBigInt(one)
	twoScalar := secp.ScalarFromBigInt(two)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(kScalar))
	xBarPoint := kPoint
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(twoScalar))
	stmt := signprep.Statement{
		Protocol:             protocol,
		SessionID:            tss.SessionID{1},
		Party:                1,
		Signers:              []tss.PartyID{1},
		ContextHash:          bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:            kPoint,
		KeygenTranscriptHash: bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:          bytes.Repeat([]byte{0xcc}, 32),
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
		EncK:                 make([]byte, 256),
		PaillierPublicKey:    make([]byte, 256),
		Gamma:                kPoint,
		Delta:                scalarBytes(one),
	}
	wit := signprep.Witness{
		KShare:   one,
		MTASum:   one,
		ChiShare: two,
	}
	proof, err := signprep.Prove(testutil.DeterministicReader(42), stmt, wit)
	if err != nil {
		tb.Fatal("signprep.Prove: " + err.Error())
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		tb.Fatal("proof.MarshalBinary: " + err.Error())
	}
	return proofBytes
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

// deliverCGGMPEnv returns a copy of env with transport authentication set for guard validation.
func deliverCGGMPEnv(env tss.Envelope) tss.Envelope {
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = env.From
	return env
}
