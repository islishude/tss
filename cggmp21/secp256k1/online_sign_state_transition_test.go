package secp256k1

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21OnlineSignPartialBuildDoesNotMutate(t *testing.T) {
	s, env := newSyntheticOnlineSignCase(t)
	before := snapshotCGGMPSignSession(s)
	tx, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(env))
	if err != nil {
		t.Fatal(err)
	}
	after := snapshotCGGMPSignSession(s)
	assertCGGMPSnapshotUnchanged(t, before, after)
	if tx.from != env.From || tx.partial.envelope.From != env.From {
		t.Fatal("prepared partial transition lost sender binding")
	}
}

func TestCGGMP21OnlineSignInvalidPartialDoesNotMutate(t *testing.T) {
	s, env := newSyntheticOnlineSignCase(t)
	payload, err := unmarshalSignPartialPayload(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.S.Destroy()
	payload.PlanHash[0] ^= 1
	env.Payload, err = marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotCGGMPSignSession(s)
	tx, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(env))
	after := snapshotCGGMPSignSession(s)
	if err == nil || tx != nil {
		t.Fatal("invalid sign partial produced a transition")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21OnlineSignConflictingPartialDoesNotMutate(t *testing.T) {
	s, env := newSyntheticOnlineSignCase(t)
	tx, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(env))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.apply(s); err != nil {
		t.Fatal(err)
	}
	tx.markCommitted()

	conflict := env.Clone()
	conflict.Payload = bytes.Clone(conflict.Payload)
	conflict.Payload[len(conflict.Payload)-1] ^= 1
	before := snapshotCGGMPSignSession(s)
	next, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(conflict))
	after := snapshotCGGMPSignSession(s)
	if err == nil || next != nil {
		t.Fatal("conflicting sign partial produced a transition")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21OnlineSignDuplicatePartialPreservesExistingPolicy(t *testing.T) {
	s, env := newSyntheticOnlineSignCase(t)
	tx, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(env))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.apply(s); err != nil {
		t.Fatal(err)
	}
	tx.markCommitted()

	before := snapshotCGGMPSignSession(s)
	next, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(env))
	after := snapshotCGGMPSignSession(s)
	if !errors.Is(err, tss.ErrDuplicateMessage) || next != nil {
		t.Fatalf("duplicate sign partial error = %v", err)
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21OnlineSignAggregationFailureDoesNotCommit(t *testing.T) {
	s, env := newSyntheticOnlineSignCase(t)
	applySyntheticSignPartial(t, s, env)
	s.publicKey = []byte{1}
	before := snapshotCGGMPSignSession(s)
	prepared, ready, err := s.prepareFinalSignature()
	after := snapshotCGGMPSignSession(s)
	if err == nil || ready || prepared != nil {
		t.Fatal("invalid aggregate verification key produced a final signature")
	}
	assertCGGMPSnapshotUnchanged(t, before, after)
}

func TestCGGMP21OnlineSignPreparesFinalSignatureWithoutStore(t *testing.T) {
	s, env := newSyntheticOnlineSignCase(t)
	if s.coordinator != nil {
		t.Fatal("synthetic online sign case unexpectedly has a coordinator")
	}
	applySyntheticSignPartial(t, s, env)
	prepared, ready, err := s.prepareFinalSignature()
	if err != nil {
		t.Fatal(err)
	}
	if !ready || prepared == nil {
		t.Fatal("complete partial set did not prepare a signature")
	}
	defer prepared.destroy()
	if !VerifyDigest(s.publicKey, s.digest, &prepared.signature) {
		t.Fatal("prepared signature did not verify")
	}
	if s.completed || s.signature != nil {
		t.Fatal("preparing final signature mutated online sign state")
	}
}

func applySyntheticSignPartial(t *testing.T, s *SignSession, env tss.Envelope) {
	t.Helper()
	tx, err := s.buildAcceptSignPartialTx(testutil.DeliverEnvelope(env))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.apply(s); err != nil {
		t.Fatal(err)
	}
	tx.markCommitted()
}

func newSyntheticOnlineSignCase(t *testing.T) (*SignSession, tss.Envelope) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)
	digest := make([]byte, 32)
	digest[31] = 3
	contextHash := bytes.Repeat([]byte{0x21}, 32)
	transcriptHash := bytes.Repeat([]byte{0x22}, 32)
	planHash := bytes.Repeat([]byte{0x23}, 32)

	rNonce := testOnlineSignScalar(11)
	rPoint := secp.ScalarBaseMult(rNonce)
	littleR := secp.ScalarFromFieldElement(rPoint.X)
	z, err := secp.ScalarFromBytesModOrder(digest)
	if err != nil {
		t.Fatal(err)
	}
	k1, chi1 := testOnlineSignScalar(2), testOnlineSignScalar(3)
	k2, chi2 := testOnlineSignScalar(5), testOnlineSignScalar(7)
	partial1 := secp.ScalarAdd(secp.ScalarMul(z, k1), secp.ScalarMul(littleR, chi1))
	partial2 := secp.ScalarAdd(secp.ScalarMul(z, k2), secp.ScalarMul(littleR, chi2))
	aggregate := secp.ScalarAdd(partial1, partial2)
	normalized, _ := secp.NormalizeLowS(aggregate)
	rInv, err := secp.ScalarInvert(littleR)
	if err != nil {
		t.Fatal(err)
	}
	publicScalar := secp.ScalarMul(
		rInv,
		secp.ScalarSub(secp.ScalarMul(normalized, rNonce), z),
	)
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(publicScalar))
	if err != nil {
		t.Fatal(err)
	}

	verifyShares := []signVerifyShare{
		{Party: 1, KPoint: secp.ScalarBaseMult(k1), ChiPoint: secp.ScalarBaseMult(chi1)},
		{Party: 2, KPoint: secp.ScalarBaseMult(k2), ChiPoint: secp.ScalarBaseMult(chi2)},
	}
	presign := &Presign{state: &presignState{
		party:          1,
		signers:        signers,
		r:              rPoint,
		littleR:        littleR,
		transcriptHash: transcriptHash,
		contextHash:    contextHash,
		verifyShares:   verifyShares,
	}}
	s := &SignSession{
		key:       &KeyShare{state: &keyShareState{party: 1}},
		presign:   presign,
		sessionID: sessionID,
		guard:     testCGGMP21Guard(1, signers, sessionID),
		log:       tss.NopLogger(),
		limits:    testLimits(),
		digest:    digest,
		planHash:  planHash,
		publicKey: publicKey,
		partials:  map[tss.PartyID]secp.Scalar{1: partial1},
	}

	partialWire, err := secpSecretScalarFromScalarAllowZero(partial2)
	if err != nil {
		t.Fatal(err)
	}
	defer partialWire.Destroy()
	partialBytes := partial2.Bytes()
	defer clear(partialBytes)
	kPointBytes, err := verifyShares[1].kPointBytes()
	if err != nil {
		t.Fatal(err)
	}
	chiPointBytes, err := verifyShares[1].chiPointBytes()
	if err != nil {
		t.Fatal(err)
	}
	payload := signPartialPayload{
		S:                 partialWire,
		PresignTranscript: transcriptHash,
		PresignContext:    contextHash,
		DigestHash:        digestHash(digest, contextHash),
		PlanHash:          planHash,
		PartialEquationHash: partialEquationHash(
			sessionID,
			2,
			transcriptHash,
			contextHash,
			planHash,
			digest,
			littleR.Bytes(),
			partialBytes,
			kPointBytes,
			chiPointBytes,
		),
	}
	raw, err := payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       1,
		From:        2,
		PayloadType: payloadSignPartial,
		Payload:     raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, env
}

func testOnlineSignScalar(v int64) secp.Scalar {
	return secp.ScalarFromBigInt(big.NewInt(v))
}
