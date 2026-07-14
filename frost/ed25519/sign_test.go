package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/sha256"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestSignNonceGenerationDependsOnSecretAndRandomness(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	message := []byte("nonce regression")

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sameRandom := bytes.Repeat([]byte{0x42}, 64)
	commit1 := startSignCommitment(t, shares[1], sessionID, signers, message, sameRandom)
	commit2 := startSignCommitment(t, shares[2], sessionID, signers, message, sameRandom)
	if bytes.Equal(commit1.DBytes(), commit2.DBytes()) && bytes.Equal(commit1.EBytes(), commit2.EBytes()) {
		t.Fatal("same randomness with different secret shares produced identical commitments")
	}

	commit3 := startSignCommitment(t, shares[1], sessionID, signers, message, bytes.Repeat([]byte{0x43}, 64))
	if bytes.Equal(commit1.DBytes(), commit3.DBytes()) && bytes.Equal(commit1.EBytes(), commit3.EBytes()) {
		t.Fatal("same secret share with different randomness produced identical commitments")
	}

	_, _, err = startFROSTSignWithOptions(shares[1], sessionID, signers, message, SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x44}, 31)),
	})
	if err == nil {
		t.Fatal("insufficient nonce randomness should fail signing start")
	}
}

func TestSignNonceGenerationBindsSigningIntent(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	signers := tss.NewPartySet(1, 2)
	randomness := bytes.Repeat([]byte{0x42}, 64)

	sessionA, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	commitA := startSignCommitment(t, shares[1], sessionA, signers, []byte("message-a"), randomness)
	commitB := startSignCommitment(t, shares[1], sessionB, signers, []byte("message-a"), randomness)
	if bytes.Equal(commitA.DBytes(), commitB.DBytes()) || bytes.Equal(commitA.EBytes(), commitB.EBytes()) {
		t.Fatal("repeated reader output reused a nonce across sessions")
	}
	commitC := startSignCommitment(t, shares[1], sessionA, signers, []byte("message-b"), randomness)
	if bytes.Equal(commitA.DBytes(), commitC.DBytes()) || bytes.Equal(commitA.EBytes(), commitC.EBytes()) {
		t.Fatal("repeated reader output reused a nonce across messages")
	}
	if bytes.Equal(commitA.DBytes(), commitA.EBytes()) {
		t.Fatal("hiding and binding nonce commitments were identical")
	}
}

func TestSignClearsNonceAfterPartial(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)

	session, _, err := startFROSTSignWithOptions(shares[1], sessionID, signers, []byte("clear nonce"), SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTSignWithOptions(shares[2], sessionID, signers, []byte("clear nonce"), SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}

	round2, err := session.Handle(testutil.DeliverEnvelope(out2[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(round2) != 1 || round2[0].PayloadType != payloadSignPartial {
		t.Fatalf("expected one partial, got %d", len(round2))
	}
	if !session.partialSent {
		t.Fatal("session did not mark partial as sent")
	}
	if session.dNonce != nil || session.eNonce != nil {
		t.Fatal("signing nonces were not cleared after partial generation")
	}

	again, err := session.tryEmitPartial()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("tryEmitPartial emitted a second partial: %d", len(again))
	}
}

func TestStartSignRejectsMessageOverLimit(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.Repeat([]byte{'x'}, DefaultLimits().Payload.MaxMessageBytes+1)
	session, out, err := startFROSTSign(shares[1], sessionID, tss.NewPartySet(1, 2), message)
	if err == nil {
		t.Fatal("expected oversized message to be rejected")
	}
	if session != nil || out != nil {
		t.Fatal("oversized message produced signing session or outbound messages")
	}
}

func TestSignOutOfOrderPartialsWaitForCommitments(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2, 3)
	message := []byte("out-of-order partials")

	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	round1 := make(map[tss.PartyID]tss.Envelope, len(signers))
	for _, id := range signers {
		session, out, err := startFROSTSign(shares[id], sessionID, signers, message)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		round1[id] = out[0]
	}
	localCommitmentPayload := bytes.Clone(round1[1].Payload)

	round2 := make([]tss.Envelope, 0, 2)
	for _, receiver := range tss.NewPartySet(2, 3) {
		for _, env := range round1 {
			if env.From == receiver {
				continue
			}
			out, err := sessions[receiver].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver commitment from %d to %d: %v", env.From, receiver, err)
			}
			round2 = append(round2, out...)
		}
	}
	if len(round2) != 2 {
		t.Fatalf("expected two remote partials, got %d", len(round2))
	}

	if _, err := sessions[1].Handle(testutil.DeliverEnvelope(round1[2])); err != nil {
		t.Fatal(err)
	}
	for _, env := range round2 {
		if _, err := sessions[1].Handle(testutil.DeliverEnvelope(env)); err != nil {
			t.Fatalf("early partial from %d returned fatal error: %v", env.From, err)
		}
	}
	if sig, ok := sessions[1].Signature(); ok {
		t.Fatalf("signature completed before all commitments arrived: %x", sig)
	}
	if len(sessions[1].partials) != 0 || len(sessions[1].pendingPartials) != 2 {
		t.Fatalf("early partial state: accepted=%d pending=%d, want 0 accepted and 2 pending", len(sessions[1].partials), len(sessions[1].pendingPartials))
	}

	out, err := sessions[1].Handle(testutil.DeliverEnvelope(round1[3]))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PayloadType != payloadSignPartial {
		t.Fatalf("expected delayed local partial, got %d", len(out))
	}
	sig, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature did not complete after delayed commitment arrived")
	}
	if !stded25519.Verify(stded25519.PublicKey(sessions[1].VerifyKey()), message, sig) {
		t.Fatal("signature from out-of-order flow failed verification")
	}
	if sessions[1].message != nil {
		t.Fatal("completed signing session retained message")
	}
	if sessions[1].partials != nil {
		t.Fatal("completed signing session retained partial scalars")
	}
	if sessions[1].partialEnvelopes != nil {
		t.Fatal("completed signing session retained partial envelopes")
	}
	if sessions[1].pendingPartials != nil || sessions[1].pendingEnvelopes != nil {
		t.Fatal("completed signing session retained pending partial state")
	}
	if sessions[1].commitments != nil || sessions[1].commitMessage.Payload != nil {
		t.Fatal("completed signing session retained nonce commitment state")
	}
	if got, ok := sessions[1].Signature(); !ok || !bytes.Equal(got, sig) {
		t.Fatal("completed signing session lost its final signature during cleanup")
	}
	if !bytes.Equal(round1[1].Payload, localCommitmentPayload) {
		t.Fatal("terminal cleanup mutated the caller-owned commitment envelope")
	}
}

func TestSignNonSignerDoesNotConsumeReplayCapacity(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2, 3)
	guard, err := tss.NewEnvelopeGuard(1, parties, tss.ProtocolFROSTEd25519, sessionID, testFROSTPolicies(), tss.NewBoundedReplayCache(1))
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := startFROSTSign(shares[1], sessionID, tss.NewPartySet(1, 2), []byte("signer guard"), guard)
	if err != nil {
		t.Fatal(err)
	}
	_, signerOut, err := startFROSTSign(shares[2], sessionID, tss.NewPartySet(1, 2), []byte("signer guard"))
	if err != nil {
		t.Fatal(err)
	}
	nonSigner, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       signStartRound,
		From:        3,
		PayloadType: payloadSignCommitment,
		Payload:     []byte("not decoded"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Handle(testutil.DeliverEnvelope(nonSigner)); err == nil {
		t.Fatal("non-signer envelope accepted")
	}
	if _, err := session.Handle(testutil.DeliverEnvelope(signerOut[0])); err != nil {
		t.Fatalf("valid signer rejected after non-signer input: %v", err)
	}
}

func TestSignBlameEvidenceBindsBadPartialPayload(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)
	message := []byte("bad partial evidence")

	session1, out1, err := startFROSTSignWithOptions(shares[1], sessionID, signers, message, SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	session2, out2, err := startFROSTSignWithOptions(shares[2], sessionID, signers, message, SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := session1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	partials2, err := session2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(partials2) != 1 || partials2[0].PayloadType != payloadSignPartial {
		t.Fatalf("expected one partial from party 2, got %d", len(partials2))
	}

	partialPayload, err := unmarshalSignPartialPayload(partials2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	partialScalar := partialPayload.Z.Scalar()
	badScalar := fed.NewScalar().Add(partialScalar, edcurve.ScalarOne())
	badZ, err := newCanonicalScalar(badScalar)
	if err != nil {
		t.Fatal(err)
	}
	badPayload, err := marshalSignPartialPayload(signPartialPayload{Z: badZ, PlanHash: partialPayload.PlanHash})
	if err != nil {
		t.Fatal(err)
	}
	badPartial := partials2[0]
	badPartial.Payload = badPayload

	_, err = session1.Handle(testutil.DeliverEnvelope(badPartial))
	protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
	if protocolErr.Blame == nil || len(protocolErr.Blame.Evidence) == 0 {
		t.Fatal("invalid partial did not carry blame evidence")
	}
	evidence, err := tss.DecodeBinary[tss.BlameEvidence](protocolErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(badPayload)
	if !bytes.Equal(evidence.PayloadHash, wantHash[:]) {
		t.Fatal("blame evidence did not bind the bad partial payload")
	}
}

func startSignCommitment(t *testing.T, key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, message, randomness []byte) nonceCommitment {
	t.Helper()
	_, out, err := startFROSTSignWithOptions(key, sessionID, signers, message, SignOptions{
		NonceReader: bytes.NewReader(randomness),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected only round-1 commitment, got %d envelopes", len(out))
	}
	commitment, err := unmarshalNonceCommitmentPayload(out[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	return commitment
}

// Helper to add test guards is already in frost_test.go (same package)

func TestNonceCommitmentMarshalJSONRejects(t *testing.T) {
	t.Parallel()
	nc := nonceCommitment{}
	if _, err := nc.MarshalJSON(); err == nil {
		t.Fatal("nonceCommitment.MarshalJSON should reject JSON encoding")
	}
}

func TestNonceCommitmentWireRejectsIdentityAndMalformedPoints(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := startFROSTSign(shares[1], sessionID, tss.NewPartySet(1, 2), []byte("wire point validation"))
	if err != nil {
		t.Fatal(err)
	}
	raw := out[0].Payload
	identity := make([]byte, 32)
	identity[0] = 1
	for _, tc := range []struct {
		name  string
		field string
		value []byte
	}{
		{name: "identity D", field: "D", value: identity},
		{name: "identity E", field: "E", value: identity},
		{name: "short D", field: "D", value: make([]byte, 31)},
		{name: "short E", field: "E", value: make([]byte, 31)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated, err := testutil.RewriteWireFieldByName(raw, nonceCommitmentPayloadWireType, nonceCommitment{}, tc.field, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := unmarshalNonceCommitmentPayload(mutated); err == nil {
				t.Fatalf("nonce commitment accepted %s", tc.name)
			}
		})
	}
}

func TestSignPartialPayloadMarshalJSONRejects(t *testing.T) {
	t.Parallel()
	sp := signPartialPayload{}
	if _, err := sp.MarshalJSON(); err == nil {
		t.Fatal("signPartialPayload.MarshalJSON should reject JSON encoding")
	}
}

func TestSecretSharePayloadMarshalJSONRejects(t *testing.T) {
	t.Parallel()
	if _, err := (keygenSharePayload{}).MarshalJSON(); err == nil {
		t.Fatal("keygenSharePayload.MarshalJSON should reject JSON encoding")
	}
	if _, err := (reshareSharePayload{}).MarshalJSON(); err == nil {
		t.Fatal("reshareSharePayload.MarshalJSON should reject JSON encoding")
	}
}
