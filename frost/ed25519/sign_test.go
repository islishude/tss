package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestSignNonceGenerationDependsOnSecretAndRandomness(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	message := []byte("nonce regression")

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sameRandom := bytes.Repeat([]byte{0x42}, 64)
	commit1 := startSignCommitment(t, shares[1], sessionID, signers, message, sameRandom)
	commit2 := startSignCommitment(t, shares[2], sessionID, signers, message, sameRandom)
	if bytes.Equal(commit1.D, commit2.D) && bytes.Equal(commit1.E, commit2.E) {
		t.Fatal("same randomness with different secret shares produced identical commitments")
	}

	commit3 := startSignCommitment(t, shares[1], sessionID, signers, message, bytes.Repeat([]byte{0x43}, 64))
	if bytes.Equal(commit1.D, commit3.D) && bytes.Equal(commit1.E, commit3.E) {
		t.Fatal("same secret share with different randomness produced identical commitments")
	}

	_, _, err = StartSignWithOptions(shares[1], sessionID, signers, message, SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x44}, 31)),
	})
	if err == nil {
		t.Fatal("insufficient nonce randomness should fail signing start")
	}
}

func TestSignClearsNonceAfterPartial(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}

	session, _, err := StartSignWithOptions(shares[1], sessionID, signers, []byte("clear nonce"), SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartSignWithOptions(shares[2], sessionID, signers, []byte("clear nonce"), SignOptions{
		NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}

	round2, err := session.HandleSignMessage(testutil.DeliverEnvelope(out2[0]))
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

func TestSignOutOfOrderPartialsWaitForCommitments(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2, 3}
	message := []byte("out-of-order partials")

	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	round1 := make(map[tss.PartyID]tss.Envelope, len(signers))
	for _, id := range signers {
		session, out, err := StartSign(shares[id], sessionID, signers, message)
		if err != nil {
			t.Fatal(err)
		}
		session.SetGuard(testFROSTGuard(id, tss.PartySet(shares[id].Parties), sessionID))
		sessions[id] = session
		round1[id] = out[0]
	}

	round2 := make([]tss.Envelope, 0, 2)
	for _, receiver := range []tss.PartyID{2, 3} {
		for _, env := range round1 {
			if env.From == receiver {
				continue
			}
			out, err := sessions[receiver].HandleSignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver commitment from %d to %d: %v", env.From, receiver, err)
			}
			round2 = append(round2, out...)
		}
	}
	if len(round2) != 2 {
		t.Fatalf("expected two remote partials, got %d", len(round2))
	}

	if _, err := sessions[1].HandleSignMessage(testutil.DeliverEnvelope(round1[2])); err != nil {
		t.Fatal(err)
	}
	for _, env := range round2 {
		if _, err := sessions[1].HandleSignMessage(testutil.DeliverEnvelope(env)); err != nil {
			t.Fatalf("early partial from %d returned fatal error: %v", env.From, err)
		}
	}
	if sig, ok := sessions[1].Signature(); ok {
		t.Fatalf("signature completed before all commitments arrived: %x", sig)
	}

	out, err := sessions[1].HandleSignMessage(testutil.DeliverEnvelope(round1[3]))
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
}

func startSignCommitment(t *testing.T, key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, message, randomness []byte) nonceCommitment {
	t.Helper()
	_, out, err := StartSignWithOptions(key, sessionID, signers, message, SignOptions{
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
	nc := nonceCommitment{D: []byte{0x01}, E: []byte{0x02}}
	if _, err := nc.MarshalJSON(); err == nil {
		t.Fatal("nonceCommitment.MarshalJSON should reject JSON encoding")
	}
}

func TestSignPartialPayloadMarshalJSONRejects(t *testing.T) {
	t.Parallel()
	sp := signPartialPayload{Z: []byte{0x03}}
	if _, err := sp.MarshalJSON(); err == nil {
		t.Fatal("signPartialPayload.MarshalJSON should reject JSON encoding")
	}
}

func TestNoopSignVerifierVerifyAckAcceptsAny(t *testing.T) {
	t.Parallel()
	var v noopSignVerifier
	// VerifyAck should accept any signature without error.
	if err := v.VerifyAck(1, [32]byte{}, []byte("anything")); err != nil {
		t.Fatalf("noopSignVerifier should accept any signature: %v", err)
	}
	if err := v.VerifyAck(99, [32]byte{0xff}, nil); err != nil {
		t.Fatalf("noopSignVerifier should accept nil signature: %v", err)
	}
	if err := v.VerifyAck(0, [32]byte{}, []byte{}); err != nil {
		t.Fatalf("noopSignVerifier should accept empty signature: %v", err)
	}
}
