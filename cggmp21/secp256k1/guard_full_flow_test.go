//go:build integration

package secp256k1

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

// ed25519Signer implements tss.BroadcastAckSigner for a test party.
type ed25519Signer struct {
	priv ed25519.PrivateKey
}

func (s *ed25519Signer) SignAck(digest [32]byte) ([]byte, error) {
	return ed25519.Sign(s.priv, digest[:]), nil
}

// ed25519Verifier implements tss.BroadcastAckVerifier for a set of parties.
type ed25519Verifier struct {
	pubs map[tss.PartyID]ed25519.PublicKey
}

func (v *ed25519Verifier) VerifyAck(party tss.PartyID, digest [32]byte, sig []byte) error {
	pub, ok := v.pubs[party]
	if !ok {
		return errors.New("unknown party")
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("invalid ack signature")
	}
	return nil
}

// keyMaterial holds per-party long-term signing keys for broadcast acks.
type keyMaterial struct {
	privKeys map[tss.PartyID]ed25519.PrivateKey
	verifier *ed25519Verifier
}

func newKeyMaterial(t *testing.T, parties tss.PartySet) *keyMaterial {
	t.Helper()
	privKeys := make(map[tss.PartyID]ed25519.PrivateKey, len(parties))
	pubKeys := make(map[tss.PartyID]ed25519.PublicKey, len(parties))
	for _, id := range parties {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubKeys[id] = pub
		privKeys[id] = priv
	}
	return &keyMaterial{
		privKeys: privKeys,
		verifier: &ed25519Verifier{pubs: pubKeys},
	}
}

func (km *keyMaterial) signerFor(party tss.PartyID) tss.BroadcastAckSigner {
	priv, ok := km.privKeys[party]
	if !ok {
		panic("no key for party")
	}
	return &ed25519Signer{priv: priv}
}

// buildBroadcastCertificate creates a certificate proving all parties saw
// the same broadcast envelope. Every party (including the sender) signs an ack
// over the same digest.
func buildBroadcastCertificate(t *testing.T, env tss.Envelope, parties tss.PartySet, km *keyMaterial) *tss.BroadcastCertificate {
	t.Helper()
	var acks []tss.BroadcastAck
	for _, id := range parties {
		ack, err := tss.SignBroadcastAck(env, id, km.signerFor(id))
		if err != nil {
			t.Fatalf("sign ack for party %d: %v", id, err)
		}
		acks = append(acks, ack)
	}
	cert, err := tss.NewBroadcastCertificate(env, parties, acks)
	if err != nil {
		t.Fatalf("build cert: %v", err)
	}
	return cert
}

// deliverAuthenticated delivers an envelope through simulated authenticated
// transport. For direct (point-to-point) messages, Confidential is set based
// on the policy. For broadcast messages with BroadcastConsistencyRequired,
// a BroadcastCertificate is built and attached.
func deliverWithCertificate(t *testing.T, env tss.Envelope, to tss.PartyID, parties tss.PartySet, km *keyMaterial) tss.Envelope {
	t.Helper()
	delivered := env.Clone()
	delivered.Security.Authenticated = true
	delivered.Security.AuthenticatedParty = env.From
	// Set confidentiality based on policy.
	for _, p := range CGGMP21Policies().Entries() {
		if p.Protocol == protocol && p.Round == env.Round && p.PayloadType == env.PayloadType {
			if p.Confidentiality == tss.ConfidentialityRequired {
				delivered.Security.Confidential = true
			}
			break
		}
	}
	// Also set confidential for any direct (point-to-point) message.
	if env.To != 0 {
		delivered.Security.Confidential = true
	}
	if env.To == 0 {
		// Broadcast: attach certificate for consistency-required payloads.
		for _, p := range CGGMP21Policies().Entries() {
			if p.Protocol == protocol && p.Round == env.Round && p.PayloadType == env.PayloadType {
				if p.BroadcastConsistency == tss.BroadcastConsistencyRequired {
					delivered.Broadcast = buildBroadcastCertificate(t, env, parties, km)
				}
				break
			}
		}
	}
	_ = to
	return delivered
}

// TestCGGMP21FullGuardProtectedKeygenSign runs a complete 2-of-3 keygen→presign→sign
// flow with every session protected by a full EnvelopeGuard (including
// BroadcastConsistencyRequired for keygen round 1). Broadcast certificates
// are generated from Ed25519 party keys and verified by the guard.
func TestCGGMP21FullGuardProtectedKeygenSign(t *testing.T) {
	parties := tss.PartySet{1, 2, 3}
	threshold := 2

	// --- Setup: identity keys for broadcast ack signing ---
	km := newKeyMaterial(t, parties)

	// --- Phase 1: Keygen ---
	kgSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	kgSessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0)

	// Start keygen for each party with guard.
	for _, id := range parties {
		cfg := tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: kgSessionID,
		}
		g, err := tss.NewEnvelopeGuard(id, parties, protocol, kgSessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		g.AckVerifier = km.verifier
		session, out, err := startCGGMP21Keygen(cfg, g)
		if err != nil {
			t.Fatal(err)
		}
		kgSessions[id] = session
		queue = append(queue, out...)
	}

	// Deliver keygen messages with authenticated transport and broadcast certificates.
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			delivered := deliverWithCertificate(t, env, id, parties, km)
			out, err := kgSessions[id].HandleKeygenMessage(delivered)
			if err != nil {
				t.Fatalf("keygen delivery from %d to %d (type=%s): %v", env.From, id, env.PayloadType, err)
			}
			queue = append(queue, out...)
		}
	}

	// Collect key shares.
	shares := make(map[tss.PartyID]*KeyShare, len(parties))
	for _, id := range parties {
		ks, ok := kgSessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen did not complete for party %d", id)
		}
		shares[id] = ks
	}

	// --- Phase 2: Presign ---
	presignSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	psSessions := make(map[tss.PartyID]*PresignSession, len(signers))
	queue = nil

	for _, id := range signers {
		g, err := tss.NewEnvelopeGuard(id, tss.PartySet(signers), protocol, presignSessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		g.AckVerifier = km.verifier
		session, out, err := startCGGMP21PresignWithContext(shares[id], presignSessionID, signers, testPresignContext(), g)
		if err != nil {
			t.Fatal(err)
		}
		psSessions[id] = session
		queue = append(queue, out...)
	}

	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			delivered := deliverWithCertificate(t, env, id, tss.PartySet(signers), km)
			out, err := psSessions[id].HandlePresignMessage(delivered)
			if err != nil {
				t.Fatalf("presign delivery from %d to %d (type=%s): %v", env.From, id, env.PayloadType, err)
			}
			queue = append(queue, out...)
		}
	}

	presigns := make(map[tss.PartyID]*Presign, len(signers))
	for _, id := range signers {
		p, ok := psSessions[id].Presign()
		if !ok {
			t.Fatalf("presign did not complete for party %d", id)
		}
		presigns[id] = p
	}

	// --- Phase 3: Sign ---
	signSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signSessions := make(map[tss.PartyID]*SignSession, len(signers))
	queue = nil

	for _, id := range signers {
		g, err := tss.NewEnvelopeGuard(id, tss.PartySet(signers), protocol, signSessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		g.AckVerifier = km.verifier
		session, out, err := startCGGMP21Sign(shares[id], presigns[id], signSessionID, SignRequest{
			Context: testPresignContext(),
			Message: []byte("hello guard-protected world"),
			LowS:    true,
		}, g)
		if err != nil {
			t.Fatal(err)
		}
		signSessions[id] = session
		queue = append(queue, out...)
	}

	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			delivered := deliverWithCertificate(t, env, id, tss.PartySet(signers), km)
			_, err := signSessions[id].HandleSignMessage(delivered)
			if err != nil {
				t.Fatalf("sign delivery from %d to %d: %v", env.From, id, err)
			}
		}
	}

	sig, ok := signSessions[1].Signature()
	if !ok {
		t.Fatal("signing did not complete")
	}

	// Verify the produced signature.
	if !VerifySignature(shares[1].PublicKeyBytes(), SignRequest{
		Context: testPresignContext(),
		Message: []byte("hello guard-protected world"),
	}, sig) {
		t.Fatal("produced ECDSA signature failed verification")
	}

	t.Logf("Full guard-protected flow completed: keygen→presign→sign with broadcast certificates")
}

// TestCGGMP21GuardRejectsBroadcastWithWrongCertificate verifies that a
// broadcast certificate with mismatched digest is rejected by the guard.
func TestCGGMP21GuardRejectsBroadcastWithWrongCertificate(t *testing.T) {
	parties := tss.PartySet{71, 72, 73}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	km := newKeyMaterial(t, parties)

	cfg := tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 71, SessionID: sessionID}
	g, err := tss.NewEnvelopeGuard(71, parties, protocol, sessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
	if err != nil {
		t.Fatal(err)
	}
	g.AckVerifier = km.verifier
	session, _, err := startCGGMP21Keygen(cfg, g)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid broadcast envelope.
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        72,
		To:          0,
		PayloadType: payloadKeygenCommitments,
		Payload:     []byte("test-commitments"),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = 72

	// Build a certificate for a DIFFERENT payload.
	wrongEnv := env
	wrongEnv.Payload = []byte("different-payload")
	wrongEnv = wrongEnv.RecomputeTranscriptHash()
	cert := buildBroadcastCertificate(t, wrongEnv, parties, km)
	env.Broadcast = cert

	// Guard should reject because cert payload hash doesn't match envelope payload.
	_, err = session.HandleKeygenMessage(env)
	if !errors.Is(err, tss.ErrInvalidBroadcastCertificate) {
		t.Fatalf("expected ErrInvalidBroadcastCertificate for mismatched cert, got %v", err)
	}
}
