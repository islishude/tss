//go:build integration

package secp256k1

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// ed25519Signer implements tss.BroadcastAckSigner for a test party.
type ed25519Signer struct {
	priv ed25519.PrivateKey
}

func (s *ed25519Signer) SignAck(digest [32]byte) ([]byte, error) {
	return ed25519.Sign(s.priv, digest[:]), nil
}

func (s *ed25519Signer) SignEnvelopeDigest(digest [32]byte) ([]byte, error) {
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

func (v *ed25519Verifier) VerifyEnvelopeSignature(party tss.PartyID, digest [32]byte, sig []byte) error {
	return v.VerifyAck(party, digest, sig)
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

// deliverWithCertificate opens an envelope through simulated authenticated
// transport and attaches a BroadcastCertificate when the policy requires one.
func deliverWithCertificate(t *testing.T, env tss.Envelope, to tss.PartyID, parties tss.PartySet, km *keyMaterial) tss.InboundEnvelope {
	t.Helper()
	protection := tss.ChannelPlaintext
	var cert *tss.BroadcastCertificate
	for _, p := range CGGMP21Policies().Entries() {
		if p.Protocol == tss.ProtocolCGGMP21Secp256k1 && p.Round == env.Round && p.PayloadType == env.PayloadType {
			if p.Confidentiality == tss.ConfidentialityRequired {
				protection = tss.ChannelConfidential
			}
			if env.To != 0 {
				protection = tss.ChannelConfidential
			}
			if env.To == 0 && p.BroadcastConsistency == tss.BroadcastConsistencyRequired {
				cert = buildBroadcastCertificate(t, env, parties, km)
			}
			break
		}
	}
	_ = to
	in, err := testutil.OpenInboundEnvelope(env, tss.ReceiveInfo{
		Peer:       env.From,
		Protection: protection,
		ChannelID:  "test",
		PeerKeyID:  "party",
	}, cert)
	if err != nil {
		t.Fatalf("open inbound envelope: %v", err)
	}
	return in
}

// TestCGGMP21FullGuardProtectedKeygenSign runs a complete 2-of-3 keygen→presign→sign
// flow with every session protected by a full EnvelopeGuard (including
// BroadcastConsistencyRequired for keygen round 1). Broadcast certificates
// are generated from Ed25519 party keys and verified by the guard.
func TestCGGMP21FullGuardProtectedKeygenSign(t *testing.T) {
	parties := tss.NewPartySet(1, 2, 3)
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
			Threshold:      threshold,
			Parties:        parties,
			Self:           id,
			SessionID:      kgSessionID,
			EnvelopeSigner: km.signerFor(id).(*ed25519Signer),
		}
		g, err := tss.NewEnvelopeGuard(id, parties, tss.ProtocolCGGMP21Secp256k1, kgSessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		g.AckVerifier = km.verifier
		g.EnvelopeVerifier = km.verifier
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
			out, err := kgSessions[id].Handle(delivered)
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
	signers := tss.NewPartySet(1, 2)
	psSessions := make(map[tss.PartyID]*PresignSession, len(signers))
	queue = nil

	for _, id := range signers {
		g, err := tss.NewEnvelopeGuard(id, signers, tss.ProtocolCGGMP21Secp256k1, presignSessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		g.AckVerifier = km.verifier
		g.EnvelopeVerifier = km.verifier
		plan, err := NewPresignPlan(PresignPlanOption{Key: shares[id], SessionID: presignSessionID, PresignID: presignSessionID[:], Signers: signers, Context: testPresignContext(), Limits: testLimitsPtr(), SecurityParams: testSecurityParamsPtr()})
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := prepareTestPresignRuntime(context.Background(), shares[id], plan, tss.LocalConfig{Self: id, EnvelopeSigner: km.signerFor(id).(*ed25519Signer)}, g)
		if err != nil {
			t.Fatal(err)
		}
		session, out, err := StartPresign(plan, runtime)
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
			delivered := deliverWithCertificate(t, env, id, signers, km)
			out, err := psSessions[id].Handle(delivered)
			if err != nil {
				t.Fatalf("presign delivery from %d to %d (type=%s): %v", env.From, id, env.PayloadType, err)
			}
			queue = append(queue, out...)
		}
	}

	presigns := make(map[tss.PartyID]*Presign, len(signers))
	for _, id := range signers {
		p, err := loadPersistedPresignForTest(psSessions[id])
		if err != nil {
			t.Fatalf("load persisted presign for party %d: %v", id, err)
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
		g, err := tss.NewEnvelopeGuard(id, signers, tss.ProtocolCGGMP21Secp256k1, signSessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
		if err != nil {
			t.Fatal(err)
		}
		g.AckVerifier = km.verifier
		g.EnvelopeVerifier = km.verifier
		session, out, err := startCGGMP21SignWithLocal(shares[id], presigns[id], signSessionID, tss.SignRequest{
			Context: testPresignContext(),
			Message: []byte("hello guard-protected world"),
		}, tss.LocalConfig{Self: id, EnvelopeSigner: km.signerFor(id).(*ed25519Signer)}, g)
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
			delivered := deliverWithCertificate(t, env, id, signers, km)
			_, err := signSessions[id].Handle(delivered)
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
	if !VerifySignature(mustKeySharePublicKey(t, shares[1]), tss.SignRequest{
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
	parties := tss.NewPartySet(71, 72, 73)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	km := newKeyMaterial(t, parties)

	cfg := tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 71, SessionID: sessionID, EnvelopeSigner: km.signerFor(71).(*ed25519Signer)}
	g, err := tss.NewEnvelopeGuard(71, parties, tss.ProtocolCGGMP21Secp256k1, sessionID, CGGMP21Policies(), tss.NewInMemoryReplayCache())
	if err != nil {
		t.Fatal(err)
	}
	g.AckVerifier = km.verifier
	g.EnvelopeVerifier = km.verifier
	session, _, err := startCGGMP21Keygen(cfg, g)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid broadcast envelope.
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       1,
		From:        72,
		To:          0,
		PayloadType: payloadFigure6Commitment,
		Payload:     []byte("test-commitments"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build a certificate for a DIFFERENT payload.
	wrongEnv := env
	wrongEnv.Payload = []byte("different-payload")
	cert := buildBroadcastCertificate(t, wrongEnv, parties, km)
	// Guard should reject because cert payload hash doesn't match envelope payload.
	in, err := testutil.OpenInboundEnvelope(env, tss.ReceiveInfo{Peer: env.From, Protection: tss.ChannelPlaintext}, cert)
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Handle(in)
	if !errors.Is(err, tss.ErrInvalidBroadcastCertificate) {
		t.Fatalf("expected ErrInvalidBroadcastCertificate for mismatched cert, got %v", err)
	}
}
