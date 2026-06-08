package tss

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

// ed25519AckSigner wraps an Ed25519 private key for broadcast ack signing.
type ed25519AckSigner struct {
	party   PartyID
	privKey ed25519.PrivateKey
}

func (s *ed25519AckSigner) SignAck(digest [32]byte) ([]byte, error) {
	return ed25519.Sign(s.privKey, digest[:]), nil
}

// ed25519AckVerifier wraps a map of PartyID → Ed25519 public key for verification.
type ed25519AckVerifier struct {
	pubKeys map[PartyID]ed25519.PublicKey
}

func (v *ed25519AckVerifier) VerifyAck(party PartyID, digest [32]byte, signature []byte) error {
	pub, ok := v.pubKeys[party]
	if !ok {
		return errors.New("unknown party")
	}
	if !ed25519.Verify(pub, digest[:], signature) {
		return errors.New("invalid signature")
	}
	return nil
}

func setupAckKeys(t *testing.T, parties PartySet) (map[PartyID]*ed25519AckSigner, *ed25519AckVerifier) {
	t.Helper()
	signers := make(map[PartyID]*ed25519AckSigner, len(parties))
	pubKeys := make(map[PartyID]ed25519.PublicKey, len(parties))
	for _, id := range parties {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers[id] = &ed25519AckSigner{party: id, privKey: priv}
		pubKeys[id] = pub
	}
	return signers, &ed25519AckVerifier{pubKeys: pubKeys}
}

func TestAckDigestDeterminism(t *testing.T) {
	sid := testSessionID(t)
	ph := sha256.Sum256([]byte("hello"))
	th := sha256.Sum256([]byte("transcript"))
	d1 := AckDigest("test", sid, 1, 2, "payload.type", ph, th)
	d2 := AckDigest("test", sid, 1, 2, "payload.type", ph, th)
	if d1 != d2 {
		t.Fatal("AckDigest must be deterministic")
	}
	// Different protocol → different digest
	d3 := AckDigest("other", sid, 1, 2, "payload.type", ph, th)
	if d1 == d3 {
		t.Fatal("different protocol should produce different digest")
	}
}

func TestNewBroadcastCertificateValid(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2, 3}
	ph := sha256.Sum256(env.Payload)
	acks := []BroadcastAck{
		{Party: 1, PayloadHash: ph, TranscriptHash: env.TranscriptHash},
		{Party: 2, PayloadHash: ph, TranscriptHash: env.TranscriptHash},
		{Party: 3, PayloadHash: ph, TranscriptHash: env.TranscriptHash},
	}
	cert, err := NewBroadcastCertificate(env, parties, acks)
	if err != nil {
		t.Fatalf("valid certificate should be created: %v", err)
	}
	if err := cert.Verify(env, parties); err != nil {
		t.Fatalf("valid certificate should verify: %v", err)
	}
}

func TestNewBroadcastCertificateRejectsMismatchedPayloadHash(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2}
	ph := sha256.Sum256(env.Payload)
	wrongHash := sha256.Sum256([]byte("wrong"))
	acks := []BroadcastAck{
		{Party: 1, PayloadHash: ph, TranscriptHash: env.TranscriptHash},
		{Party: 2, PayloadHash: wrongHash, TranscriptHash: env.TranscriptHash},
	}
	_, err := NewBroadcastCertificate(env, parties, acks)
	if err == nil {
		t.Fatal("should reject mismatched payload hash")
	}
}

func TestSignAndVerifyBroadcastAck(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	signers, verifier := setupAckKeys(t, PartySet{1})
	ack, err := SignBroadcastAck(env, 1, signers[1])
	if err != nil {
		t.Fatalf("sign ack: %v", err)
	}
	if err := VerifyBroadcastAck(env, ack, verifier); err != nil {
		t.Fatalf("verify ack: %v", err)
	}
}

func TestVerifyBroadcastAckRejectsTamperedEnvelope(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	signers, verifier := setupAckKeys(t, PartySet{1})
	ack, err := SignBroadcastAck(env, 1, signers[1])
	if err != nil {
		t.Fatalf("sign ack: %v", err)
	}
	// Tamper with the envelope payload
	tampered := env
	tampered.Payload = []byte("tampered")
	tampered = tampered.RecomputeTranscriptHash()
	if err := VerifyBroadcastAck(tampered, ack, verifier); err == nil {
		t.Fatal("should reject ack for tampered envelope")
	}
}

func TestVerifyBroadcastCertificateWithSignatures(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2, 3}
	signers, verifier := setupAckKeys(t, parties)

	var acks []BroadcastAck
	for _, id := range parties {
		ack, err := SignBroadcastAck(env, id, signers[id])
		if err != nil {
			t.Fatalf("sign ack for party %d: %v", id, err)
		}
		acks = append(acks, ack)
	}

	cert, err := NewBroadcastCertificate(env, parties, acks)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	if err := VerifyBroadcastCertificateWithSignatures(env, parties, cert, verifier); err != nil {
		t.Fatalf("full verify should pass: %v", err)
	}
}

func TestBroadcastConsistencyFullFlow(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2, 3}
	signers, verifier := setupAckKeys(t, parties)

	bc := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)

	// Commit the broadcast digest
	if err := bc.Commit(env); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Each party signs and submits an ack
	for _, id := range parties {
		ack, err := SignBroadcastAck(env, id, signers[id])
		if err != nil {
			t.Fatalf("party %d sign: %v", id, err)
		}
		if err := bc.AddAck(env, ack); err != nil {
			t.Fatalf("party %d add ack: %v", id, err)
		}
	}

	if !bc.Complete() {
		t.Fatal("should be complete")
	}

	cert, err := bc.Certificate()
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}

	if err := VerifyBroadcastCertificateWithSignatures(env, parties, cert, verifier); err != nil {
		t.Fatalf("full verify: %v", err)
	}
}

func TestBroadcastConsistencyDetectsEquivocation(t *testing.T) {
	sid := testSessionID(t)
	env1 := testBroadcastEnvelope(t, sid)
	env2 := testBroadcastEnvelope(t, sid)
	env2.Payload = []byte("different payload")
	env2 = env2.RecomputeTranscriptHash()
	parties := PartySet{1, 2}
	_, verifier := setupAckKeys(t, parties)

	bc := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)

	// Commit first digest
	if err := bc.Commit(env1); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Trying to commit a different digest must fail
	if err := bc.Commit(env2); !errors.Is(err, ErrBroadcastEquivocation) {
		t.Fatalf("expected ErrBroadcastEquivocation, got %v", err)
	}
}

func TestBroadcastConsistencyRejectsInvalidSignature(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2}
	signers, verifier := setupAckKeys(t, parties)

	bc := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if err := bc.Commit(env); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Party 1 signs correctly
	ack1, err := SignBroadcastAck(env, 1, signers[1])
	if err != nil {
		t.Fatalf("sign ack: %v", err)
	}
	if err := bc.AddAck(env, ack1); err != nil {
		t.Fatalf("add valid ack: %v", err)
	}

	// Party 2 submits an ack with a forged signature (party 1's signature)
	ack2 := BroadcastAck{
		Party:          2,
		PayloadHash:    ack1.PayloadHash,
		TranscriptHash: ack1.TranscriptHash,
		Signature:      ack1.Signature, // wrong signer
	}
	if err := bc.AddAck(env, ack2); err == nil {
		t.Fatal("should reject invalid signature")
	}
}

func TestBroadcastConsistencyRejectsEquivocatingAck(t *testing.T) {
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2}
	signers, verifier := setupAckKeys(t, parties)

	bc := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if err := bc.Commit(env); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Create a tampered envelope
	tampered := env
	tampered.Payload = []byte("equivocating payload")
	tampered = tampered.RecomputeTranscriptHash()

	ack, err := SignBroadcastAck(tampered, 1, signers[1])
	if err != nil {
		t.Fatalf("sign ack: %v", err)
	}

	// AddAck with a different envelope than committed must fail
	if err := bc.AddAck(tampered, ack); !errors.Is(err, ErrBroadcastEquivocation) {
		t.Fatalf("expected ErrBroadcastEquivocation, got %v", err)
	}
}

func testBroadcastEnvelope(t *testing.T, sid SessionID) Envelope {
	t.Helper()
	env, err := NewEnvelope(EnvelopeInput{
		Protocol:    "test",
		Version:     Version,
		SessionID:   sid,
		Round:       1,
		From:        2,
		To:          0, // broadcast
		PayloadType: "test.broadcast",
		Payload:     []byte("test broadcast payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}
