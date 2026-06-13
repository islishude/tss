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
	t.Parallel()
	sid := testSessionID(t)
	ph := sha256.Sum256([]byte("hello"))
	th := sha256.Sum256([]byte("transcript"))
	base := AckDigest("test", sid, 1, 2, "payload.type", ph, th)
	if got := AckDigest("test", sid, 1, 2, "payload.type", ph, th); got != base {
		t.Fatal("AckDigest must be deterministic")
	}

	otherSID := sid
	otherSID[0] ^= 1
	otherPH := ph
	otherPH[0] ^= 1
	otherTH := th
	otherTH[0] ^= 1
	tests := []struct {
		name string
		got  [32]byte
	}{
		{name: "protocol", got: AckDigest("other", sid, 1, 2, "payload.type", ph, th)},
		{name: "session", got: AckDigest("test", otherSID, 1, 2, "payload.type", ph, th)},
		{name: "round", got: AckDigest("test", sid, 2, 2, "payload.type", ph, th)},
		{name: "sender", got: AckDigest("test", sid, 1, 3, "payload.type", ph, th)},
		{name: "payload type", got: AckDigest("test", sid, 1, 2, "other.type", ph, th)},
		{name: "payload hash", got: AckDigest("test", sid, 1, 2, "payload.type", otherPH, th)},
		{name: "transcript hash", got: AckDigest("test", sid, 1, 2, "payload.type", ph, otherTH)},
	}
	for _, tt := range tests {
		if tt.got == base {
			t.Errorf("%s change did not change digest", tt.name)
		}
	}
}

func TestNewBroadcastCertificateValid(t *testing.T) {
	t.Parallel()
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
	if err := cert.VerifyStructure(env, parties); err != nil {
		t.Fatalf("valid certificate should verify: %v", err)
	}
}

func TestNewBroadcastCertificateRejectsMismatchedPayloadHash(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2, 3}
	signers, verifier := setupAckKeys(t, parties)

	bc, err := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if err != nil {
		t.Fatal(err)
	}

	// Commit the broadcast digest
	if ok, err := bc.Commit(env); err != nil || !ok {
		t.Fatalf("commit: ok=%v err=%v", ok, err)
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
	t.Parallel()
	sid := testSessionID(t)
	env1 := testBroadcastEnvelope(t, sid)
	env2 := testBroadcastEnvelope(t, sid)
	env2.Payload = []byte("different payload")
	env2 = env2.RecomputeTranscriptHash()
	parties := PartySet{1, 2}
	_, verifier := setupAckKeys(t, parties)

	bc, err := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if err != nil {
		t.Fatal(err)
	}

	// Commit first digest
	if ok, err := bc.Commit(env1); err != nil || !ok {
		t.Fatalf("commit: ok=%v err=%v", ok, err)
	}

	// Trying to commit a different digest must fail
	if _, err := bc.Commit(env2); !errors.Is(err, ErrBroadcastEquivocation) {
		t.Fatalf("expected ErrBroadcastEquivocation, got %v", err)
	}
}

func TestBroadcastConsistencyRejectsInvalidSignature(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2}
	signers, verifier := setupAckKeys(t, parties)

	bc, err := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := bc.Commit(env); err != nil || !ok {
		t.Fatalf("commit: ok=%v err=%v", ok, err)
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
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2}
	signers, verifier := setupAckKeys(t, parties)

	bc, err := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := bc.Commit(env); err != nil || !ok {
		t.Fatalf("commit: ok=%v err=%v", ok, err)
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

func TestAckCountReturnsCollectedCount(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2, 3}
	signers, verifier := setupAckKeys(t, parties)

	bc, _ := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", parties, verifier)
	if bc.AckCount() != 0 {
		t.Fatalf("AckCount = %d, want 0 after init", bc.AckCount())
	}

	if _, err := bc.Commit(env); err != nil {
		t.Fatal(err)
	}
	// Add one ack
	ack, _ := SignBroadcastAck(env, 1, signers[1])
	if err := bc.AddAck(env, ack); err != nil {
		t.Fatal(err)
	}
	if bc.AckCount() != 1 {
		t.Fatalf("AckCount = %d, want 1", bc.AckCount())
	}

	// Add another
	ack, _ = SignBroadcastAck(env, 2, signers[2])
	if err := bc.AddAck(env, ack); err != nil {
		t.Fatal(err)
	}
	if bc.AckCount() != 2 {
		t.Fatalf("AckCount = %d, want 2", bc.AckCount())
	}
}

func TestNewInMemoryAckSignerAndSignAck(t *testing.T) {
	t.Parallel()
	signer := NewInMemoryAckSigner(5, func(digest [32]byte) ([]byte, error) {
		return append([]byte("sig:"), digest[:4]...), nil
	})
	digest := sha256.Sum256([]byte("test-digest"))
	sig, err := signer.SignAck(digest)
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte("sig:"), digest[:4]...)
	if string(sig) != string(expected) {
		t.Fatalf("SignAck returned %x, want %x", sig, expected)
	}
}

func TestNewInMemoryAckSignerError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("signing failed")
	signer := NewInMemoryAckSigner(1, func(digest [32]byte) ([]byte, error) {
		return nil, wantErr
	})
	_, err := signer.SignAck([32]byte{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

func TestNewInMemoryAckVerifierAndVerifyAck(t *testing.T) {
	t.Parallel()
	verifier := NewInMemoryAckVerifier(func(party PartyID, digest [32]byte, signature []byte) error {
		if party == 1 && string(signature) == "valid-sig" {
			return nil
		}
		return errors.New("invalid")
	})
	// Valid
	if err := verifier.VerifyAck(1, [32]byte{}, []byte("valid-sig")); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Invalid party
	if err := verifier.VerifyAck(2, [32]byte{}, []byte("valid-sig")); err == nil {
		t.Fatal("invalid party should be rejected")
	}
	// Invalid signature
	if err := verifier.VerifyAck(1, [32]byte{}, []byte("bad-sig")); err == nil {
		t.Fatal("invalid signature should be rejected")
	}
}

func TestBroadcastAckCloneReturnsDeepCopy(t *testing.T) {
	t.Parallel()
	ack := BroadcastAck{
		Party:          1,
		PayloadHash:    sha256.Sum256([]byte("ph")),
		TranscriptHash: sha256.Sum256([]byte("th")),
		Signature:      []byte{0x01, 0x02, 0x03},
	}
	clone := ack.Clone()
	clone.Signature[0] = 0xff
	if ack.Signature[0] != 0x01 {
		t.Fatal("Clone shares signature backing array")
	}
	// Party is a uint32 value type, so it is inherently copied by value
	// when Clone() returns a BroadcastAck value.
	_ = clone.Party
}

func TestBroadcastCertificateCloneReturnsDeepCopy(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2}
	signers, _ := setupAckKeys(t, parties)

	var acks []BroadcastAck
	for _, id := range parties {
		ack, _ := SignBroadcastAck(env, id, signers[id])
		acks = append(acks, ack)
	}
	cert, _ := NewBroadcastCertificate(env, parties, acks)
	clone := cert.Clone()
	// Mutate clone
	clone.Acks[0].Signature[0] ^= 0xff
	if cert.Acks[0].Signature[0] == clone.Acks[0].Signature[0] {
		t.Fatal("Clone shares ack signature backing array")
	}
	clone.Recipients[0] = 99
	if cert.Recipients[0] == 99 {
		t.Fatal("Clone shares recipients backing array")
	}
	// Nil clone
	var nilCert *BroadcastCertificate
	if nilCert.Clone() != nil {
		t.Fatal("nil certificate Clone should return nil")
	}
}

func TestVerifyFullWithValidSignatures(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1, 2, 3}
	signers, verifier := setupAckKeys(t, parties)

	var acks []BroadcastAck
	for _, id := range parties {
		ack, _ := SignBroadcastAck(env, id, signers[id])
		acks = append(acks, ack)
	}
	cert, _ := NewBroadcastCertificate(env, parties, acks)
	if err := cert.VerifyFull(env, parties, verifier); err != nil {
		t.Fatalf("VerifyFull should pass: %v", err)
	}
}

func TestVerifyFullRejectsNilVerifier(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1}
	signers, _ := setupAckKeys(t, parties)
	ack, _ := SignBroadcastAck(env, 1, signers[1])
	cert, _ := NewBroadcastCertificate(env, parties, []BroadcastAck{ack})
	if err := cert.VerifyFull(env, parties, nil); err == nil {
		t.Fatal("VerifyFull should reject nil verifier")
	}
}

func TestVerifyFullRejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	parties := PartySet{1}
	signers, verifier := setupAckKeys(t, parties)
	ack, _ := SignBroadcastAck(env, 1, signers[1])
	// Tamper the signature
	ack.Signature[0] ^= 0xff
	cert, err := NewBroadcastCertificate(env, parties, []BroadcastAck{ack})
	// NewBroadcastCertificate only checks structure, not signatures, so it succeeds.
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyFull(env, parties, verifier); err == nil {
		t.Fatal("VerifyFull should reject tampered signature")
	}
}

func TestNewBroadcastConsistencyRejectsNilVerifier(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	_, err := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", PartySet{1}, nil)
	if err == nil {
		t.Fatal("expected error for nil verifier")
	}
}

func TestBroadcastConsistencyAckCountAndCompleteAfterInit(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	_, verifier := setupAckKeys(t, PartySet{1, 2})
	bc, _ := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", PartySet{1, 2}, verifier)
	if bc.Complete() {
		t.Fatal("should not be complete with no acks")
	}
	if bc.AckCount() != 0 {
		t.Fatalf("AckCount = %d, want 0", bc.AckCount())
	}
}

func TestBroadcastConsistencyAddAckRejectsUnknownParty(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	signers, verifier := setupAckKeys(t, PartySet{1, 2, 3})
	bc, _ := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", PartySet{1, 2}, verifier)
	if _, err := bc.Commit(env); err != nil {
		t.Fatal(err)
	}
	ack, _ := SignBroadcastAck(env, 3, signers[3]) // party 3 is NOT a recipient
	if err := bc.AddAck(env, ack); err == nil {
		t.Fatal("should reject ack from non-recipient party")
	}
}

func TestBroadcastConsistencyAddAckRejectsDuplicate(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	signers, verifier := setupAckKeys(t, PartySet{1, 2})
	bc, _ := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", PartySet{1, 2}, verifier)
	if _, err := bc.Commit(env); err != nil {
		t.Fatal(err)
	}
	ack, _ := SignBroadcastAck(env, 1, signers[1])
	if err := bc.AddAck(env, ack); err != nil {
		t.Fatal(err)
	}
	if err := bc.AddAck(env, ack); err == nil {
		t.Fatal("should reject duplicate ack")
	}
}

func TestBroadcastConsistencyCertificateIncomplete(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	signers, verifier := setupAckKeys(t, PartySet{1, 2, 3})
	bc, _ := NewBroadcastConsistency("test", sid, 1, 2, "test.broadcast", PartySet{1, 2, 3}, verifier)
	if _, err := bc.Commit(env); err != nil {
		t.Fatal(err)
	}
	// Only collect one out of three acks
	ack, _ := SignBroadcastAck(env, 1, signers[1])
	if err := bc.AddAck(env, ack); err != nil {
		t.Fatal(err)
	}
	_, err := bc.Certificate()
	if err == nil {
		t.Fatal("Certificate() should fail when acks are incomplete")
	}
}

func TestVerifyBroadcastAckRejectsNilVerifier(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	ack := BroadcastAck{Party: 1}
	if err := VerifyBroadcastAck(env, ack, nil); err == nil {
		t.Fatal("should reject nil verifier")
	}
}

func TestVerifyBroadcastAckRejectsPayloadHashMismatch(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	_, verifier := setupAckKeys(t, PartySet{1})
	ack := BroadcastAck{
		Party:          1,
		PayloadHash:    sha256.Sum256([]byte("wrong")),
		TranscriptHash: env.TranscriptHash,
	}
	if err := VerifyBroadcastAck(env, ack, verifier); err == nil {
		t.Fatal("should reject payload hash mismatch")
	}
}

func TestVerifyBroadcastAckRejectsTranscriptHashMismatch(t *testing.T) {
	t.Parallel()
	sid := testSessionID(t)
	env := testBroadcastEnvelope(t, sid)
	_, verifier := setupAckKeys(t, PartySet{1})
	ack := BroadcastAck{
		Party:          1,
		PayloadHash:    sha256.Sum256(env.Payload),
		TranscriptHash: sha256.Sum256([]byte("wrong-transcript")),
	}
	if err := VerifyBroadcastAck(env, ack, verifier); err == nil {
		t.Fatal("should reject transcript hash mismatch")
	}
}
