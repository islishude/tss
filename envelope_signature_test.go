package tss

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

type ed25519EnvelopeSigner struct {
	private ed25519.PrivateKey
}

func (s ed25519EnvelopeSigner) SignEnvelopeDigest(digest [32]byte) ([]byte, error) {
	return ed25519.Sign(s.private, digest[:]), nil
}

type ed25519EnvelopeVerifier struct {
	keys map[PartyID]ed25519.PublicKey
}

func (v ed25519EnvelopeVerifier) VerifyEnvelopeSignature(party PartyID, digest [32]byte, signature []byte) error {
	public, ok := v.keys[party]
	if !ok || !ed25519.Verify(public, digest[:], signature) {
		return errors.New("invalid Ed25519 signature")
	}
	return nil
}

func TestEnvelopeSenderSignatureBindsCanonicalSlotAndPayload(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := testSessionID(t)
	env, err := NewEnvelope(EnvelopeInput{
		Protocol: "test-proto", SessionID: session, Round: 1, From: 2, To: 1,
		PayloadType: "test.direct.signed", Payload: []byte("payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEnvelope(env, ed25519EnvelopeSigner{private: private})
	if err != nil {
		t.Fatal(err)
	}
	verifier := ed25519EnvelopeVerifier{keys: map[PartyID]ed25519.PublicKey{2: public}}
	if err := VerifyEnvelopeSignature(signed, verifier); err != nil {
		t.Fatal(err)
	}

	mutations := []func(*Envelope){
		func(e *Envelope) { e.Protocol = "other" },
		func(e *Envelope) { e.SessionID[0] ^= 1 },
		func(e *Envelope) { e.Round++ },
		func(e *Envelope) { e.From = 3 },
		func(e *Envelope) { e.To = 3 },
		func(e *Envelope) { e.PayloadType = "other" },
		func(e *Envelope) { e.Payload[0] ^= 1 },
	}
	for i, mutate := range mutations {
		candidate := signed.Clone()
		mutate(&candidate)
		if err := VerifyEnvelopeSignature(candidate, verifier); err == nil {
			t.Fatalf("mutation %d retained a valid sender signature", i)
		}
	}
}

func TestEnvelopeGuardRequiresPortableSignatureBeforeReplayMutation(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := testSessionID(t)
	policies := MustNewPolicySet(DeliveryPolicy{
		Protocol: "test-proto", Round: 1, PayloadType: "test.direct.signed",
		Mode: DeliveryDirect, Confidentiality: ConfidentialityForbidden,
		BroadcastConsistency: BroadcastConsistencyNone, RequireSenderSignature: true,
	})
	guard, err := NewEnvelopeGuard(1, PartySet{1, 2}, "test-proto", session, policies, NewInMemoryReplayCache())
	if err != nil {
		t.Fatal(err)
	}
	guard.EnvelopeVerifier = ed25519EnvelopeVerifier{keys: map[PartyID]ed25519.PublicKey{2: public}}
	env, err := NewEnvelope(EnvelopeInput{
		Protocol: "test-proto", SessionID: session, Round: 1, From: 2, To: 1,
		PayloadType: "test.direct.signed", Payload: []byte("payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := InboundEnvelope{env: env, receiveInfo: ReceiveInfo{Peer: 2, Protection: ChannelPlaintext}}
	if err := guard.Validate(inbound); !errors.Is(err, ErrMissingEnvelopeSignature) {
		t.Fatalf("unsigned Validate error = %v", err)
	}
	if got := guardReplayCacheEntries(t, guard); got != 0 {
		t.Fatalf("unsigned envelope mutated %d replay entries", got)
	}
	signed, err := SignEnvelope(env, ed25519EnvelopeSigner{private: private})
	if err != nil {
		t.Fatal(err)
	}
	inbound.env = signed
	if err := guard.Validate(inbound); err != nil {
		t.Fatal(err)
	}
}
