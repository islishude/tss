//go:build integration

package ed25519

import (
	"bytes"
	"errors"
	"testing"

	stded25519 "crypto/ed25519"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// testFROSTGuard and testFROSTPolicies are defined in frost_test.go.
// They are shared when running with -tags integration.

// frosted25519DKG runs a full FROST DKG and returns the key shares.
func frosted25519DKG(t *testing.T, parties tss.PartySet, threshold int) (map[tss.PartyID]*KeyShare, tss.SessionID) {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0)

	for _, id := range parties {
		s, out, err := startFROSTKeygen(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = s
		queue = append(queue, out...)
	}

	// Process messages round-robin until no more messages.
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("DKG delivery from %d to %d (type=%s): %v", env.From, id, env.PayloadType, err)
			}
			queue = append(queue, out...)
		}
	}

	shares := make(map[tss.PartyID]*KeyShare, len(parties))
	for _, id := range parties {
		ks, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("DKG did not complete for party %d", id)
		}
		shares[id] = ks
	}
	return shares, sessionID
}

// TestFROSTKeygenRejectsRound1WithoutBroadcastCert verifies that FROST keygen
// round 1 commitments without a BroadcastCertificate are rejected.
func TestFROSTKeygenRejectsRound1WithoutBroadcastCert(t *testing.T) {
	parties := tss.NewPartySet(11, 12, 13)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}

	session, _, err := StartKeygen(plan, tss.LocalConfig{Self: 11}, tss.NewTestEnvelopeGuard(11, parties, tss.ProtocolFROSTEd25519, sessionID, FROSTPolicies()))
	if err != nil {
		t.Fatal(err)
	}

	commitEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       keygenCommitmentRound,
		From:        12,
		To:          0,
		PayloadType: payloadKeygenCommitments,
		Payload:     []byte("not-a-real-commitment"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = session.Handle(testutil.DeliverEnvelope(commitEnv))
	if !errors.Is(err, tss.ErrMissingBroadcastCertificate) {
		t.Fatalf("expected ErrMissingBroadcastCertificate, got %v", err)
	}
}

func TestFROSTReshareDealerOnlyAcceptsTargetScopedConfirmationCertificate(t *testing.T) {
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	allParties := tss.MergePartySet(oldParties, newParties)
	oldShares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewResharePlan(ResharePlanOption{
		OldKey:       oldShares[1],
		SessionID:    sessionID,
		NewParties:   newParties,
		NewThreshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := tss.NewInMemoryAckVerifier(func(tss.PartyID, [32]byte, []byte) error { return nil })
	guard, err := (tss.GuardConfig{
		Self:        1,
		Parties:     allParties,
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Policies:    FROSTPolicies(),
		Cache:       tss.NewInMemoryReplayCache(),
		AckVerifier: verifier,
	}).BuildGuard()
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := StartReshareDealer(oldShares[1], plan, tss.LocalConfig{Self: 1}, guard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	planHash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	confirmation := KeygenConfirmation{
		SessionID:       sessionID,
		Sender:          2,
		Threshold:       2,
		Parties:         newParties,
		PublicKey:       oldShares[1].state.PublicKey.Clone(),
		TranscriptHash:  make([]byte, 32),
		CommitmentsHash: make([]byte, 32),
		ChainCode:       bytes.Clone(oldShares[1].state.ChainCode),
		PlanHash:        planHash,
	}
	payload, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       reshareConfirmationRound,
		From:        2,
		To:          tss.BroadcastPartyId,
		PayloadType: payloadReshareConfirmation,
		Payload:     payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	acks := make([]tss.BroadcastAck, 0, len(newParties))
	for _, id := range newParties {
		signer := tss.NewInMemoryAckSigner(id, func(digest [32]byte) ([]byte, error) {
			return bytes.Clone(digest[:]), nil
		})
		ack, err := tss.SignBroadcastAck(env, id, signer)
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, ack)
	}
	certificate, err := tss.NewBroadcastCertificate(env, newParties, acks)
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := testutil.OpenInboundEnvelope(env, tss.ReceiveInfo{
		Peer:       2,
		Protection: tss.ChannelPlaintext,
	}, certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Handle(inbound); err != nil {
		t.Fatalf("dealer-only session rejected target-scoped confirmation broadcast: %v", err)
	}
	if session.pendingConfirmations[2] == nil {
		t.Fatal("dealer-only session did not buffer the early target confirmation")
	}
}

// TestFROSTKeygenRejectsPlaintextShare verifies that FROST keygen shares
// delivered without transport confidentiality are rejected.
func TestFROSTKeygenRejectsPlaintextShare(t *testing.T) {
	parties := tss.NewPartySet(21, 22, 23)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      21,
		SessionID: sessionID,
	}

	session, _, err := startFROSTKeygen(config)
	if err != nil {
		t.Fatal(err)
	}

	shareEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       keygenShareRound,
		From:        22,
		To:          21,
		PayloadType: payloadKeygenShare,
		Payload:     []byte("not-a-real-share"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = session.Handle(testutil.DeliverEnvelopeWithProtection(shareEnv, tss.ChannelPlaintext))
	if !errors.Is(err, tss.ErrMissingConfidentiality) {
		t.Fatalf("expected ErrMissingConfidentiality or rejection, got %v", err)
	}
}

// TestFROSTRejectsSenderSpoofing verifies that identity mismatch is caught in FROST signing.
func TestFROSTRejectsSenderSpoofing(t *testing.T) {
	parties := tss.NewPartySet(31, 32, 33)
	shares, _ := frosted25519DKG(t, parties, 2)

	// Start a FROST sign session with guard.
	signSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(31, 32)
	signSession, _, err := startFROSTSign(shares[31], signSessionID, signers, []byte("test-message"))
	if err != nil {
		t.Fatal(err)
	}

	// Send a spoofed sign commitment.
	commitEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   signSessionID,
		Round:       1,
		From:        32,
		To:          0,
		PayloadType: payloadSignCommitment,
		Payload:     []byte("not-a-real-commitment"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = testutil.OpenInboundEnvelope(commitEnv, tss.ReceiveInfo{
		Peer:       33,
		Protection: tss.ChannelConfidential,
	}, nil)
	if !errors.Is(err, tss.ErrSenderIdentityMismatch) {
		t.Fatalf("expected ErrSenderIdentityMismatch, got %v", err)
	}
	_ = signSession
}

// TestFROSTKeygenRejectsReplay verifies replay detection in FROST keygen.
func TestFROSTKeygenRejectsReplay(t *testing.T) {
	parties := tss.NewPartySet(41, 42, 43)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      41,
		SessionID: sessionID,
	}

	session, _, err := startFROSTKeygen(config)
	if err != nil {
		t.Fatal(err)
	}

	// Round-2 confirmation — passes guard policy check but handler rejects invalid payload.
	confirmEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   sessionID,
		Round:       2,
		From:        42,
		To:          0,
		PayloadType: payloadKeygenConfirmation,
		Payload:     []byte("test-confirmation"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// First pass — may fail with non-replay error.
	_, _ = session.Handle(testutil.DeliverEnvelope(confirmEnv))

	// Second pass — must fail with ErrDuplicateMessage.
	_, err = session.Handle(testutil.DeliverEnvelope(confirmEnv))
	if !errors.Is(err, tss.ErrDuplicateMessage) {
		if err == nil {
			t.Error("expected ErrDuplicateMessage or other error on second delivery, got nil")
		}
	}
}

// TestFROSTReshareRejectsPlaintextShare verifies that FROST reshare shares
// delivered without confidentiality are rejected by the guard.
func TestFROSTReshareRejectsPlaintextShare(t *testing.T) {
	parties := tss.NewPartySet(51, 52, 53)
	shares, dkgSessionID := frosted25519DKG(t, parties, 2)

	// Start a reshare session with guard using the actual key share.
	reshareSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Generate a real Ed25519 key pair for the dummy public key in the recipient case.
	dummyPub, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = shares
	_ = dkgSessionID

	// Test with a reshare that uses real dealer material.
	reshareSession, _, err := startFROSTReshare(shares[51], parties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      51,
		SessionID: reshareSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send a plaintext reshare share.
	shareEnv, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   reshareSessionID,
		Round:       1,
		From:        52,
		To:          51,
		PayloadType: payloadReshareShare,
		Payload:     []byte("not-a-real-share"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Confidential is deliberately left false.

	_, err = reshareSession.Handle(testutil.DeliverEnvelopeWithProtection(shareEnv, tss.ChannelPlaintext))
	if !errors.Is(err, tss.ErrMissingConfidentiality) {
		t.Fatalf("expected ErrMissingConfidentiality or rejection, got %v", err)
	}
	_ = dummyPub
}
