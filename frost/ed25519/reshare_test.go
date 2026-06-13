package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"strings"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestReshareHDChainCodePreservedForNewRecipient(t *testing.T) {
	t.Parallel()
	oldShares := frostKeygenHD(t, 2, 3)
	oldParties := []tss.PartyID{1, 2, 3}
	newParties := []tss.PartyID{2, 3, 4}
	newThreshold := 2
	oldPublicKey := oldShares[1].PublicKeyBytes()
	oldChainCode := append([]byte(nil), oldShares[1].state.chainCode...)

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	reshareSessions := make(map[tss.PartyID]*ReshareSession, 4)
	messages := make([]tss.Envelope, 0)
	for _, id := range oldParties {
		session, out, err := startFROSTReshare(oldShares[id], newParties, newThreshold, tss.ThresholdConfig{
			Threshold: newThreshold,
			Parties:   oldParties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		reshareSessions[id] = session
		messages = append(messages, out...)
	}

	recipient, err := startFROSTReshareRecipient(oldPublicKey, oldChainCode, oldParties, newParties, newThreshold, tss.ThresholdConfig{
		Threshold: newThreshold,
		Parties:   oldParties,
		Self:      4,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	reshareSessions[4] = recipient

	deliverReshareMessages(t, []tss.PartyID{1, 2, 3, 4}, messages, reshareSessions)
	newShares := collectReshareShares(t, newParties, reshareSessions)

	for _, id := range newParties {
		if !bytes.Equal(newShares[id].state.chainCode, oldChainCode) {
			t.Fatalf("party %d chain code was not preserved", id)
		}
		if err := newShares[id].ValidateConsistency(); err != nil {
			t.Fatalf("party %d invalid reshared key: %v", id, err)
		}
	}

	path := []uint32{0, 1, 2}
	r2, err := DeriveNonHardenedBIP32(newShares[2].state.publicKey, newShares[2].state.chainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	r4, err := DeriveNonHardenedBIP32(newShares[4].state.publicKey, newShares[4].state.chainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r2.ChildPublicKey, r4.ChildPublicKey) || !bytes.Equal(r2.AdditiveShift, r4.AdditiveShift) || !bytes.Equal(r2.ChildChainCode, r4.ChildChainCode) {
		t.Fatal("HD derivation diverged across reshared recipients")
	}

	message := []byte("HD reshare recipient signing")
	pub, sig, err := SignWithOptions(message, []*KeyShare{newShares[2], newShares[4]}, SignOptions{AdditiveShift: r2.AdditiveShift})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, r2.ChildPublicKey) {
		t.Fatal("HD signing returned the wrong derived public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(r2.ChildPublicKey), message, sig) {
		t.Fatal("HD reshared signature failed verification")
	}
}

func TestStartRefreshRequiresMatchingSelf(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = startFROSTRefresh(shares[1], tss.ThresholdConfig{
		Threshold: 2,
		Parties:   []tss.PartyID{1, 2},
		Self:      2,
		SessionID: sessionID,
	})
	if err == nil || !strings.Contains(err.Error(), "config.Self") {
		t.Fatalf("expected config.Self mismatch rejection, got %v", err)
	}
}

func TestStartReshareValidatesNewParticipantSet(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := tss.ThresholdConfig{
		Threshold: 2,
		Parties:   []tss.PartyID{1, 2, 3},
		Self:      1,
		SessionID: sessionID,
	}

	for _, tc := range []struct {
		name       string
		newParties []tss.PartyID
	}{
		{name: "zero party", newParties: []tss.PartyID{0, 1, 2}},
		{name: "duplicate party", newParties: []tss.PartyID{1, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			session, out, err := startFROSTReshare(shares[1], tc.newParties, 2, config)
			if err == nil || !strings.Contains(err.Error(), "invalid new participant set") {
				t.Fatalf("expected invalid new participant set rejection, got %v", err)
			}
			if session != nil || out != nil {
				t.Fatal("invalid reshare target produced session or outbound messages")
			}
		})
	}
}

func TestStartReshareRejectsProductionOneOfOneTarget(t *testing.T) {
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := testDefaultLimits
	testDefaultLimits = nil
	defer func() { testDefaultLimits = saved }()

	session, out, err := startFROSTReshare(shares[1], []tss.PartyID{1}, 1, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   []tss.PartyID{1, 2},
		Self:      1,
		SessionID: sessionID,
	})
	if err == nil || !strings.Contains(err.Error(), "below production minimum") {
		t.Fatalf("expected production threshold rejection, got %v", err)
	}
	if session != nil || out != nil {
		t.Fatal("invalid production reshare target produced session or outbound messages")
	}
}

func TestStartReshareRecipientValidatesAgainstNewParties(t *testing.T) {
	t.Parallel()
	oldShares := frostKeygen(t, 2, 3)
	oldParties := []tss.PartyID{1, 2, 3}
	newParties := []tss.PartyID{2, 3, 4}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, oldParties, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   oldParties,
		Self:      4,
		SessionID: sessionID,
	}); err != nil {
		t.Fatalf("recipient with config.Parties=oldParties should succeed: %v", err)
	}

	if _, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, oldParties, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      4,
		SessionID: sessionID,
	}); err != nil {
		t.Fatalf("recipient with config.Parties=newParties should succeed: %v", err)
	}

	if _, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, oldParties, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      5,
		SessionID: sessionID,
	}); err == nil || !strings.Contains(err.Error(), "recipient must be in the new participant set") {
		t.Fatalf("expected self-not-in-newParties failure, got %v", err)
	}

	if _, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, oldParties, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      2,
		SessionID: sessionID,
	}); err == nil || !strings.Contains(err.Error(), "use StartReshare") {
		t.Fatalf("expected old-party recipient failure, got %v", err)
	}

	if _, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, []tss.PartyID{1, 1, 2}, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      4,
		SessionID: sessionID,
	}); err == nil || !strings.Contains(err.Error(), "invalid old participant set") {
		t.Fatalf("expected duplicate old-party failure, got %v", err)
	}

	if _, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, []tss.PartyID{0, 1, 2}, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      4,
		SessionID: sessionID,
	}); err == nil || !strings.Contains(err.Error(), "invalid old participant set") {
		t.Fatalf("expected zero old-party failure, got %v", err)
	}
}

func TestReshareNewRecipientBindsGuard(t *testing.T) {
	t.Parallel()
	oldShares := frostKeygen(t, 2, 3)
	oldParties := []tss.PartyID{1, 2, 3}
	newParties := []tss.PartyID{2, 3, 4}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := startFROSTReshareRecipient(oldShares[1].state.publicKey, nil, oldParties, newParties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   newParties,
		Self:      4,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	guard := recipient.Guard()
	if guard.Self != 4 {
		t.Fatalf("guard self = %d, want 4", guard.Self)
	}
}

func TestReshareVerificationErrorAbortsSession(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	session, _, err := startFROSTReshare(shares[1], parties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTReshare(shares[2], parties, 2, tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleReshareMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}

	payload, err := unmarshalReshareSharePayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := edcurve.ScalarFromCanonical(payload.Share)
	if err != nil {
		t.Fatal(err)
	}
	badShare := edcurve.ScalarOne().Add(edcurve.ScalarOne(), scalar)
	badShareBytes := badShare.Bytes()
	badPayload, err := marshalReshareSharePayload(reshareSharePayload{Share: badShareBytes})
	if err != nil {
		t.Fatal(err)
	}
	bad := out2[1]
	bad.Payload = badPayload
	bad = bad.RecomputeTranscriptHash()

	_, err = session.HandleReshareMessage(testutil.DeliverEnvelope(bad))
	_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
	if !session.aborted {
		t.Fatal("verification error did not abort reshare session")
	}
	if len(session.shares) != 0 {
		t.Fatal("aborted reshare session retained share references")
	}

	_, err = session.HandleReshareMessage(testutil.DeliverEnvelope(out2[1]))
	if err == nil || !strings.Contains(err.Error(), "reshare session is aborted") {
		t.Fatalf("expected terminal aborted error, got %v", err)
	}
}

func TestReshareCompletionClearsIntermediateShares(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 1, 1)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := startFROSTRefresh(shares[1], tss.ThresholdConfig{
		Threshold: 1,
		Parties:   []tss.PartyID{1},
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || len(out[0].Payload) == 0 {
		t.Fatal("refresh completion cleared caller-owned outbound payload")
	}
	if !session.completed {
		t.Fatal("single-party refresh did not complete")
	}
	if len(session.shares) != 0 {
		t.Fatal("completed reshare retained intermediate share scalars")
	}
}
