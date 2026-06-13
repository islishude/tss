//go:build slowcrypto

package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// useProductionLimits temporarily clears testDefaultLimits so that
// DefaultLimits returns the production fail-closed defaults for the
// duration of the test. Callers must not use t.Parallel because
// testDefaultLimits is a package-level variable.
func useProductionLimits(t *testing.T) {
	t.Helper()
	saved := testDefaultLimits
	testDefaultLimits = nil
	t.Cleanup(func() { testDefaultLimits = saved })
}

// slowFrostKeygen runs a fresh FROST DKG with production limits and no
// fixture cache. It returns the confirmed key shares.
func slowFrostKeygen(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	useProductionLimits(t)

	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*KeygenSession, n)
	var pending []tss.Envelope
	for _, id := range parties {
		kg, out, err := startFROSTKeygen(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		pending = append(pending, out...)
	}

	deliverFROSTKeygenMessages(t, parties, sessions, pending)

	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("party %d keygen did not complete", id)
		}
		shares[id] = share
	}

	return shares
}

// slowFrostKeygenHD runs a fresh HD-enabled FROST DKG with production
// limits and no fixture cache.
func slowFrostKeygenHD(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	useProductionLimits(t)

	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := make(map[tss.PartyID]*KeygenSession, n)
	var pending []tss.Envelope
	for _, id := range parties {
		cfg := tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		}
		kg, out, err := startFROSTKeygenWithOptions(cfg, KeygenOptions{EnableHD: true})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		pending = append(pending, out...)
	}

	deliverFROSTKeygenMessages(t, parties, sessions, pending)

	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("party %d HD keygen did not complete", id)
		}
		shares[id] = share
	}

	return shares
}

// TestSlowCrypto_Keygen3of5 verifies 3-of-5 keygen with production limits.
func TestSlowCrypto_Keygen3of5(t *testing.T) {
	shares := slowFrostKeygen(t, 3, 5)
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}
	// Verify all shares share the same public key.
	pk := shares[1].PublicKeyBytes()
	for i := 2; i <= 5; i++ {
		if !bytes.Equal(pk, shares[tss.PartyID(i)].PublicKeyBytes()) {
			t.Fatalf("party %d public key mismatch", i)
		}
	}
}

// TestSlowCrypto_Sign3of5 verifies 3-of-5 sign with production limits.
func TestSlowCrypto_Sign3of5(t *testing.T) {
	useProductionLimits(t)
	shares := slowFrostKeygen(t, 3, 5)
	signers := []tss.PartyID{1, 3, 5}

	selected := make([]*KeyShare, 0, len(signers))
	for _, id := range signers {
		selected = append(selected, shares[id])
	}
	msg := []byte("slowcrypto frost 3-of-5 production")
	pub, sig, err := Sign(msg, selected)
	if err != nil {
		t.Fatal(err)
	}
	if !stded25519.Verify(stded25519.PublicKey(pub), msg, sig) {
		t.Fatal("signature did not verify with crypto/ed25519")
	}
}

// TestSlowCrypto_Refresh2of3 verifies a 2-of-3 refresh cycle with
// production limits, then signs with the refreshed shares.
func TestSlowCrypto_Refresh2of3(t *testing.T) {
	useProductionLimits(t)
	shares := slowFrostKeygen(t, 2, 3)
	parties := []tss.PartyID{1, 2, 3}

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	oldPubs := make(map[tss.PartyID][]byte, 3)
	for id, share := range shares {
		oldPubs[id] = share.PublicKeyBytes()
	}

	sessions := make(map[tss.PartyID]*ReshareSession, 3)
	var pending []tss.Envelope
	for _, id := range parties {
		cfg := tss.ThresholdConfig{
			Threshold: 2,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		}
		rs, out, err := startFROSTRefresh(shares[id], cfg)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = rs
		pending = append(pending, out...)
	}

	for len(pending) > 0 {
		env := pending[0]
		pending = pending[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleReshareMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			pending = append(pending, out...)
		}
	}

	refreshed := make(map[tss.PartyID]*KeyShare, 3)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("party %d refresh did not complete", id)
		}
		refreshed[id] = share
	}

	// Verify group public key preserved.
	for _, id := range parties {
		if !bytes.Equal(oldPubs[id], refreshed[id].PublicKeyBytes()) {
			t.Fatalf("party %d public key changed after refresh", id)
		}
	}

	// Sign with refreshed shares.
	msg := []byte("slowcrypto frost refresh production")
	signers := []*KeyShare{refreshed[1], refreshed[2]}
	pub, sig, err := Sign(msg, signers)
	if err != nil {
		t.Fatal(err)
	}
	if !stded25519.Verify(stded25519.PublicKey(pub), msg, sig) {
		t.Fatal("refreshed signature did not verify")
	}
}

// TestSlowCrypto_Reshare3of4 verifies a reshare that adds a party
// (2-of-3 → 2-of-4) with production limits.
func TestSlowCrypto_Reshare3of4(t *testing.T) {
	useProductionLimits(t)
	oldShares := slowFrostKeygen(t, 2, 3)
	oldParties := []tss.PartyID{1, 2, 3}
	newParties := []tss.PartyID{1, 2, 3, 4}
	newThreshold := 2
	oldPublicKey := oldShares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	reshareSessions := make(map[tss.PartyID]*ReshareSession, 4)
	var messages []tss.Envelope

	// Old parties act as dealers.
	for _, id := range oldParties {
		cfg := tss.ThresholdConfig{
			Threshold: newThreshold,
			Parties:   oldParties,
			Self:      id,
			SessionID: sessionID,
		}
		session, out, err := startFROSTReshare(oldShares[id], newParties, newThreshold, cfg)
		if err != nil {
			t.Fatal(err)
		}
		reshareSessions[id] = session
		messages = append(messages, out...)
	}

	// Party 4 is a recipient-only.
	recipient, err := startFROSTReshareRecipient(oldPublicKey, nil, oldParties, newParties, newThreshold, tss.ThresholdConfig{
		Threshold: newThreshold,
		Parties:   newParties,
		Self:      4,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	reshareSessions[4] = recipient

	deliverReshareMessages(t, newParties, messages, reshareSessions)
	newShares := collectReshareShares(t, newParties, reshareSessions)

	// Verify group public key preserved.
	if !bytes.Equal(oldPublicKey, newShares[1].PublicKeyBytes()) {
		t.Fatal("group public key changed after reshare")
	}

	// All 4 new parties can sign (need 2-of-4).
	msg := []byte("slowcrypto frost reshare production")
	pub, sig, err := Sign(msg, []*KeyShare{newShares[1], newShares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if !stded25519.Verify(stded25519.PublicKey(pub), msg, sig) {
		t.Fatal("reshared signature did not verify")
	}
}

// TestSlowCrypto_HDDeriveAndSign verifies BIP32 HD derivation and
// signing with production limits.
func TestSlowCrypto_HDDeriveAndSign(t *testing.T) {
	useProductionLimits(t)
	shares := slowFrostKeygenHD(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	path := []uint32{0, 17}

	// Derive child public key.
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), path)
	if err != nil {
		t.Fatal(err)
	}
	derivedPub := result.ChildPublicKey

	// Sign with additive shift.
	selected := make([]*KeyShare, 0, len(signers))
	for _, id := range signers {
		selected = append(selected, shares[id])
	}
	msg := []byte("slowcrypto frost hd production")
	pub, sig, err := SignWithOptions(msg, selected, SignOptions{AdditiveShift: result.AdditiveShift})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, derivedPub) {
		t.Fatal("HD signing returned wrong derived public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(derivedPub), msg, sig) {
		t.Fatal("HD-derived signature did not verify")
	}

	// Sanity check: signature must not verify against the original key.
	if stded25519.Verify(stded25519.PublicKey(shares[1].PublicKeyBytes()), msg, sig) {
		t.Fatal("HD-derived signature incorrectly verified against parent key")
	}
}
