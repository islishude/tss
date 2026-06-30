//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

// runRefresh starts refresh sessions for all parties, delivers messages, and
// returns the completed sessions.
func runRefresh(t *testing.T, shares map[tss.PartyID]*KeyShare, parties tss.PartySet, sessionID tss.SessionID) map[tss.PartyID]*RefreshSession {
	t.Helper()
	sessions := make(map[tss.PartyID]*RefreshSession)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := startCGGMP21Refresh(shares[id], tss.ThresholdConfig{Threshold: shares[id].Threshold(), Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("refresh did not complete for party %d", id)
		}
		if err := validateKeySharePartyDataSet(share, parties); err != nil {
			t.Fatalf("refresh party %d: %v", id, err)
		}
	}
	return sessions
}

func TestThresholdECDSAProactiveRefresh1of1(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 1, 1)
	oldPub := mustKeySharePublicKey(t, shares[1])

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := tss.ThresholdConfig{Threshold: 1, Self: 1, SessionID: sessionID}
	session, out, err := startCGGMP21Refresh(shares[1], config)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range out {
		if _, err := session.Handle(testutil.DeliverEnvelope(env)); err != nil {
			if !strings.Contains(err.Error(), "already completed") {
				t.Fatal(err)
			}
		}
	}
	newShare, ok := session.KeyShare()
	if !ok {
		t.Fatal("refresh did not complete")
	}
	if err := newShare.ValidateWithLimits(testLimits()); err != nil {
		t.Fatal(err)
	}
	if err := validateKeySharePartyDataSet(newShare, tss.NewPartySet(1)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldPub, mustKeySharePublicKey(t, newShare)) {
		t.Fatal("public key changed after refresh")
	}
	if !bytes.Equal(mustKeyShareChainCode(t, shares[1]), mustKeyShareChainCode(t, newShare)) {
		t.Fatal("chain code changed after refresh")
	}
	digest := sha256.Sum256([]byte("refresh 1-of-1"))
	pub, sig, err := SignDigest(digest[:], []*KeyShare{newShare})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after refresh did not verify")
	}
	if !bytes.Equal(oldPub, pub) {
		t.Fatal("public key from signing differs from original")
	}
}

func TestThresholdECDSARefreshInvalidShareCarriesEvidence(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	session, _, err := startCGGMP21Refresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startCGGMP21Refresh(shares[2], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalRefreshSharePayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	shareScalar, err := secpScalarFromSecret(payload.Share)
	if err != nil {
		t.Fatal(err)
	}
	badScalar := secp.ScalarAdd(shareScalar, secp.ScalarOne())
	if badScalar.IsZero() {
		badScalar = secp.ScalarOne()
	}
	badShare, err := secpSecretScalarFromScalar(badScalar)
	if err != nil {
		t.Fatal(err)
	}
	out2[1].Payload, err = (refreshSharePayload{Share: badShare, PlanHash: payload.PlanHash}).MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Handle(testutil.DeliverEnvelope(out2[1]))
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSARefreshRejectsMismatchedSelf(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = startCGGMP21Refresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
	if err == nil || !strings.Contains(err.Error(), "local self") {
		t.Fatalf("expected local self mismatch rejection, got %v", err)
	}
}

func TestThresholdECDSARefreshRejectsNonzeroConstantCommitment(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := startCGGMP21Refresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startCGGMP21Refresh(shares[2], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalRefreshCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Commitments[0], err = secp.PointBytes(secp.G)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload, err = testutil.RewriteWireFieldByName(
		out2[0].Payload,
		refreshCommitmentsPayloadWireType,
		refreshCommitmentsPayload{},
		"Commitments",
		wire.EncodeBytesList(payload.Commitments),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Handle(testutil.DeliverEnvelope(out2[0]))
	if err == nil || !strings.Contains(err.Error(), "constant commitment") {
		t.Fatalf("expected nonzero constant commitment rejection, got %v", err)
	}
}

func TestThresholdECDSARefreshValidationBindsPreservedChainCode(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	parties := tss.NewPartySet(1, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := runRefresh(t, shares, parties, sessionID)
	share, ok := sessions[1].KeyShare()
	if !ok {
		t.Fatal("refresh did not produce party 1 key share")
	}
	share.state.ChainCode[0] ^= 1
	if err := share.ValidateWithLimits(testLimits()); err == nil {
		t.Fatal("Validate accepted refreshed share with tampered preserved chain code")
	}
}

// TestThresholdECDSAProactiveRefreshScenarios verifies multi-party proactive
// refresh preserves the group public key and HD chain code.
func TestThresholdECDSAProactiveRefreshScenarios(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		n         int
		signers   tss.PartySet
	}{
		{name: "2-of-3 preserves chain code", threshold: 2, n: 3, signers: tss.NewPartySet(1, 3)},
		{name: "2-of-2 preserves chain code", threshold: 2, n: 2, signers: tss.NewPartySet(1, 2)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shares := CachedKeygenShares(t, tc.threshold, tc.n)
			oldPub := mustKeySharePublicKey(t, shares[1])

			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			parties := testutil.MustPartySet(tc.n)

			sessions := runRefresh(t, shares, parties, sessionID)

			newShares := make(map[tss.PartyID]*KeyShare)
			for _, id := range parties {
				share, ok := sessions[id].KeyShare()
				if !ok {
					t.Fatalf("refresh not complete for %d", id)
				}
				newShares[id] = share
				if !bytes.Equal(oldPub, mustKeySharePublicKey(t, share)) {
					t.Fatalf("party %d public key changed after refresh", id)
				}
				if len(mustKeyShareChainCode(t, share)) != 32 {
					t.Fatalf("party %d missing chain code after refresh", id)
				}
				if !bytes.Equal(mustKeyShareChainCode(t, shares[id]), mustKeyShareChainCode(t, share)) {
					t.Fatalf("party %d chain code changed after refresh", id)
				}
			}
			for _, id := range parties {
				if err := newShares[id].ValidateWithLimits(testLimits()); err != nil {
					t.Fatal(err)
				}
			}
			signerShares := make([]*KeyShare, 0, len(tc.signers))
			for _, id := range tc.signers {
				signerShares = append(signerShares, newShares[id])
			}
			digest := sha256.Sum256([]byte("refresh " + tc.name))
			pub, sig, err := SignDigest(digest[:], signerShares)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyDigest(pub, digest[:], sig) {
				t.Fatal("signature after refresh did not verify")
			}
		})
	}
}
