//go:build integration

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestKeygenConfirmationRoundTrip(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	share := shares[1]
	c, err := share.KeygenConfirmationWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeygenConfirmation(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatal("confirmation did not remarshal deterministically")
	}
	if _, err := UnmarshalKeygenConfirmation(append(raw, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}

func TestKeygenConfirmationAcceptsMatching(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	var confirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, err := shares[id].KeygenConfirmationWithLimits(testLimits())
		if err != nil {
			t.Fatal(err)
		}
		confirmations = append(confirmations, c)
	}
	if err := applyKeygenConfirmationSet(shares[1], confirmations, testLimits()); err != nil {
		t.Fatal(err)
	}
	if len(shares[1].KeygenConfirmations()) != len(confirmations) {
		t.Fatal("confirmation evidence not stored after successful verification")
	}
	if err := shares[1].ValidateWithLimits(testLimits()); err != nil {
		t.Fatalf("confirmed share did not validate: %v", err)
	}
}

// TestKeygenConfirmationRejectsTamperedFields verifies that a confirmation
// with a mismatched transcript hash, public key, or commitments hash is rejected.
func TestKeygenConfirmationRejectsTamperedFields(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	var baseConfirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, err := shares[id].KeygenConfirmationWithLimits(testLimits())
		if err != nil {
			t.Fatal(err)
		}
		baseConfirmations = append(baseConfirmations, c)
	}

	tests := []struct {
		name     string
		tamperAt int // index into confirmations slice
		mutate   func(c *KeygenConfirmation)
	}{
		{
			name:     "mismatched transcript hash",
			tamperAt: 1,
			mutate:   func(c *KeygenConfirmation) { c.TranscriptHash[0] ^= 1 },
		},
		{
			name:     "mismatched public key",
			tamperAt: 1,
			mutate:   func(c *KeygenConfirmation) { c.PublicKey[0] ^= 1 },
		},
		{
			name:     "mismatched commitments hash",
			tamperAt: 2,
			mutate:   func(c *KeygenConfirmation) { c.CommitmentsHash[0] ^= 1 },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			confirmations := make([]*KeygenConfirmation, len(baseConfirmations))
			for i, c := range baseConfirmations {
				clone := *c
				clone.TranscriptHash = bytes.Clone(c.TranscriptHash)
				clone.PublicKey = bytes.Clone(c.PublicKey)
				clone.CommitmentsHash = bytes.Clone(c.CommitmentsHash)
				confirmations[i] = &clone
			}
			tc.mutate(confirmations[tc.tamperAt])
			if err := applyKeygenConfirmationSet(shares[1], confirmations, testLimits()); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

// TestKeygenConfirmationRejectsInvalidSenderSets verifies that confirmation
// sets with duplicate, missing, unknown, or wrong-count senders are rejected.
func TestKeygenConfirmationRejectsInvalidSenderSets(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)

	tests := []struct {
		name          string
		confirmations func(t *testing.T) []*KeygenConfirmation
	}{
		{
			name: "duplicate sender",
			confirmations: func(t *testing.T) []*KeygenConfirmation {
				c1, _ := shares[1].KeygenConfirmationWithLimits(testLimits())
				c2, _ := shares[2].KeygenConfirmationWithLimits(testLimits())
				c3dup, _ := shares[2].KeygenConfirmationWithLimits(testLimits())
				return []*KeygenConfirmation{c1, c2, c3dup}
			},
		},
		{
			name: "missing sender",
			confirmations: func(t *testing.T) []*KeygenConfirmation {
				c1, _ := shares[1].KeygenConfirmationWithLimits(testLimits())
				c2, _ := shares[2].KeygenConfirmationWithLimits(testLimits())
				return []*KeygenConfirmation{c1, c2}
			},
		},
		{
			name: "unknown sender",
			confirmations: func(t *testing.T) []*KeygenConfirmation {
				c1, _ := shares[1].KeygenConfirmationWithLimits(testLimits())
				c2, _ := shares[2].KeygenConfirmationWithLimits(testLimits())
				c3, _ := shares[3].KeygenConfirmationWithLimits(testLimits())
				c3.Sender = 99
				return []*KeygenConfirmation{c1, c2, c3}
			},
		},
		{
			name: "wrong count",
			confirmations: func(t *testing.T) []*KeygenConfirmation {
				c1, _ := shares[1].KeygenConfirmationWithLimits(testLimits())
				return []*KeygenConfirmation{c1}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			confirmations := tc.confirmations(t)
			if err := applyKeygenConfirmationSet(shares[1], confirmations, testLimits()); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestUnconfirmedKeyShareRejectedByRequireMPC(t *testing.T) {
	t.Parallel()
	shares := secpKeygenWithoutConfirmation(t, 2, 3)
	// Shares from secpKeygenWithoutConfirmation are NOT confirmed.
	if err := shares[1].requireMPCMaterial(testLimits()); err == nil {
		t.Fatal("expected requireMPCMaterial to reject unconfirmed share")
	}
}

func TestUnconfirmedKeyShareValidateAndMarshalReject(t *testing.T) {
	t.Parallel()
	shares := secpKeygenWithoutConfirmation(t, 2, 3)
	if err := shares[1].ValidateWithLimits(testLimits()); err == nil {
		t.Fatal("expected Validate to reject unconfirmed share")
	}
	if _, err := shares[1].MarshalBinary(); err == nil {
		t.Fatal("expected MarshalBinary to reject unconfirmed share")
	}
}

func TestConfirmedKeyShareAcceptedByRequireMPC(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3, false)
	if err := shares[1].requireMPCMaterial(testLimits()); err != nil {
		t.Fatalf("requireMPCMaterial rejected confirmed share: %v", err)
	}
}

func TestKeygenSessionRejectsConflictingConfirmation(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2, 3}
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}

	confirmations := make([]tss.Envelope, 0, len(parties))
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleKeygenMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			for _, produced := range out {
				if produced.PayloadType == payloadKeygenConfirmation {
					confirmations = append(confirmations, produced)
				}
			}
		}
	}

	var fromParty2 tss.Envelope
	for _, env := range confirmations {
		if env.From == 2 {
			fromParty2 = env
			break
		}
	}
	if fromParty2.PayloadType == "" {
		t.Fatal("missing confirmation from party 2")
	}
	if _, err := sessions[1].HandleKeygenMessage(testutil.DeliverEnvelope(fromParty2)); err != nil {
		t.Fatal(err)
	}
	if share, ok := sessions[1].KeyShare(); ok || share != nil {
		t.Fatal("session completed before all confirmations arrived")
	}

	conflicting := fromParty2
	decoded, err := UnmarshalKeygenConfirmation(conflicting.Payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded.TranscriptHash = bytes.Clone(decoded.TranscriptHash)
	decoded.TranscriptHash[0] ^= 1
	conflicting.Payload, err = decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = sessions[1].HandleKeygenMessage(testutil.DeliverEnvelope(conflicting))
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if share, ok := sessions[1].KeyShare(); ok || share != nil {
		t.Fatal("aborted session returned a key share")
	}
}
