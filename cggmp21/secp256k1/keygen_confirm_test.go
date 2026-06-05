//go:build integration

package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestKeygenConfirmationRoundTrip(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	share := shares[1]
	c, err := share.KeygenConfirmation()
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
	shares := secpKeygen(t, 2, 3)
	var confirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, err := shares[id].KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		confirmations = append(confirmations, c)
	}
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err != nil {
		t.Fatal(err)
	}
	if !shares[1].KeygenConfirmed {
		t.Fatal("KeygenConfirmed not set after successful verification")
	}
}

func TestKeygenConfirmationRejectsMismatchedTranscriptHash(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	var confirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, err := shares[id].KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		confirmations = append(confirmations, c)
	}
	// Tamper with party 2's transcript hash.
	confirmations[1].TranscriptHash = bytes.Clone(confirmations[1].TranscriptHash)
	confirmations[1].TranscriptHash[0] ^= 1
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for mismatched transcript hash")
	}
}

func TestKeygenConfirmationRejectsMismatchedPublicKey(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	var confirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, err := shares[id].KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		confirmations = append(confirmations, c)
	}
	confirmations[1].PublicKey = bytes.Clone(confirmations[1].PublicKey)
	confirmations[1].PublicKey[0] ^= 1
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for mismatched public key")
	}
}

func TestKeygenConfirmationRejectsMismatchedCommitmentsHash(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	var confirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, err := shares[id].KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		confirmations = append(confirmations, c)
	}
	confirmations[2].CommitmentsHash = bytes.Clone(confirmations[2].CommitmentsHash)
	confirmations[2].CommitmentsHash[0] ^= 1
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for mismatched commitments hash")
	}
}

func TestKeygenConfirmationRejectsDuplicateSender(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	c1, _ := shares[1].KeygenConfirmation()
	c2, _ := shares[2].KeygenConfirmation()
	// Replace party 3's confirmation with a duplicate of party 2's.
	c3dup, _ := shares[2].KeygenConfirmation()
	confirmations := []*KeygenConfirmation{c1, c2, c3dup}
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for duplicate sender")
	}
}

func TestKeygenConfirmationRejectsMissingSender(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	c1, _ := shares[1].KeygenConfirmation()
	c2, _ := shares[2].KeygenConfirmation()
	// Only 2 confirmations for 3 parties.
	confirmations := []*KeygenConfirmation{c1, c2}
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for missing sender")
	}
}

func TestKeygenConfirmationRejectsUnknownSender(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	c1, _ := shares[1].KeygenConfirmation()
	c2, _ := shares[2].KeygenConfirmation()
	c3, _ := shares[3].KeygenConfirmation()
	// Replace party 3's sender ID with an unknown party.
	c3.Sender = 99
	confirmations := []*KeygenConfirmation{c1, c2, c3}
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for unknown sender")
	}
}

func TestKeygenConfirmationRejectsWrongCount(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	c1, _ := shares[1].KeygenConfirmation()
	confirmations := []*KeygenConfirmation{c1}
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for wrong count")
	}
}

func TestUnconfirmedKeyShareRejectedByRequireMPC(t *testing.T) {
	shares := secpKeygenWithoutConfirmation(t, 2, 3)
	// Shares from secpKeygenWithoutConfirmation are NOT confirmed.
	if err := shares[1].requireMPCMaterial(); err == nil {
		t.Fatal("expected requireMPCMaterial to reject unconfirmed share")
	}
}

func TestConfirmedKeyShareAcceptedByRequireMPC(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	var confirmations []*KeygenConfirmation
	for _, id := range []tss.PartyID{1, 2, 3} {
		c, _ := shares[id].KeygenConfirmation()
		confirmations = append(confirmations, c)
	}
	if err := VerifyKeygenConfirmations(shares[1], confirmations); err != nil {
		t.Fatal(err)
	}
	if err := shares[1].requireMPCMaterial(); err != nil {
		t.Fatalf("requireMPCMaterial rejected confirmed share: %v", err)
	}
}
