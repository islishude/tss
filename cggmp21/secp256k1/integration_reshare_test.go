//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"math/big"
	"testing"
)

func TestThresholdECDSAReshareInvalidShareCarriesEvidence(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	plan, err := NewResharePlan(shares[1], sessionID, parties, parties, 2, SecurityParameters{})
	if err != nil {
		t.Fatal(err)
	}
	session, out1, err := StartReshareOverlap(shares[1], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	session2, out2, err := StartReshareOverlap(shares[2], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleReshareMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	dealer2Out, err := session2.HandleReshareMessage(out1[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(dealer2Out) < 2 {
		t.Fatalf("dealer 2 emitted %d messages, want commitment and share", len(dealer2Out))
	}
	if _, err := session.HandleReshareMessage(dealer2Out[0]); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalReshareSharePayload(dealer2Out[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	badShare := new(big.Int).SetBytes(payload.Share)
	badShare.Add(badShare, big.NewInt(1))
	badShare.Mod(badShare, secp.Order())
	if badShare.Sign() == 0 {
		badShare.SetInt64(1)
	}
	payload.Share = scalarBytes(badShare)
	dealer2Out[1].Payload, err = marshalReshareSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	dealer2Out[1] = dealer2Out[1].WithTranscriptHash()
	_, err = session.HandleReshareMessage(dealer2Out[1])
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSAReshareAddsParty(t *testing.T) {
	oldShares := secpKeygen(t, 2, 3)
	oldPub := oldShares[1].PublicKeyBytes()
	newParties := []tss.PartyID{1, 2, 3, 4}
	newShares, _ := runCGGMP21Reshare(t, oldShares, newParties, 2)
	if len(newShares) != len(newParties) {
		t.Fatalf("got %d new shares, want %d", len(newShares), len(newParties))
	}
	for _, id := range newParties {
		if !bytes.Equal(newShares[id].PublicKey, oldPub) {
			t.Fatalf("party %d public key changed after reshare", id)
		}
	}
	digest := sha256.Sum256([]byte("reshare add party"))
	pub, sig, err := SignDigest(digest[:], []*KeyShare{newShares[2], newShares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after add-party reshare did not verify")
	}
	if !bytes.Equal(pub, oldPub) {
		t.Fatal("reshare changed group public key")
	}
}

func TestThresholdECDSAReshareRemovesParty(t *testing.T) {
	oldShares := secpKeygen(t, 2, 3)
	oldPub := oldShares[1].PublicKeyBytes()
	newParties := []tss.PartyID{1, 3}
	newShares, sessions := runCGGMP21Reshare(t, oldShares, newParties, 2)
	if _, ok := newShares[2]; ok {
		t.Fatal("removed party received a new key share")
	}
	if share, ok := sessions[2].KeyShare(); ok || share != nil {
		t.Fatal("removed party session produced a key share")
	}
	digest := sha256.Sum256([]byte("reshare remove party"))
	pub, sig, err := SignDigest(digest[:], []*KeyShare{newShares[1], newShares[3]})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after remove-party reshare did not verify")
	}
	if !bytes.Equal(pub, oldPub) {
		t.Fatal("reshare changed group public key")
	}
}

func TestThresholdECDSAReshareChangesThreshold(t *testing.T) {
	oldShares := secpKeygen(t, 2, 3)
	oldPub := oldShares[1].PublicKeyBytes()
	newParties := []tss.PartyID{1, 2, 3, 4, 5}
	newShares, _ := runCGGMP21Reshare(t, oldShares, newParties, 3)
	digest := sha256.Sum256([]byte("reshare threshold change"))
	pub, sig, err := SignDigest(digest[:], []*KeyShare{newShares[1], newShares[4], newShares[5]})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after threshold-changing reshare did not verify")
	}
	if !bytes.Equal(pub, oldPub) {
		t.Fatal("reshare changed group public key")
	}
}

func TestThresholdECDSAReshareDisjointDealerSubset(t *testing.T) {
	oldShares := secpKeygen(t, 2, 3)
	oldPub := oldShares[1].PublicKeyBytes()
	dealerParties := []tss.PartyID{1, 3}
	newParties := []tss.PartyID{4, 5, 6}
	newShares, _ := runCGGMP21ReshareWithDealers(t, oldShares, dealerParties, newParties, 2)
	if len(newShares) != len(newParties) {
		t.Fatalf("got %d new shares, want %d", len(newShares), len(newParties))
	}
	digest := sha256.Sum256([]byte("reshare disjoint dealer subset"))
	pub, sig, err := SignDigest(digest[:], []*KeyShare{newShares[4], newShares[6]})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after disjoint reshare did not verify")
	}
	if !bytes.Equal(pub, oldPub) {
		t.Fatal("reshare changed group public key")
	}
}
