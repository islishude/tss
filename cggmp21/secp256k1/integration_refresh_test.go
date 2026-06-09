//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"math/big"
	"strings"
	"testing"
)

func TestThresholdECDSAProactiveRefresh1of1(t *testing.T) {
	shares := secpKeygen(t, 1, 1)
	oldPub := shares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := tss.ThresholdConfig{Threshold: 1, Self: 1, SessionID: sessionID}
	session, out, err := StartRefresh(shares[1], config)
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	for _, env := range out {
		if _, err := session.HandleRefreshMessage(deliverCGGMPEnv(env)); err != nil {
			if !strings.Contains(err.Error(), "already completed") {
				t.Fatal(err)
			}
		}
	}
	newShare, ok := session.KeyShare()
	if !ok {
		t.Fatal("refresh did not complete")
	}
	if err := newShare.Validate(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldPub, newShare.PublicKey) {
		t.Fatal("public key changed after refresh")
	}
	if !bytes.Equal(shares[1].ChainCode, newShare.ChainCode) {
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
	shares := secpKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	session, _, err := StartRefresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	session.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartRefresh(shares[2], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleRefreshMessage(deliverCGGMPEnv(out2[0])); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalRefreshSharePayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	badShare := new(big.Int).Set(payload.Share)
	badShare.Add(badShare, big.NewInt(1))
	badShare.Mod(badShare, secp.Order())
	if badShare.Sign() == 0 {
		badShare.SetInt64(1)
	}
	out2[1].Payload, err = marshalRefreshSharePayload(refreshSharePayload{Share: badShare})
	if err != nil {
		t.Fatal(err)
	}
	out2[1] = out2[1].RecomputeTranscriptHash()
	_, err = session.HandleRefreshMessage(deliverCGGMPEnv(out2[1]))
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSARefreshRejectsMismatchedSelf(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = StartRefresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
	if err == nil || !strings.Contains(err.Error(), "config.Self") {
		t.Fatalf("expected config.Self mismatch rejection, got %v", err)
	}
}

func TestThresholdECDSARefreshRejectsNonzeroConstantCommitment(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := StartRefresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartRefresh(shares[2], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
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
	out2[0].Payload, err = marshalRefreshCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0] = out2[0].RecomputeTranscriptHash()
	_, err = session.HandleRefreshMessage(deliverCGGMPEnv(out2[0]))
	if err == nil || !strings.Contains(err.Error(), "constant commitment") {
		t.Fatalf("expected nonzero constant commitment rejection, got %v", err)
	}
}

func TestThresholdECDSAProactiveRefresh2of3(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	oldPub := shares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2, 3}
	sessions := make(map[tss.PartyID]*RefreshSession)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := StartRefresh(shares[id], tss.ThresholdConfig{Threshold: 2, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		session.SetGuard(testCGGMP21Guard(id, tss.PartySet(shares[id].Parties), sessionID))
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
			out, err := sessions[id].HandleRefreshMessage(deliverCGGMPEnv(env))
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	newShares := make(map[tss.PartyID]*KeyShare)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("refresh not complete for %d", id)
		}
		newShares[id] = share
		if !bytes.Equal(oldPub, share.PublicKey) {
			t.Fatalf("party %d public key changed after refresh", id)
		}
	}
	for _, id := range parties {
		if err := newShares[id].Validate(); err != nil {
			t.Fatal(err)
		}
	}
	signers := []*KeyShare{newShares[1], newShares[3]}
	digest := sha256.Sum256([]byte("refresh 2-of-3"))
	pub, sig, err := SignDigest(digest[:], signers)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after refresh did not verify")
	}
}

func TestThresholdECDSAProactiveRefreshPreservesChainCode(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 2, KeygenOptions{EnableHD: true})
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	sessions := make(map[tss.PartyID]*RefreshSession)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := StartRefresh(shares[id], tss.ThresholdConfig{Threshold: 2, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		session.SetGuard(testCGGMP21Guard(id, tss.PartySet(shares[id].Parties), sessionID))
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
			out, err := sessions[id].HandleRefreshMessage(deliverCGGMPEnv(env))
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	for _, id := range parties {
		newShare, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("refresh not complete for %d", id)
		}
		if len(newShare.ChainCode) != 32 {
			t.Fatalf("party %d missing chain code after refresh", id)
		}
		if !bytes.Equal(shares[id].ChainCode, newShare.ChainCode) {
			t.Fatalf("party %d chain code changed after refresh", id)
		}
	}
	signers := []*KeyShare{sessions[1].newShare, sessions[2].newShare}
	digest := sha256.Sum256([]byte("hd refresh"))
	pub, sig, err := SignDigest(digest[:], signers)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after HD refresh did not verify")
	}
}
