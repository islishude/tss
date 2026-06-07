//go:build integration || vectorgen

package secp256k1

import (
	"slices"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestCGGMP21KeyShareProofDomainBindsContext(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 2, KeygenOptions{PaillierBits: defaultPaillierBits()})
	share := shares[1]
	pk, err := pai.UnmarshalPublicKey(share.PaillierPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zkpai.UnmarshalModulusProof(share.PaillierProof)
	if err != nil {
		t.Fatal(err)
	}
	if !zkpai.VerifyModulus(keySharePaillierProofDomain(share), pk, uint32(share.Party), proof) {
		t.Fatal("key-share Paillier proof did not verify")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*KeyShare)
	}{
		{name: "party", mutate: func(k *KeyShare) { k.Party = 2 }},
		{name: "threshold", mutate: func(k *KeyShare) { k.Threshold++ }},
		{name: "parties", mutate: func(k *KeyShare) { k.Parties = []tss.PartyID{1, 2, 3} }},
		{name: "public key", mutate: func(k *KeyShare) { k.PublicKey[0] ^= 1 }},
		{name: "keygen transcript", mutate: func(k *KeyShare) { k.KeygenTranscriptHash[0] ^= 1 }},
		{name: "paillier public key", mutate: func(k *KeyShare) { k.PaillierPublicKey = shares[2].PaillierPublicKey }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := share.Clone()
			tc.mutate(mutated)
			if zkpai.VerifyModulus(keySharePaillierProofDomain(mutated), pk, uint32(mutated.Party), proof) {
				t.Fatal("key-share Paillier proof verified under mutated context")
			}
		})
	}
}

func TestCGGMP21MTADomainsBindPresignContext(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 2, KeygenOptions{PaillierBits: defaultPaillierBits()})
	signers := []tss.PartyID{1, 2}
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := StartPresign(shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := StartPresign(shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}

	round1From2, err := unmarshalPresignRound1Payload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	round1ProofFrom2, err := unmarshalPresignRound1ProofPayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	startFrom2 := mta.StartMessage{
		Ciphertext: round1From2.EncK,
	}
	pk2, err := shares[1].paillierPublicFor(2)
	if err != nil {
		t.Fatal(err)
	}
	rp1, err := shares[1].ringPedersenPublicFor(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := mta.VerifyStart(mtaStartProofDomain(shares[1], sessionID, signers, 2, 1, round1From2.PaillierPublicKey, s1.contextHash), startFrom2, pk2, rp1, round1ProofFrom2.EncKProof); err != nil {
		t.Fatal("MtA start proof did not verify")
	}
	mutatedKey := (shares[1]).Clone()
	mutatedKey.KeygenTranscriptHash[0] ^= 1
	if err := mta.VerifyStart(mtaStartProofDomain(mutatedKey, sessionID, signers, 2, 1, round1From2.PaillierPublicKey, s1.contextHash), startFrom2, pk2, rp1, round1ProofFrom2.EncKProof); err == nil {
		t.Fatal("MtA start proof verified under mutated key context")
	}
	if err := mta.VerifyStart(mtaStartProofDomain(shares[1], sessionID, []tss.PartyID{1, 2, 3}, 2, 1, round1From2.PaillierPublicKey, s1.contextHash), startFrom2, pk2, rp1, round1ProofFrom2.EncKProof); err == nil {
		t.Fatal("MtA start proof verified under mutated signer set")
	}
	wrongContextHash := slices.Clone(s1.contextHash)
	wrongContextHash[0] ^= 1
	if err := mta.VerifyStart(mtaStartProofDomain(shares[1], sessionID, signers, 2, 1, round1From2.PaillierPublicKey, wrongContextHash), startFrom2, pk2, rp1, round1ProofFrom2.EncKProof); err == nil {
		t.Fatal("MtA start proof verified under mutated presign context")
	}

	if _, err := s1.HandlePresignMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandlePresignMessage(out2[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.HandlePresignMessage(out1[0]); err != nil {
		t.Fatal(err)
	}
	round2, err := s2.HandlePresignMessage(out1[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(round2) != 1 {
		t.Fatalf("got %d round2 messages, want 1", len(round2))
	}
	round2Payload, err := unmarshalPresignRound2Payload(round2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	localStart := mta.StartMessage{
		Ciphertext: s1.round1[s1.key.Party].EncK,
	}
	responseDomain := mtaResponseDomain(s1.key, sessionID, signers, s1.key.Party, 2, "delta", s1.key.PaillierPublicKey, s1.contextHash)

	responderPK, err := s1.key.paillierPublicFor(2)
	if err != nil {
		t.Fatal(err)
	}
	selfRP, err := s1.key.ringPedersenPublicFor(s1.key.Party)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mta.Finish(responseDomain, localStart, round2Payload.Delta, s1.round1[2].Gamma, s1.paillier, responderPK, selfRP); err != nil {
		t.Fatal(err)
	}
	wrongResponseDomain := mtaResponseDomain(s1.key, sessionID, signers, s1.key.Party, 2, "sigma", s1.key.PaillierPublicKey, s1.contextHash)
	if _, err := mta.Finish(wrongResponseDomain, localStart, round2Payload.Delta, s1.round1[2].Gamma, s1.paillier, responderPK, selfRP); err == nil {
		t.Fatal("MtA response proof verified under wrong response kind")
	}
}
