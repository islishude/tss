package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestCGGMP21KeyShareProofDomainBindsContext(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(minKeygenPaillierBits)
	defer restore()
	shares := secpKeygenWithOptions(t, 2, 2, KeygenOptions{PaillierBits: minKeygenPaillierBits})
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
			mutated := cloneKeyShare(share)
			tc.mutate(mutated)
			if zkpai.VerifyModulus(keySharePaillierProofDomain(mutated), pk, uint32(mutated.Party), proof) {
				t.Fatal("key-share Paillier proof verified under mutated context")
			}
		})
	}
}

func TestCGGMP21MTADomainsBindPresignContext(t *testing.T) {
	restore := pai.SetMinimumModulusBitsForTesting(minKeygenPaillierBits)
	defer restore()
	shares := secpKeygenWithOptions(t, 2, 2, KeygenOptions{PaillierBits: minKeygenPaillierBits})
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
	startFrom2 := mta.StartMessage{
		Ciphertext: round1From2.EncK,
		EncrProof:  round1From2.EncKProof,
	}
	pk2, err := shares[1].paillierPublicFor(2)
	if err != nil {
		t.Fatal(err)
	}
	if !mta.VerifyStart(mtaStartDomain(shares[1], sessionID, signers, 2, round1From2.PaillierPublicKey), startFrom2, pk2) {
		t.Fatal("MtA start proof did not verify")
	}
	mutatedKey := cloneKeyShare(shares[1])
	mutatedKey.KeygenTranscriptHash[0] ^= 1
	if mta.VerifyStart(mtaStartDomain(mutatedKey, sessionID, signers, 2, round1From2.PaillierPublicKey), startFrom2, pk2) {
		t.Fatal("MtA start proof verified under mutated key context")
	}
	if mta.VerifyStart(mtaStartDomain(shares[1], sessionID, []tss.PartyID{1, 2, 3}, 2, round1From2.PaillierPublicKey), startFrom2, pk2) {
		t.Fatal("MtA start proof verified under mutated signer set")
	}

	if _, err := s1.HandlePresignMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	round2, err := s2.HandlePresignMessage(out1[0])
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
		EncrProof:  s1.round1[s1.key.Party].EncKProof,
	}
	startDomain := mtaStartDomain(s1.key, sessionID, signers, s1.key.Party, s1.key.PaillierPublicKey)
	responseDomain := mtaResponseDomain(s1.key, sessionID, signers, s1.key.Party, 2, "delta", s1.key.PaillierPublicKey)
	if _, err := mta.Finish(startDomain, responseDomain, localStart, round2Payload.Delta, s1.round1[2].Gamma, s1.paillier); err != nil {
		t.Fatal(err)
	}
	wrongResponseDomain := mtaResponseDomain(s1.key, sessionID, signers, s1.key.Party, 2, "sigma", s1.key.PaillierPublicKey)
	if _, err := mta.Finish(startDomain, wrongResponseDomain, localStart, round2Payload.Delta, s1.round1[2].Gamma, s1.paillier); err == nil {
		t.Fatal("MtA response proof verified under wrong response kind")
	}
}

func secpKeygenWithOptions(t testing.TB, threshold, n int, opts KeygenOptions) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygenWithOptions(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session}, opts)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		out[id] = share
	}
	return out
}
