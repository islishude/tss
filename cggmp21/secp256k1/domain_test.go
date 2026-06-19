//go:build integration || vectorgen

package secp256k1

import (
	"slices"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/testutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestCGGMP21KeyShareProofDomainBindsContext(t *testing.T) {
	t.Parallel()
	shares := secpKeygenWithPlanOption(t, 2, 2, KeygenPlanOption{})
	share := shares[1]
	paillierShare, ok := share.PaillierPublicShare(share.PartyID())
	if !ok {
		t.Fatal("missing Paillier public share")
	}
	pk, err := pai.UnmarshalPublicKey(paillierShare.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zkpai.UnmarshalModulusProof(paillierShare.Proof)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := keySharePaillierProofDomain(share, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !zkpai.VerifyModulus(domain, pk, share.PartyID(), proof) {
		t.Fatal("key-share Paillier proof did not verify")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*KeyShare)
	}{
		{name: "party", mutate: func(k *KeyShare) { k.state.party = 2 }},
		{name: "threshold", mutate: func(k *KeyShare) { k.state.threshold++ }},
		{name: "parties", mutate: func(k *KeyShare) { k.state.parties = tss.NewPartySet(1, 2, 3) }},
		{name: "public key", mutate: func(k *KeyShare) { k.state.publicKey[0] ^= 1 }},
		{name: "keygen transcript", mutate: func(k *KeyShare) { k.state.keygenTranscriptHash[0] ^= 1 }},
		{name: "lifecycle plan", mutate: func(k *KeyShare) { k.state.planHash[0] ^= 1 }},
		{name: "paillier public key", mutate: func(k *KeyShare) {
			data := k.state.partyData[k.state.party]
			data.paillierPublicKey = shares[2].state.partyData[shares[2].state.party].paillierPublicKey.Clone()
			k.state.partyData[k.state.party] = data
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := cloneKeyShareValue(share)
			tc.mutate(mutated)
			domain, err := keySharePaillierProofDomain(mutated, testLimits())
			if err != nil {
				return
			}
			if zkpai.VerifyModulus(domain, pk, mutated.PartyID(), proof) {
				t.Fatal("key-share Paillier proof verified under mutated context")
			}
		})
	}
}

func TestCGGMP21MTADomainsBindPresignContext(t *testing.T) {
	t.Parallel()
	shares := secpKeygenWithPlanOption(t, 2, 2, KeygenPlanOption{})
	signers := tss.NewPartySet(1, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := startTestPresign(shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startTestPresign(shares[2], sessionID, signers)
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
	pk2, err := shares[1].paillierPublicFor(2, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	rp1, err := shares[1].ringPedersenPublicFor(1, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	startDomain, err := mtaStartProofDomain(shares[1], sessionID, signers, 2, 1, &round1From2.PaillierPublicKey, s1.contextHash, s1.planHash, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := mta.VerifyStart(s1.securityParams, startDomain, startFrom2, pk2, rp1, &round1ProofFrom2.EncKProof); err != nil {
		t.Fatal("MtA start proof did not verify")
	}
	mutatedKey := cloneKeyShareValue(shares[1])
	mutatedKey.state.keygenTranscriptHash[0] ^= 1
	mutatedDomain, err := mtaStartProofDomain(mutatedKey, sessionID, signers, 2, 1, &round1From2.PaillierPublicKey, s1.contextHash, s1.planHash, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := mta.VerifyStart(s1.securityParams, mutatedDomain, startFrom2, pk2, rp1, &round1ProofFrom2.EncKProof); err == nil {
		t.Fatal("MtA start proof verified under mutated key context")
	}
	mutatedSignersDomain, err := mtaStartProofDomain(shares[1], sessionID, tss.NewPartySet(1, 2, 3), 2, 1, &round1From2.PaillierPublicKey, s1.contextHash, s1.planHash, testLimits())
	if err == nil && mta.VerifyStart(s1.securityParams, mutatedSignersDomain, startFrom2, pk2, rp1, &round1ProofFrom2.EncKProof) == nil {
		t.Fatal("MtA start proof verified under mutated signer set")
	}
	wrongContextHash := slices.Clone(s1.contextHash)
	wrongContextHash[0] ^= 1
	wrongContextDomain, err := mtaStartProofDomain(shares[1], sessionID, signers, 2, 1, &round1From2.PaillierPublicKey, wrongContextHash, s1.planHash, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := mta.VerifyStart(s1.securityParams, wrongContextDomain, startFrom2, pk2, rp1, &round1ProofFrom2.EncKProof); err == nil {
		t.Fatal("MtA start proof verified under mutated presign context")
	}

	if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[1])); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.HandlePresignMessage(testutil.DeliverEnvelope(out1[0])); err != nil {
		t.Fatal(err)
	}
	round2, err := s2.HandlePresignMessage(testutil.DeliverEnvelope(out1[1]))
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
		Ciphertext: s1.round1[s1.key.PartyID()].EncK,
	}
	responseDomain, err := mtaDeltaResponseDomain(s1.key, sessionID, signers, s1.key.PartyID(), 2, &s1.paillier.PublicKey, s1.contextHash, s1.planHash, s1.limits)
	if err != nil {
		t.Fatal(err)
	}

	responderPK, err := s1.key.paillierPublicFor(2, s1.limits)
	if err != nil {
		t.Fatal(err)
	}
	selfRP, err := s1.key.ringPedersenPublicFor(s1.key.PartyID(), s1.limits)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mta.Finish(s1.securityParams, responseDomain, localStart, round2Payload.Delta, s1.round1[2].Gamma, s1.paillier, responderPK, selfRP); err != nil {
		t.Fatal(err)
	}
	wrongResponseDomain, err := mtaSigmaResponseDomain(s1.key, sessionID, signers, s1.key.PartyID(), 2, &s1.paillier.PublicKey, s1.contextHash, s1.planHash, s1.limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mta.Finish(s1.securityParams, wrongResponseDomain, localStart, round2Payload.Delta, s1.round1[2].Gamma, s1.paillier, responderPK, selfRP); err == nil {
		t.Fatal("MtA response proof verified under wrong response kind")
	}
}
