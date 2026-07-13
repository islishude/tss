//go:build integration

package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestCGGMP21KeyShareProofDomainBindsEpochContext(t *testing.T) {
	t.Parallel()
	shares := secpKeygenWithPlanOption(t, 2, 2, KeygenPlanOption{})
	share := shares[1]
	paillierShare, ok := share.PaillierPublicShare(share.PartyID())
	if !ok {
		t.Fatal("missing Paillier public share")
	}
	pk, err := tss.DecodeBinary[pai.PublicKey](paillierShare.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tss.DecodeBinary[zkpai.ModulusProof](paillierShare.Proof)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := keySharePaillierProofDomain(share)
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
		{name: "party", mutate: func(k *KeyShare) { k.state.Party = 2 }},
		{name: "threshold", mutate: func(k *KeyShare) { k.state.Threshold++ }},
		{name: "parties", mutate: func(k *KeyShare) { k.state.Parties = tss.NewPartySet(1, 2, 3) }},
		{name: "public key", mutate: func(k *KeyShare) { k.state.PublicKey[0] ^= 1 }},
		{name: "transcript", mutate: func(k *KeyShare) { k.state.KeygenTranscriptHash[0] ^= 1 }},
		{name: "plan", mutate: func(k *KeyShare) { k.state.PlanHash[0] ^= 1 }},
		{name: "epoch RID", mutate: func(k *KeyShare) { k.state.Epoch.RID[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneKeyShareValue(share)
			defer mutated.Destroy()
			tc.mutate(mutated)
			mutatedDomain, err := keySharePaillierProofDomain(mutated)
			if err == nil && zkpai.VerifyModulus(mutatedDomain, pk, mutated.PartyID(), proof) {
				t.Fatal("key-share Paillier proof verified under mutated epoch context")
			}
		})
	}
}

func TestCGGMP21RefreshKeyShareProofDomainBindsFinalContext(t *testing.T) {
	t.Parallel()
	original := secpKeygenWithPlanOption(t, 1, 1, KeygenPlanOption{})
	defer original[1].Destroy()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := runRefresh(t, original, tss.NewPartySet(1), sessionID)
	refreshed, ok := sessions[1].KeyShare()
	if !ok {
		t.Fatal("refresh did not produce a key share")
	}
	defer refreshed.Destroy()

	paillierShare, ok := refreshed.PaillierPublicShare(refreshed.PartyID())
	if !ok {
		t.Fatal("missing refreshed Paillier public share")
	}
	pk, err := tss.DecodeBinary[pai.PublicKey](paillierShare.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tss.DecodeBinary[zkpai.ModulusProof](paillierShare.Proof)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := keySharePaillierProofDomain(refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if !zkpai.VerifyModulus(domain, pk, refreshed.PartyID(), proof) {
		t.Fatal("refreshed key-share Paillier proof did not verify")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*KeyShare)
	}{
		{name: "public key", mutate: func(k *KeyShare) { k.state.PublicKey[0] ^= 1 }},
		{name: "transcript", mutate: func(k *KeyShare) { k.state.KeygenTranscriptHash[0] ^= 1 }},
		{name: "epoch RID", mutate: func(k *KeyShare) { k.state.Epoch.RID[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneKeyShareValue(refreshed)
			defer mutated.Destroy()
			tc.mutate(mutated)
			mutatedDomain, err := keySharePaillierProofDomain(mutated)
			if err == nil && zkpai.VerifyModulus(mutatedDomain, pk, mutated.PartyID(), proof) {
				t.Fatal("refreshed key-share Paillier proof verified under mutated final context")
			}
		})
	}
}
