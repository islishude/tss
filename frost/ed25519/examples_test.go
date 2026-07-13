package ed25519_test

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"fmt"

	"github.com/islishude/tss"
	frost "github.com/islishude/tss/frost/ed25519"
)

// ExampleGenerateTrustedDealerKeyShares demonstrates centralized share
// generation followed by explicit threshold reconstruction. Production callers
// must encrypt every returned key share before distribution or persistence.
func ExampleGenerateTrustedDealerKeyShares() {
	seed := bytes.Repeat([]byte{0x2a}, 32)
	secretKey, err := frost.NewSecretKeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	defer secretKey.Destroy()
	var sessionID tss.SessionID
	sessionID[31] = 1
	_, shares, err := frost.GenerateTrustedDealerKeyShares(secretKey, frost.TrustedDealerImportOption{
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x44}, 32),
	}, nil)
	if err != nil {
		panic(err)
	}
	defer shares[1].Destroy()
	defer shares[2].Destroy()
	reconstructed, err := frost.ReconstructSecretKey(shares[1], shares[2])
	if err != nil {
		panic(err)
	}
	defer reconstructed.Destroy()
	want, _ := secretKey.PublicKey()
	got, _ := reconstructed.PublicKey()
	fmt.Println(got.Equal(want))
	// Output: true
}

// ExampleSign demonstrates production-shaped FROST key generation and signing.
func ExampleSign() {
	parties := tss.NewPartySet(1, 2)
	shares, err := runExampleFROSTKeygen(frost.KeygenPlanOption{
		Parties:   parties,
		Threshold: 2,
	})
	if err != nil {
		panic(err)
	}

	message := []byte("hello frost")
	publicKey, signature, err := runExampleFROSTSign(shares, parties, message, frost.SignOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}

// ExampleSign_multiParty demonstrates signing with a threshold subset.
func ExampleSign_multiParty() {
	parties := tss.NewPartySet(1, 2, 3)
	shares, err := runExampleFROSTKeygen(frost.KeygenPlanOption{
		Parties:   parties,
		Threshold: 2,
	})
	if err != nil {
		panic(err)
	}

	signers := tss.NewPartySet(1, 3)
	message := []byte("hello frost multi-party")
	publicKey, signature, err := runExampleFROSTSign(shares, signers, message, frost.SignOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}

// ExampleKeyShare demonstrates the canonical binary persistence format.
func ExampleKeyShare() {
	parties := tss.NewPartySet(1, 2)
	shares, err := runExampleFROSTKeygen(frost.KeygenPlanOption{
		Parties:   parties,
		Threshold: 2,
	})
	if err != nil {
		panic(err)
	}

	raw, err := shares[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	loaded, err := tss.DecodeBinary[frost.KeyShare](raw)
	if err != nil {
		panic(err)
	}
	shares[1] = loaded

	message := []byte("roundtrip test")
	publicKey, signature, err := runExampleFROSTSign(shares, parties, message, frost.SignOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}

// ExampleStartRefresh demonstrates proactive refresh with production policies.
func ExampleStartRefresh() {
	parties := tss.NewPartySet(1, 2, 3)
	partySet := parties
	shares, err := runExampleFROSTKeygen(frost.KeygenPlanOption{
		Parties:   parties,
		Threshold: 2,
	})
	if err != nil {
		panic(err)
	}
	metadata, err := exampleFROSTKeyShareMetadata(shares[1])
	if err != nil {
		panic(err)
	}
	oldPublicKey := metadata.PublicKey

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	security := newExampleFROSTSecurity(partySet)
	sessions := make(map[tss.PartyID]*frost.ReshareSession, len(parties))
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		guard, err := security.guard(id, partySet, sessionID)
		if err != nil {
			panic(err)
		}
		plan, err := frost.NewRefreshPlan(frost.RefreshPlanOption{OldKey: shares[id], SessionID: sessionID})
		if err != nil {
			panic(err)
		}
		session, out, err := frost.StartRefresh(shares[id], plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			panic(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, partySet, func(tss.Envelope) tss.PartySet {
		return partySet
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].Handle(env)
	}); err != nil {
		panic(err)
	}

	refreshed := make(map[tss.PartyID]*frost.KeyShare, len(parties))
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("refresh not complete for party %d", id))
		}
		refreshed[id] = share
	}
	refreshedMetadata, err := exampleFROSTKeyShareMetadata(refreshed[1])
	if err != nil {
		panic(err)
	}
	fmt.Println("public key preserved:", oldPublicKey.Equal(refreshedMetadata.PublicKey))

	message := []byte("post-refresh signing")
	publicKey, signature, err := runExampleFROSTSign(refreshed, tss.NewPartySet(1, 2), message, frost.SignOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// public key preserved: true
	// true
}

// ExampleStartReshare demonstrates adding a party while preserving the group key.
func ExampleStartReshare() {
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(1, 2, 3, 4)
	allParties := tss.MergePartySet(oldParties, newParties)
	shares, err := runExampleFROSTKeygen(frost.KeygenPlanOption{
		Parties:   oldParties,
		Threshold: 2,
	})
	if err != nil {
		panic(err)
	}
	metadata, err := exampleFROSTKeyShareMetadata(shares[1])
	if err != nil {
		panic(err)
	}
	oldPublicKey := metadata.PublicKey
	oldChainCode := metadata.ChainCode

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	security := newExampleFROSTSecurity(allParties)
	sessions := make(map[tss.PartyID]*frost.ReshareSession, len(newParties))
	queue := make([]tss.Envelope, 0)
	for _, id := range oldParties {
		guard, err := security.guard(id, allParties, sessionID)
		if err != nil {
			panic(err)
		}
		plan, err := frost.NewResharePlan(frost.ResharePlanOption{
			OldKey: shares[id], SessionID: sessionID, NewParties: newParties, NewThreshold: 2,
		})
		if err != nil {
			panic(err)
		}
		session, out, err := frost.StartReshare(shares[id], plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			panic(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	guard, err := security.guard(4, allParties, sessionID)
	if err != nil {
		panic(err)
	}
	recipientPlan, err := frost.NewPublicResharePlan(frost.PublicResharePlanOption{
		OldPublicKey: oldPublicKey.Bytes(), OldChainCode: oldChainCode, OldParties: oldParties, SessionID: sessionID,
		OldGroupCommitments: metadata.GroupCommitments, OldKeygenSessionID: metadata.KeygenSessionID,
		OldKeygenTranscriptHash: metadata.KeygenTranscriptHash, OldPlanHash: metadata.PlanHash,
		NewParties: newParties, NewThreshold: 2,
	})
	if err != nil {
		panic(err)
	}
	sessions[4], err = frost.StartReshareRecipient(recipientPlan, tss.LocalConfig{Self: 4}, guard)
	if err != nil {
		panic(err)
	}
	if err := security.route(queue, allParties, func(env tss.Envelope) tss.PartySet {
		if env.Round == 2 {
			return newParties
		}
		return oldParties
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].Handle(env)
	}); err != nil {
		panic(err)
	}

	reshared := make(map[tss.PartyID]*frost.KeyShare, len(newParties))
	for _, id := range newParties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("reshare not complete for party %d", id))
		}
		reshared[id] = share
	}
	resharedMetadata, err := exampleFROSTKeyShareMetadata(reshared[4])
	if err != nil {
		panic(err)
	}
	fmt.Println("public key preserved:", oldPublicKey.Equal(resharedMetadata.PublicKey))

	message := []byte("post-reshare signing")
	publicKey, signature, err := runExampleFROSTSign(reshared, tss.NewPartySet(2, 4), message, frost.SignOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// public key preserved: true
	// true
}

// ExampleDeriveNonHardenedBIP32 demonstrates HD derivation and child-key signing.
func ExampleDeriveNonHardenedBIP32() {
	parties := tss.NewPartySet(1, 2)
	shares, err := runExampleFROSTKeygen(frost.KeygenPlanOption{
		Parties:   parties,
		Threshold: 2,
	})
	if err != nil {
		panic(err)
	}
	metadata, err := exampleFROSTKeyShareMetadata(shares[1])
	if err != nil {
		panic(err)
	}
	derived, err := frost.DeriveNonHardenedBIP32(metadata.PublicKey.Bytes(), metadata.ChainCode, []uint32{0, 1})
	if err != nil {
		panic(err)
	}

	message := []byte("bip32 derived signing")
	_, signature, err := runExampleFROSTSign(shares, parties, message, frost.SignOptions{
		Context: exampleFROSTSigningContext([]uint32{0, 1}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(derived.ChildPublicKey), message, signature))
	fmt.Println(stded25519.Verify(stded25519.PublicKey(metadata.PublicKey.Bytes()), message, signature))
	// Output:
	// true
	// false
}
