package ed25519_test

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"fmt"

	"github.com/islishude/tss"
	frost "github.com/islishude/tss/frost/ed25519"
)

// ExampleSign demonstrates production-shaped FROST key generation and signing.
func ExampleSign() {
	parties := []tss.PartyID{1, 2}
	shares, err := runExampleFROSTKeygen(parties, 2, frost.KeygenPlanOption{})
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
	parties := []tss.PartyID{1, 2, 3}
	shares, err := runExampleFROSTKeygen(parties, 2, frost.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}

	signers := []tss.PartyID{1, 3}
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
	parties := []tss.PartyID{1, 2}
	shares, err := runExampleFROSTKeygen(parties, 2, frost.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}

	raw, err := shares[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	loaded, err := frost.UnmarshalKeyShare(raw)
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
	parties := []tss.PartyID{1, 2, 3}
	partySet := tss.PartySet(parties)
	shares, err := runExampleFROSTKeygen(parties, 2, frost.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	oldPublicKey := shares[1].PublicKeyBytes()

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
		plan, err := frost.NewRefreshPlan(shares[id], sessionID)
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
	}, func(id tss.PartyID, env tss.Envelope) ([]tss.Envelope, error) {
		return sessions[id].HandleReshareMessage(env)
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
	fmt.Println("public key preserved:", bytes.Equal(oldPublicKey, refreshed[1].PublicKeyBytes()))

	message := []byte("post-refresh signing")
	publicKey, signature, err := runExampleFROSTSign(refreshed, []tss.PartyID{1, 2}, message, frost.SignOptions{})
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
	oldParties := []tss.PartyID{1, 2, 3}
	newParties := []tss.PartyID{1, 2, 3, 4}
	oldPartySet := tss.PartySet(oldParties)
	allParties := mergeExamplePartySets(oldParties, newParties)
	shares, err := runExampleFROSTKeygen(oldParties, 2, frost.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	oldPublicKey := shares[1].PublicKeyBytes()

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
		plan, err := frost.NewResharePlan(shares[id], sessionID, newParties, 2)
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
	recipientPlan, err := frost.NewResharePlanFromPublic(oldPublicKey, nil, oldParties, sessionID, newParties, 2)
	if err != nil {
		panic(err)
	}
	sessions[4], err = frost.StartReshareRecipient(recipientPlan, tss.LocalConfig{Self: 4}, guard)
	if err != nil {
		panic(err)
	}
	if err := security.route(queue, allParties, func(tss.Envelope) tss.PartySet {
		return oldPartySet
	}, func(id tss.PartyID, env tss.Envelope) ([]tss.Envelope, error) {
		return sessions[id].HandleReshareMessage(env)
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
	fmt.Println("public key preserved:", bytes.Equal(oldPublicKey, reshared[4].PublicKeyBytes()))

	message := []byte("post-reshare signing")
	publicKey, signature, err := runExampleFROSTSign(reshared, []tss.PartyID{2, 4}, message, frost.SignOptions{})
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
	parties := []tss.PartyID{1, 2}
	shares, err := runExampleFROSTKeygen(parties, 2, frost.KeygenPlanOption{EnableHD: true})
	if err != nil {
		panic(err)
	}
	derived, err := frost.DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), []uint32{0, 1})
	if err != nil {
		panic(err)
	}

	message := []byte("bip32 derived signing")
	_, signature, err := runExampleFROSTSign(shares, parties, message, frost.SignOptions{
		AdditiveShift: derived.AdditiveShift,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(derived.ChildPublicKey), message, signature))
	fmt.Println(stded25519.Verify(stded25519.PublicKey(shares[1].PublicKeyBytes()), message, signature))
	// Output:
	// true
	// false
}
