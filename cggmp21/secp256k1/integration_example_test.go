//go:build integration

package secp256k1_test

import (
	"bytes"
	"fmt"

	"github.com/islishude/tss"
	cggmp "github.com/islishude/tss/cggmp21/secp256k1"
)

// Example_full_lifecycle demonstrates keygen, persistence, presign, and signing.
func Example_full_lifecycle() {
	parties := []tss.PartyID{1, 2}
	shares, err := runExampleCGGMPKeygen(parties, 2, cggmp.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	rawShare, err := shares[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	shares[1], err = cggmp.UnmarshalKeyShare(rawShare)
	if err != nil {
		panic(err)
	}

	ctx := examplePresignContext()
	presigns, err := runExampleCGGMPPresign(shares, parties, ctx)
	if err != nil {
		panic(err)
	}
	rawPresign, err := presigns[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	presigns[1], err = cggmp.UnmarshalPresign(rawPresign)
	if err != nil {
		panic(err)
	}

	store, cleanup, err := newExampleFileSignAttemptStore()
	if err != nil {
		panic(err)
	}
	defer cleanup()
	request := cggmp.SignRequest{
		Context:      ctx,
		Message:      []byte("example full lifecycle"),
		LowS:         true,
		AttemptStore: store,
	}
	publicKey, signature, err := runExampleCGGMPSign(shares, presigns, parties, request)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(publicKey, request, signature))
	// Output:
	// true
}

// Example_multiParty demonstrates a 2-of-3 threshold ECDSA signature.
func Example_multiParty() {
	parties := []tss.PartyID{1, 2, 3}
	shares, err := runExampleCGGMPKeygen(parties, 2, cggmp.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	signers := []tss.PartyID{1, 3}
	ctx := examplePresignContext()
	presigns, err := runExampleCGGMPPresign(shares, signers, ctx)
	if err != nil {
		panic(err)
	}
	store, cleanup, err := newExampleFileSignAttemptStore()
	if err != nil {
		panic(err)
	}
	defer cleanup()
	request := cggmp.SignRequest{
		Context:      ctx,
		Message:      []byte("multi-party threshold signature"),
		LowS:         true,
		AttemptStore: store,
	}
	publicKey, signature, err := runExampleCGGMPSign(shares, presigns, signers, request)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(publicKey, request, signature))
	// Output:
	// true
}

// ExampleStartRefresh demonstrates proactive share and Paillier-key refresh.
func ExampleStartRefresh() {
	parties := []tss.PartyID{1, 2}
	partySet := tss.PartySet(parties)
	shares, err := runExampleCGGMPKeygen(parties, 2, cggmp.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	oldPublicKey := shares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	security := newExampleCGGMPSecurity(partySet)
	sessions := make(map[tss.PartyID]*cggmp.RefreshSession, len(parties))
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		guard, err := security.guard(id, partySet, sessionID)
		if err != nil {
			panic(err)
		}
		plan, err := cggmp.NewRefreshPlan(shares[id], sessionID)
		if err != nil {
			panic(err)
		}
		session, out, err := cggmp.StartRefresh(shares[id], plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			panic(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, partySet, func(tss.Envelope) tss.PartySet {
		return partySet
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].HandleRefreshMessage(env)
	}); err != nil {
		panic(err)
	}

	refreshed := make(map[tss.PartyID]*cggmp.KeyShare, len(parties))
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("refresh not complete for party %d", id))
		}
		refreshed[id] = share
	}
	fmt.Println("public key preserved:", bytes.Equal(oldPublicKey, refreshed[1].PublicKeyBytes()))

	ctx := examplePresignContext()
	presigns, err := runExampleCGGMPPresign(refreshed, parties, ctx)
	if err != nil {
		panic(err)
	}
	store, cleanup, err := newExampleFileSignAttemptStore()
	if err != nil {
		panic(err)
	}
	defer cleanup()
	request := cggmp.SignRequest{
		Context:      ctx,
		Message:      []byte("post-refresh signing"),
		LowS:         true,
		AttemptStore: store,
	}
	publicKey, signature, err := runExampleCGGMPSign(refreshed, presigns, parties, request)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(publicKey, request, signature))
	// Output:
	// public key preserved: true
	// true
}

// ExampleStartReshareDealer demonstrates a disjoint committee change.
func ExampleStartReshareDealer() {
	oldParties := []tss.PartyID{1, 2}
	newParties := []tss.PartyID{3, 4}
	oldPartySet := tss.PartySet(oldParties)
	newPartySet := tss.PartySet(newParties)
	allParties := mergeExampleCGGMPPartySets(oldParties, newParties)
	shares, err := runExampleCGGMPKeygen(oldParties, 2, cggmp.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	oldPublicKey := shares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	plan, err := cggmp.NewResharePlan(shares[1], sessionID, oldParties, newParties, 2)
	if err != nil {
		panic(err)
	}
	security := newExampleCGGMPSecurity(allParties)
	sessions := make(map[tss.PartyID]*cggmp.ReshareSession, len(allParties))
	queue := make([]tss.Envelope, 0)
	for _, id := range oldParties {
		guard, err := security.guard(id, allParties, sessionID)
		if err != nil {
			panic(err)
		}
		session, out, err := cggmp.StartReshareDealer(shares[id], plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			panic(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	for _, id := range newParties {
		guard, err := security.guard(id, allParties, sessionID)
		if err != nil {
			panic(err)
		}
		session, out, err := cggmp.StartReshareReceiver(plan, tss.LocalConfig{Self: id}, guard)
		if err != nil {
			panic(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	if err := security.route(queue, allParties, func(env tss.Envelope) tss.PartySet {
		if oldPartySet.Contains(env.From) {
			return oldPartySet
		}
		return newPartySet
	}, func(id tss.PartyID, env tss.InboundEnvelope) ([]tss.Envelope, error) {
		return sessions[id].HandleReshareMessage(env)
	}); err != nil {
		panic(err)
	}

	reshared := make(map[tss.PartyID]*cggmp.KeyShare, len(newParties))
	for _, id := range newParties {
		share, err := sessions[id].Result()
		if err != nil {
			panic(err)
		}
		reshared[id] = share
	}
	fmt.Println("public key preserved:", bytes.Equal(oldPublicKey, reshared[3].PublicKeyBytes()))

	ctx := examplePresignContext()
	presigns, err := runExampleCGGMPPresign(reshared, newParties, ctx)
	if err != nil {
		panic(err)
	}
	store, cleanup, err := newExampleFileSignAttemptStore()
	if err != nil {
		panic(err)
	}
	defer cleanup()
	request := cggmp.SignRequest{
		Context:      ctx,
		Message:      []byte("post-reshare signing"),
		LowS:         true,
		AttemptStore: store,
	}
	publicKey, signature, err := runExampleCGGMPSign(reshared, presigns, newParties, request)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(publicKey, request, signature))
	// Output:
	// public key preserved: true
	// true
}

// ExampleDeriveNonHardenedBIP32 demonstrates child-key threshold signing.
func ExampleDeriveNonHardenedBIP32() {
	parties := []tss.PartyID{1, 2}
	shares, err := runExampleCGGMPKeygen(parties, 2, cggmp.KeygenPlanOption{EnableHD: true})
	if err != nil {
		panic(err)
	}
	path := []uint32{0, 1}
	derived, err := cggmp.DeriveNonHardenedBIP32(shares[1].PublicKeyBytes(), shares[1].ChainCodeBytes(), path)
	if err != nil {
		panic(err)
	}

	ctx := examplePresignContext()
	ctx.DerivationPath = path
	presigns, err := runExampleCGGMPPresign(shares, parties, ctx)
	if err != nil {
		panic(err)
	}
	store, cleanup, err := newExampleFileSignAttemptStore()
	if err != nil {
		panic(err)
	}
	defer cleanup()
	request := cggmp.SignRequest{
		Context:      ctx,
		Message:      []byte("bip32 derived signing"),
		LowS:         true,
		AttemptStore: store,
	}
	_, signature, err := runExampleCGGMPSign(shares, presigns, parties, request)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(derived.ChildPublicKey, request, signature))
	fmt.Println(cggmp.VerifySignature(shares[1].PublicKeyBytes(), request, signature))
	// Output:
	// true
	// false
}

// Example_serialization demonstrates key-share and presign binary round trips.
func Example_serialization() {
	parties := []tss.PartyID{1, 2}
	shares, err := runExampleCGGMPKeygen(parties, 2, cggmp.KeygenPlanOption{})
	if err != nil {
		panic(err)
	}
	rawShare, err := shares[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	restoredShare, err := cggmp.UnmarshalKeyShare(rawShare)
	if err != nil {
		panic(err)
	}
	fmt.Println("key share round-trip:", bytes.Equal(restoredShare.PublicKeyBytes(), shares[1].PublicKeyBytes()))

	ctx := examplePresignContext()
	presigns, err := runExampleCGGMPPresign(shares, parties, ctx)
	if err != nil {
		panic(err)
	}
	rawPresign, err := presigns[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	restoredPresign, err := cggmp.UnmarshalPresign(rawPresign)
	if err != nil {
		panic(err)
	}
	fmt.Println("presign round-trip:", !cggmp.IsPresignConsumed(restoredPresign))
	// Output:
	// key share round-trip: true
	// presign round-trip: true
}
