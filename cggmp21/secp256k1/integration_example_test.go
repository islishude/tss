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
	parties := tss.NewPartySet(1, 2)
	shares, err := runExampleCGGMPKeygen(cggmp.KeygenPlanOption{Parties: parties, Threshold: 2})
	if err != nil {
		panic(err)
	}
	rawShare, err := shares[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	shares[1], err = tss.DecodeBinary[cggmp.KeyShare](rawShare)
	if err != nil {
		panic(err)
	}

	ctx := examplePresignContext()
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
		Context: ctx,
		Message: []byte("example full lifecycle"),
	}
	publicKey, signature, err := runExampleCGGMPSign(shares, presigns, parties, request, store)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(publicKey, request, signature))
	// Output:
	// true
}

// Example_multiParty demonstrates a 2-of-3 threshold ECDSA signature.
func Example_multiParty() {
	parties := tss.NewPartySet(1, 2, 3)
	shares, err := runExampleCGGMPKeygen(cggmp.KeygenPlanOption{Parties: parties, Threshold: 2})
	if err != nil {
		panic(err)
	}
	signers := tss.NewPartySet(1, 3)
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
		Context: ctx,
		Message: []byte("multi-party threshold signature"),
	}
	publicKey, signature, err := runExampleCGGMPSign(shares, presigns, signers, request, store)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(publicKey, request, signature))
	// Output:
	// true
}

// ExampleStartRefresh demonstrates proactive share and Paillier-key refresh.
func ExampleStartRefresh() {
	parties := tss.NewPartySet(1, 2)
	partySet := parties
	shares, err := runExampleCGGMPKeygen(cggmp.KeygenPlanOption{Parties: parties, Threshold: 2})
	if err != nil {
		panic(err)
	}
	oldPublicKey := exampleKeyShareMetadata(shares[1]).PublicKey

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	security := newExampleCGGMPSecurity(partySet)
	sessions := make(map[tss.PartyID]*cggmp.RefreshSession, len(parties))
	queue := make([]tss.Envelope, 0)
	// Production refresh is started from one refresh job. Each party
	// reconstructs its own RefreshPlan from its current local KeyShare and the
	// shared session ID.
	for _, id := range parties {
		guard, err := security.guard(id, partySet, sessionID)
		if err != nil {
			panic(err)
		}
		signer, err := security.envelopeSigner(id)
		if err != nil {
			panic(err)
		}
		plan, err := cggmp.NewRefreshPlan(cggmp.RefreshPlanOption{OldKey: shares[id], SessionID: sessionID})
		if err != nil {
			panic(err)
		}
		session, out, err := cggmp.StartRefresh(shares[id], plan, tss.LocalConfig{Self: id, EnvelopeSigner: signer}, guard)
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

	refreshed := make(map[tss.PartyID]*cggmp.KeyShare, len(parties))
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("refresh not complete for party %d", id))
		}
		refreshed[id] = share
	}
	fmt.Println("public key preserved:", bytes.Equal(oldPublicKey, exampleKeyShareMetadata(refreshed[1]).PublicKey))

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
		Context: ctx,
		Message: []byte("post-refresh signing"),
	}
	publicKey, signature, err := runExampleCGGMPSign(refreshed, presigns, parties, request, store)
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
	oldParties := tss.NewPartySet(1, 2)
	newParties := tss.NewPartySet(3, 4)
	oldPartySet := oldParties
	newPartySet := newParties
	allParties := tss.MergePartySet(oldParties, newParties)
	shares, err := runExampleCGGMPKeygen(cggmp.KeygenPlanOption{Parties: oldParties, Threshold: 2})
	if err != nil {
		panic(err)
	}
	oldPublicKey := exampleKeyShareMetadata(shares[1]).PublicKey

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	plan, err := cggmp.NewResharePlan(cggmp.ResharePlanOption{OldKey: shares[1], SessionID: sessionID, DealerParties: oldParties, NewParties: newParties, NewThreshold: 2})
	if err != nil {
		panic(err)
	}
	security := newExampleCGGMPSecurity(allParties)
	sessions := make(map[tss.PartyID]*cggmp.ReshareSession, len(allParties))
	queue := make([]tss.Envelope, 0)
	// Production reshare assigns roles from the same reshare job. Old dealers
	// and new receivers do not call the same start function.
	for _, id := range oldParties {
		guard, err := security.guard(id, allParties, sessionID)
		if err != nil {
			panic(err)
		}
		signer, err := security.envelopeSigner(id)
		if err != nil {
			panic(err)
		}
		session, out, err := cggmp.StartReshareDealer(shares[id], plan, tss.LocalConfig{Self: id, EnvelopeSigner: signer}, guard)
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
		signer, err := security.envelopeSigner(id)
		if err != nil {
			panic(err)
		}
		session, out, err := cggmp.StartReshareReceiver(plan, tss.LocalConfig{Self: id, EnvelopeSigner: signer}, guard)
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
		return sessions[id].Handle(env)
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
	fmt.Println("public key preserved:", bytes.Equal(oldPublicKey, exampleKeyShareMetadata(reshared[3]).PublicKey))

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
		Context: ctx,
		Message: []byte("post-reshare signing"),
	}
	publicKey, signature, err := runExampleCGGMPSign(reshared, presigns, newParties, request, store)
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
	parties := tss.NewPartySet(1, 2)
	shares, err := runExampleCGGMPKeygen(cggmp.KeygenPlanOption{Parties: parties, Threshold: 2})
	if err != nil {
		panic(err)
	}
	path := []uint32{0, 1}
	shareMetadata := exampleKeyShareMetadata(shares[1])
	derived, err := cggmp.DeriveNonHardenedBIP32(shareMetadata.PublicKey, shareMetadata.ChainCode, path)
	if err != nil {
		panic(err)
	}

	ctx := examplePresignContext()
	ctx.Derivation.Path = tss.DerivationPath(path).Clone()
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
		Context: ctx,
		Message: []byte("bip32 derived signing"),
	}
	_, signature, err := runExampleCGGMPSign(shares, presigns, parties, request, store)
	if err != nil {
		panic(err)
	}
	fmt.Println(cggmp.VerifySignature(derived.ChildPublicKey, request, signature))
	fmt.Println(cggmp.VerifySignature(shareMetadata.PublicKey, request, signature))
	// Output:
	// true
	// false
}

// Example_serialization demonstrates key-share round trips and consumed presign snapshots.
func Example_serialization() {
	parties := tss.NewPartySet(1, 2)
	shares, err := runExampleCGGMPKeygen(cggmp.KeygenPlanOption{Parties: parties, Threshold: 2})
	if err != nil {
		panic(err)
	}
	rawShare, err := shares[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	restoredShare, err := tss.DecodeBinary[cggmp.KeyShare](rawShare)
	if err != nil {
		panic(err)
	}
	fmt.Println("key share round-trip:", bytes.Equal(exampleKeyShareMetadata(restoredShare).PublicKey, exampleKeyShareMetadata(shares[1]).PublicKey))

	ctx := examplePresignContext()
	presigns, err := runExampleCGGMPPresign(shares, parties, ctx)
	if err != nil {
		panic(err)
	}
	rawPresign, err := presigns[1].MarshalBinary()
	if err != nil {
		panic(err)
	}
	restoredPresign, err := tss.DecodeBinary[cggmp.Presign](rawPresign)
	if err != nil {
		panic(err)
	}
	fmt.Println("presign restored usable:", !cggmp.IsPresignConsumed(restoredPresign))
	// Output:
	// key share round-trip: true
	// presign restored usable: false
}
