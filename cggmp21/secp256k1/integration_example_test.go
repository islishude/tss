//go:build integration

package secp256k1

import (
	"bytes"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// Example_full_lifecycle demonstrates the complete CGGMP21 lifecycle for
// a 1-of-1 configuration: key generation, presign, and online signing.
// This is the simplest threshold setup; for multi-party flows see
// Example_multiParty.
//
// This example requires the integration build tag because it generates
// a Paillier key.
func Example_full_lifecycle() {
	// --- 1. Key generation (completes immediately for 1-of-1) ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	keygen, _, err := StartKeygen(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   []tss.PartyID{1},
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		panic(err)
	}
	share, ok := keygen.KeyShare()
	if !ok {
		panic("keygen did not complete")
	}

	// --- 2. Serialize and deserialize the key share ---
	// This is the canonical pattern for persisting shares.
	raw, err := share.MarshalBinary()
	if err != nil {
		panic(err)
	}
	loaded, err := UnmarshalKeyShare(raw)
	if err != nil {
		panic(err)
	}

	// --- 3. Presign: create a pre-computed nonce share ---
	// The PresignContext binds the presign to a specific key, chain, and
	// domain policy. A presign can be created ahead of time and consumed
	// exactly once during signing.
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	ctx := PresignContext{
		KeyID:         "example-key",
		ChainID:       "example-chain",
		PolicyDomain:  "example-policy",
		MessageDomain: "example-message",
	}
	ps, _, err := StartPresignWithContext(loaded, presignID, []tss.PartyID{1}, ctx)
	if err != nil {
		panic(err)
	}
	presign, ok := ps.Presign()
	if !ok {
		panic("presign did not complete")
	}

	// --- 4. Serialize and deserialize the presign ---
	rawPresign, err := presign.MarshalBinary()
	if err != nil {
		panic(err)
	}
	loadedPresign, err := UnmarshalPresign(rawPresign)
	if err != nil {
		panic(err)
	}

	// --- 5. Online signing: consume the presign ---
	// The SignRequest binds the message to the same PresignContext.
	// A presign can only be consumed once; reusing it returns ErrCodeConsumed.
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	request := SignRequest{
		Context:      ctx,
		Message:      []byte("example full lifecycle"),
		LowS:         true,
		PresignStore: newTestPresignStore(),
	}
	ss, _, err := StartSign(loaded, loadedPresign, signID, request)
	if err != nil {
		panic(err)
	}
	sig, ok := ss.Signature()
	if !ok {
		panic("signing did not complete")
	}

	// --- 6. Verify the threshold signature ---
	// VerifySignature checks the ECDSA signature against the public key,
	// message, and derivation path embedded in the SignRequest.
	fmt.Println(VerifySignature(loaded.PublicKeyBytes(), request, sig))
	// Output:
	// true
}

// Example_multiParty demonstrates a 2-of-3 threshold ECDSA signing flow.
// Three parties perform interactive keygen, then two of them run presign
// and online signing with full message routing.
func Example_multiParty() {
	const threshold, n = 2, 3
	parties := []tss.PartyID{1, 2, 3}

	// --- 1. Keygen with message routing ---
	shares := runCGGMPKeygen(parties, threshold)

	// --- 2. Presign for signers {1, 3} ---
	signers := []tss.PartyID{1, 3}
	presigns := runCGGMPPresign(shares, signers)

	// --- 3. Online signing with message routing ---
	message := []byte("multi-party threshold signature")
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	// Build a SignRequest that binds the message to the presign context.
	ctx := testPresignContext()
	request := SignRequest{Context: ctx, Message: message, LowS: true}

	// Start sign sessions for each signer.
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := StartSign(shares[id], presigns[id], signID, request)
		if err != nil {
			panic(err)
		}
		session.SetGuard(testCGGMP21Guard(id, tss.PartySet(parties), signID))
		sessions[id] = session
		messages = append(messages, out...)
	}

	// Route sign partials between signers.
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleSignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				panic(err)
			}
			messages = append(messages, out...)
		}
	}

	// --- 4. Collect and verify the signature ---
	sig, ok := sessions[1].Signature()
	if !ok {
		panic("signature not completed")
	}

	fmt.Println(VerifySignature(shares[1].PublicKeyBytes(), request, sig))
	// Output:
	// true
}

// ExampleStartRefresh demonstrates a 2-of-3 proactive refresh. After
// refresh, all parties hold new shares of the same group public key.
// Old shares are incompatible with the new sharing and cannot sign.
func ExampleStartRefresh() {
	const threshold, n = 2, 3
	parties := []tss.PartyID{1, 2, 3}

	// --- 1. Initial keygen ---
	shares := runCGGMPKeygen(parties, threshold)
	oldPub := shares[1].PublicKeyBytes()

	// --- 2. Start refresh for all parties ---
	// Refresh generates fresh polynomial shares that sum to zero,
	// keeping the group secret key unchanged.
	refreshID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	sessions := make(map[tss.PartyID]*RefreshSession, n)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := StartRefresh(shares[id], tss.ThresholdConfig{
			Threshold: threshold,
			Self:      id,
			SessionID: refreshID,
		})
		if err != nil {
			panic(err)
		}
		session.SetGuard(testCGGMP21Guard(id, tss.PartySet(parties), refreshID))
		sessions[id] = session
		queue = append(queue, out...)
	}

	// --- 3. Route refresh messages ---
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleRefreshMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				panic(err)
			}
			queue = append(queue, out...)
		}
	}

	// --- 4. Collect refreshed shares ---
	newShares := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("refresh not complete for party %d", id))
		}
		newShares[id] = share
	}

	// --- 5. Verify public key preserved and new shares can sign ---
	pubPreserved := bytes.Equal(newShares[1].PublicKeyBytes(), oldPub)
	fmt.Println("public key preserved:", pubPreserved)

	signers := []*KeyShare{newShares[1], newShares[3]}
	message := []byte("post-refresh signing")
	ctx := testPresignContext()
	pub, sig, err := Sign(message, signers, ctx)
	if err != nil {
		panic(err)
	}
	request := SignRequest{Context: ctx, Message: message, LowS: true}
	fmt.Println(VerifySignature(pub, request, sig))
	// Output:
	// public key preserved: true
	// true
}

// ExampleStartReshare demonstrates changing the party set via resharing.
// A 2-of-3 group is reshared to 2-of-4, adding party 4. The group public
// key is preserved, and the new party can participate in signing.
func ExampleStartReshare() {
	const oldThreshold, oldN = 2, 3
	oldParties := []tss.PartyID{1, 2, 3}
	newParties := []tss.PartyID{1, 2, 3, 4}
	newThreshold := 2

	// --- 1. Initial keygen ---
	shares := runCGGMPKeygen(oldParties, oldThreshold)
	oldPub := shares[1].PublicKeyBytes()

	// --- 2. Create a reshare plan ---
	// The plan authorizes a specific dealer set, new party set, and
	// threshold. All sessions must use the same plan.
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	plan, err := NewResharePlan(shares[1], sessionID, oldParties, newParties, newThreshold)
	if err != nil {
		panic(err)
	}

	// --- 3. Start reshare sessions ---
	// Existing parties act as overlap dealers, redistributing shares.
	// Party 4 is a new receiver with no prior share.
	sessions := make(map[tss.PartyID]*ReshareOverlapSession, len(newParties))
	queue := make([]tss.Envelope, 0)
	for _, id := range oldParties {
		session, out, err := StartReshareOverlap(shares[id], plan, nil)
		if err != nil {
			panic(err)
		}
		session.SetGuard(testCGGMP21Guard(id, tss.PartySet(newParties), sessionID))
		sessions[id] = session
		queue = append(queue, out...)
	}
	receiverSession, out, err := StartReshareReceiver(plan, 4, nil)
	if err != nil {
		panic(err)
	}
	receiverSession.SetGuard(testCGGMP21Guard(4, tss.PartySet(newParties), sessionID))
	sessions[4] = receiverSession
	queue = append(queue, out...)

	// --- 4. Route reshare messages ---
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range newParties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleReshareMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				panic(err)
			}
			queue = append(queue, out...)
		}
	}

	// --- 5. Collect new shares ---
	newShares := make(map[tss.PartyID]*KeyShare, len(newParties))
	for _, id := range newParties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("reshare not complete for party %d", id))
		}
		newShares[id] = share
	}

	// --- 6. Verify public key preserved and new party can sign ---
	pubPreserved := bytes.Equal(newShares[1].PublicKeyBytes(), oldPub)
	fmt.Println("public key preserved:", pubPreserved)

	signers := []*KeyShare{newShares[2], newShares[4]}
	message := []byte("post-reshare signing")
	ctx := testPresignContext()
	pub, sig, err := Sign(message, signers, ctx)
	if err != nil {
		panic(err)
	}
	request := SignRequest{Context: ctx, Message: message, LowS: true}
	fmt.Println(VerifySignature(pub, request, sig))
	// Output:
	// public key preserved: true
	// true
}

// ExampleDeriveNonHardenedBIP32 demonstrates BIP32 non-hardened HD
// derivation for threshold ECDSA. The keygen produces HD-enabled shares
// with a chain code; DeriveNonHardenedBIP32 computes the child public key
// and additive shift; the presign embeds the derivation path so the online
// signing session applies the shift and produces a signature that verifies
// against the derived child key.
func ExampleDeriveNonHardenedBIP32() {
	// --- 1. Keygen with HD enabled ---
	parties := []tss.PartyID{1, 2, 3}
	shares := runCGGMPKeygenWithOptions(parties, 2, KeygenOptions{EnableHD: true})

	// --- 2. Derive a child key at path m/0/1 ---
	path := []uint32{0, 1}
	result, err := DeriveNonHardenedBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		panic(err)
	}
	childPub := result.ChildPublicKey

	// --- 3. Presign with the derivation path ---
	ctx := testPresignContext()
	ctx.DerivationPath = path
	signers := []tss.PartyID{1, 2}
	presigns := runCGGMPPresignWithContext(shares, signers, ctx)

	// --- 4. Sign with the derivation path in the request ---
	request := SignRequest{
		Context: ctx,
		Message: []byte("bip32 derived signing"),
		LowS:    true,
	}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := StartSign(shares[id], presigns[id], signID, request)
		if err != nil {
			panic(err)
		}
		session.SetGuard(testCGGMP21Guard(id, tss.PartySet(parties), signID))
		sessions[id] = session
		messages = append(messages, out...)
	}
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleSignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				panic(err)
			}
			messages = append(messages, out...)
		}
	}
	sig, ok := sessions[1].Signature()
	if !ok {
		panic("signature not completed")
	}

	// --- 5. Verify against the derived child key ---
	fmt.Println(VerifySignature(childPub, request, sig))

	// --- 6. The signature should NOT verify against the parent key ---
	fmt.Println(VerifySignature(shares[1].PublicKey, request, sig))
	// Output:
	// true
	// false
}

// Example_serialization demonstrates KeyShare and Presign binary round-trips
// after a real CGGMP21 keygen and presign. This is the canonical pattern
// for persisting and restoring protocol state.
func Example_serialization() {
	// --- 1. Generate a key share ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	keygen, _, err := StartKeygen(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   []tss.PartyID{1},
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		panic(err)
	}
	share, ok := keygen.KeyShare()
	if !ok {
		panic("keygen did not complete")
	}

	// --- 2. KeyShare round-trip ---
	rawShare, err := share.MarshalBinary()
	if err != nil {
		panic(err)
	}
	restoredShare, err := UnmarshalKeyShare(rawShare)
	if err != nil {
		panic(err)
	}
	shareOK := bytes.Equal(restoredShare.PublicKeyBytes(), share.PublicKeyBytes())
	fmt.Println("key share round-trip:", shareOK)

	// --- 3. Generate a presign ---
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	ctx := testPresignContext()
	ps, _, err := StartPresignWithContext(restoredShare, presignID, []tss.PartyID{1}, ctx)
	if err != nil {
		panic(err)
	}
	presign, ok := ps.Presign()
	if !ok {
		panic("presign did not complete")
	}

	// --- 4. Presign round-trip ---
	rawPresign, err := presign.MarshalBinary()
	if err != nil {
		panic(err)
	}
	restoredPresign, err := UnmarshalPresign(rawPresign)
	if err != nil {
		panic(err)
	}
	presignOK := !restoredPresign.Consumed
	fmt.Println("presign round-trip:", presignOK)
	// Output:
	// key share round-trip: true
	// presign round-trip: true
}

// --- Integration example helpers ---
//
// These helpers encapsulate the message-routing boilerplate shared across
// multi-party examples. They mirror the pattern used in the production
// integration tests.

// runCGGMPKeygen performs an interactive CGGMP21 DKG for the given parties
// and returns the completed key shares.
func runCGGMPKeygen(parties []tss.PartyID, threshold int) map[tss.PartyID]*KeyShare {
	return runCGGMPKeygenWithOptions(parties, threshold, KeygenOptions{})
}

// runCGGMPKeygenWithOptions performs an interactive CGGMP21 DKG with the
// given options (e.g. EnableHD) and returns the completed key shares.
func runCGGMPKeygenWithOptions(parties []tss.PartyID, threshold int, opts KeygenOptions) map[tss.PartyID]*KeyShare {
	n := len(parties)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	// Start keygen for each party.
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygenWithOptions(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		}, opts)
		if err != nil {
			panic(err)
		}
		kg.SetGuard(testCGGMP21Guard(id, tss.PartySet(parties), sessionID))
		sessions[id] = kg
		queue = append(queue, out...)
	}

	// Route messages until the DKG converges.
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleKeygenMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				panic(err)
			}
			queue = append(queue, out...)
		}
	}

	// Collect completed shares.
	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		ks, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("keygen not complete for party %d", id))
		}
		shares[id] = ks
	}
	return shares
}

// runCGGMPPresign performs an interactive CGGMP21 presign for the given
// signers and returns the completed presign records.
func runCGGMPPresign(shares map[tss.PartyID]*KeyShare, signers []tss.PartyID) map[tss.PartyID]*Presign {
	return runCGGMPPresignWithContext(shares, signers, testPresignContext())
}

// runCGGMPPresignWithContext performs an interactive CGGMP21 presign with
// the given PresignContext (which may include a derivation path for BIP32).
func runCGGMPPresignWithContext(shares map[tss.PartyID]*KeyShare, signers []tss.PartyID, ctx PresignContext) map[tss.PartyID]*Presign {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	// Determine the full party set from the first share.
	first := shares[signers[0]]
	allParties := tss.PartySet(first.Parties)

	// Start presign for each signer.
	sessions := make(map[tss.PartyID]*PresignSession, len(signers))
	queue := make([]tss.Envelope, 0)
	for _, id := range signers {
		ps, out, err := StartPresignWithContext(shares[id], sessionID, signers, ctx)
		if err != nil {
			panic(err)
		}
		ps.SetGuard(testCGGMP21Guard(id, allParties, sessionID))
		sessions[id] = ps
		queue = append(queue, out...)
	}

	// Route presign messages.
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandlePresignMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				panic(err)
			}
			queue = append(queue, out...)
		}
	}

	// Collect completed presign records.
	presigns := make(map[tss.PartyID]*Presign, len(signers))
	for _, id := range signers {
		ps, ok := sessions[id].Presign()
		if !ok {
			panic(fmt.Sprintf("presign not complete for party %d", id))
		}
		// Clone so the session can be garbage-collected.
		presigns[id] = ps.Clone()
	}
	return presigns
}
