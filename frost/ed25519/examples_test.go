package ed25519

import (
	stded25519 "crypto/ed25519"
	"fmt"

	"github.com/islishude/tss"
)

// ExampleSign demonstrates the simplest FROST Ed25519 flow: single-party
// keygen followed by signing. For 1-of-1 the [Sign] convenience function
// performs keygen and signing in one call without any message routing.
func ExampleSign() {
	// --- 1. Generate a session ID ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	// --- 2. Start keygen — for 1-of-1 this completes immediately ---
	keygen, _, err := StartKeygen(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   []tss.PartyID{1},
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		panic(err)
	}

	// --- 3. Retrieve the completed key share ---
	share, ok := keygen.KeyShare()
	if !ok {
		panic("keygen did not complete")
	}

	// --- 4. Sign a message ---
	// Sign performs the full two-round FROST signing protocol locally.
	// It returns the group public key and an Ed25519-compatible signature.
	message := []byte("hello frost")
	publicKey, signature, err := Sign(message, []*KeyShare{share})
	if err != nil {
		panic(err)
	}

	// --- 5. Verify with the standard library ---
	// FROST Ed25519 signatures are compatible with crypto/ed25519.
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}

// ExampleSign_multiParty demonstrates a 2-of-3 FROST Ed25519 signing flow
// with interactive message routing. Each party runs a local keygen session;
// messages are collected in a queue and delivered to recipients until the
// DKG converges. Two of the three shares then produce a threshold signature.
func ExampleSign_multiParty() {
	const threshold, n = 2, 3

	// --- 1. Create a session ID shared by all parties ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	// --- 2. Build the sorted party list ---
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}

	// --- 3. Start keygen for every party ---
	// Each party emits initial messages. Sessions need a guard that
	// validates inbound envelopes before the protocol handler sees them.
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			panic(err)
		}
		// testFROSTGuard creates a guard with the FROST policy set and
		// relaxed broadcast consistency (suitable for examples without
		// a broadcast certificate infrastructure).
		kg.SetGuard(testFROSTGuard(id, tss.PartySet(parties), sessionID))
		sessions[id] = kg
		messages = append(messages, out...)
	}

	// --- 4. Route messages until the DKG finishes ---
	// Messages are delivered to all parties except the sender; point-to-point
	// messages (To != 0) are delivered only to the named recipient.
	// Transport authentication is simulated by setting Security.Authenticated.
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]
		for _, id := range parties {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			out, err := sessions[id].HandleKeygenMessage(deliverEnv(env))
			if err != nil {
				panic(err)
			}
			messages = append(messages, out...)
		}
	}

	// --- 5. Collect completed key shares ---
	shares := make([]*KeyShare, n)
	for i, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic("keygen did not complete")
		}
		shares[i] = share
	}

	// --- 6. Sign with a threshold subset (parties 1 and 2) ---
	message := []byte("hello frost multi-party")
	signers := []*KeyShare{shares[0], shares[1]}
	publicKey, signature, err := Sign(message, signers)
	if err != nil {
		panic(err)
	}

	// --- 7. Verify with the standard library ---
	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}

// ExampleKeyShare demonstrates marshaling a key share to binary and
// unmarshaling it back via [KeyShare.MarshalBinary] and [UnmarshalKeyShare].
// This is the canonical pattern for persisting shares to disk or
// transmitting them over a secure channel.
func ExampleKeyShare() {
	// --- 1. Generate a key share via a 1-of-1 keygen ---
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

	// --- 2. Serialize to binary ---
	raw, err := share.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// --- 3. Deserialize from binary ---
	loaded, err := UnmarshalKeyShare(raw)
	if err != nil {
		panic(err)
	}

	// --- 4. Sign with the round-tripped share ---
	message := []byte("roundtrip test")
	pub, sig, err := Sign(message, []*KeyShare{loaded})
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(pub), message, sig))
	// Output:
	// true
}

// ExampleStartRefresh demonstrates a 2-of-3 proactive refresh. After
// refresh, each party holds a new share of the same group public key.
// Old shares become incompatible with the new sharing and cannot be used
// for signing.
func ExampleStartRefresh() {
	const threshold, n = 2, 3

	// --- 1. Run an initial DKG to obtain shares ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	parties := []tss.PartyID{1, 2, 3}
	shares, _ := runFrostKeygen(parties, threshold, sessionID)
	oldPub := shares[1].PublicKeyBytes()

	// --- 2. Start refresh sessions for every party ---
	// Refresh uses the same ReshareSession as resharing but keeps the
	// same party set. Each party generates fresh polynomial shares that
	// sum to zero, so the group secret is unchanged.
	refreshID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	sessions := make(map[tss.PartyID]*ReshareSession, n)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := StartRefresh(shares[id], tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: refreshID,
		})
		if err != nil {
			panic(err)
		}
		session.SetGuard(testFROSTGuard(id, tss.PartySet(parties), refreshID))
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
			out, err := sessions[id].HandleReshareMessage(deliverEnv(env))
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

	// --- 5. Verify the public key is preserved ---
	pubPreserved := string(newShares[1].PublicKeyBytes()) == string(oldPub)
	fmt.Println("public key preserved:", pubPreserved)

	// --- 6. Sign with refreshed shares ---
	signers := []*KeyShare{newShares[1], newShares[2]}
	message := []byte("post-refresh signing")
	pub, sig, err := Sign(message, signers)
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(pub), message, sig))
	// Output:
	// public key preserved: true
	// true
}

// ExampleStartReshare demonstrates changing the party set via resharing.
// A 2-of-3 group reshared to 2-of-4 adds a new party. The group public key
// is preserved, and the new party can participate in signing.
func ExampleStartReshare() {
	const oldThreshold, oldN = 2, 3
	const newThreshold, newN = 2, 4

	// --- 1. Run an initial DKG ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	oldParties := []tss.PartyID{1, 2, 3}
	shares, _ := runFrostKeygen(oldParties, oldThreshold, sessionID)
	oldPub := shares[1].PublicKeyBytes()

	// --- 2. Prepare the new party set (party 4 is added) ---
	newParties := []tss.PartyID{1, 2, 3, 4}

	// --- 3. Start reshare sessions for existing parties ---
	reshareID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}

	allPs := tss.PartySet{1, 2, 3, 4}
	sessions := make(map[tss.PartyID]*ReshareSession, newN)
	queue := make([]tss.Envelope, 0)

	// Existing parties act as dealers, redistributing their shares.
	for _, id := range oldParties {
		session, out, err := StartReshare(shares[id], newParties, newThreshold, tss.ThresholdConfig{
			Threshold: newThreshold,
			Parties:   oldParties,
			Self:      id,
			SessionID: reshareID,
		})
		if err != nil {
			panic(err)
		}
		session.SetGuard(testFROSTGuard(id, allPs, reshareID))
		sessions[id] = session
		queue = append(queue, out...)
	}

	// The new party starts as a recipient (no existing share).
	recipient, err := StartReshareRecipient(oldPub, nil, oldParties, newParties, newThreshold, tss.ThresholdConfig{
		Threshold: newThreshold,
		Parties:   oldParties,
		Self:      4,
		SessionID: reshareID,
	})
	if err != nil {
		panic(err)
	}
	recipient.SetGuard(testFROSTGuard(4, allPs, reshareID))
	sessions[4] = recipient

	// --- 4. Route reshare messages ---
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range newParties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleReshareMessage(deliverEnv(env))
			if err != nil {
				panic(err)
			}
			queue = append(queue, out...)
		}
	}

	// --- 5. Collect new shares ---
	newShares := make(map[tss.PartyID]*KeyShare, newN)
	for _, id := range newParties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("reshare not complete for party %d", id))
		}
		newShares[id] = share
	}

	// --- 6. Verify the public key is preserved and new party can sign ---
	pubPreserved := string(newShares[1].PublicKeyBytes()) == string(oldPub)
	fmt.Println("public key preserved:", pubPreserved)

	signers := []*KeyShare{newShares[2], newShares[4]}
	message := []byte("post-reshare signing")
	pub, sig, err := Sign(message, signers)
	if err != nil {
		panic(err)
	}
	fmt.Println(stded25519.Verify(stded25519.PublicKey(pub), message, sig))
	// Output:
	// public key preserved: true
	// true
}

// ExampleDeriveNonHardenedBIP32 demonstrates BIP32 non-hardened HD
// derivation for FROST Ed25519. The keygen produces HD-enabled shares
// with a chain code; DeriveNonHardenedBIP32 computes the child public
// key and additive shift; SignWithOptions applies the shift during
// signing so the resulting signature verifies against the derived
// child key.
func ExampleDeriveNonHardenedBIP32() {
	// --- 1. Run keygen with HD enabled ---
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	kg, _, err := StartKeygenWithOptions(tss.ThresholdConfig{
		Threshold: 1,
		Parties:   []tss.PartyID{1},
		Self:      1,
		SessionID: sessionID,
	}, KeygenOptions{EnableHD: true})
	if err != nil {
		panic(err)
	}
	share, ok := kg.KeyShare()
	if !ok {
		panic("keygen did not complete")
	}

	// --- 2. Derive a child key at path m/0/1 ---
	path := []uint32{0, 1}
	result, err := DeriveNonHardenedBIP32(share.PublicKey, share.ChainCode, path)
	if err != nil {
		panic(err)
	}
	childPub := result.ChildPublicKey

	// --- 3. Sign with the additive shift applied ---
	message := []byte("bip32 derived signing")
	_, sig, err := SignWithOptions(message, []*KeyShare{share}, SignOptions{
		AdditiveShift: result.AdditiveShift,
	})
	if err != nil {
		panic(err)
	}

	// --- 4. Verify against the derived child public key ---
	fmt.Println(stded25519.Verify(stded25519.PublicKey(childPub), message, sig))

	// --- 5. The signature should NOT verify against the parent key ---
	// HD derivation with additive shift produces a signature bound to the
	// child key. The parent key cannot verify it.
	fmt.Println(stded25519.Verify(stded25519.PublicKey(share.PublicKey), message, sig))
	// Output:
	// true
	// false
}

// runFrostKeygen is a helper that runs a full FROST DKG and returns
// the completed key shares. It is used by multi-party examples to
// avoid repeating the message-routing boilerplate.
func runFrostKeygen(parties []tss.PartyID, threshold int, sessionID tss.SessionID) (map[tss.PartyID]*KeyShare, tss.SessionID) {
	n := len(parties)
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	queue := make([]tss.Envelope, 0)

	for _, id := range parties {
		s, out, err := StartKeygen(tss.ThresholdConfig{
			Threshold: threshold,
			Parties:   parties,
			Self:      id,
			SessionID: sessionID,
		})
		if err != nil {
			panic(err)
		}
		s.SetGuard(testFROSTGuard(id, tss.PartySet(parties), sessionID))
		sessions[id] = s
		queue = append(queue, out...)
	}

	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleKeygenMessage(deliverEnv(env))
			if err != nil {
				panic(err)
			}
			queue = append(queue, out...)
		}
	}

	shares := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		ks, ok := sessions[id].KeyShare()
		if !ok {
			panic(fmt.Sprintf("keygen not complete for party %d", id))
		}
		shares[id] = ks
	}
	return shares, sessionID
}
