package ed25519

import (
	stded25519 "crypto/ed25519"
	"fmt"

	"github.com/islishude/tss"
)

func ExampleSign() {
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

	message := []byte("hello frost")
	publicKey, signature, err := Sign(message, []*KeyShare{share})
	if err != nil {
		panic(err)
	}

	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}

func ExampleSign_multiParty() {
	const threshold, n = 2, 3
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}

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
		sessions[id] = kg
		messages = append(messages, out...)
	}

	for _, env := range messages {
		for _, id := range parties {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				panic(err)
			}
		}
	}

	shares := make([]*KeyShare, n)
	for i, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			panic("keygen did not complete")
		}
		shares[i] = share
	}

	message := []byte("hello frost multi-party")
	signers := []*KeyShare{shares[0], shares[1]}
	publicKey, signature, err := Sign(message, signers)
	if err != nil {
		panic(err)
	}

	fmt.Println(stded25519.Verify(stded25519.PublicKey(publicKey), message, signature))
	// Output:
	// true
}
