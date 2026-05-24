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
