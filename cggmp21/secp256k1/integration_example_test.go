//go:build integration

package secp256k1

import (
	"fmt"

	"github.com/islishude/tss"
)

// Example_full_lifecycle demonstrates the complete CGGMP21 lifecycle: keygen,
// serialization, presign, and signing. It requires the
// integration build tag because it generates a Paillier key.
func Example_full_lifecycle() {
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

	raw, err := share.MarshalBinary()
	if err != nil {
		panic(err)
	}
	loaded, err := UnmarshalKeyShare(raw)
	if err != nil {
		panic(err)
	}

	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	ctx := PresignContext{KeyID: "example-key", ChainID: "example-chain", PolicyDomain: "example-policy", MessageDomain: "example-message"}
	ps, _, err := StartPresignWithContext(loaded, presignID, []tss.PartyID{1}, ctx)
	if err != nil {
		panic(err)
	}
	presign, ok := ps.Presign()
	if !ok {
		panic("presign did not complete")
	}

	rawPresign, err := presign.MarshalBinary()
	if err != nil {
		panic(err)
	}
	loadedPresign, err := UnmarshalPresign(rawPresign)
	if err != nil {
		panic(err)
	}

	signID, err := tss.NewSessionID(nil)
	if err != nil {
		panic(err)
	}
	request := SignRequest{Context: ctx, Message: []byte("example full lifecycle"), LowS: true}
	ss, _, err := StartSign(loaded, loadedPresign, signID, request)
	if err != nil {
		panic(err)
	}
	sig, ok := ss.Signature()
	if !ok {
		panic("signing did not complete")
	}

	fmt.Println(VerifySignature(loaded.PublicKeyBytes(), request, sig))
	// Output:
	// true
}
