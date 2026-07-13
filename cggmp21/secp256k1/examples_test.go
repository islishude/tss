package secp256k1_test

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/islishude/tss"
	cggmp "github.com/islishude/tss/cggmp21/secp256k1"
)

// ExampleNewTrustedDealerImport demonstrates creation of a public import plan
// and one confidential contribution per participant. The contributions must be
// provisioned through a caller-managed confidential channel.
func ExampleNewTrustedDealerImport() {
	encoded := make([]byte, 32)
	encoded[31] = 7
	secretKey, err := cggmp.ParseSecretKey(encoded)
	if err != nil {
		panic(err)
	}
	defer secretKey.Destroy()
	var sessionID tss.SessionID
	sessionID[31] = 2
	plan, contributions, err := cggmp.NewTrustedDealerImport(secretKey, cggmp.TrustedDealerImportOption{
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
		ChainCode: bytes.Repeat([]byte{0x45}, 32),
	}, nil)
	if err != nil {
		panic(err)
	}
	for _, contribution := range contributions {
		defer contribution.Destroy()
	}
	snapshot, _ := plan.Snapshot()
	fmt.Println(snapshot.Threshold, len(contributions))
	// Output: 2 2
}

// ExampleVerifyDigest verifies a fixed public CGGMP21 protocol vector.
func ExampleVerifyDigest() {
	publicKey, err := hex.DecodeString("0232b6a8d851397f9564a05f7a1d2a873266471d3ee513b8fd977244ceef056a38")
	if err != nil {
		panic(err)
	}
	digest, err := hex.DecodeString("0360ea0d1a3b6b7db198b31c22e8d93d8d7976b43e3e89676755bdd31ceed1f5")
	if err != nil {
		panic(err)
	}
	r, err := hex.DecodeString("ac99b283cdd4f3024da08ced4088bd9445bb08c8660541316189d9a642dc60f2")
	if err != nil {
		panic(err)
	}
	s, err := hex.DecodeString("6cecc6ba1b1d26d6c616157402d915990b4037cd75d9a2e9743c24a1465a6c23")
	if err != nil {
		panic(err)
	}

	fmt.Println(cggmp.VerifyDigest(publicKey, digest, &cggmp.Signature{R: r, S: s}))
	// Output:
	// true
}

// ExampleVerifyBlameEvidence verifies a fixed, public-only evidence vector.
func ExampleVerifyBlameEvidence() {
	encoded, err := hex.DecodeString(
		"5453533100097473732e626c616d650001000b0001000000116367676d7032312d736563703235366b31000200000020444444444444444444444444444444444444444444444444444444444444444400030000000101000400000004000000010005000000040000000000060000001e6367676d7032312e736563703235366b312e7369676e2e7061727469616c0007000000203a6d26e75af02fd981bf250052015a218be16d30cae3da5a580d374be1d25b9e000800000020674d31c3dc1f2c771ac22d209937be45297827a5fbd95ef900c1b4d752657b0900090000000c7369676e5f7061727469616c000a00000014696e76616c6964207369676e207061727469616c000b0000000400000000")
	if err != nil {
		panic(err)
	}
	sessionID, err := tss.NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x44}, 32)))
	if err != nil {
		panic(err)
	}

	err = cggmp.VerifyBlameEvidence(encoded, cggmp.EvidenceContext{SessionID: sessionID})
	fmt.Println(err == nil)
	// Output:
	// true
}
