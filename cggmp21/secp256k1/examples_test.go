package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func ExampleVerifyDigest() {
	digest := sha256.Sum256([]byte("hello secp256k1"))
	secret := big.NewInt(1)
	nonce := big.NewInt(2)

	r, s, err := secp.SignECDSAWithNonce(digest[:], secret, nonce, true)
	if err != nil {
		panic(err)
	}
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secret))
	if err != nil {
		panic(err)
	}
	signature := &Signature{R: scalarBytes(r), S: scalarBytes(s)}

	fmt.Println(VerifyDigest(publicKey, digest[:], signature))
	// Output:
	// true
}

func ExampleVerifyBlameEvidence() {
	sessionID, err := tss.NewSessionID(bytes.NewReader(bytes.Repeat([]byte{0x44}, 32)))
	if err != nil {
		panic(err)
	}
	envelope := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        1,
		PayloadType: payloadSignPartial,
		Payload:     []byte("bad sign partial"),
	}.WithTranscriptHash()
	evidence, err := tss.NewBlameEvidence(envelope, tss.EvidenceKindSignPartial, "invalid sign partial", []tss.EvidenceField{
		{Key: evidenceFieldPartiesHash, Value: partySetHash([]tss.PartyID{1})},
		{Key: evidenceFieldSignerSetHash, Value: partySetHash([]tss.PartyID{1})},
	})
	if err != nil {
		panic(err)
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		panic(err)
	}

	err = VerifyBlameEvidence(encoded, EvidenceContext{
		SessionID: sessionID,
		Parties:   []tss.PartyID{1},
		Signers:   []tss.PartyID{1},
	})
	fmt.Println(err == nil)
	// Output:
	// true
}
