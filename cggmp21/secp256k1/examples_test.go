package secp256k1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire/wireutil"
)

func ExampleVerifyDigest() {
	digest := sha256.Sum256([]byte("hello secp256k1"))
	secret, err := secp.RandomScalar(rand.Reader)
	if err != nil {
		panic(err)
	}

	r, s, err := secp.SignECDSA(rand.Reader, digest[:], secret, true)
	if err != nil {
		panic(err)
	}
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secret))
	if err != nil {
		panic(err)
	}
	signature := &Signature{R: r.Bytes(), S: s.Bytes()}

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
		{Key: evidenceFieldPartiesHash, Value: wireutil.PartySetHash([]tss.PartyID{1}, partySetHashLabel)},
		{Key: evidenceFieldSignerSetHash, Value: wireutil.PartySetHash([]tss.PartyID{1}, partySetHashLabel)},
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
