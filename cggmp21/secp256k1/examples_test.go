package secp256k1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
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

func Example_full_lifecycle() {
	// Use small Paillier keys for fast example execution.
	reset := SetDefaultPaillierBitsForTesting(768)
	defer reset()

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
