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

	r, s, err := secp.SignECDSAWithNonce(digest[:], secp.ScalarFromBigInt(secret), secp.ScalarFromBigInt(nonce), true)
	if err != nil {
		panic(err)
	}
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(secret)))
	if err != nil {
		panic(err)
	}
	signature := &Signature{R: secp.ScalarBytes(r), S: secp.ScalarBytes(s)}

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
	ps, _, err := StartPresign(loaded, presignID, []tss.PartyID{1})
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
	digest := sha256.Sum256([]byte("example full lifecycle"))
	ss, _, err := StartSignDigest(loaded, loadedPresign, signID, digest[:])
	if err != nil {
		panic(err)
	}
	sig, ok := ss.Signature()
	if !ok {
		panic("signing did not complete")
	}

	fmt.Println(VerifyDigest(loaded.PublicKeyBytes(), digest[:], sig))
	// Output:
	// true
}
