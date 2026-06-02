package secp256k1

import (
	"errors"

	"github.com/islishude/tss"
)

func testPresignContext() PresignContext {
	return PresignContext{
		KeyID:         "test-key",
		ChainID:       "test-chain",
		PolicyDomain:  "test-policy",
		MessageDomain: "test-message",
	}
}

func StartPresign(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID) (*PresignSession, []tss.Envelope, error) {
	return StartPresignWithContext(key, sessionID, signers, testPresignContext())
}

func StartSignDigest(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte) (*SignSession, []tss.Envelope, error) {
	if presign == nil {
		return nil, nil, errors.New("nil presign")
	}
	return startSignDigestBound(key, presign, sessionID, digest32, presign.ContextHash, true)
}

func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	return SignDigestInteractive(digest32, signers, testPresignContext())
}
