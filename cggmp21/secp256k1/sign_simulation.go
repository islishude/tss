package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
)

// Sign runs an in-memory presign and signing exchange for a context-bound message.
func Sign(message []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	return signWithDigest(message, signers, ctx, false)
}

// SignDigestInteractive runs a full interactive signing exchange for a raw
// digest after binding ctx before nonce generation. It does not return or
// persist a reusable Presign.
func SignDigestInteractive(digest32 []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	return signWithDigest(digest32, signers, ctx, true)
}

func signWithDigest(input []byte, signers []*KeyShare, ctx PresignContext, rawDigest bool) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.requireMPCMaterial(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.Party
		shares[share.Party] = share
	}
	ids = tss.SortParties(ids)
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	presignSessions := make(map[tss.PartyID]*PresignSession, len(ids))
	presignQueue := make([]tss.Envelope, 0)
	for _, id := range ids {
		session, out, err := StartPresignWithContext(shares[id], presignID, ids, ctx)
		if err != nil {
			return nil, nil, err
		}
		presignSessions[id] = session
		presignQueue = append(presignQueue, out...)
	}
	for len(presignQueue) > 0 {
		env := presignQueue[0]
		presignQueue = presignQueue[1:]
		for _, id := range ids {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].HandlePresignMessage(env)
			if err != nil {
				return nil, nil, err
			}
			presignQueue = append(presignQueue, out...)
		}
	}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	signSessions := make(map[tss.PartyID]*SignSession, len(ids))
	signMessages := make([]tss.Envelope, 0, len(ids))
	for _, id := range ids {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			return nil, nil, fmt.Errorf("presign not completed for %d", id)
		}
		var session *SignSession
		var out []tss.Envelope
		var err error
		if rawDigest {
			session, out, err = startSignDigestBound(shares[id], presign, signID, input, presign.ContextHash, true, nil)
		} else {
			session, out, err = StartSign(shares[id], presign, signID, SignRequest{
				Context: ctx,
				Message: input,
				LowS:    true,
			})
		}
		if err != nil {
			return nil, nil, err
		}
		signSessions[id] = session
		signMessages = append(signMessages, out...)
	}
	for _, env := range signMessages {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if _, err := signSessions[id].HandleSignMessage(env); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, id := range ids {
		if sig, ok := signSessions[id].Signature(); ok {
			return append([]byte(nil), signSessions[id].publicKey...), sig, nil
		}
	}
	return nil, nil, errors.New("signature not completed")
}
