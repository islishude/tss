package secp256k1

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/codec"
)

const proofDomainVersion = "cggmp21-secp256k1-proof-domain-v2"

type proofDomainContext struct {
	label                string
	sessionID            tss.SessionID
	threshold            int
	parties              []tss.PartyID
	signers              []tss.PartyID
	sender               tss.PartyID
	receiver             tss.PartyID
	kind                 string
	publicKey            []byte
	keygenTranscriptHash []byte
	paillierPublicKey    []byte
}

func keygenModulusDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             "keygen.modulus",
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              "paillier-modulus",
		paillierPublicKey: paillierPublicKey,
	})
}

func keySharePaillierProofDomain(key *KeyShare) []byte {
	if key == nil {
		return nil
	}
	return proofDomain(proofDomainContext{
		label:                "keyshare.paillier-modulus",
		threshold:            key.Threshold,
		parties:              key.Parties,
		sender:               key.Party,
		kind:                 "paillier-modulus",
		publicKey:            key.PublicKey,
		keygenTranscriptHash: key.KeygenTranscriptHash,
		paillierPublicKey:    key.PaillierPublicKey,
	})
}

func mtaStartDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, owner tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:                "presign.mta-start",
		sessionID:            sessionID,
		threshold:            key.Threshold,
		parties:              key.Parties,
		signers:              signers,
		sender:               owner,
		kind:                 "encrypted-k",
		publicKey:            key.PublicKey,
		keygenTranscriptHash: key.KeygenTranscriptHash,
		paillierPublicKey:    paillierPublicKey,
	})
}

func mtaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, kind string, initiatorPaillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:                "presign.mta-response",
		sessionID:            sessionID,
		threshold:            key.Threshold,
		parties:              key.Parties,
		signers:              signers,
		sender:               responder,
		receiver:             initiator,
		kind:                 kind,
		publicKey:            key.PublicKey,
		keygenTranscriptHash: key.KeygenTranscriptHash,
		paillierPublicKey:    initiatorPaillierPublicKey,
	})
}

func proofDomain(ctx proofDomainContext) []byte {
	h := sha256.New()
	writeHashPart(h, []byte(proofDomainVersion))
	writeHashPart(h, []byte(protocol))
	writeHashPart(h, codec.Uint32(uint32(tss.Version)))
	writeHashPart(h, []byte(ctx.label))
	writeHashPart(h, ctx.sessionID[:])
	writeHashPart(h, codec.Uint32(uint32(ctx.threshold)))
	writePartySet(h, ctx.parties)
	writePartySet(h, ctx.signers)
	writePartyID(h, ctx.sender)
	writePartyID(h, ctx.receiver)
	writeHashPart(h, []byte(ctx.kind))
	writeHashPart(h, ctx.publicKey)
	writeHashPart(h, ctx.keygenTranscriptHash)
	writeHashPart(h, ctx.paillierPublicKey)
	return h.Sum(nil)
}

func writePartySet(h interface{ Write([]byte) (int, error) }, parties []tss.PartyID) {
	writeHashPart(h, codec.Uint32(uint32(len(parties))))
	for _, id := range parties {
		writePartyID(h, id)
	}
}

func writePartyID(h interface{ Write([]byte) (int, error) }, id tss.PartyID) {
	writeHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
}
