package secp256k1

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const (
	proofDomainVersion = "cggmp21-secp256k1-proof-domain-v1"

	// Domain labels identify the protocol phase for domain separation.
	domainLabelKeygenModulus      = "keygen.modulus"
	domainLabelKeySharePaillier   = "keyshare.paillier-modulus"
	domainLabelPresignMTAStart    = "presign.mta-start"
	domainLabelPresignMTAResponse = "presign.mta-response"
	domainLabelResharePaillier    = "reshare.paillier-modulus"
	domainLabelRefreshPaillier    = "refresh.paillier-modulus"

	// Domain kinds identify the cryptographic object bound into a proof.
	domainKindPaillierModulus = "paillier-modulus"
	domainKindEncryptedK      = "encrypted-k"
)

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
		label:             domainLabelKeygenModulus,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              domainKindPaillierModulus,
		paillierPublicKey: paillierPublicKey,
	})
}

func keySharePaillierProofDomain(key *KeyShare) []byte {
	if key == nil {
		return nil
	}
	return proofDomain(proofDomainContext{
		label:                domainLabelKeySharePaillier,
		threshold:            key.Threshold,
		parties:              key.Parties,
		sender:               key.Party,
		kind:                 domainKindPaillierModulus,
		publicKey:            key.PublicKey,
		keygenTranscriptHash: key.KeygenTranscriptHash,
		paillierPublicKey:    key.PaillierPublicKey,
	})
}

func mtaStartDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, owner tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:                domainLabelPresignMTAStart,
		sessionID:            sessionID,
		threshold:            key.Threshold,
		parties:              key.Parties,
		signers:              signers,
		sender:               owner,
		kind:                 domainKindEncryptedK,
		publicKey:            key.PublicKey,
		keygenTranscriptHash: key.KeygenTranscriptHash,
		paillierPublicKey:    paillierPublicKey,
	})
}

func resharePaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelResharePaillier,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              domainKindPaillierModulus,
		paillierPublicKey: paillierPublicKey,
	})
}

func refreshPaillierDomain(config tss.ThresholdConfig, sender tss.PartyID, paillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:             domainLabelRefreshPaillier,
		sessionID:         config.SessionID,
		threshold:         config.Threshold,
		parties:           config.Parties,
		sender:            sender,
		kind:              domainKindPaillierModulus,
		paillierPublicKey: paillierPublicKey,
	})
}

func mtaResponseDomain(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, initiator, responder tss.PartyID, kind string, initiatorPaillierPublicKey []byte) []byte {
	return proofDomain(proofDomainContext{
		label:                domainLabelPresignMTAResponse,
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
	wire.WriteHashPart(h, []byte(proofDomainVersion))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, []byte(ctx.label))
	wire.WriteHashPart(h, ctx.sessionID[:])
	wire.WriteHashPart(h, wire.Uint32(uint32(ctx.threshold)))
	wire.WritePartySet(h, ctx.parties)
	wire.WritePartySet(h, ctx.signers)
	wire.WritePartyID(h, ctx.sender)
	wire.WritePartyID(h, ctx.receiver)
	wire.WriteHashPart(h, []byte(ctx.kind))
	wire.WriteHashPart(h, ctx.publicKey)
	wire.WriteHashPart(h, ctx.keygenTranscriptHash)
	wire.WriteHashPart(h, ctx.paillierPublicKey)
	return h.Sum(nil)
}
