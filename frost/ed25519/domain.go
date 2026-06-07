package ed25519

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// RFC 9591 Section 5.4.1 defines the Ed25519 ciphersuite context string.
const rfc9591ContextString = "FROST-ED25519-SHA512-v1"

const (
	frostKeygenTranscriptLabel  = "frost-ed25519-keygen-transcript-v1"
	frostReshareTranscriptLabel = "frost-ed25519-reshare-transcript-v1"
)

func frostKeygenTranscriptHash(sessionID tss.SessionID, threshold int, parties []tss.PartyID, chainCode []byte, dealerCommitments map[tss.PartyID][][]byte, groupCommitments [][]byte, verificationShares []VerificationShare) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(rfc9591ContextString))
	wire.WriteHashPart(h, []byte(frostKeygenTranscriptLabel))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, sessionID[:])
	wire.WriteHashPart(h, wire.Uint32(uint32(threshold)))
	wire.WritePartySet(h, parties)
	wire.WriteHashPart(h, chainCode)
	for _, id := range parties {
		wire.WritePartyID(h, id)
		wire.WriteHashPart(h, wire.EncodeBytesList(dealerCommitments[id]))
	}
	for _, commitment := range groupCommitments {
		wire.WriteHashPart(h, commitment)
	}
	for _, share := range verificationShares {
		wire.WritePartyID(h, share.Party)
		wire.WriteHashPart(h, share.PublicKey)
	}
	return h.Sum(nil)
}

func frostReshareTranscriptHash(sessionID tss.SessionID, oldParties, newParties []tss.PartyID, newThreshold int, oldPublicKey, chainCode []byte, refreshMode bool, dealerCommitments map[tss.PartyID][][]byte, newCommitments [][]byte, verificationShares []VerificationShare) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(rfc9591ContextString))
	wire.WriteHashPart(h, []byte(frostReshareTranscriptLabel))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, sessionID[:])
	wire.WritePartySet(h, oldParties)
	wire.WritePartySet(h, newParties)
	wire.WriteHashPart(h, wire.Uint32(uint32(newThreshold)))
	wire.WriteHashPart(h, oldPublicKey)
	wire.WriteHashPart(h, chainCode)
	wire.WriteHashPart(h, wire.Bool(refreshMode))
	for _, dealer := range oldParties {
		wire.WritePartyID(h, dealer)
		wire.WriteHashPart(h, wire.EncodeBytesList(dealerCommitments[dealer]))
	}
	for _, commitment := range newCommitments {
		wire.WriteHashPart(h, commitment)
	}
	for _, share := range verificationShares {
		wire.WritePartyID(h, share.Party)
		wire.WriteHashPart(h, share.PublicKey)
	}
	return h.Sum(nil)
}
