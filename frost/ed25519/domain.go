package ed25519

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// RFC 9591 Section 5.4.1 defines the Ed25519 ciphersuite context string.
const rfc9591ContextString = "FROST-ED25519-SHA512-v1"

const frostDomainVersion = "frost-ed25519-domain-v1"

// Domain labels identify the protocol phase for domain separation.
const (
	domainLabelKeygen = "keygen"
)

// Domain kinds identify the cryptographic object bound into a proof.
const (
	domainKindCommitment = "commitment"
)

// frostDomainContext carries the protocol-level fields that are bound into
// every FROST Ed25519 proof domain and transcript.
type frostDomainContext struct {
	label     string
	sessionID tss.SessionID
	threshold int
	parties   []tss.PartyID
	signers   []tss.PartyID
	sender    tss.PartyID
	receiver  tss.PartyID
	kind      string
	publicKey []byte
}

// keygenDomain returns the domain separator for DKG commitment transcripts.
func keygenDomain(sessionID tss.SessionID, threshold int, parties []tss.PartyID, sender tss.PartyID, publicKey []byte) []byte {
	return frostProofDomain(frostDomainContext{
		label:     domainLabelKeygen,
		sessionID: sessionID,
		threshold: threshold,
		parties:   parties,
		sender:    sender,
		kind:      domainKindCommitment,
		publicKey: publicKey,
	})
}

func frostProofDomain(ctx frostDomainContext) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(rfc9591ContextString))
	wire.WriteHashPart(h, []byte(frostDomainVersion))
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
	return h.Sum(nil)
}
