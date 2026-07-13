package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
)

var (
	errAuxInfoOutOfOrder           = errors.New("auxinfo message is out of order")
	errAuxInfoOutboundConstruction = errors.New("construct auxinfo outbound envelope")
)

func auxInfoPreparationError(env tss.Envelope, parties tss.PartySet, err error) error {
	switch {
	case errors.Is(err, tss.ErrDuplicateMessage):
		return tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, err)
	case errors.Is(err, errAuxInfoOutOfOrder):
		return tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, err)
	case errors.Is(err, errAuxInfoOutboundConstruction):
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, err)
	default:
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindPaillierAux,
			"invalid Figure 7 message",
			tss.NewPartySet(env.From),
			err,
			rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(parties, partySetHashLabel)),
		)
	}
}

func auxInfoOutOfOrder(message string) error {
	return fmt.Errorf("%w: %s", errAuxInfoOutOfOrder, message)
}

func auxInfoOutboundConstruction(err error) error {
	return fmt.Errorf("%w: %w", errAuxInfoOutboundConstruction, err)
}
