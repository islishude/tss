package secp256k1

import (
	"fmt"

	"github.com/islishude/tss"
)

type presignEarlyMessageError struct {
	payloadType tss.PayloadType
	from        tss.PartyID
	missing     string
}

// Error describes the presign prerequisite that has not been accepted yet.
func (e *presignEarlyMessageError) Error() string {
	return fmt.Sprintf("early %s from party %d: %s is not ready", e.payloadType, e.from, e.missing)
}

// validatePresignInboundReadiness checks protocol prerequisites without
// touching replay state. Handle must call it after stateless envelope-policy
// validation and before the full replay-committing guard validation.
func (s *PresignSession) validatePresignInboundReadiness(env tss.Envelope) error {
	var missing string
	switch env.PayloadType {
	case payloadPresignRound2:
		if !s.allRound1PayloadsAccepted() || !s.allRound1Verified() {
			missing = "complete verified round1 state"
		}
	case payloadPresignRound3:
		if !s.allRound2Accepted() {
			missing = "complete verified round2 state"
		}
	}
	if missing == "" {
		return nil
	}
	cause := &presignEarlyMessageError{payloadType: env.PayloadType, from: env.From, missing: missing}
	return tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, cause)
}
