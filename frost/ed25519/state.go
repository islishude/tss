// Package ed25519 implements FROST Ed25519 threshold signatures.
//
// Session types (SignSession, KeygenSession, ReshareSession) serialize message
// handling internally, so concurrent delivery cannot race state mutation.
//
// Duplicate messages with identical payloads are ignored and do not change
// session state. Sending a different payload for the same round and sender pair
// is rejected as equivocation with ErrCodeVerification.
package ed25519

import (
	"errors"

	"github.com/islishude/tss"
)

func completedSessionError(round uint8, party tss.PartyID) *tss.ProtocolError {
	return tss.NewProtocolError(tss.ErrCodeCompleted, round, party, errors.New("session already completed"))
}

func abortedSessionError(round uint8, party tss.PartyID) *tss.ProtocolError {
	return tss.NewProtocolError(tss.ErrCodeAborted, round, party, errors.New("session already aborted"))
}

func shouldAbortSession(err error) bool {
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) {
		return false
	}
	if protocolErr.Code == tss.ErrCodeDuplicate {
		return false
	}
	if protocolErr.Code == tss.ErrCodeVerification && errors.Is(protocolErr.Err, tss.ErrPlanHashMismatch) {
		return false
	}
	return protocolErr.Code == tss.ErrCodeVerification ||
		protocolErr.Code == tss.ErrCodeInvariant ||
		protocolErr.Blame != nil
}
