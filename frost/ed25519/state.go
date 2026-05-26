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
	return protocolErr.Code == tss.ErrCodeVerification || protocolErr.Blame != nil
}
