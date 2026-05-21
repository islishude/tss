package tss

import "fmt"

const (
	ErrCodeInvalidConfig  = "invalid_config"
	ErrCodeInvalidMessage = "invalid_message"
	ErrCodeDuplicate      = "duplicate_message"
	ErrCodeRound          = "wrong_round"
	ErrCodeVerification   = "verification_failed"
	ErrCodeNotReady       = "not_ready"
	ErrCodeConsumed       = "consumed"
	ErrCodeNotImplemented = "not_implemented"
)

type ProtocolError struct {
	Code  string
	Round uint8
	Party PartyID
	Blame *Blame
	Err   error
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := e.Code
	if e.Round != 0 {
		msg = fmt.Sprintf("%s round=%d", msg, e.Round)
	}
	if e.Party != 0 {
		msg = fmt.Sprintf("%s party=%d", msg, e.Party)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e *ProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewProtocolError(code string, round uint8, party PartyID, err error) *ProtocolError {
	return &ProtocolError{Code: code, Round: round, Party: party, Err: err}
}
