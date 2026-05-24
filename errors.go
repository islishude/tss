package tss

import "fmt"

const (
	// ErrCodeInvalidConfig marks invalid local protocol configuration.
	ErrCodeInvalidConfig = "invalid_config"
	// ErrCodeInvalidMessage marks malformed or cross-session protocol messages.
	ErrCodeInvalidMessage = "invalid_message"
	// ErrCodeDuplicate marks replayed or repeated messages for a round.
	ErrCodeDuplicate = "duplicate_message"
	// ErrCodeRound marks a message delivered to the wrong protocol round.
	ErrCodeRound = "wrong_round"
	// ErrCodeVerification marks a failed cryptographic or transcript check.
	ErrCodeVerification = "verification_failed"
	// ErrCodeNotReady marks a protocol state that has not collected enough messages.
	ErrCodeNotReady = "not_ready"
	// ErrCodeConsumed marks one-use material that has already been consumed.
	ErrCodeConsumed = "consumed"
	// ErrCodeNotImplemented marks intentionally unsupported protocol features.
	ErrCodeNotImplemented = "not_implemented"
)

// ProtocolError is the stable error shape returned by protocol state machines.
type ProtocolError struct {
	Code  string
	Round uint8
	Party PartyID
	Blame *Blame
	Err   error
}

// Error formats the protocol code with optional round, party, and wrapped error.
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

// Unwrap returns the underlying error for errors.Is/errors.As callers.
func (e *ProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewProtocolError constructs a ProtocolError without blame evidence.
func NewProtocolError(code string, round uint8, party PartyID, err error) *ProtocolError {
	return &ProtocolError{Code: code, Round: round, Party: party, Err: err}
}
