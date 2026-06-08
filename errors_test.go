package tss

import (
	"errors"
	"fmt"
	"testing"
)

func TestProtocolErrorError(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var pe *ProtocolError
		got := pe.Error()
		if got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})

	t.Run("code only", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeInvalidConfig}
		got := pe.Error()
		if got != ErrCodeInvalidConfig {
			t.Errorf("got %q, want %q", got, ErrCodeInvalidConfig)
		}
	})

	t.Run("code with round", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeVerification, Round: 3}
		got := pe.Error()
		want := "verification_failed round=3"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("code with party", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeInvalidMessage, Party: 7}
		got := pe.Error()
		want := "invalid_message party=7"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("code with round and party", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeDuplicate, Round: 2, Party: 5}
		got := pe.Error()
		want := "duplicate_message round=2 party=5"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("code with round, party, and wrapped error", func(t *testing.T) {
		pe := &ProtocolError{
			Code:  ErrCodeVerification,
			Round: 1,
			Party: 3,
			Err:   fmt.Errorf("signature mismatch"),
		}
		got := pe.Error()
		want := "verification_failed round=1 party=3: signature mismatch"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("zero round and party are omitted", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeNotReady, Round: 0, Party: 0}
		got := pe.Error()
		if got != ErrCodeNotReady {
			t.Errorf("got %q, want %q", got, ErrCodeNotReady)
		}
	})

	t.Run("wrapped error without round or party", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeCompleted, Err: fmt.Errorf("already done")}
		got := pe.Error()
		want := "completed: already done"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestProtocolErrorUnwrap(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var pe *ProtocolError
		if err := pe.Unwrap(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("no wrapped error", func(t *testing.T) {
		pe := &ProtocolError{Code: ErrCodeAborted}
		if err := pe.Unwrap(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("with wrapped error", func(t *testing.T) {
		sentinel := fmt.Errorf("underlying cause")
		pe := &ProtocolError{Code: ErrCodeInvalidConfig, Err: sentinel}
		if err := pe.Unwrap(); !errors.Is(err, sentinel) {
			t.Errorf("got %v, want %v", err, sentinel)
		}
	})

	t.Run("errors.Is with wrapped sentinel", func(t *testing.T) {
		sentinel := fmt.Errorf("specific error")
		pe := &ProtocolError{Code: ErrCodeDuplicate, Err: sentinel}
		if !errors.Is(pe, sentinel) {
			t.Error("errors.Is should find the wrapped sentinel")
		}
	})

	t.Run("errors.As finds ProtocolError through non-ProtocolError wrapper", func(t *testing.T) {
		inner := &ProtocolError{Code: ErrCodeAborted, Party: 9}
		// Wrap the ProtocolError in a plain fmt error, so errors.As must unwrap to find it.
		outer := fmt.Errorf("outer context: %w", inner)
		var found *ProtocolError
		if !errors.As(outer, &found) {
			t.Error("errors.As should find ProtocolError through fmt wrapper")
		}
		if found.Code != ErrCodeAborted {
			t.Errorf("found.Code = %q, want %q", found.Code, ErrCodeAborted)
		}
		if found.Party != 9 {
			t.Errorf("found.Party = %d, want 9", found.Party)
		}
	})
}

func TestNewProtocolError(t *testing.T) {
	underlying := fmt.Errorf("test error")
	pe := NewProtocolError(ErrCodeInvalidMessage, 4, 2, underlying)

	if pe.Code != ErrCodeInvalidMessage {
		t.Errorf("Code = %q, want %q", pe.Code, ErrCodeInvalidMessage)
	}
	if pe.Round != 4 {
		t.Errorf("Round = %d, want 4", pe.Round)
	}
	if pe.Party != 2 {
		t.Errorf("Party = %d, want 2", pe.Party)
	}
	if !errors.Is(pe.Err, underlying) {
		t.Errorf("Err = %v, want %v", pe.Err, underlying)
	}
	if pe.Blame != nil {
		t.Error("Blame must be nil from NewProtocolError")
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Ensure error code constants have the expected values and are distinct.
	codes := map[string]struct{}{}
	for _, c := range []string{
		ErrCodeInvalidConfig,
		ErrCodeInvalidMessage,
		ErrCodeDuplicate,
		ErrCodeRound,
		ErrCodeVerification,
		ErrCodeNotReady,
		ErrCodeConsumed,
		ErrCodeCompleted,
		ErrCodeAborted,
		ErrCodeNotImplemented,
	} {
		if c == "" {
			t.Error("error code must not be empty")
		}
		if _, dup := codes[c]; dup {
			t.Errorf("duplicate error code %q", c)
		}
		codes[c] = struct{}{}
	}
}
