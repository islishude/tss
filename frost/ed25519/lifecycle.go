package ed25519

import (
	"context"
	"errors"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/tssrun"
)

func validateSessionDisposition(ctx context.Context, reason string) error {
	if ctx == nil {
		return errors.New("nil session disposition context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if reason == "" {
		return errors.New("session abort reason must not be empty")
	}
	return nil
}

// Abort terminally aborts an active keygen session and clears staged secrets.
func (s *KeygenSession) Abort(ctx context.Context, reason string) error {
	if err := validateSessionDisposition(ctx, reason); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.aborted {
		return nil
	}
	if s.completed {
		return tssrun.ErrRunCompleted
	}
	s.abort()
	return nil
}

// Close clears all keygen-session state after an authoritative disposition.
func (s *KeygenSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil session close context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.completed && !s.aborted {
		s.abort()
	}
	if s.keyShare != nil {
		s.keyShare.Destroy()
		s.keyShare = nil
	}
	s.closed = true
	return nil
}

// Abort terminally aborts an active signing session and clears nonce state.
func (s *SignSession) Abort(ctx context.Context, reason string) error {
	if err := validateSessionDisposition(ctx, reason); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.aborted {
		return nil
	}
	if s.completed {
		return tssrun.ErrRunCompleted
	}
	s.abort()
	return nil
}

// Close clears all signing-session state after an authoritative disposition.
func (s *SignSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil session close context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.completed && !s.aborted {
		s.abort()
	} else {
		s.clearCompletedSigningState()
		if s.derivation != nil {
			s.derivation.Destroy()
			s.derivation = nil
		}
		clear(s.signature)
		s.signature = nil
	}
	s.closed = true
	return nil
}

func (s *SignSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.clearNonceScalars()
	s.clearSigningCommitments()
	if s.deltaScalar != nil {
		s.deltaScalar.Set(fed.NewScalar())
		s.deltaScalar = nil
	}
	if s.derivation != nil {
		s.derivation.Destroy()
		s.derivation = nil
	}
	clearScalarMap(s.partials)
	s.partialEnvelopes = nil
	clearScalarMap(s.pendingPartials)
	s.pendingPartials = nil
	s.pendingEnvelopes = nil
	clear(s.message)
	s.message = nil
	clear(s.signature)
	s.signature = nil
}

func (s *SignSession) clearCompletedSigningState() {
	if s == nil {
		return
	}
	s.clearNonceScalars()
	s.clearSigningCommitments()
	clearScalarMap(s.partials)
	s.partials = nil
	s.partialEnvelopes = nil
	clearScalarMap(s.pendingPartials)
	s.pendingPartials = nil
	s.pendingEnvelopes = nil
	clear(s.message)
	s.message = nil
}

func (s *SignSession) clearSigningCommitments() {
	if s == nil {
		return
	}
	s.commitments = nil
	s.commitMessage = tss.Envelope{}
}

// Abort terminally aborts an active refresh or reshare session.
func (s *ReshareSession) Abort(ctx context.Context, reason string) error {
	if err := validateSessionDisposition(ctx, reason); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.aborted {
		return nil
	}
	if s.completed {
		return tssrun.ErrRunCompleted
	}
	s.abort()
	return nil
}

// Close clears all refresh or reshare session state.
func (s *ReshareSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil session close context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.completed && !s.aborted {
		s.abort()
	}
	if s.newShare != nil {
		s.newShare.Destroy()
		s.newShare = nil
	}
	s.closed = true
	return nil
}

func (s *ReshareSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.clearSensitive()
	s.clearReshareConfirmationState()
	if s.pendingShare != nil {
		s.pendingShare.Destroy()
		s.pendingShare = nil
	}
}

func clearScalars(xs []*fed.Scalar) {
	for i := range xs {
		if xs[i] != nil {
			xs[i].Set(fed.NewScalar())
		}
	}
}

func clearScalarMap(xs map[tss.PartyID]*fed.Scalar) {
	for id := range xs {
		if xs[id] != nil {
			xs[id].Set(fed.NewScalar())
		}
		delete(xs, id)
	}
}

func clearSecretScalarMap(xs map[tss.PartyID]*secret.Scalar) {
	for id := range xs {
		if xs[id] != nil {
			xs[id].Destroy()
		}
		delete(xs, id)
	}
}

func clearEnvelopePayloads(envelopes []tss.Envelope) {
	for i := range envelopes {
		clear(envelopes[i].Payload)
		envelopes[i].Payload = nil
	}
}
