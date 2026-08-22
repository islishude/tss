package ed25519

import (
	"errors"

	"github.com/islishude/tss"
)

type sessionEffects struct {
	envelopes []tss.Envelope
}

type sessionTransition[S any] interface {
	apply(*S) (sessionEffects, error)
	cleanupOnReject()
	markCommitted()
}

func handleSessionEnvelope[S any](
	state *S,
	env tss.InboundEnvelope,
	completed bool,
	aborted bool,
	abort func(),
	build func(tss.InboundEnvelope) (sessionTransition[S], error),
) (out []tss.Envelope, err error) {
	base := env.Envelope()
	if completed {
		return nil, completedSessionError(base.Round, base.From)
	}
	if aborted {
		return nil, abortedSessionError(base.Round, base.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			abort()
		}
	}()
	transition, err := build(env)
	if err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	defer transition.cleanupOnReject()
	effects, err := transition.apply(state)
	if err != nil {
		return nil, err
	}
	transition.markCommitted()
	return effects.envelopes, nil
}
