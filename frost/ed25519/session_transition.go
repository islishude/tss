package ed25519

import "github.com/islishude/tss"

type sessionEffects struct {
	envelopes []tss.Envelope
}

type sessionTransition[S any] interface {
	apply(*S) (sessionEffects, error)
	cleanupOnReject()
	markCommitted()
}
