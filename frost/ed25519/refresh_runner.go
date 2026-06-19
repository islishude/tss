package ed25519

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/islishude/tss"
)

// RefreshRunnerOptions configures the FROST refresh protocol adapter.
type RefreshRunnerOptions struct {
	Rand         io.Reader
	RoundTimeout time.Duration
	Log          tss.Logger
	Limits       *Limits
}

type refreshRunner struct {
	rand         io.Reader
	roundTimeout time.Duration
	log          tss.Logger
	limits       *Limits
}

// NewRefreshRunner constructs a FROST adapter for [tss.RefreshScheduler].
func NewRefreshRunner(options RefreshRunnerOptions) tss.RefreshRunner[*KeyShare] {
	runner := &refreshRunner{
		rand:         options.Rand,
		roundTimeout: options.RoundTimeout,
		log:          options.Log,
	}
	if options.Limits != nil {
		limits := *options.Limits
		runner.limits = &limits
	}
	return runner
}

// StartRefresh constructs one FROST refresh session.
func (r *refreshRunner) StartRefresh(ctx context.Context, current *KeyShare, config tss.RefreshRunConfig) (tss.RefreshSession[*KeyShare], []tss.Envelope, error) {
	metadata, ok := current.PublicMetadata()
	if !ok {
		return nil, nil, errors.New("nil key share")
	}
	guard, err := (tss.GuardConfig{
		Self:        current.PartyID(),
		Parties:     metadata.Parties,
		Protocol:    tss.ProtocolFROSTEd25519,
		SessionID:   config.SessionID,
		Policies:    FROSTPolicies(),
		Cache:       config.ReplayCache,
		AckVerifier: config.AckVerifier,
	}).BuildGuard()
	if err != nil {
		return nil, nil, err
	}
	plan, err := NewRefreshPlan(RefreshPlanOption{
		OldKey:    current,
		SessionID: config.SessionID,
		Limits:    r.limits,
	})
	if err != nil {
		return nil, nil, err
	}
	session, out, err := StartRefresh(current, plan, tss.LocalConfig{
		Self:         current.PartyID(),
		Rand:         r.rand,
		Context:      ctx,
		RoundTimeout: r.roundTimeout,
		Log:          r.log,
	}, guard)
	if err != nil {
		return nil, nil, err
	}
	return frostRefreshSession{session}, out, nil
}

type frostRefreshSession struct {
	session *ReshareSession
}

// Handle applies one inbound FROST refresh envelope.
func (s frostRefreshSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.session.HandleReshareMessage(in)
}

// KeyShare returns the refreshed FROST key share after completion.
func (s frostRefreshSession) KeyShare() (*KeyShare, bool) {
	return s.session.KeyShare()
}

// Destroy clears secret material retained by the FROST refresh session.
func (s frostRefreshSession) Destroy() {
	s.session.Destroy()
}
