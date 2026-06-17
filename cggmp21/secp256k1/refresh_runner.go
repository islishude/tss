package secp256k1

import (
	"context"
	"io"
	"time"

	"github.com/islishude/tss"
)

// RefreshRunnerOptions configures the CGGMP21 refresh protocol adapter.
type RefreshRunnerOptions struct {
	Rand           io.Reader
	RoundTimeout   time.Duration
	Log            tss.Logger
	PaillierBits   int
	Limits         *Limits
	SecurityParams *SecurityParams
}

type refreshRunner struct {
	rand           io.Reader
	roundTimeout   time.Duration
	log            tss.Logger
	paillierBits   int
	limits         *Limits
	securityParams *SecurityParams
}

// NewRefreshRunner constructs a CGGMP21 adapter for [tss.RefreshScheduler].
func NewRefreshRunner(options RefreshRunnerOptions) tss.RefreshRunner[*KeyShare] {
	runner := &refreshRunner{
		rand:         options.Rand,
		roundTimeout: options.RoundTimeout,
		log:          options.Log,
		paillierBits: options.PaillierBits,
	}
	if options.Limits != nil {
		limits := *options.Limits
		runner.limits = &limits
	}
	if options.SecurityParams != nil {
		securityParams := *options.SecurityParams
		runner.securityParams = &securityParams
	}
	return runner
}

// StartRefresh constructs one CGGMP21 refresh session.
func (r *refreshRunner) StartRefresh(ctx context.Context, current *KeyShare, config tss.RefreshRunConfig) (tss.RefreshSession[*KeyShare], []tss.Envelope, error) {
	guard, err := (tss.GuardConfig{
		Self:        current.PartyID(),
		Parties:     current.Parties(),
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   config.SessionID,
		Policies:    CGGMP21Policies(),
		Cache:       config.ReplayCache,
		AckVerifier: config.AckVerifier,
	}).BuildGuard()
	if err != nil {
		return nil, nil, err
	}
	plan, err := NewRefreshPlan(RefreshPlanOption{
		OldKey:         current,
		SessionID:      config.SessionID,
		PaillierBits:   r.paillierBits,
		Limits:         r.limits,
		SecurityParams: r.securityParams,
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
	return cggmpRefreshSession{session}, out, nil
}

type cggmpRefreshSession struct {
	session *RefreshSession
}

// Handle applies one inbound CGGMP21 refresh envelope.
func (s cggmpRefreshSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	return s.session.HandleRefreshMessage(in)
}

// KeyShare returns the refreshed CGGMP21 key share after completion.
func (s cggmpRefreshSession) KeyShare() (*KeyShare, bool) {
	return s.session.KeyShare()
}

// Destroy clears secret material retained by the CGGMP21 refresh session.
func (s cggmpRefreshSession) Destroy() {
	s.session.Destroy()
}
