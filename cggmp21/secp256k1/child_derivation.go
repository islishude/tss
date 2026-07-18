package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/planvalidation"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/tssrun"
)

// ChildDerivationRun contains local execution and durability dependencies for
// one child-derivation run. Shared intent belongs exclusively in
// ChildDerivationPlan. StartChildDerivation loads the parent from
// LifecycleStore and never accepts a caller-supplied secret KeyShare.
type ChildDerivationRun struct {
	Local               tss.LocalConfig
	Guard               *tss.EnvelopeGuard
	LifecycleStore      tssrun.LifecycleStore
	DurableStoreTimeout time.Duration
}

// ChildDerivationSession runs a fresh Figure 7 epoch for a non-hardened BIP32
// child and atomically installs the confirmed child generation. It never
// exposes an unpersisted child KeyShare.
type ChildDerivationSession struct {
	mu sync.Mutex

	cfg            tss.ThresholdConfig
	plan           ChildDerivationPlanSnapshot
	planHash       []byte
	limits         Limits
	securityParams SecurityParams
	guard          *tss.EnvelopeGuard
	store          tssrun.LifecycleStore
	lease          tssrun.RunLease
	storeTimeout   time.Duration
	leaseFinished  bool

	auxInfo        *auxInfoState
	pending        *KeyShare
	confirmations  map[tss.PartyID]*KeygenConfirmation
	accepted       map[paperKeygenMessageKey]struct{}
	installed      *tssrun.GenerationBinding
	figure7Failure *Figure7Failure
	completed      bool
	aborted        bool
}

// ChildDerivationResultMetadata is a public-only lifecycle disposition.
type ChildDerivationResultMetadata struct {
	Terminal  bool
	Installed bool
	Binding   tssrun.GenerationBinding
	Failure   *Figure7Failure
}

// StartChildDerivation fences the exact current parent generation before any
// Figure 7 envelope becomes visible. All post-lease failures abort the lease
// and destroy prepared secret state.
func StartChildDerivation(plan *ChildDerivationPlan, run ChildDerivationRun) (session *ChildDerivationSession, out []tss.Envelope, err error) {
	local := run.Local
	if plan == nil || plan.state == nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("nil child derivation plan"))
	}
	if run.LifecycleStore == nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("ChildDerivationRun.LifecycleStore is required"))
	}
	if err := plan.ValidateWithLimits(plan.limits); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	snapshot, ok := plan.Snapshot()
	if !ok {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("invalid child derivation plan snapshot"))
	}
	defer snapshot.Derivation.Destroy()

	timeout := durableStoreTimeout(run.DurableStoreTimeout)
	parent, err := loadLifecycleKeyShare(local.Ctx(), run.LifecycleStore, snapshot.ParentBinding, plan.limits, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("load child parent generation: %w", err)
	}
	defer parent.Destroy()
	if local.Self == tss.BroadcastPartyId {
		local.Self = parent.state.Party
	}
	if err := tss.RequireEnvelopeGuard(run.Guard, tss.ProtocolCGGMP21Secp256k1, snapshot.SessionID, local.Self); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	if err := requireLocalEnvelopeSigner(run.Guard, local.EnvelopeSigner); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	if err := plan.validateParentKey(parent, local); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	cfg, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}

	storeCtx, cancel := durableStoreContext(local.Ctx(), timeout)
	lease, err := run.LifecycleStore.AcquireRunLease(storeCtx, snapshot.ParentBinding, tssrun.RunChildDerivation, snapshot.SessionID)
	cancel()
	if err != nil {
		clear(planHash)
		return nil, nil, err
	}
	leaseOwned := true
	defer func() {
		if err == nil || !leaseOwned {
			return
		}
		for i := range out {
			clearEnvelope(&out[i])
		}
		out = nil
		if session != nil {
			session.abortLocked()
			session = nil
		}
		storeCtx, finishCancel := durableStoreContext(local.Ctx(), timeout)
		finishErr := run.LifecycleStore.FinishRunLease(storeCtx, lease, tssrun.LeaseAborted)
		finishCancel()
		if finishErr != nil {
			err = errors.Join(err, fmt.Errorf("abort child derivation lease: %w", finishErr))
		}
	}()

	contribution, expected, err := childFigure7Contributions(parent, plan)
	if err != nil {
		clear(planHash)
		return nil, nil, err
	}
	defer contribution.Destroy()
	defer clearPublicPointMap(expected)
	auxInfo, initial, err := startAuxInfo(auxInfoStartOption{
		Config:                cfg,
		StableSID:             snapshot.ChildSID,
		Limits:                plan.limits,
		SecurityParams:        snapshot.SecurityParams,
		EnvelopeVerifier:      run.Guard.EnvelopeVerifier,
		PaillierBits:          snapshot.PaillierBits,
		PlanHash:              planHash,
		SourceEpochID:         snapshot.ParentBinding.EpochID.Bytes(),
		ExpectedPublicKey:     snapshot.Derivation.ChildPublicKey,
		ExpectedContributions: expected,
		Contribution:          contribution,
		Schedule: auxInfoSchedule{
			CommitmentRound: childAuxInfoCommitmentRound,
			RevealRound:     childAuxInfoRevealRound,
			ProofRound:      childAuxInfoProofRound,
		},
	})
	if err != nil {
		clear(planHash)
		return nil, nil, err
	}
	session = &ChildDerivationSession{
		cfg:            cfg,
		plan:           snapshot.Clone(),
		planHash:       bytes.Clone(planHash),
		limits:         plan.limits,
		securityParams: snapshot.SecurityParams,
		guard:          run.Guard,
		store:          run.LifecycleStore,
		lease:          lease,
		storeTimeout:   timeout,
		auxInfo:        auxInfo,
		confirmations:  make(map[tss.PartyID]*KeygenConfirmation, len(cfg.Parties)),
		accepted:       make(map[paperKeygenMessageKey]struct{}, 4*len(cfg.Parties)),
	}
	clear(planHash)
	leaseOwned = false
	return session, initial, nil
}

func childFigure7Contributions(parent *KeyShare, plan *ChildDerivationPlan) (*secret.Scalar, map[tss.PartyID][]byte, error) {
	if parent == nil || parent.state == nil || parent.state.Epoch == nil || plan == nil || plan.state == nil {
		return nil, nil, errors.New("invalid child Figure 7 contribution input")
	}
	tweak, err := secp.ScalarFromBytesAllowZero(plan.state.Tweak)
	if err != nil {
		return nil, nil, fmt.Errorf("decode child tweak: %w", err)
	}
	expected := make(map[tss.PartyID][]byte, len(parent.state.Parties))
	cleanupExpected := true
	defer func() {
		if cleanupExpected {
			clearPublicPointMap(expected)
		}
	}()
	tweakPoint := secp.ScalarBaseMult(tweak)
	aggregate := secp.NewInfinity()
	for _, party := range parent.state.Parties {
		lambda, err := epochLagrangeCoefficient(parent.state.Epoch, party, parent.state.Parties)
		if err != nil {
			return nil, nil, fmt.Errorf("child contribution coefficient for party %d: %w", party, err)
		}
		publicShare, ok := parent.state.Epoch.PublicShare(party)
		if !ok {
			return nil, nil, fmt.Errorf("missing parent epoch public share for party %d", party)
		}
		point, err := secp.PointFromBytes(publicShare.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid parent epoch public share for party %d: %w", party, err)
		}
		// Interpolating all dynamic parent shares gives Σ λ_i*x_i = x and
		// Σ λ_i = 1. Applying the public tweak inside each weighted term
		// therefore yields Σ λ_i*(x_i+tweak) = x+tweak exactly once.
		weighted := secp.ScalarMult(secp.Add(point, tweakPoint), lambda)
		encoded, err := secp.PointBytes(weighted)
		if err != nil {
			return nil, nil, fmt.Errorf("encode child expected contribution for party %d: %w", party, err)
		}
		expected[party] = encoded
		aggregate = secp.Add(aggregate, weighted)
	}
	aggregateBytes, err := secp.PointBytes(aggregate)
	if err != nil {
		return nil, nil, fmt.Errorf("encode aggregate child contribution: %w", err)
	}
	if !bytes.Equal(aggregateBytes, plan.state.ChildPublicKey) {
		return nil, nil, errors.New("weighted child contributions do not match child public key")
	}
	parentSecret, err := secpScalarFromSecret(parent.state.Secret)
	if err != nil {
		return nil, nil, err
	}
	localLambda, err := epochLagrangeCoefficient(parent.state.Epoch, parent.state.Party, parent.state.Parties)
	if err != nil {
		return nil, nil, err
	}
	localContribution := secp.ScalarMul(localLambda, secp.ScalarAdd(parentSecret, tweak))
	contribution, err := secpSecretScalarFromScalar(localContribution)
	if err != nil {
		return nil, nil, fmt.Errorf("child Figure 7 local contribution: %w", err)
	}
	cleanupExpected = false
	return contribution, expected, nil
}

func clearPublicPointMap(values map[tss.PartyID][]byte) {
	for party, value := range values {
		clear(value)
		delete(values, party)
	}
}

// Guard returns the session's mandatory envelope guard.
func (s *ChildDerivationSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// Handle validates and applies one Figure 7 or child-confirmation envelope.
func (s *ChildDerivationSession) Handle(in tss.InboundEnvelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil child derivation session")
	}
	env := in.Envelope()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		err = bindInboundAuthenticationEvidence(err, in)
		if shouldAbortSession(err) {
			for i := range out {
				clearEnvelope(&out[i])
			}
			out = nil
			err = s.abortRunLocked(err)
		}
	}()
	if err := tss.ValidateInboundWithoutReplay(s.guard, in, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self); err != nil {
		return nil, err
	}
	key := newPaperKeygenMessageKey(env)
	if _, ok := s.accepted[key]; ok {
		if err := s.validateInbound(in); err != nil {
			return nil, err
		}
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("child derivation message slot is already accepted"))
	}
	if env.PayloadType == payloadChildConfirmation {
		return s.handleChildConfirmationLocked(in, key)
	}
	if s.auxInfo == nil || s.pending != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("AuxInfo message arrived outside child Figure 7"))
	}
	prepared, err := s.auxInfo.prepareInbound(env)
	if err != nil {
		return nil, paperKeygenPreparationError(env, err)
	}
	defer prepared.destroy()
	var output *preparedChildDerivationOutput
	if prepared.result != nil {
		output, err = s.prepareChildDerivationOutput(prepared.result)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		defer output.destroy()
	}
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	if err := prepared.apply(); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, s.cfg.Self, fmt.Errorf("commit child Figure 7 transition: %w", err))
	}
	s.accepted[key] = struct{}{}
	if prepared.failure != nil {
		if finishErr := s.terminalFigure7FailureLocked(prepared.failure); finishErr != nil {
			for i := range prepared.out {
				clearEnvelope(&prepared.out[i])
			}
			return nil, finishErr
		}
		return prepared.out, nil
	}
	if output == nil {
		return prepared.out, nil
	}
	s.commitChildDerivationOutputLocked(output)
	if output.final != nil {
		if err := s.persistChildGenerationLocked(output.final); err != nil {
			for i := range prepared.out {
				clearEnvelope(&prepared.out[i])
			}
			clearEnvelope(&output.confirmationEnvelope)
			return nil, s.abortRunLocked(err)
		}
	}
	return append(prepared.out, output.confirmationEnvelope), nil
}

func (s *ChildDerivationSession) validateInbound(in tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, in, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// Completed reports whether the child generation was durably installed.
func (s *ChildDerivationSession) Completed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed && !s.aborted
}

// ResultMetadata returns a public-only child lifecycle disposition.
func (s *ChildDerivationSession) ResultMetadata() ChildDerivationResultMetadata {
	if s == nil {
		return ChildDerivationResultMetadata{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := ChildDerivationResultMetadata{
		Terminal:  s.completed || s.aborted,
		Installed: s.completed && !s.aborted && s.installed != nil,
		Failure:   cloneFigure7Failure(s.figure7Failure),
	}
	if s.installed != nil {
		result.Binding = *s.installed
	}
	return result
}

// InstalledBinding returns the durable child generation binding only after
// CommitInitialGenerationFromLease succeeds.
func (s *ChildDerivationSession) InstalledBinding() (tssrun.GenerationBinding, bool) {
	meta := s.ResultMetadata()
	return meta.Binding, meta.Installed
}

// Figure7Failure returns a public-only terminal Figure 7 failure.
func (s *ChildDerivationSession) Figure7Failure() (Figure7Failure, bool) {
	if s == nil {
		return Figure7Failure{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.figure7Failure == nil {
		return Figure7Failure{}, false
	}
	return s.figure7Failure.Clone(), true
}

// Destroy aborts an unfinished lease and clears all session-owned secret state.
func (s *ChildDerivationSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.completed && !s.aborted {
		_ = s.abortRunLocked(errors.New("child derivation session destroyed"))
	} else {
		s.clearSecretStateLocked()
	}
	s.mu.Unlock()
}

func (s *ChildDerivationSession) abortRunLocked(cause error) error {
	if s == nil {
		return cause
	}
	s.abortLocked()
	if s.leaseFinished || s.store == nil || s.lease.Token == 0 {
		return cause
	}
	storeCtx, cancel := durableStoreContext(s.cfg.Ctx(), s.storeTimeout)
	finishErr := s.store.FinishRunLease(storeCtx, s.lease, tssrun.LeaseAborted)
	cancel()
	if finishErr != nil {
		return errors.Join(cause, fmt.Errorf("abort child derivation run lease: %w", finishErr))
	}
	s.leaseFinished = true
	return cause
}

func (s *ChildDerivationSession) abortLocked() {
	if s == nil {
		return
	}
	s.aborted = true
	s.completed = false
	s.clearSecretStateLocked()
	for party, confirmation := range s.confirmations {
		if confirmation != nil {
			clear(confirmation.ChainCode)
		}
		delete(s.confirmations, party)
	}
	s.accepted = nil
}

func (s *ChildDerivationSession) clearSecretStateLocked() {
	if s.pending != nil {
		s.pending.Destroy()
		s.pending = nil
	}
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
}

func (s *ChildDerivationSession) terminalFigure7FailureLocked(failure *Figure7Failure) error {
	clone := cloneFigure7Failure(failure)
	s.abortLocked()
	var err error
	if !s.leaseFinished && s.store != nil && s.lease.Token != 0 {
		storeCtx, cancel := durableStoreContext(s.cfg.Ctx(), s.storeTimeout)
		err = s.store.FinishRunLease(storeCtx, s.lease, tssrun.LeaseAborted)
		cancel()
		if err == nil {
			s.leaseFinished = true
		} else {
			err = fmt.Errorf("abort failed child derivation lease: %w", err)
		}
	}
	s.figure7Failure = clone
	return err
}
