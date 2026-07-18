package secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/planvalidation"
	"github.com/islishude/tss/tssrun"
)

// refreshPartyData retains only post-Figure-7 public confirmation evidence.
// All polynomial, DH, Paillier, and proof witnesses are owned by auxInfoState
// and destroyed as soon as the pending KeyShare has taken defensive copies.
type refreshPartyData struct {
	confirmation *KeygenConfirmation
}

// RefreshSession runs Figure 7/F.1 to establish a fresh auxiliary-key epoch
// while preserving the existing group public key and chain code.
type RefreshSession struct {
	mu sync.Mutex

	oldKey          *KeyShare
	cfg             tss.ThresholdConfig
	log             tss.Logger
	limits          Limits
	securityParams  SecurityParams
	planHash        []byte
	partyData       map[tss.PartyID]*refreshPartyData
	completed       bool
	aborted         bool
	refreshDisabled bool
	guard           *tss.EnvelopeGuard
	newShare        *KeyShare
	auxInfo         *auxInfoState
	figure7Failure  *Figure7Failure
	accepted        map[paperKeygenMessageKey]struct{}

	lifecycleStore            tssrun.LifecycleStore
	lifecycleLease            tssrun.RunLease
	lifecycleSource           tssrun.GenerationBinding
	lifecycleTargetGeneration tssrun.KeyGeneration
	lifecycleTimeout          time.Duration
	lifecycleFinished         bool
	lifecycleFinal            *preparedPaperFinalKeyShare
	lifecycleOutbox           []tss.Envelope
}

// RefreshRuntime contains this process's local execution and authoritative
// lifecycle dependencies for one refresh run. TargetKeyGeneration names the
// generation installed after the protocol derives its new epoch.
type RefreshRuntime struct {
	Local               tss.LocalConfig
	Guard               *tss.EnvelopeGuard
	LifecycleStore      tssrun.LifecycleStore
	Binding             tssrun.GenerationBinding
	TargetKeyGeneration tssrun.KeyGeneration
	DurableStoreTimeout time.Duration
}

// StartRefresh starts Figure 7/F.1 auxiliary-key refresh after acquiring an
// exclusive lease on the exact current generation loaded from LifecycleStore.
func StartRefresh(plan *RefreshPlan, runtime RefreshRuntime) (*RefreshSession, []tss.Envelope, error) {
	local := runtime.Local
	if plan == nil || plan.state == nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("nil refresh plan"))
	}
	if local.Self == tss.BroadcastPartyId {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("RefreshRuntime.Local.Self is required"))
	}
	if runtime.LifecycleStore == nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("RefreshRuntime.LifecycleStore is required"))
	}
	if err := runtime.Binding.Validate(); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	targetProbe := runtime.Binding
	targetProbe.KeyGeneration = runtime.TargetKeyGeneration
	if err := targetProbe.Validate(); err != nil || runtime.TargetKeyGeneration == runtime.Binding.KeyGeneration {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("invalid refresh target key generation"))
	}
	config, err := plan.thresholdConfig(local)
	if err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	config.Parties = config.SortedParties()
	if err := config.ValidateWithLimits(plan.limits.ThresholdLimits()); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	if plan.SourceEpochID() != runtime.Binding.EpochID {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("refresh plan source epoch does not match lifecycle binding"))
	}
	if _, err := plan.Digest(); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	if err := tss.RequireEnvelopeGuard(runtime.Guard, tss.ProtocolCGGMP21Secp256k1, plan.state.sessionID, local.Self); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	if err := requireLocalEnvelopeSigner(runtime.Guard, local.EnvelopeSigner); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}

	ctx := local.Ctx()
	timeout := durableStoreTimeout(runtime.DurableStoreTimeout)
	oldKey, err := loadLifecycleKeyShare(ctx, runtime.LifecycleStore, runtime.Binding, plan.limits, timeout)
	if err != nil {
		return nil, nil, err
	}
	keyOwned := true
	defer func() {
		if keyOwned {
			oldKey.Destroy()
		}
	}()
	if oldKey.state.Party != local.Self {
		return nil, nil, planvalidation.InvalidConfig(local.Self, errors.New("local self does not match lifecycle key share party"))
	}
	if err := validateRefreshSourceKey(oldKey, plan); err != nil {
		return nil, nil, planvalidation.InvalidConfig(local.Self, err)
	}
	storeCtx, cancel := durableStoreContext(ctx, timeout)
	lease, err := runtime.LifecycleStore.AcquireRunLease(storeCtx, runtime.Binding, tssrun.RunRefresh, plan.state.sessionID)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	session, out, err := startPaperRefresh(oldKey, plan, local, runtime.Guard)
	if err != nil {
		return nil, nil, finishLifecycleLease(ctx, runtime.LifecycleStore, lease, timeout, err)
	}
	session.lifecycleStore = runtime.LifecycleStore
	session.lifecycleLease = lease
	session.lifecycleSource = runtime.Binding
	session.lifecycleTargetGeneration = runtime.TargetKeyGeneration
	session.lifecycleTimeout = timeout
	keyOwned = false
	if session.auxInfo != nil && session.auxInfo.completed() {
		clearEnvelopePayloads(out)
		out = nil
		if err := session.completeSingletonPaperRefresh(); err != nil {
			// A durable cutover failure leaves lifecycleFinal and its exact
			// confirmation outbox owned by the session for RetryLifecycleCommit.
			if session.lifecycleFinal != nil {
				return session, nil, err
			}
			session.abort()
			return nil, nil, finishLifecycleLease(ctx, runtime.LifecycleStore, lease, timeout, err)
		}
	}
	return session, out, nil
}

func (s *RefreshSession) completeSingletonPaperRefresh() error {
	if s == nil || len(s.cfg.Parties) != 1 || s.cfg.Parties[0] != s.cfg.Self || s.auxInfo == nil {
		return errors.New("invalid singleton refresh state")
	}
	result, ok := s.auxInfo.resultSnapshot()
	if !ok {
		return errors.New("singleton Figure 7 result is unavailable")
	}
	defer result.destroy()
	prepared, err := s.preparePaperRefreshOutput(result)
	if err != nil {
		return err
	}
	defer prepared.destroy()
	if err := s.commitPaperRefreshOutput(prepared); err != nil {
		clear(prepared.confirmationEnvelope.Payload)
		return err
	}
	clear(prepared.confirmationEnvelope.Payload)
	return nil
}

// Guard returns the session's envelope guard for transport adapters.
func (s *RefreshSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

func (s *RefreshSession) partyEntry(id tss.PartyID) (*refreshPartyData, error) {
	if s == nil {
		return nil, errors.New("nil refresh session")
	}
	pd, ok := s.partyData[id]
	if !ok {
		return nil, fmt.Errorf("party %d is not a refresh participant", id)
	}
	return pd, nil
}

func (s *RefreshSession) validateInbound(env tss.InboundEnvelope) error {
	return tss.ValidateInbound(s.guard, env, tss.ProtocolCGGMP21Secp256k1, s.cfg.SessionID, s.cfg.Parties, s.cfg.Self)
}

// Handle validates and applies one Figure 7 or confirmation envelope.
func (s *RefreshSession) Handle(in tss.InboundEnvelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil refresh session")
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
			s.refreshDisabled = true
			if lifecycleErr := s.markRefreshProtocolFailed(s.cfg.Ctx()); lifecycleErr != nil {
				err = errors.Join(err, lifecycleErr)
			}
			s.abort()
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
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("refresh message slot is already accepted"))
	}
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handlePaperRefreshConfirmation(in, key)
	}
	if s.auxInfo == nil || s.newShare != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("AuxInfo message arrived outside refresh Figure 7"))
	}
	prepared, err := s.auxInfo.prepareInbound(env)
	if err != nil {
		return nil, auxInfoPreparationError(env, s.cfg.Parties, err)
	}
	defer prepared.destroy()
	var output *preparedPaperRefreshOutput
	if prepared.result != nil {
		output, err = s.preparePaperRefreshOutput(prepared.result)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		defer output.destroy()
	}
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	if err := prepared.apply(); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, s.cfg.Self, fmt.Errorf("commit refresh Figure 7 transition: %w", err))
	}
	s.accepted[key] = struct{}{}
	if prepared.failure != nil {
		if err := s.terminalFigure7Failure(prepared.failure); err != nil {
			return nil, err
		}
		return prepared.out, nil
	}
	if output == nil {
		return prepared.out, nil
	}
	if err := s.commitPaperRefreshOutput(output); err != nil {
		return nil, err
	}
	return append(prepared.out, output.confirmationEnvelope), nil
}

// RefreshResultMetadata is a caller-owned refresh lifecycle disposition.
type RefreshResultMetadata struct {
	ProtocolStarted bool
	Completed       bool
	RefreshDisabled bool
	Terminal        bool
	Failure         *Figure7Failure
}

// ResultMetadata returns lifecycle disposition without secret state.
func (s *RefreshSession) ResultMetadata() RefreshResultMetadata {
	if s == nil {
		return RefreshResultMetadata{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return RefreshResultMetadata{
		ProtocolStarted: true,
		Completed:       s.completed && !s.aborted,
		RefreshDisabled: s.refreshDisabled,
		Terminal:        s.completed,
		Failure:         cloneFigure7Failure(s.figure7Failure),
	}
}

// Figure7Failure returns a public-only terminal Figure 7 accusation result.
func (s *RefreshSession) Figure7Failure() (Figure7Failure, bool) {
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

func (s *RefreshSession) terminalFigure7Failure(failure *Figure7Failure) error {
	s.refreshDisabled = true
	lifecycleErr := s.markRefreshProtocolFailed(s.cfg.Ctx())
	s.abort()
	s.figure7Failure = cloneFigure7Failure(failure)
	// Completed is used by tssrun as a terminal-disposition signal. KeyShare and
	// ResultMetadata.Completed still distinguish this aborted outcome.
	s.completed = true
	return lifecycleErr
}

// KeyShare returns the confirmed refreshed key share.
func (s *RefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed || s.aborted || s.newShare == nil {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}

// Destroy clears secret state owned by the session.
func (s *RefreshSession) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.lifecycleFinished && s.lifecycleFinal == nil && s.lifecycleStore != nil && s.lifecycleLease.Token != 0 {
		if s.refreshDisabled {
			_ = s.markRefreshProtocolFailed(s.cfg.Ctx())
		} else {
			storeCtx, cancel := durableStoreContext(s.cfg.Ctx(), s.lifecycleTimeout)
			_ = s.lifecycleStore.FinishRunLease(storeCtx, s.lifecycleLease, tssrun.LeaseAborted)
			cancel()
		}
	}
	s.abort()
	s.mu.Unlock()
}

func (s *RefreshSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	s.completed = false
	if s.newShare != nil {
		s.newShare.Destroy()
		s.newShare = nil
	}
	if s.auxInfo != nil {
		s.auxInfo.destroy()
		s.auxInfo = nil
	}
	if s.oldKey != nil {
		s.oldKey.Destroy()
		s.oldKey = nil
	}
	if s.lifecycleFinal != nil {
		s.lifecycleFinal.committed = false
		s.lifecycleFinal.destroy()
		s.lifecycleFinal = nil
	}
	clearLifecycleEnvelopes(s.lifecycleOutbox)
	s.lifecycleOutbox = nil
	for party, pd := range s.partyData {
		if pd != nil && pd.confirmation != nil {
			clear(pd.confirmation.ChainCode)
			pd.confirmation = nil
		}
		delete(s.partyData, party)
	}
	s.accepted = nil
}

func validatePaperRefreshConfirmationPublicBinding(s *RefreshSession, confirmation *KeygenConfirmation) error {
	if confirmation.SessionID != s.cfg.SessionID || confirmation.Threshold != s.cfg.Threshold ||
		!slices.Equal(confirmation.Parties, s.cfg.Parties) ||
		!bytes.Equal(confirmation.PublicKey, s.oldKey.state.PublicKey) ||
		!bytes.Equal(confirmation.ChainCode, s.oldKey.state.ChainCode) {
		return errors.New("refresh confirmation public binding mismatch")
	}
	return nil
}
