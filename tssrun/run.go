package tssrun

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/islishude/tss"
)

// RunKind classifies a protocol run lifecycle.
type RunKind string

const (
	// RunKeygen identifies a key-generation run.
	RunKeygen RunKind = "keygen"
	// RunPresign identifies an offline presign run.
	RunPresign RunKind = "presign"
	// RunSign identifies an online signing run.
	RunSign RunKind = "sign"
	// RunRefresh identifies a same-party key-share refresh run.
	RunRefresh RunKind = "refresh"
	// RunReshare identifies a party-set-changing reshare run.
	RunReshare RunKind = "reshare"
)

// RunStatus is the local lifecycle status of a run.
type RunStatus string

const (
	// RunProposed means the run exists but the local party has not started it.
	RunProposed RunStatus = "proposed"
	// RunAccepted means at least one local party has accepted the plan digest.
	RunAccepted RunStatus = "accepted"
	// RunStarted means the local session is registered and outbound delivery may begin.
	RunStarted RunStatus = "started"
	// RunCompleted means the local run output has been durably committed.
	RunCompleted RunStatus = "completed"
	// RunAborted means the local run has been aborted.
	RunAborted RunStatus = "aborted"
)

// KeyGeneration identifies one durable generation of a key share.
type KeyGeneration string

// RunIntent is the public control-plane metadata for one protocol run.
type RunIntent struct {
	RunID     string
	Protocol  tss.ProtocolID
	Kind      RunKind
	SessionID tss.SessionID

	Parties   tss.PartySet
	Signers   tss.PartySet
	Threshold int

	KeyID         string
	KeyGeneration KeyGeneration
	ParentKeyID   string
	PresignID     string

	PlanDigest    []byte
	ContextDigest []byte
}

// Clone returns a caller-owned copy of the run intent.
func (r RunIntent) Clone() RunIntent {
	r.Parties = r.Parties.Clone()
	r.Signers = r.Signers.Clone()
	r.PlanDigest = bytes.Clone(r.PlanDigest)
	r.ContextDigest = bytes.Clone(r.ContextDigest)
	return r
}

// LocalRunResult records the local durable output of a completed run.
type LocalRunResult struct {
	KeyID         string
	KeyGeneration KeyGeneration
	PresignID     string
	OutputDigest  []byte
}

// Clone returns a caller-owned copy of the local run result.
func (r LocalRunResult) Clone() LocalRunResult {
	r.OutputDigest = bytes.Clone(r.OutputDigest)
	return r
}

// RunStore records run intent, plan acceptance, and local run lifecycle state.
type RunStore interface {
	CreateRun(ctx context.Context, run RunIntent) error
	AcceptPlan(ctx context.Context, runID string, self tss.PartyID, digest []byte) error
	LookupBySession(ctx context.Context, protocol tss.ProtocolID, sessionID tss.SessionID) (RunIntent, error)
	MarkStarted(ctx context.Context, runID string, self tss.PartyID) error
	MarkCompleted(ctx context.Context, runID string, self tss.PartyID, result LocalRunResult) error
	AbortRun(ctx context.Context, runID string, self tss.PartyID, reason string) error
}

type runRecord struct {
	intent    RunIntent
	status    RunStatus
	accepted  map[tss.PartyID][]byte
	started   map[tss.PartyID]bool
	completed map[tss.PartyID]LocalRunResult
	aborted   map[tss.PartyID]string
}

// MemoryRunStore is a mutex-protected reference RunStore for tests and examples.
type MemoryRunStore struct {
	mu        sync.Mutex
	byRunID   map[string]*runRecord
	bySession map[sessionIndex]string
}

type sessionIndex struct {
	protocol  tss.ProtocolID
	sessionID tss.SessionID
}

// NewMemoryRunStore returns an empty in-memory run store.
func NewMemoryRunStore() *MemoryRunStore {
	return &MemoryRunStore{
		byRunID:   make(map[string]*runRecord),
		bySession: make(map[sessionIndex]string),
	}
}

// CreateRun stores new run metadata if the run ID and protocol session are unused.
func (s *MemoryRunStore) CreateRun(ctx context.Context, run RunIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRunIntent(run); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byRunID[run.RunID]; ok {
		return ErrRunConflict
	}
	idx := sessionIndex{protocol: run.Protocol, sessionID: run.SessionID}
	if _, ok := s.bySession[idx]; ok {
		return ErrSessionAlreadyUsed
	}
	s.byRunID[run.RunID] = &runRecord{
		intent:    run.Clone(),
		status:    RunProposed,
		accepted:  make(map[tss.PartyID][]byte),
		started:   make(map[tss.PartyID]bool),
		completed: make(map[tss.PartyID]LocalRunResult),
		aborted:   make(map[tss.PartyID]string),
	}
	s.bySession[idx] = run.RunID
	return nil
}

// AcceptPlan records one party's accepted plan digest. Repeating the same digest
// is idempotent; changing it fails with ErrPlanDigestConflict.
func (s *MemoryRunStore) AcceptPlan(ctx context.Context, runID string, self tss.PartyID, digest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if self == 0 || len(digest) == 0 {
		return ErrInvalidRunIntent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byRunID[runID]
	if !ok {
		return ErrRunNotFound
	}
	rec.refreshStatus()
	if _, ok := rec.aborted[self]; ok {
		return ErrRunAborted
	}
	if _, ok := rec.completed[self]; ok {
		return ErrRunCompleted
	}
	if old, ok := rec.accepted[self]; ok {
		if bytes.Equal(old, digest) {
			return nil
		}
		return ErrPlanDigestConflict
	}
	switch rec.status {
	case RunAborted:
		return ErrRunAborted
	case RunCompleted:
		return ErrRunCompleted
	}
	rec.accepted[self] = bytes.Clone(digest)
	rec.refreshStatus()
	return nil
}

// LookupBySession returns accepted or started runs by protocol/session.
func (s *MemoryRunStore) LookupBySession(ctx context.Context, protocol tss.ProtocolID, sessionID tss.SessionID) (RunIntent, error) {
	if err := ctx.Err(); err != nil {
		return RunIntent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	runID, ok := s.bySession[sessionIndex{protocol: protocol, sessionID: sessionID}]
	if !ok {
		return RunIntent{}, ErrRunNotFound
	}
	rec := s.byRunID[runID]
	rec.refreshStatus()
	switch rec.status {
	case RunAccepted, RunStarted:
		return rec.intent.Clone(), nil
	case RunCompleted:
		return RunIntent{}, ErrRunCompleted
	case RunAborted:
		return RunIntent{}, ErrRunAborted
	default:
		return RunIntent{}, ErrRunNotAccepted
	}
}

// MarkStarted records that a local party registered the session.
func (s *MemoryRunStore) MarkStarted(ctx context.Context, runID string, self tss.PartyID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byRunID[runID]
	if !ok {
		return ErrRunNotFound
	}
	if _, ok := rec.aborted[self]; ok {
		return ErrRunAborted
	}
	if _, ok := rec.completed[self]; ok {
		return ErrRunCompleted
	}
	if _, ok := rec.accepted[self]; !ok {
		return ErrRunNotAccepted
	}
	rec.started[self] = true
	rec.refreshStatus()
	return nil
}

// MarkCompleted records the local durable output and retires session lookup.
func (s *MemoryRunStore) MarkCompleted(ctx context.Context, runID string, self tss.PartyID, result LocalRunResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byRunID[runID]
	if !ok {
		return ErrRunNotFound
	}
	if _, ok := rec.aborted[self]; ok {
		return ErrRunAborted
	}
	if _, ok := rec.started[self]; !ok {
		return ErrRunNotAccepted
	}
	rec.completed[self] = result.Clone()
	rec.refreshStatus()
	return nil
}

// AbortRun records a local abort and retires session lookup.
func (s *MemoryRunStore) AbortRun(ctx context.Context, runID string, self tss.PartyID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byRunID[runID]
	if !ok {
		return ErrRunNotFound
	}
	if _, ok := rec.completed[self]; ok {
		return ErrRunCompleted
	}
	rec.aborted[self] = reason
	rec.refreshStatus()
	return nil
}

func (r *runRecord) refreshStatus() {
	if r == nil {
		return
	}
	activeAccepted := false
	activeStarted := false
	for party := range r.accepted {
		if _, ok := r.completed[party]; ok {
			continue
		}
		if _, ok := r.aborted[party]; ok {
			continue
		}
		activeAccepted = true
		if r.started[party] {
			activeStarted = true
		}
	}
	switch {
	case activeStarted:
		r.status = RunStarted
	case activeAccepted:
		r.status = RunAccepted
	case len(r.completed) > 0:
		r.status = RunCompleted
	case len(r.aborted) > 0:
		r.status = RunAborted
	default:
		r.status = RunProposed
	}
}

// AcceptPlanDigest records local plan acceptance through the RunStore.
func AcceptPlanDigest(ctx context.Context, store RunStore, run RunIntent, self tss.PartyID, digest []byte) error {
	if store == nil {
		return ErrRunNotFound
	}
	return store.AcceptPlan(ctx, run.RunID, self, digest)
}

// RegisterStartedSession marks a run as started and registers the session before
// callers release any outbound envelopes.
func RegisterStartedSession(ctx context.Context, store RunStore, registry SessionRegistry, run RunIntent, self tss.PartyID, session ProtocolSession) error {
	if store == nil || registry == nil || session == nil {
		return ErrInvalidSessionKey
	}
	key := SessionKey{Protocol: run.Protocol, SessionID: run.SessionID, Party: self}
	if err := registry.Put(ctx, key, session); err != nil {
		return err
	}
	if err := store.MarkStarted(ctx, run.RunID, self); err != nil {
		_ = registry.Retire(ctx, key)
		return err
	}
	return nil
}

func validateRunIntent(run RunIntent) error {
	if run.RunID == "" || run.Protocol == "" || run.Kind == "" || !run.SessionID.Valid() {
		return ErrInvalidRunIntent
	}
	if len(run.Parties) == 0 || run.Threshold <= 0 || run.Threshold > len(run.Parties) {
		return fmt.Errorf("%w: invalid threshold or party set", ErrInvalidRunIntent)
	}
	if !isCanonicalPartySet(run.Parties) {
		return fmt.Errorf("%w: parties must be sorted, unique, and non-zero", ErrInvalidRunIntent)
	}
	switch run.Kind {
	case RunPresign, RunSign:
		if len(run.Signers) == 0 {
			return fmt.Errorf("%w: signers required", ErrInvalidRunIntent)
		}
		if !isCanonicalPartySet(run.Signers) {
			return fmt.Errorf("%w: signers must be sorted, unique, and non-zero", ErrInvalidRunIntent)
		}
		for _, signer := range run.Signers {
			if !run.Parties.Contains(signer) {
				return fmt.Errorf("%w: signer %d is not a party", ErrInvalidRunIntent, signer)
			}
		}
	case RunKeygen, RunRefresh, RunReshare:
	default:
		return fmt.Errorf("%w: unknown run kind %q", ErrInvalidRunIntent, run.Kind)
	}
	if slices.Contains(run.Parties, tss.PartyID(0)) {
		return fmt.Errorf("%w: party id 0 is reserved", ErrInvalidRunIntent)
	}
	return nil
}

func isCanonicalPartySet(parties tss.PartySet) bool {
	var prev tss.PartyID
	for i, id := range parties {
		if id == 0 {
			return false
		}
		if i > 0 && id <= prev {
			return false
		}
		prev = id
	}
	return true
}
