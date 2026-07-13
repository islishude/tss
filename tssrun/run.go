package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
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
	// RunChildDerivation identifies creation of a signable child epoch.
	RunChildDerivation RunKind = "child-derivation"
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

	Binding     GenerationBinding
	ParentKeyID string
	PresignID   string

	// TargetKeyID and TargetKeyGeneration are the public target descriptor for
	// refresh, reshare, and child derivation. The target epoch is intentionally
	// absent because the protocol derives it during the run. The protocol plan
	// represented by PlanDigest must bind both target fields.
	TargetKeyID         string
	TargetKeyGeneration KeyGeneration

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

// AcceptanceDigest returns a caller-owned canonical digest that wraps the
// protocol PlanDigest together with every immutable RunIntent field. Parties
// must accept this digest, rather than accepting PlanDigest directly, so a
// control plane cannot substitute lifecycle or routing metadata while reusing
// the same protocol plan.
func (r RunIntent) AcceptanceDigest() []byte {
	t := transcript.New("tssrun-run-intent-acceptance-v1")
	t.AppendString("run_id", r.RunID)
	t.AppendString("protocol", string(r.Protocol))
	t.AppendString("kind", string(r.Kind))
	t.AppendBytes("session_id", r.SessionID[:])
	t.AppendUint32List("parties", r.Parties)
	t.AppendUint32List("signers", r.Signers)
	t.AppendUint64("threshold", uint64(r.Threshold))
	t.AppendString("source_key_id", r.Binding.KeyID)
	t.AppendString("source_key_generation", string(r.Binding.KeyGeneration))
	t.AppendBytes("source_epoch_id", r.Binding.EpochID[:])
	t.AppendString("target_key_id", r.TargetKeyID)
	t.AppendString("target_key_generation", string(r.TargetKeyGeneration))
	t.AppendString("parent_key_id", r.ParentKeyID)
	t.AppendString("presign_id", r.PresignID)
	t.AppendBytes("protocol_plan_digest", r.PlanDigest)
	t.AppendBytes("context_digest", r.ContextDigest)
	return t.Sum()
}

// LocalRunResult records the local durable output of a completed run.
type LocalRunResult struct {
	Binding      GenerationBinding
	PresignID    string
	OutputDigest []byte
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

// AcceptPlan records one party's accepted RunIntent acceptance digest.
// Repeating the same digest is idempotent; changing it fails with
// ErrPlanDigestConflict.
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
	if !rec.intent.participants().Contains(self) {
		return ErrRunPartyNotParticipant
	}
	if !bytes.Equal(digest, rec.intent.AcceptanceDigest()) {
		return ErrPlanDigestConflict
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
	if !rec.intent.participants().Contains(self) {
		return ErrRunPartyNotParticipant
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
	if !rec.intent.participants().Contains(self) {
		return ErrRunPartyNotParticipant
	}
	if _, ok := rec.aborted[self]; ok {
		return ErrRunAborted
	}
	if _, ok := rec.started[self]; !ok {
		return ErrRunNotAccepted
	}
	if err := validateLocalRunResult(rec.intent, result); err != nil {
		return err
	}
	if old, ok := rec.completed[self]; ok {
		if localRunResultsEqual(old, result) {
			return nil
		}
		return ErrRunCompleted
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
	if !rec.intent.participants().Contains(self) {
		return ErrRunPartyNotParticipant
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

// AcceptPlanDigest records local RunIntent acceptance through the RunStore.
// digest must be the value returned by run.AcceptanceDigest.
func AcceptPlanDigest(ctx context.Context, store RunStore, run RunIntent, self tss.PartyID, digest []byte) error {
	if store == nil {
		return ErrRunNotFound
	}
	if err := validateRunIntent(run); err != nil {
		return err
	}
	if !bytes.Equal(run.AcceptanceDigest(), digest) {
		return ErrPlanDigestConflict
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
	gated := newStartGatedSession(session)
	if err := registry.Put(ctx, key, gated); err != nil {
		return err
	}
	if err := store.MarkStarted(ctx, run.RunID, self); err != nil {
		gated.fail(err)
		if cleanupErr := registry.Retire(context.WithoutCancel(ctx), key); cleanupErr != nil {
			return errors.Join(err, fmt.Errorf("retire unstarted session: %w", cleanupErr))
		}
		return err
	}
	gated.activate()
	return nil
}

// startGatedSession keeps a registry-visible session inert until durable run
// state records that the local party started it.
type startGatedSession struct {
	mu       sync.RWMutex
	session  ProtocolSession
	ready    chan struct{}
	active   bool
	startErr error
}

func newStartGatedSession(session ProtocolSession) *startGatedSession {
	return &startGatedSession{session: session, ready: make(chan struct{})}
}

func (s *startGatedSession) activate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active || s.startErr != nil {
		return
	}
	s.active = true
	close(s.ready)
}

func (s *startGatedSession) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active || s.startErr != nil {
		return
	}
	s.startErr = err
	close(s.ready)
}

func (s *startGatedSession) target() (ProtocolSession, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.session, s.active, s.startErr
}

// Handle waits for the durable-start decision so registry-visible messages are
// neither processed early nor discarded during startup.
func (s *startGatedSession) Handle(in tss.InboundEnvelope) ([]tss.Envelope, error) {
	<-s.ready
	target, active, err := s.target()
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrRunNotAccepted
	}
	return target.Handle(in)
}

// Completed reports completion only after the durable-start gate is active.
func (s *startGatedSession) Completed() bool {
	target, active, _ := s.target()
	return active && target.Completed()
}

// Destroy releases the wrapped session's secret state.
func (s *startGatedSession) Destroy() {
	s.session.Destroy()
}

func validateRunIntent(run RunIntent) error {
	if run.RunID == "" || run.Protocol == "" || run.Kind == "" || !run.SessionID.Valid() {
		return ErrInvalidRunIntent
	}
	if len(run.Parties) == 0 || run.Threshold <= 0 || run.Threshold > len(run.Parties) {
		return fmt.Errorf("%w: invalid threshold or party set", ErrInvalidRunIntent)
	}
	if len(run.PlanDigest) != sha256.Size {
		return fmt.Errorf("%w: plan digest must be %d bytes", ErrInvalidRunIntent, sha256.Size)
	}
	if run.Protocol != tss.ProtocolCGGMP21Secp256k1 && run.Protocol != tss.ProtocolFROSTEd25519 {
		return fmt.Errorf("%w: unsupported protocol %q", ErrInvalidRunIntent, run.Protocol)
	}
	if len(run.ContextDigest) != 0 && len(run.ContextDigest) != sha256.Size {
		return fmt.Errorf("%w: context digest must be empty or %d bytes", ErrInvalidRunIntent, sha256.Size)
	}
	if !isCanonicalPartySet(run.Parties) {
		return fmt.Errorf("%w: parties must be sorted, unique, and non-zero", ErrInvalidRunIntent)
	}
	if err := run.Binding.Validate(); err != nil {
		return fmt.Errorf("%w: generation binding required: %w", ErrInvalidRunIntent, err)
	}
	switch run.Kind {
	case RunPresign:
		if run.Protocol != tss.ProtocolCGGMP21Secp256k1 {
			return fmt.Errorf("%w: presign is only supported by %q", ErrInvalidRunIntent, tss.ProtocolCGGMP21Secp256k1)
		}
		if run.PresignID == "" || len(run.ContextDigest) != sha256.Size {
			return fmt.Errorf("%w: presign requires presign id and %d-byte context digest", ErrInvalidRunIntent, sha256.Size)
		}
		if err := validateRunSigners(run); err != nil {
			return err
		}
	case RunSign:
		if len(run.ContextDigest) != sha256.Size {
			return fmt.Errorf("%w: sign requires a %d-byte context digest", ErrInvalidRunIntent, sha256.Size)
		}
		switch run.Protocol {
		case tss.ProtocolCGGMP21Secp256k1:
			if run.PresignID == "" {
				return fmt.Errorf("%w: CGGMP21 sign requires presign id", ErrInvalidRunIntent)
			}
		case tss.ProtocolFROSTEd25519:
			if run.PresignID != "" {
				return fmt.Errorf("%w: FROST sign does not use presign id", ErrInvalidRunIntent)
			}
		default:
			return fmt.Errorf("%w: unsupported protocol %q", ErrInvalidRunIntent, run.Protocol)
		}
		if err := validateRunSigners(run); err != nil {
			return err
		}
	case RunChildDerivation:
		if len(run.ContextDigest) != sha256.Size {
			return fmt.Errorf("%w: child derivation requires a %d-byte context digest", ErrInvalidRunIntent, sha256.Size)
		}
		if err := validateRunTargetDescriptor(run, true); err != nil {
			return err
		}
	case RunRefresh, RunReshare:
		if err := validateRunTargetDescriptor(run, false); err != nil {
			return err
		}
	case RunKeygen:
	default:
		return fmt.Errorf("%w: unknown run kind %q", ErrInvalidRunIntent, run.Kind)
	}
	if run.Kind != RunRefresh && run.Kind != RunReshare && run.Kind != RunChildDerivation &&
		(run.TargetKeyID != "" || run.TargetKeyGeneration != "") {
		return fmt.Errorf("%w: target descriptor is not valid for %s", ErrInvalidRunIntent, run.Kind)
	}
	if slices.Contains(run.Parties, tss.PartyID(0)) {
		return fmt.Errorf("%w: party id 0 is reserved", ErrInvalidRunIntent)
	}
	return nil
}

func validateRunTargetDescriptor(run RunIntent, distinctKey bool) error {
	if validateLifecycleIdentifier(run.TargetKeyID) != nil || validateLifecycleIdentifier(string(run.TargetKeyGeneration)) != nil {
		return fmt.Errorf("%w: %s requires a target key id and generation", ErrInvalidRunIntent, run.Kind)
	}
	if distinctKey {
		if run.TargetKeyID == run.Binding.KeyID {
			return fmt.Errorf("%w: child target key id must differ from parent", ErrInvalidRunIntent)
		}
		return nil
	}
	if run.TargetKeyID != run.Binding.KeyID {
		return fmt.Errorf("%w: %s target key id must match the source", ErrInvalidRunIntent, run.Kind)
	}
	if run.TargetKeyGeneration == run.Binding.KeyGeneration {
		return fmt.Errorf("%w: %s target generation must differ from the source", ErrInvalidRunIntent, run.Kind)
	}
	return nil
}

func validateRunSigners(run RunIntent) error {
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
	return nil
}

func (r RunIntent) participants() tss.PartySet {
	switch r.Kind {
	case RunPresign, RunSign:
		return r.Signers
	default:
		return r.Parties
	}
}

func validateLocalRunResult(intent RunIntent, result LocalRunResult) error {
	if len(result.OutputDigest) != sha256.Size {
		return fmt.Errorf("%w: output digest must be %d bytes", ErrInvalidRunResult, sha256.Size)
	}
	if result.PresignID != intent.PresignID {
		return fmt.Errorf("%w: presign id does not match run intent", ErrInvalidRunResult)
	}
	if err := result.Binding.Validate(); err != nil {
		return fmt.Errorf("%w: invalid output generation binding", ErrInvalidRunResult)
	}
	switch intent.Kind {
	case RunKeygen:
		if result.Binding != intent.Binding {
			return fmt.Errorf("%w: keygen output binding does not match run intent", ErrInvalidRunResult)
		}
	case RunRefresh, RunReshare:
		if result.Binding.KeyID != intent.TargetKeyID ||
			result.Binding.KeyGeneration != intent.TargetKeyGeneration ||
			result.Binding.EpochID == intent.Binding.EpochID {
			return fmt.Errorf("%w: %s output does not match the target generation and a new epoch", ErrInvalidRunResult, intent.Kind)
		}
	case RunChildDerivation:
		if result.Binding.KeyID != intent.TargetKeyID ||
			result.Binding.KeyGeneration != intent.TargetKeyGeneration ||
			result.Binding.EpochID == intent.Binding.EpochID {
			return fmt.Errorf("%w: child output does not match the distinct target generation and a new epoch", ErrInvalidRunResult)
		}
	case RunPresign, RunSign:
		if result.Binding != intent.Binding {
			return fmt.Errorf("%w: generation binding does not match run intent", ErrInvalidRunResult)
		}
	}
	return nil
}

func localRunResultsEqual(a, b LocalRunResult) bool {
	return a.Binding == b.Binding &&
		a.PresignID == b.PresignID &&
		bytes.Equal(a.OutputDigest, b.OutputDigest)
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
