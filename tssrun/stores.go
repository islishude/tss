package tssrun

import (
	"context"
	"strconv"
	"sync"

	"github.com/islishude/tss"
)

// KeyShareStore defines durable current-generation key-share semantics.
type KeyShareStore[K tss.KeyShare] interface {
	LoadCurrent(ctx context.Context, keyID string) (K, KeyGeneration, error)
	InstallNew(ctx context.Context, keyID string, share K) (KeyGeneration, error)
	CompareAndSwap(ctx context.Context, keyID string, expected KeyGeneration, next K) (KeyGeneration, error)
	Retire(ctx context.Context, keyID string, generation KeyGeneration) error
}

// KeyShareCloner returns an independent key-share handle owned by the caller.
type KeyShareCloner[K tss.KeyShare] func(K) (K, error)

// PresignInventory tracks presign availability and atomically transfers a
// one-use presign to exactly one signing attempt.
type PresignInventory[P any] interface {
	PutAvailable(ctx context.Context, keyID string, presignID string, presign P) error
	ClaimAvailable(ctx context.Context, presignID string, attemptID string) (P, error)
	Burn(ctx context.Context, presignID string, reason string) error
}

// PresignCloner returns an independent presign handle owned by the caller.
type PresignCloner[P any] func(P) (P, error)

// PresignDestroyer releases secret material held by a presign handle.
type PresignDestroyer[P any] func(P)

// CutoverStore serializes refresh and reshare output installation.
type CutoverStore interface {
	BeginCutover(ctx context.Context, keyID string, expected KeyGeneration, runID string) error
	CommitCutover(ctx context.Context, keyID string, expected KeyGeneration, next KeyGeneration, runID string, outputDigest []byte) error
	AbortCutover(ctx context.Context, keyID string, expected KeyGeneration, runID string, reason string) error
}

// MemoryKeyShareStore is a reference in-memory KeyShareStore.
type MemoryKeyShareStore[K tss.KeyShare] struct {
	mu      sync.Mutex
	current map[string]keyShareRecord[K]
	retired map[string]map[KeyGeneration]bool
	next    uint64
	clone   KeyShareCloner[K]
}

type keyShareRecord[K tss.KeyShare] struct {
	share      K
	generation KeyGeneration
}

// NewMemoryKeyShareStore returns an empty in-memory key-share store. clone must
// create independent handles so callers cannot mutate store-owned key shares.
func NewMemoryKeyShareStore[K tss.KeyShare](clone KeyShareCloner[K]) *MemoryKeyShareStore[K] {
	return &MemoryKeyShareStore[K]{
		current: make(map[string]keyShareRecord[K]),
		retired: make(map[string]map[KeyGeneration]bool),
		clone:   clone,
	}
}

// LoadCurrent returns the current share and generation for keyID.
func (s *MemoryKeyShareStore[K]) LoadCurrent(ctx context.Context, keyID string) (K, KeyGeneration, error) {
	var zero K
	if err := ctx.Err(); err != nil {
		return zero, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.current[keyID]
	if !ok {
		return zero, "", ErrRunNotFound
	}
	if s.clone == nil {
		return zero, "", ErrStoreConflict
	}
	share, err := s.clone(rec.share)
	if err != nil {
		return zero, "", err
	}
	return share, rec.generation, nil
}

// InstallNew installs a key only when no current generation exists.
func (s *MemoryKeyShareStore[K]) InstallNew(ctx context.Context, keyID string, share K) (KeyGeneration, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if keyID == "" {
		return "", ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.current[keyID]; ok {
		return "", ErrStoreConflict
	}
	if s.clone == nil {
		return "", ErrStoreConflict
	}
	owned, err := s.clone(share)
	if err != nil {
		return "", err
	}
	gen := s.nextGeneration()
	s.current[keyID] = keyShareRecord[K]{share: owned, generation: gen}
	return gen, nil
}

// CompareAndSwap replaces current only when expected matches the current generation.
func (s *MemoryKeyShareStore[K]) CompareAndSwap(ctx context.Context, keyID string, expected KeyGeneration, next K) (KeyGeneration, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if keyID == "" || expected == "" {
		return "", ErrStoreConflict
	}
	s.mu.Lock()
	rec, ok := s.current[keyID]
	if !ok {
		s.mu.Unlock()
		return "", ErrRunNotFound
	}
	if rec.generation != expected {
		s.mu.Unlock()
		return rec.generation, ErrStoreConflict
	}
	if s.clone == nil {
		s.mu.Unlock()
		return "", ErrStoreConflict
	}
	owned, err := s.clone(next)
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	gen := s.nextGeneration()
	s.current[keyID] = keyShareRecord[K]{share: owned, generation: gen}
	s.mu.Unlock()
	rec.share.Destroy()
	return gen, nil
}

// Retire marks a non-current generation retired.
func (s *MemoryKeyShareStore[K]) Retire(ctx context.Context, keyID string, generation KeyGeneration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID == "" || generation == "" {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.current[keyID]; ok && rec.generation == generation {
		return ErrStoreConflict
	}
	if s.retired[keyID] == nil {
		s.retired[keyID] = make(map[KeyGeneration]bool)
	}
	s.retired[keyID][generation] = true
	return nil
}

func (s *MemoryKeyShareStore[K]) nextGeneration() KeyGeneration {
	s.next++
	return KeyGeneration("gen-" + strconv.FormatUint(s.next, 10))
}

type presignState uint8

const (
	presignAvailable presignState = iota
	presignConsumed
	presignBurned
)

// MemoryPresignInventory is a reference in-memory PresignInventory.
type MemoryPresignInventory[P any] struct {
	mu      sync.Mutex
	records map[string]presignRecord[P]
	clone   PresignCloner[P]
	destroy PresignDestroyer[P]
}

type presignRecord[P any] struct {
	keyID     string
	presign   P
	state     presignState
	attemptID string
	reason    string
}

// NewMemoryPresignInventory returns an empty in-memory presign inventory. clone
// must create independent handles and destroy must release their secret state.
func NewMemoryPresignInventory[P any](clone PresignCloner[P], destroy PresignDestroyer[P]) *MemoryPresignInventory[P] {
	return &MemoryPresignInventory[P]{
		records: make(map[string]presignRecord[P]),
		clone:   clone,
		destroy: destroy,
	}
}

// PutAvailable stores a new available presign.
func (s *MemoryPresignInventory[P]) PutAvailable(ctx context.Context, keyID string, presignID string, presign P) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID == "" || presignID == "" {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[presignID]; ok {
		return ErrStoreConflict
	}
	if s.clone == nil || s.destroy == nil {
		return ErrStoreConflict
	}
	owned, err := s.clone(presign)
	if err != nil {
		return err
	}
	s.records[presignID] = presignRecord[P]{keyID: keyID, presign: owned, state: presignAvailable}
	return nil
}

// ClaimAvailable atomically tombstones a presign and transfers its handle to
// one signing attempt. The inventory no longer retains the claimed handle.
func (s *MemoryPresignInventory[P]) ClaimAvailable(ctx context.Context, presignID string, attemptID string) (P, error) {
	var zero P
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if presignID == "" || attemptID == "" {
		return zero, ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[presignID]
	if !ok {
		return zero, ErrRunNotFound
	}
	if rec.state != presignAvailable {
		return zero, ErrPresignUnavailable
	}
	claimed := rec.presign
	rec.presign = zero
	rec.state = presignConsumed
	rec.attemptID = attemptID
	s.records[presignID] = rec
	return claimed, nil
}

// Burn tombstones a presign as unavailable.
func (s *MemoryPresignInventory[P]) Burn(ctx context.Context, presignID string, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if presignID == "" {
		return ErrStoreConflict
	}
	s.mu.Lock()
	rec, ok := s.records[presignID]
	if !ok {
		s.mu.Unlock()
		return ErrRunNotFound
	}
	if rec.state == presignBurned {
		s.mu.Unlock()
		return nil
	}
	if rec.state != presignAvailable {
		s.mu.Unlock()
		return ErrPresignUnavailable
	}
	if s.destroy == nil {
		s.mu.Unlock()
		return ErrStoreConflict
	}
	owned := rec.presign
	var zero P
	rec.presign = zero
	rec.state = presignBurned
	rec.reason = reason
	s.records[presignID] = rec
	s.mu.Unlock()
	s.destroy(owned)
	return nil
}

// MemoryCutoverStore is a reference in-memory CutoverStore.
type MemoryCutoverStore struct {
	mu     sync.Mutex
	active map[string]cutoverRecord
}

type cutoverRecord struct {
	expected KeyGeneration
	runID    string
}

// NewMemoryCutoverStore returns an empty in-memory cutover store.
func NewMemoryCutoverStore() *MemoryCutoverStore {
	return &MemoryCutoverStore{active: make(map[string]cutoverRecord)}
}

// BeginCutover starts one active cutover for keyID and expected generation.
func (s *MemoryCutoverStore) BeginCutover(ctx context.Context, keyID string, expected KeyGeneration, runID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID == "" || expected == "" || runID == "" {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.active[keyID]; ok && (rec.expected != expected || rec.runID != runID) {
		return ErrStoreConflict
	}
	s.active[keyID] = cutoverRecord{expected: expected, runID: runID}
	return nil
}

// CommitCutover completes the active cutover when expected and runID match.
func (s *MemoryCutoverStore) CommitCutover(ctx context.Context, keyID string, expected KeyGeneration, next KeyGeneration, runID string, outputDigest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID == "" || expected == "" || next == "" || runID == "" || len(outputDigest) == 0 {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.active[keyID]
	if !ok || rec.expected != expected || rec.runID != runID {
		return ErrStoreConflict
	}
	delete(s.active, keyID)
	return nil
}

// AbortCutover clears the active cutover for the same run and generation.
func (s *MemoryCutoverStore) AbortCutover(ctx context.Context, keyID string, expected KeyGeneration, runID string, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID == "" || expected == "" || runID == "" {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.active[keyID]
	if !ok {
		return nil
	}
	if rec.expected != expected || rec.runID != runID {
		return ErrStoreConflict
	}
	delete(s.active, keyID)
	return nil
}
