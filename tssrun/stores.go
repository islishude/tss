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

// PresignInventory tracks presign availability for scheduling and visibility.
type PresignInventory[P any] interface {
	PutAvailable(ctx context.Context, keyID string, presignID string, presign P) error
	LoadAvailable(ctx context.Context, presignID string) (P, error)
	MarkConsumed(ctx context.Context, presignID string, attemptID string) error
	Burn(ctx context.Context, presignID string, reason string) error
}

// CutoverStore serializes refresh and reshare output installation.
type CutoverStore interface {
	BeginCutover(ctx context.Context, keyID string, expected KeyGeneration, runID string) error
	CommitCutover(ctx context.Context, keyID string, expected KeyGeneration, next KeyGeneration, outputDigest []byte) error
	AbortCutover(ctx context.Context, keyID string, expected KeyGeneration, runID string, reason string) error
}

// MemoryKeyShareStore is a reference in-memory KeyShareStore.
type MemoryKeyShareStore[K tss.KeyShare] struct {
	mu      sync.Mutex
	current map[string]keyShareRecord[K]
	retired map[string]map[KeyGeneration]bool
	next    uint64
}

type keyShareRecord[K tss.KeyShare] struct {
	share      K
	generation KeyGeneration
}

// NewMemoryKeyShareStore returns an empty in-memory key-share store.
func NewMemoryKeyShareStore[K tss.KeyShare]() *MemoryKeyShareStore[K] {
	return &MemoryKeyShareStore[K]{
		current: make(map[string]keyShareRecord[K]),
		retired: make(map[string]map[KeyGeneration]bool),
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
	return rec.share, rec.generation, nil
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
	gen := s.nextGeneration()
	s.current[keyID] = keyShareRecord[K]{share: share, generation: gen}
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
	defer s.mu.Unlock()
	rec, ok := s.current[keyID]
	if !ok {
		return "", ErrRunNotFound
	}
	if rec.generation != expected {
		return rec.generation, ErrStoreConflict
	}
	gen := s.nextGeneration()
	s.current[keyID] = keyShareRecord[K]{share: next, generation: gen}
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
}

type presignRecord[P any] struct {
	keyID     string
	presign   P
	state     presignState
	attemptID string
	reason    string
}

// NewMemoryPresignInventory returns an empty in-memory presign inventory.
func NewMemoryPresignInventory[P any]() *MemoryPresignInventory[P] {
	return &MemoryPresignInventory[P]{records: make(map[string]presignRecord[P])}
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
	s.records[presignID] = presignRecord[P]{keyID: keyID, presign: presign, state: presignAvailable}
	return nil
}

// LoadAvailable returns an available presign or ErrPresignUnavailable.
func (s *MemoryPresignInventory[P]) LoadAvailable(ctx context.Context, presignID string) (P, error) {
	var zero P
	if err := ctx.Err(); err != nil {
		return zero, err
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
	return rec.presign, nil
}

// MarkConsumed tombstones a presign as consumed.
func (s *MemoryPresignInventory[P]) MarkConsumed(ctx context.Context, presignID string, attemptID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if presignID == "" || attemptID == "" {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[presignID]
	if !ok {
		return ErrRunNotFound
	}
	if rec.state == presignConsumed && rec.attemptID == attemptID {
		return nil
	}
	if rec.state != presignAvailable {
		return ErrPresignUnavailable
	}
	rec.state = presignConsumed
	rec.attemptID = attemptID
	s.records[presignID] = rec
	return nil
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
	defer s.mu.Unlock()
	rec, ok := s.records[presignID]
	if !ok {
		return ErrRunNotFound
	}
	if rec.state == presignBurned {
		return nil
	}
	if rec.state != presignAvailable {
		return ErrPresignUnavailable
	}
	rec.state = presignBurned
	rec.reason = reason
	s.records[presignID] = rec
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

// CommitCutover completes the active cutover when expected matches.
func (s *MemoryCutoverStore) CommitCutover(ctx context.Context, keyID string, expected KeyGeneration, next KeyGeneration, outputDigest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID == "" || expected == "" || next == "" || len(outputDigest) == 0 {
		return ErrStoreConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.active[keyID]
	if !ok || rec.expected != expected {
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
