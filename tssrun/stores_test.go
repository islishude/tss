package tssrun

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

func TestMemoryKeyShareStoreCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryKeyShareStore[*fakeShare]()
	firstGen, err := store.InstallNew(ctx, "key-1", &fakeShare{party: 1})
	if err != nil {
		t.Fatalf("InstallNew: %v", err)
	}
	if _, err := store.CompareAndSwap(ctx, "key-1", "wrong", &fakeShare{party: 1}); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected ErrStoreConflict, got %v", err)
	}
	nextGen, err := store.CompareAndSwap(ctx, "key-1", firstGen, &fakeShare{party: 1})
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	if nextGen == firstGen {
		t.Fatal("generation did not advance")
	}
	if err := store.Retire(ctx, "key-1", nextGen); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected current generation retire conflict, got %v", err)
	}
	if err := store.Retire(ctx, "key-1", firstGen); err != nil {
		t.Fatalf("Retire old generation: %v", err)
	}
}

func TestMemoryPresignInventoryTombstones(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPresignInventory[string]()
	if err := store.PutAvailable(ctx, "key-1", "presign-1", "secret-handle"); err != nil {
		t.Fatalf("PutAvailable: %v", err)
	}
	if _, err := store.LoadAvailable(ctx, "presign-1"); err != nil {
		t.Fatalf("LoadAvailable: %v", err)
	}
	if err := store.MarkConsumed(ctx, "presign-1", "attempt-1"); err != nil {
		t.Fatalf("MarkConsumed: %v", err)
	}
	if _, err := store.LoadAvailable(ctx, "presign-1"); !errors.Is(err, ErrPresignUnavailable) {
		t.Fatalf("expected ErrPresignUnavailable, got %v", err)
	}
	if err := store.Burn(ctx, "presign-1", "discard"); !errors.Is(err, ErrPresignUnavailable) {
		t.Fatalf("expected ErrPresignUnavailable, got %v", err)
	}
}

func TestMemoryCutoverStoreConflicts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCutoverStore()
	if err := store.BeginCutover(ctx, "key-1", "gen-1", "run-1"); err != nil {
		t.Fatalf("BeginCutover: %v", err)
	}
	if err := store.BeginCutover(ctx, "key-1", "gen-1", "run-2"); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected ErrStoreConflict, got %v", err)
	}
	if err := store.CommitCutover(ctx, "key-1", "gen-2", "gen-3", []byte("out")); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected ErrStoreConflict, got %v", err)
	}
	if err := store.CommitCutover(ctx, "key-1", "gen-1", "gen-2", []byte("out")); err != nil {
		t.Fatalf("CommitCutover: %v", err)
	}
}

type fakeShare struct {
	party tss.PartyID
}

func (s *fakeShare) Algorithm() tss.Algorithm { return tss.AlgorithmFROSTEd25519 }

func (s *fakeShare) PartyID() tss.PartyID { return s.party }

func (s *fakeShare) Derive(tss.DerivationPath, ...tss.DeriveOption) (*tss.DerivationResult, error) {
	return nil, errors.New("not implemented")
}

func (s *fakeShare) MarshalBinary() ([]byte, error) { return []byte{byte(s.party)}, nil }

func (s *fakeShare) Destroy() {}
