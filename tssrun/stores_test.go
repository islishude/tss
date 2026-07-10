package tssrun

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/islishude/tss"
)

func TestMemoryKeyShareStoreCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryKeyShareStore(cloneFakeShare)
	input := &fakeShare{party: 1}
	firstGen, err := store.InstallNew(ctx, "key-1", input)
	if err != nil {
		t.Fatalf("InstallNew: %v", err)
	}
	input.party = 2
	loaded, loadedGen, err := store.LoadCurrent(ctx, "key-1")
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if loadedGen != firstGen || loaded.party != 1 || loaded == input {
		t.Fatalf("LoadCurrent returned aliased or incorrect share: gen=%q party=%d aliased=%v", loadedGen, loaded.party, loaded == input)
	}
	loaded.party = 3
	reloaded, _, err := store.LoadCurrent(ctx, "key-1")
	if err != nil {
		t.Fatalf("second LoadCurrent: %v", err)
	}
	if reloaded.party != 1 {
		t.Fatalf("caller mutation changed stored share party to %d", reloaded.party)
	}
	if _, err := store.CompareAndSwap(ctx, "key-1", "wrong", &fakeShare{party: 1}); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected ErrStoreConflict, got %v", err)
	}
	oldOwned := store.current["key-1"].share
	nextGen, err := store.CompareAndSwap(ctx, "key-1", firstGen, &fakeShare{party: 1})
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	if !oldOwned.destroyed {
		t.Fatal("CompareAndSwap did not destroy the replaced store-owned share")
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
	destroy := func(p *fakePresign) { p.destroyed = true }
	store := NewMemoryPresignInventory(cloneFakePresign, destroy)
	input := &fakePresign{secret: "secret-handle"}
	if err := store.PutAvailable(ctx, "key-1", "presign-1", input); err != nil {
		t.Fatalf("PutAvailable: %v", err)
	}
	input.secret = "mutated"
	claimed, err := store.ClaimAvailable(ctx, "presign-1", "attempt-1")
	if err != nil {
		t.Fatalf("ClaimAvailable: %v", err)
	}
	if claimed == input || claimed.secret != "secret-handle" {
		t.Fatalf("ClaimAvailable returned aliased or mutated handle: aliased=%v secret=%q", claimed == input, claimed.secret)
	}
	if store.records["presign-1"].presign != nil {
		t.Fatal("consumed tombstone retained the secret handle")
	}
	if _, err := store.ClaimAvailable(ctx, "presign-1", "attempt-2"); !errors.Is(err, ErrPresignUnavailable) {
		t.Fatalf("expected ErrPresignUnavailable, got %v", err)
	}
	if err := store.Burn(ctx, "presign-1", "discard"); !errors.Is(err, ErrPresignUnavailable) {
		t.Fatalf("expected ErrPresignUnavailable, got %v", err)
	}

	if err := store.PutAvailable(ctx, "key-1", "presign-2", &fakePresign{secret: "burn-me"}); err != nil {
		t.Fatalf("PutAvailable burn target: %v", err)
	}
	owned := store.records["presign-2"].presign
	if err := store.Burn(ctx, "presign-2", "discard"); err != nil {
		t.Fatalf("Burn: %v", err)
	}
	if !owned.destroyed || store.records["presign-2"].presign != nil {
		t.Fatal("burn did not destroy and clear the store-owned handle")
	}
}

func TestMemoryPresignInventoryClaimIsAtomic(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPresignInventory(cloneFakePresign, func(p *fakePresign) { p.destroyed = true })
	if err := store.PutAvailable(ctx, "key-1", "presign-1", &fakePresign{secret: "one-use"}); err != nil {
		t.Fatalf("PutAvailable: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, attemptID := range []string{"attempt-1", "attempt-2"} {
		wg.Go(func() {
			<-start
			_, err := store.ClaimAvailable(ctx, "presign-1", attemptID)
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)

	var claimed, unavailable int
	for err := range results {
		switch {
		case err == nil:
			claimed++
		case errors.Is(err, ErrPresignUnavailable):
			unavailable++
		default:
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if claimed != 1 || unavailable != 1 {
		t.Fatalf("claims: successful=%d unavailable=%d, want 1 each", claimed, unavailable)
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
	if err := store.CommitCutover(ctx, "key-1", "gen-2", "gen-3", "run-1", []byte("out")); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected ErrStoreConflict, got %v", err)
	}
	if err := store.CommitCutover(ctx, "key-1", "gen-1", "gen-2", "run-2", []byte("out")); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("expected wrong-run ErrStoreConflict, got %v", err)
	}
	if err := store.CommitCutover(ctx, "key-1", "gen-1", "gen-2", "run-1", []byte("out")); err != nil {
		t.Fatalf("CommitCutover: %v", err)
	}
}

type fakeShare struct {
	party     tss.PartyID
	destroyed bool
}

func cloneFakeShare(s *fakeShare) (*fakeShare, error) {
	return &fakeShare{party: s.party}, nil
}

func (s *fakeShare) Algorithm() tss.Algorithm { return tss.AlgorithmFROSTEd25519 }

func (s *fakeShare) PartyID() tss.PartyID { return s.party }

func (s *fakeShare) Derive(tss.DerivationPath, ...tss.DeriveOption) (*tss.DerivationResult, error) {
	return nil, errors.New("not implemented")
}

func (s *fakeShare) MarshalBinary() ([]byte, error) { return []byte{byte(s.party)}, nil }

func (s *fakeShare) Destroy() { s.destroyed = true }

type fakePresign struct {
	secret    string
	destroyed bool
}

func cloneFakePresign(p *fakePresign) (*fakePresign, error) {
	return &fakePresign{secret: p.secret}, nil
}
