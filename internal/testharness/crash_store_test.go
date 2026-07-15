package testharness

import (
	"bytes"
	"errors"
	"testing"
)

func TestCrashyStoreOwnsLoadedAndStoredBytes(t *testing.T) {
	t.Parallel()
	initial := []byte{1, 2, 3}
	store := NewCrashyStore(initial, CrashDisabled)
	defer store.Destroy()
	replaced := store.blob
	initial[0] = 9
	loaded := store.Load()
	if !bytes.Equal(loaded, []byte{1, 2, 3}) {
		t.Fatal("constructor retained caller-owned storage")
	}
	loaded[0] = 8
	if got := store.Load(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatal("Load returned aliased storage")
	}
	next := []byte{4, 5, 6}
	if err := store.CompareAndSwap([]byte{1, 2, 3}, next); err != nil {
		t.Fatal(err)
	}
	if !zeroCrashStoreBytes(next) {
		t.Fatal("successful compare-and-swap retained the caller's replacement blob")
	}
	if !zeroCrashStoreBytes(replaced) {
		t.Fatal("successful compare-and-swap did not clear the replaced durable blob")
	}
	if got := store.Load(); !bytes.Equal(got, []byte{4, 5, 6}) {
		t.Fatal("successful compare-and-swap did not install replacement")
	}
}

func TestCrashyStoreRejectsConflictWithoutMutation(t *testing.T) {
	t.Parallel()
	store := NewCrashyStore([]byte{1, 2, 3}, CrashDisabled)
	defer store.Destroy()
	rejected := []byte{4, 5, 6}
	if err := store.CompareAndSwap([]byte{9}, rejected); !errors.Is(err, ErrCrashStoreConflict) {
		t.Fatalf("compare-and-swap error = %v, want ErrCrashStoreConflict", err)
	}
	if !zeroCrashStoreBytes(rejected) {
		t.Fatal("compare-and-swap conflict retained the rejected blob")
	}
	if got := store.Load(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatal("compare-and-swap conflict mutated durable blob")
	}
}

func TestCrashyStoreNilReceiverClearsRejectedBlob(t *testing.T) {
	t.Parallel()
	var store *CrashyStore
	rejected := []byte{1, 2, 3}
	if err := store.CompareAndSwap(nil, rejected); err == nil {
		t.Fatal("nil crash store accepted a replacement")
	}
	if !zeroCrashStoreBytes(rejected) {
		t.Fatal("nil crash store retained the rejected blob")
	}
}

func TestCrashyStorePersistenceCrashPoints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		point     CrashPoint
		wantBlob  []byte
		wantRetry bool
	}{
		{name: "before persist", point: CrashBeforePersist, wantBlob: []byte{1}, wantRetry: true},
		{name: "after persist", point: CrashAfterPersist, wantBlob: []byte{2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := NewCrashyStore([]byte{1}, tc.point)
			defer store.Destroy()
			replacement := []byte{2}
			if err := store.CompareAndSwap([]byte{1}, replacement); !errors.Is(err, ErrCrashInjected) {
				t.Fatalf("compare-and-swap error = %v, want ErrCrashInjected", err)
			}
			if !zeroCrashStoreBytes(replacement) {
				t.Fatal("crashed compare-and-swap retained the caller's replacement blob")
			}
			if got := store.Load(); !bytes.Equal(got, tc.wantBlob) {
				t.Fatalf("durable blob after crash = %v, want %v", got, tc.wantBlob)
			}
			if tc.wantRetry {
				retry := []byte{2}
				if err := store.CompareAndSwap([]byte{1}, retry); err != nil {
					t.Fatalf("one-shot crash prevented retry: %v", err)
				}
				if !zeroCrashStoreBytes(retry) {
					t.Fatal("successful retry retained the caller's replacement blob")
				}
			}
		})
	}
}

func TestCrashyStoreOutboundCrashPointsAreOneShot(t *testing.T) {
	t.Parallel()
	for _, point := range []CrashPoint{CrashBeforeOutbound, CrashAfterOutbound} {
		t.Run(pointName(point), func(t *testing.T) {
			t.Parallel()
			store := NewCrashyStore(nil, point)
			defer store.Destroy()
			if err := store.Hit(CrashAfterPersist); err != nil {
				t.Fatalf("non-matching crash point failed: %v", err)
			}
			if err := store.Hit(point); !errors.Is(err, ErrCrashInjected) {
				t.Fatalf("matching crash point error = %v, want ErrCrashInjected", err)
			}
			if err := store.Hit(point); err != nil {
				t.Fatalf("one-shot crash point fired twice: %v", err)
			}
		})
	}
}

func TestCrashyStoreDestroyClearsBlob(t *testing.T) {
	t.Parallel()
	store := NewCrashyStore([]byte{1, 2, 3}, CrashDisabled)
	store.Destroy()
	if got := store.Load(); got != nil {
		t.Fatal("destroyed crash store retained a blob")
	}
}

func pointName(point CrashPoint) string {
	switch point {
	case CrashBeforeOutbound:
		return "before outbound"
	case CrashAfterOutbound:
		return "after outbound"
	default:
		return "unexpected"
	}
}

func zeroCrashStoreBytes(in []byte) bool {
	for _, value := range in {
		if value != 0 {
			return false
		}
	}
	return true
}
