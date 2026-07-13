package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
)

func commitTestAvailablePresign(
	t testing.TB,
	store LifecycleStore,
	binding GenerationBinding,
	presignID string,
	blob, metadata []byte,
	label string,
) RunLease {
	t.Helper()

	h := sha256.New()
	_, _ = h.Write([]byte("tssrun-test-presign-lease"))
	_, _ = h.Write([]byte(t.Name()))
	_, _ = h.Write([]byte(binding.KeyID))
	_, _ = h.Write([]byte(binding.KeyGeneration))
	_, _ = h.Write(binding.EpochID[:])
	_, _ = h.Write([]byte(presignID))
	_, _ = h.Write([]byte(label))
	sessionID, err := tss.NewSessionID(bytes.NewReader(h.Sum(nil)))
	if err != nil {
		t.Fatalf("NewSessionID for available presign: %v", err)
	}
	lease, err := store.AcquireRunLease(context.Background(), binding, RunPresign, sessionID)
	if err != nil {
		t.Fatalf("AcquireRunLease for available presign: %v", err)
	}
	if err := store.CommitAvailablePresignFromLease(context.Background(), lease, presignID, blob, metadata); err != nil {
		t.Fatalf("CommitAvailablePresignFromLease: %v", err)
	}
	return lease
}
