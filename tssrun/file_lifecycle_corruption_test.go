package tssrun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestFileLifecycleStoreReferencedEncryptedBlobCorruptionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "tampered-authentication-tag",
			mutate: func(ciphertext []byte) []byte {
				corrupted := bytes.Clone(ciphertext)
				corrupted[len(corrupted)-1] ^= 0x80
				return corrupted
			},
		},
		{
			name: "truncated-ciphertext",
			mutate: func(ciphertext []byte) []byte {
				return bytes.Clone(ciphertext[:len(ciphertext)/2])
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			passphrase := []byte("file-lifecycle-corruption-passphrase")
			binding := testGenerationBinding("corruption-key", "gen-1", "corruption-epoch")

			store := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := store.InstallInitialGeneration(ctx, binding, []byte("referenced-generation-secret"), nil); err != nil {
				t.Fatalf("InstallInitialGeneration: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("Close setup store: %v", err)
			}

			blobPath := fileLifecycleTestBlobPaths(t, directory, 1)[0]
			// #nosec G304 G703 -- blobPath is enumerated beneath this test's
			// private temporary lifecycle directory.
			ciphertext, err := os.ReadFile(blobPath)
			if err != nil {
				t.Fatalf("read referenced lifecycle blob: %v", err)
			}
			if len(ciphertext) < 2 {
				t.Fatal("referenced lifecycle ciphertext unexpectedly short")
			}
			// #nosec G304 G703 -- blobPath has the constrained test-owned origin
			// documented above and the existing private file keeps mode 0600.
			if err := os.WriteFile(blobPath, tc.mutate(ciphertext), 0o600); err != nil {
				t.Fatalf("corrupt referenced lifecycle blob: %v", err)
			}

			reopened := newTestFileLifecycleStore(t, directory, passphrase)
			if _, err := reopened.LoadCurrentGeneration(ctx, binding.KeyID); !errors.Is(err, ErrLifecycleCorrupt) {
				t.Fatalf("LoadCurrentGeneration after blob corruption got %v, want ErrLifecycleCorrupt", err)
			}
		})
	}
}

func TestFileLifecycleStoreSameKindCiphertextSwapFailsIDBoundAAD(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	passphrase := []byte("file-lifecycle-swap-passphrase")
	first := testGenerationBinding("swap-key-1", "gen-1", "swap-epoch-1")
	second := testGenerationBinding("swap-key-2", "gen-1", "swap-epoch-2")

	store := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := store.InstallInitialGeneration(ctx, first, []byte("generation-secret-one"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration first: %v", err)
	}
	if _, err := store.InstallInitialGeneration(ctx, second, []byte("generation-secret-two"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration second: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close setup store: %v", err)
	}

	paths := fileLifecycleTestBlobPaths(t, directory, 2)
	// #nosec G304 G703 -- both paths are enumerated beneath this test's private
	// temporary lifecycle directory.
	firstCiphertext, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read first generation ciphertext: %v", err)
	}
	// #nosec G304 G703 -- see the constrained path derivation above.
	secondCiphertext, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatalf("read second generation ciphertext: %v", err)
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Fatal("distinct generation blobs produced identical ciphertext")
	}
	// #nosec G304 G703 -- the paths have the constrained test-owned origin
	// documented above and the existing private files keep mode 0600.
	if err := os.WriteFile(paths[0], secondCiphertext, 0o600); err != nil {
		t.Fatalf("replace first generation ciphertext: %v", err)
	}
	// #nosec G304 G703 -- see the constrained path derivation above.
	if err := os.WriteFile(paths[1], firstCiphertext, 0o600); err != nil {
		t.Fatalf("replace second generation ciphertext: %v", err)
	}

	reopened := newTestFileLifecycleStore(t, directory, passphrase)
	if _, err := reopened.LoadCurrentGeneration(ctx, first.KeyID); !errors.Is(err, ErrLifecycleCorrupt) {
		t.Fatalf("LoadCurrentGeneration after same-kind ciphertext swap got %v, want ErrLifecycleCorrupt", err)
	}
}

func TestFileLifecycleStoreAttemptPayloadsAreEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store := newTestFileLifecycleStore(t, directory, []byte("file-lifecycle-attempt-redaction-passphrase"))
	binding := testGenerationBinding("attempt-redaction-key", "gen-1", "attempt-redaction-epoch")
	if _, err := store.InstallInitialGeneration(ctx, binding, []byte("attempt-generation-secret"), nil); err != nil {
		t.Fatalf("InstallInitialGeneration: %v", err)
	}
	commitTestAvailablePresign(t, store, binding, "attempt-redaction-presign", []byte("attempt-presign-secret"), []byte("attempt-presign-metadata"), "redaction")
	sessionID := fileLifecycleSessionID(t, "attempt-redaction-session")
	if _, err := store.AcquireRunLease(ctx, binding, RunSign, sessionID); err != nil {
		t.Fatalf("AcquireRunLease: %v", err)
	}
	intent := SignAttemptIntent{
		AttemptID:    "attempt-redaction-attempt",
		SessionID:    sessionID,
		IntentDigest: testRunDigest("attempt-redaction-intent"),
	}
	payloads := []struct {
		name      string
		plaintext []byte
	}{
		{name: "exact outbox", plaintext: []byte("exact-outbox-plaintext-marker-0f43baf5")},
		{name: "delivery", plaintext: []byte("delivery-plaintext-marker-55e4229c")},
		{name: "completion", plaintext: []byte("completion-plaintext-marker-cd38f11a")},
	}
	commit, err := store.CommitSignAttempt(ctx, binding, "attempt-redaction-presign", intent, payloads[0].plaintext)
	if err != nil {
		t.Fatalf("CommitSignAttempt: %v", err)
	}
	query := commit.Record.Query()
	if _, err := store.MarkAttemptDelivered(ctx, query, payloads[1].plaintext); err != nil {
		t.Fatalf("MarkAttemptDelivered: %v", err)
	}
	terminal, err := store.CompleteAttempt(ctx, query, payloads[2].plaintext)
	if err != nil {
		t.Fatalf("CompleteAttempt: %v", err)
	}
	if !terminal.Terminal() || !bytes.Equal(terminal.Delivery, payloads[1].plaintext) || !bytes.Equal(terminal.Completion, payloads[2].plaintext) {
		t.Fatal("attempt payload persistence did not reach the expected terminal state")
	}

	for path, content := range lifecycleRegularFiles(t, directory) {
		for _, payload := range payloads {
			if bytes.Contains(content, payload.plaintext) {
				t.Fatalf("%s plaintext appeared in lifecycle file %s", payload.name, path)
			}
		}
	}
}

func fileLifecycleTestBlobPaths(t *testing.T, directory string, want int) []string {
	t.Helper()
	blobDirectory := filepath.Join(
		directory,
		fileLifecycleKeysDirectory,
		fileLifecycleKeyHash(fileLifecycleGlobalKeyID),
		fileLifecycleBlobsDirectory,
	)
	entries, err := os.ReadDir(blobDirectory)
	if err != nil {
		t.Fatalf("read lifecycle blob directory: %v", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".enc") {
			paths = append(paths, filepath.Join(blobDirectory, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) != want {
		t.Fatalf("lifecycle blob count=%d, want %d", len(paths), want)
	}
	return paths
}
