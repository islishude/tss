package tssrun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/islishude/tss"
)

const (
	fileLifecycleMetaName   = "store.meta"
	fileLifecycleMetaSchema = 1
	fileLifecycleStoreIDLen = 16
	fileLifecycleDEKLen     = chacha20poly1305.KeySize
	fileLifecycleSaltLen    = 32
)

type fileLifecycleMeta struct {
	Format     string
	Schema     uint16
	StoreID    []byte
	KDFTime    uint32
	KDFMemory  uint32
	KDFThreads uint8
	Salt       []byte
	Nonce      []byte
	WrappedDEK []byte
}

func openOrCreateFileLifecycleKey(directory string, passphrase []byte, params tss.PassphraseParams) ([]byte, []byte, error) {
	if len(passphrase) == 0 {
		return nil, nil, ErrInvalidLifecycleRecord
	}
	lockOwner := &FileLifecycleStore{directory: directory}
	release, err := lockOwner.acquireKeyLock(context.Background(), "metadata:"+fileLifecycleGlobalKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("lock lifecycle store metadata: %w", err)
	}
	defer release()
	return openOrCreateFileLifecycleKeyLocked(directory, passphrase, params)
}

func openOrCreateFileLifecycleKeyLocked(directory string, passphrase []byte, params tss.PassphraseParams) ([]byte, []byte, error) {
	metaPath := filepath.Join(directory, fileLifecycleMetaName)
	if _, err := os.Lstat(metaPath); errors.Is(err, os.ErrNotExist) {
		stateExists, stateErr := fileLifecycleEncryptedStateExists(directory)
		if stateErr != nil {
			return nil, nil, stateErr
		}
		if stateExists {
			return nil, nil, fmt.Errorf("%w: lifecycle store metadata is missing for existing encrypted state", ErrLifecycleCorrupt)
		}
		legacyPath := filepath.Join(directory, fileLifecycleKeysDirectory, fileLifecycleKeyHash(fileLifecycleGlobalKeyID), fileLifecycleManifestName)
		if _, legacyErr := os.Lstat(legacyPath); legacyErr == nil {
			return nil, nil, fmt.Errorf("%w: retired lifecycle manifest format", ErrLifecycleCorrupt)
		} else if !errors.Is(legacyErr, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("inspect retired lifecycle manifest: %w", legacyErr)
		}
		return createFileLifecycleMeta(directory, metaPath, passphrase, params)
	} else if err != nil {
		return nil, nil, fmt.Errorf("inspect lifecycle store metadata: %w", err)
	}
	return readFileLifecycleMeta(metaPath, passphrase)
}

func fileLifecycleEncryptedStateExists(directory string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(directory, fileLifecycleRootName)); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect lifecycle root without metadata: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".root-") && strings.HasSuffix(entry.Name(), ".tmp") {
			return true, nil
		}
	}
	for _, child := range []string{fileLifecycleSnapshotsDirectory, fileLifecycleIndexesDirectory} {
		found := false
		err := filepath.WalkDir(filepath.Join(directory, child), func(_ string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				found = true
				return filepath.SkipAll
			}
			return nil
		})
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

func createFileLifecycleMeta(directory, metaPath string, passphrase []byte, params tss.PassphraseParams) ([]byte, []byte, error) {
	if err := validateFileLifecycleKDFParams(params); err != nil {
		return nil, nil, err
	}
	storeID := make([]byte, fileLifecycleStoreIDLen)
	salt := make([]byte, fileLifecycleSaltLen)
	dek := make([]byte, fileLifecycleDEKLen)
	for _, value := range [][]byte{storeID, salt, dek} {
		if _, err := io.ReadFull(rand.Reader, value); err != nil {
			clear(dek)
			return nil, nil, fmt.Errorf("generate lifecycle store key material: %w", err)
		}
	}
	meta := fileLifecycleMeta{
		Format: "tssrun-file-lifecycle", Schema: fileLifecycleMetaSchema, StoreID: bytes.Clone(storeID),
		KDFTime: params.Time, KDFMemory: params.Memory, KDFThreads: params.Threads,
		Salt: bytes.Clone(salt),
	}
	nonce, wrappedDEK, err := wrapFileLifecycleDEK(passphrase, salt, params, meta, dek)
	if err != nil {
		clear(dek)
		return nil, nil, err
	}
	meta.Nonce = nonce
	meta.WrappedDEK = wrappedDEK
	encoded, err := json.Marshal(meta)
	if err != nil {
		clear(dek)
		return nil, nil, err
	}
	defer clear(encoded)
	// #nosec G304 -- metaPath is the fixed store.meta name beneath the constructor-validated private store root.
	file, err := os.OpenFile(metaPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		clear(dek)
		return nil, nil, fmt.Errorf("%w: lifecycle store metadata appeared while creation lock was held", ErrLifecycleCorrupt)
	}
	if err != nil {
		clear(dek)
		return nil, nil, fmt.Errorf("create lifecycle store metadata: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(metaPath)
		}
	}()
	if err := writeLifecycleFile(file, encoded); err != nil {
		clear(dek)
		return nil, nil, err
	}
	if err := file.Sync(); err != nil {
		clear(dek)
		return nil, nil, fmt.Errorf("fsync lifecycle store metadata: %w", err)
	}
	if err := file.Close(); err != nil {
		clear(dek)
		return nil, nil, err
	}
	if err := syncLifecycleDirectory(directory); err != nil {
		clear(dek)
		return nil, nil, err
	}
	remove = false
	return dek, storeID, nil
}

func wrapFileLifecycleDEK(passphrase, salt []byte, params tss.PassphraseParams, meta fileLifecycleMeta, dek []byte) ([]byte, []byte, error) {
	kek := argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, chacha20poly1305.KeySize)
	defer clear(kek)
	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, dek, fileLifecycleMetaAAD(meta)), nil
}

func readFileLifecycleMeta(metaPath string, passphrase []byte) ([]byte, []byte, error) {
	info, err := os.Lstat(metaPath)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect lifecycle store metadata: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 16<<10 {
		return nil, nil, fmt.Errorf("%w: invalid lifecycle store metadata file", ErrLifecycleCorrupt)
	}
	// #nosec G304 -- metaPath is the fixed store.meta path validated by Lstat above.
	encoded, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, nil, err
	}
	defer clear(encoded)
	var meta fileLifecycleMeta
	if err := decodeFileLifecycleJSON(encoded, &meta); err != nil {
		return nil, nil, fmt.Errorf("%w: decode lifecycle store metadata: %w", ErrLifecycleCorrupt, err)
	}
	if meta.Format != "tssrun-file-lifecycle" || meta.Schema != fileLifecycleMetaSchema || len(meta.StoreID) != fileLifecycleStoreIDLen || len(meta.Salt) != fileLifecycleSaltLen || len(meta.Nonce) != chacha20poly1305.NonceSize {
		return nil, nil, fmt.Errorf("%w: lifecycle store metadata identity mismatch", ErrLifecycleCorrupt)
	}
	params := tss.PassphraseParams{Time: meta.KDFTime, Memory: meta.KDFMemory, Threads: meta.KDFThreads}
	if err := validateFileLifecycleKDFParams(params); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrLifecycleCorrupt, err)
	}
	kek := argon2.IDKey(passphrase, meta.Salt, params.Time, params.Memory, params.Threads, chacha20poly1305.KeySize)
	defer clear(kek)
	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, nil, err
	}
	dek, err := aead.Open(nil, meta.Nonce, meta.WrappedDEK, fileLifecycleMetaAAD(meta))
	if err != nil || len(dek) != fileLifecycleDEKLen {
		clear(dek)
		return nil, nil, fmt.Errorf("%w: unwrap lifecycle data key", ErrLifecycleCorrupt)
	}
	return dek, bytes.Clone(meta.StoreID), nil
}

func decodeFileLifecycleJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateFileLifecycleKDFParams(params tss.PassphraseParams) error {
	if params.Time == 0 || params.Time > 4 || params.Threads == 0 || params.Threads > 8 || params.Memory < 8*uint32(params.Threads) || params.Memory > 128*1024 {
		return fmt.Errorf("%w: invalid lifecycle Argon2id parameters", ErrInvalidLifecycleRecord)
	}
	return nil
}

func fileLifecycleMetaAAD(meta fileLifecycleMeta) []byte {
	return fmt.Appendf(nil, "%s|%d|%x|%d|%d|%d|%x", meta.Format, meta.Schema, meta.StoreID, meta.KDFTime, meta.KDFMemory, meta.KDFThreads, meta.Salt)
}

func sealFileLifecycleData(store *FileLifecycleStore, aad string, plaintext []byte) ([]byte, error) {
	if store == nil || len(store.dek) != fileLifecycleDEKLen || len(store.storeID) != fileLifecycleStoreIDLen {
		return nil, ErrFileLifecycleStoreClosed
	}
	aead, err := chacha20poly1305.New(store.dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	boundAAD := fmt.Appendf(nil, "tssrun-file-lifecycle|%x|%s", store.storeID, aad)
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, boundAAD), nil
}

func openFileLifecycleData(store *FileLifecycleStore, aad string, encoded []byte) ([]byte, error) {
	if store == nil || len(store.dek) != fileLifecycleDEKLen || len(store.storeID) != fileLifecycleStoreIDLen {
		return nil, ErrFileLifecycleStoreClosed
	}
	aead, err := chacha20poly1305.New(store.dek)
	if err != nil {
		return nil, err
	}
	if len(encoded) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrLifecycleCorrupt
	}
	nonce := encoded[:aead.NonceSize()]
	boundAAD := fmt.Appendf(nil, "tssrun-file-lifecycle|%x|%s", store.storeID, aad)
	return aead.Open(nil, nonce, encoded[aead.NonceSize():], boundAAD)
}
