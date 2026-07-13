package secp256k1

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"golang.org/x/crypto/argon2"
)

const (
	signAttemptFileObjectKeyLabel = "cggmp21-secp256k1-sign-attempt-file-object-v1"
	signAttemptStoreKeyLabel      = "cggmp21-secp256k1-sign-attempt-store-key-v1"
	signAttemptBurnMagic          = "cggmp21-sign-attempt-burn-v1\n"
	signAttemptStoreSaltFile      = ".store-key-salt"
	signAttemptStoreSaltSize      = 32
	signAttemptStoreMaxKDFTime    = 4
	signAttemptStoreMaxKDFMemory  = 128 * 1024
	signAttemptStoreMaxKDFThreads = 8
)

// FileSignAttemptStore is an encrypted append-only reference implementation of
// SignAttemptStore. Production deployments should use a transactional database
// or KMS/HSM-backed storage service.
type FileSignAttemptStore struct {
	root                 string
	objects              string
	claims               string
	deliveryAcks         string
	deliveryCertificates string
	completions          string
	burns                string
	passphrase           []byte
	storeSecret          []byte
	params               *tss.PassphraseParams
}

// NewFileSignAttemptStore creates an encrypted append-only file store. All
// directories must reside on one filesystem because atomic hard links establish
// presign claims and durable delivery/completion objects. Paths use an
// HMAC-derived opaque store key rather than the secret-tainted presign content
// ID. The root is canonicalized, an explicit root or non-system ancestor
// symlink is rejected, and every owned directory is restricted to mode 0700.
// A nil params value selects [tss.DefaultPassphraseParams].
func NewFileSignAttemptStore(directory string, passphrase []byte, params *tss.PassphraseParams) (*FileSignAttemptStore, error) {
	if directory == "" {
		return nil, errors.New("empty sign attempt store directory")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("empty sign attempt store passphrase")
	}
	secureRoot, err := secureSignAttemptStoreRoot(directory)
	if err != nil {
		return nil, err
	}
	directory = secureRoot
	store := &FileSignAttemptStore{
		root:                 directory,
		objects:              filepath.Join(directory, "objects"),
		claims:               filepath.Join(directory, "claims"),
		deliveryAcks:         filepath.Join(directory, "delivery-acks"),
		deliveryCertificates: filepath.Join(directory, "delivery-certificates"),
		completions:          filepath.Join(directory, "completions"),
		burns:                filepath.Join(directory, "burns"),
		passphrase:           slices.Clone(passphrase),
	}
	if params == nil {
		params = tss.DefaultPassphraseParams()
	}
	copied := *params
	if err := validateSignAttemptStoreKDFParams(&copied); err != nil {
		store.Destroy()
		return nil, err
	}
	store.params = &copied
	for _, path := range []string{
		store.root,
		store.objects,
		store.claims,
		store.deliveryAcks,
		store.deliveryCertificates,
		store.completions,
		store.burns,
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			store.Destroy()
			return nil, fmt.Errorf("create sign attempt store directory: %w", err)
		}
		if err := validateSecureSignAttemptStoreDirectory(path); err != nil {
			store.Destroy()
			return nil, err
		}
	}
	salt, err := loadOrCreateSignAttemptStoreSalt(store.root)
	if err != nil {
		store.Destroy()
		return nil, err
	}
	store.storeSecret, err = deriveSignAttemptStoreSecret(passphrase, salt, store.params)
	clear(salt)
	if err != nil {
		store.Destroy()
		return nil, err
	}
	return store, nil
}

// Destroy clears the in-memory passphrase retained by the reference store.
func (s *FileSignAttemptStore) Destroy() {
	if s == nil {
		return
	}
	clear(s.passphrase)
	s.passphrase = nil
	clear(s.storeSecret)
	s.storeSecret = nil
}

// LoadSignAttempt loads the immutable claim and merges append-only delivery and
// completion objects. A burn tombstone returns ErrSignAttemptBurned.
func (s *FileSignAttemptStore) LoadSignAttempt(ctx context.Context, presignContentID []byte) (SignAttemptRecord, error) {
	if err := validateFileStoreCall(ctx, s, presignContentID); err != nil {
		return SignAttemptRecord{}, err
	}
	base, err := s.readClaimRecord(presignContentID)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if !bytes.Equal(base.PresignContentID, presignContentID) {
		return SignAttemptRecord{}, fmt.Errorf("%w: claim key mismatch", ErrSignAttemptCorrupt)
	}
	record := base.Clone()
	if err := s.mergeDeliveryAcks(&record, presignContentID); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := s.mergeDeliveryCertificate(&record, presignContentID); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := s.mergeCompletion(&record, presignContentID); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := record.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	return record, nil
}

// CommitSignAttempt atomically creates the only claim for candidate.PresignContentID.
// An existing exact attempt is returned idempotently; the same intent with a
// different attempt is ErrSignAttemptNonDeterminism.
func (s *FileSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	if ctx == nil {
		return SignAttemptCommit{}, errors.New("nil context")
	}
	if err := validateSignAttemptCandidate(candidate); err != nil {
		return SignAttemptCommit{}, err
	}
	if err := validateFileStoreCall(ctx, s, candidate.PresignContentID); err != nil {
		return SignAttemptCommit{}, err
	}
	objectPath, err := s.writeEncryptedObject(candidate, "base-attempt")
	if err != nil {
		return SignAttemptCommit{}, err
	}
	claimPath := s.claimPath(candidate.PresignContentID)
	if err := os.Link(objectPath, claimPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			return s.existingCommit(ctx, candidate)
		}
		return SignAttemptCommit{}, fmt.Errorf("link sign attempt claim: %w", err)
	}
	if err := syncDirectory(s.claims); err != nil {
		return SignAttemptCommit{}, fmt.Errorf("sync sign attempt claims: %w", err)
	}
	return SignAttemptCommit{Status: SignAttemptCreated, Record: candidate.Clone()}, nil
}

// UpdateSignAttemptDelivery atomically persists a valid delivery ACK or final
// authenticated broadcast certificate for the exact attempt hash.
func (s *FileSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if len(update.PresignContentID) != sha256.Size {
		return SignAttemptRecord{}, errors.New("invalid delivery update presign content ID")
	}
	if err := validateFileStoreCall(ctx, s, update.PresignContentID); err != nil {
		return SignAttemptRecord{}, err
	}
	record, err := s.LoadSignAttempt(ctx, update.PresignContentID)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	updated, err := applySignAttemptDeliveryUpdate(record, update)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if record.DeliveryState.Equal(updated.DeliveryState) {
		return updated, nil
	}
	if update.Ack != nil {
		if err := s.persistDeliveryAck(ctx, record, update.Ack.Clone()); err != nil {
			return SignAttemptRecord{}, err
		}
	}
	if update.Certificate != nil {
		if err := s.persistDeliveryCertificate(ctx, updated, updated.DeliveryState.Certificate.Clone()); err != nil {
			return SignAttemptRecord{}, err
		}
	}
	return s.LoadSignAttempt(context.WithoutCancel(ctx), update.PresignContentID)
}

// CompleteSignAttempt atomically persists the final signature for an existing
// attempt. Repeating the same result is idempotent.
func (s *FileSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := result.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := validateFileStoreCall(ctx, s, result.PresignContentID); err != nil {
		return SignAttemptRecord{}, err
	}
	record, err := s.LoadSignAttempt(ctx, result.PresignContentID)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if !bytes.Equal(record.AttemptHash, result.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if record.Completed {
		if bytes.Equal(record.SignatureR, result.Signature.R) && bytes.Equal(record.SignatureS, result.Signature.S) && record.SignatureRecoveryID == result.Signature.RecoveryID {
			return record, nil
		}
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	completed := record.Clone()
	completed.Completed = true
	completed.SignatureR = slices.Clone(result.Signature.R)
	completed.SignatureS = slices.Clone(result.Signature.S)
	completed.SignatureRecoveryID = result.Signature.RecoveryID
	if err := completed.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	objectPath, err := s.writeEncryptedObject(completed, "completion")
	if err != nil {
		return SignAttemptRecord{}, err
	}
	completionPath := s.completionPath(result.PresignContentID)
	if err := os.Link(objectPath, completionPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			existing, loadErr := s.LoadSignAttempt(context.WithoutCancel(ctx), result.PresignContentID)
			if loadErr != nil {
				return SignAttemptRecord{}, loadErr
			}
			if existing.Completed &&
				bytes.Equal(existing.AttemptHash, result.AttemptHash) &&
				bytes.Equal(existing.SignatureR, result.Signature.R) &&
				bytes.Equal(existing.SignatureS, result.Signature.S) &&
				existing.SignatureRecoveryID == result.Signature.RecoveryID {
				return existing, nil
			}
			return SignAttemptRecord{}, ErrSignAttemptConflict
		}
		return SignAttemptRecord{}, fmt.Errorf("link sign attempt completion: %w", err)
	}
	if err := syncDirectory(s.completions); err != nil {
		return SignAttemptRecord{}, fmt.Errorf("sync sign attempt completions: %w", err)
	}
	return completed, nil
}

// BurnPresign durably writes a tombstone for a presign with no existing attempt.
// The burn and attempt commit share the same claim path, so only one can win.
func (s *FileSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	if err := validateFileStoreCall(ctx, s, burn.PresignContentID); err != nil {
		return err
	}
	objectPath, err := s.writeBurnObject(burn)
	if err != nil {
		return err
	}
	claimPath := s.claimPath(burn.PresignContentID)
	if err := os.Link(objectPath, claimPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			_, loadErr := s.LoadSignAttempt(context.WithoutCancel(ctx), burn.PresignContentID)
			if errors.Is(loadErr, ErrSignAttemptBurned) {
				return nil
			}
			if loadErr == nil {
				return ErrSignAttemptConflict
			}
			return loadErr
		}
		return fmt.Errorf("link sign attempt burn claim: %w", err)
	}
	if err := syncDirectory(s.claims); err != nil {
		return fmt.Errorf("sync sign attempt burn claim: %w", err)
	}
	burnPath := s.burnPath(burn.PresignContentID)
	if err := os.Link(objectPath, burnPath); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("link sign attempt burn tombstone: %w", err)
	}
	if err := syncDirectory(s.burns); err != nil {
		return fmt.Errorf("sync sign attempt burns: %w", err)
	}
	return nil
}

func (s *FileSignAttemptStore) existingCommit(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	existing, loadErr := s.LoadSignAttempt(context.WithoutCancel(ctx), candidate.PresignContentID)
	if loadErr != nil {
		return SignAttemptCommit{}, loadErr
	}
	if candidate.SameBaseAttempt(existing) {
		return SignAttemptCommit{Status: SignAttemptExistingSame, Record: existing}, nil
	}
	if bytes.Equal(existing.IntentHash, candidate.IntentHash) {
		return SignAttemptCommit{}, ErrSignAttemptNonDeterminism
	}
	return SignAttemptCommit{}, ErrSignAttemptConflict
}

func (s *FileSignAttemptStore) mergeDeliveryAcks(record *SignAttemptRecord, presignContentID []byte) error {
	pattern := filepath.Join(s.deliveryAcks, hex.EncodeToString(s.storeKey(presignContentID))+"-*")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob sign attempt delivery acks: %w", err)
	}
	slices.Sort(paths)
	for _, path := range paths {
		ackRecord, err := s.readRecord(path, "delivery-ack")
		if err != nil {
			return err
		}
		if !record.SameBaseAttempt(ackRecord) || len(ackRecord.DeliveryState.Acks) == 0 ||
			ackRecord.DeliveryState.Certificate != nil || ackRecord.DeliveryState.DeliveryComplete {
			return fmt.Errorf("%w: delivery ack does not match claim", ErrSignAttemptCorrupt)
		}
		for _, ack := range ackRecord.DeliveryState.Acks {
			updated, err := applySignAttemptDeliveryUpdate(*record, SignAttemptDeliveryUpdate{
				PresignContentID: presignContentID,
				AttemptHash:      record.AttemptHash,
				Ack:              &ack,
				ackVerified:      true,
			})
			if err != nil {
				return err
			}
			*record = updated
		}
	}
	return nil
}

func (s *FileSignAttemptStore) mergeDeliveryCertificate(record *SignAttemptRecord, presignContentID []byte) error {
	certRecord, err := s.readRecord(s.certificatePath(presignContentID), "delivery-certificate")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !record.SameBaseAttempt(certRecord) || certRecord.DeliveryState.Certificate == nil ||
		!certRecord.DeliveryState.DeliveryComplete {
		return fmt.Errorf("%w: delivery certificate does not match claim", ErrSignAttemptCorrupt)
	}
	updated, err := applySignAttemptDeliveryUpdate(*record, SignAttemptDeliveryUpdate{
		PresignContentID:    presignContentID,
		AttemptHash:         record.AttemptHash,
		Certificate:         certRecord.DeliveryState.Certificate,
		certificateVerified: true,
	})
	if err != nil {
		return err
	}
	*record = updated
	return nil
}

func (s *FileSignAttemptStore) mergeCompletion(record *SignAttemptRecord, presignContentID []byte) error {
	completed, err := s.readRecord(s.completionPath(presignContentID), "completion")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !completed.Completed || !record.SameBaseAttempt(completed) {
		return fmt.Errorf("%w: completion does not match claim", ErrSignAttemptCorrupt)
	}
	record.Completed = true
	record.SignatureR = slices.Clone(completed.SignatureR)
	record.SignatureS = slices.Clone(completed.SignatureS)
	record.SignatureRecoveryID = completed.SignatureRecoveryID
	return nil
}

func (s *FileSignAttemptStore) persistDeliveryAck(ctx context.Context, base SignAttemptRecord, ack tss.BroadcastAck) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ackRecord := base.Clone()
	ackRecord.Completed = false
	ackRecord.SignatureR = nil
	ackRecord.SignatureS = nil
	ackRecord.SignatureRecoveryID = 0
	ackRecord.DeliveryState = SignAttemptDeliveryState{Acks: []tss.BroadcastAck{ack.Clone()}}
	if err := ackRecord.Validate(); err != nil {
		return err
	}
	objectPath, err := s.writeEncryptedObject(ackRecord, "delivery-ack")
	if err != nil {
		return err
	}
	ackPath := s.ackPath(base.PresignContentID, ack.Party)
	if err := os.Link(objectPath, ackPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return fmt.Errorf("link sign attempt delivery ack: %w", err)
	}
	if err := syncDirectory(s.deliveryAcks); err != nil {
		return fmt.Errorf("sync sign attempt delivery acks: %w", err)
	}
	return nil
}

func (s *FileSignAttemptStore) persistDeliveryCertificate(ctx context.Context, base SignAttemptRecord, cert *tss.BroadcastCertificate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	certRecord := base.Clone()
	certRecord.Completed = false
	certRecord.SignatureR = nil
	certRecord.SignatureS = nil
	certRecord.SignatureRecoveryID = 0
	certRecord.DeliveryState = SignAttemptDeliveryState{
		Acks:             tss.CloneSlice(cert.Acks),
		Certificate:      cert.Clone(),
		DeliveryComplete: true,
	}
	if err := certRecord.Validate(); err != nil {
		return err
	}
	objectPath, err := s.writeEncryptedObject(certRecord, "delivery-certificate")
	if err != nil {
		return err
	}
	certPath := s.certificatePath(base.PresignContentID)
	if err := os.Link(objectPath, certPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return fmt.Errorf("link sign attempt delivery certificate: %w", err)
	}
	if err := syncDirectory(s.deliveryCertificates); err != nil {
		return fmt.Errorf("sync sign attempt delivery certificates: %w", err)
	}
	return nil
}

func validateFileStoreCall(ctx context.Context, store *FileSignAttemptStore, presignContentID []byte) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if store == nil {
		return errors.New("nil file sign attempt store")
	}
	if len(store.passphrase) == 0 {
		return errors.New("file sign attempt store is destroyed")
	}
	if len(store.storeSecret) != sha256.Size {
		return errors.New("file sign attempt store key is unavailable")
	}
	if len(presignContentID) != sha256.Size {
		return errors.New("invalid presign content ID")
	}
	return ctx.Err()
}

func (s *FileSignAttemptStore) writeEncryptedObject(record SignAttemptRecord, kind string) (string, error) {
	raw, err := record.MarshalBinary()
	if err != nil {
		return "", err
	}
	keyID := s.signAttemptFileObjectKeyID(kind, record)
	encrypted, err := tss.EncryptSignAttemptWithPassphrase(raw, s.passphrase, keyID, s.params)
	clear(raw)
	if err != nil {
		return "", err
	}
	ciphertextHash := sha256.Sum256(encrypted)
	path, err := writeSyncedTempFile(s.objects, "attempt-*", encrypted)
	clear(encrypted)
	if err != nil {
		return "", err
	}
	meta := fmt.Appendf(nil, "kind=%s\nciphertext_sha256=%x\n", kind, ciphertextHash[:])
	if err := writeFileStoreMeta(path, meta); err != nil {
		removeFileStoreObject(path)
		return "", err
	}
	if err := syncDirectory(s.objects); err != nil {
		removeFileStoreObject(path)
		return "", fmt.Errorf("sync sign attempt objects: %w", err)
	}
	return path, nil
}

func (s *FileSignAttemptStore) writeBurnObject(burn SignAttemptBurn) (string, error) {
	if err := validateSignAttemptBurn(burn); err != nil {
		return "", err
	}
	raw := append([]byte(signAttemptBurnMagic), []byte(burn.Reason)...)
	keyID := s.signAttemptBurnObjectKeyID(burn)
	encrypted, err := tss.EncryptSignAttemptWithPassphrase(raw, s.passphrase, keyID, s.params)
	clear(raw)
	if err != nil {
		return "", err
	}
	ciphertextHash := sha256.Sum256(encrypted)
	path, err := writeSyncedTempFile(s.objects, "burn-*", encrypted)
	clear(encrypted)
	if err != nil {
		return "", err
	}
	meta := fmt.Appendf(nil, "kind=burn\nciphertext_sha256=%x\n", ciphertextHash[:])
	if err := writeFileStoreMeta(path, meta); err != nil {
		removeFileStoreObject(path)
		return "", err
	}
	if err := syncDirectory(s.objects); err != nil {
		removeFileStoreObject(path)
		return "", fmt.Errorf("sync sign attempt burn object: %w", err)
	}
	return path, nil
}

func writeSyncedTempFile(directory, pattern string, data []byte) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", fmt.Errorf("create sign attempt object: %w", err)
	}
	path := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", fmt.Errorf("write sign attempt object: %w", err)
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync sign attempt object: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close sign attempt object: %w", err)
	}
	return path, nil
}

func writeFileStoreMeta(path string, meta []byte) error {
	file, err := os.OpenFile(path+".meta", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // derived from private temp object path
	if err != nil {
		return fmt.Errorf("create sign attempt object metadata: %w", err)
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path + ".meta")
	}
	if _, err := file.Write(meta); err != nil {
		cleanup()
		return fmt.Errorf("write sign attempt object metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync sign attempt object metadata: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path + ".meta")
		return fmt.Errorf("close sign attempt object metadata: %w", err)
	}
	return nil
}

func (s *FileSignAttemptStore) readClaimRecord(presignContentID []byte) (SignAttemptRecord, error) {
	encrypted, err := os.ReadFile(s.claimPath(presignContentID))
	if errors.Is(err, fs.ErrNotExist) {
		if s.burnExists(presignContentID) {
			return SignAttemptRecord{}, ErrSignAttemptBurned
		}
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	if err != nil {
		return SignAttemptRecord{}, err
	}
	raw, keyID, err := s.decryptObject(encrypted)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	defer clear(raw)
	if isSignAttemptBurnObject(raw) {
		burn := SignAttemptBurn{
			PresignContentID: slices.Clone(presignContentID),
			Reason:           string(raw[len(signAttemptBurnMagic):]),
		}
		if err := validateSignAttemptBurn(burn); err != nil ||
			keyID != s.signAttemptBurnObjectKeyID(burn) {
			return SignAttemptRecord{}, fmt.Errorf("%w: burn object binding mismatch", ErrSignAttemptCorrupt)
		}
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, err := tss.DecodeBinaryValue[SignAttemptRecord](raw)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: decode attempt: %w", ErrSignAttemptCorrupt, err)
	}
	if keyID != s.signAttemptFileObjectKeyID("base-attempt", record) {
		return SignAttemptRecord{}, fmt.Errorf("%w: base attempt AAD binding mismatch", ErrSignAttemptCorrupt)
	}
	return record, nil
}

func (s *FileSignAttemptStore) readRecord(path, kind string) (SignAttemptRecord, error) {
	encrypted, err := os.ReadFile(path) //nolint:gosec // fixed-width hex names under caller-selected root
	if err != nil {
		return SignAttemptRecord{}, err
	}
	return s.decryptRecord(encrypted, kind)
}

func (s *FileSignAttemptStore) decryptRecord(encrypted []byte, kind string) (SignAttemptRecord, error) {
	raw, keyID, err := s.decryptObject(encrypted)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	defer clear(raw)
	if isSignAttemptBurnObject(raw) {
		return SignAttemptRecord{}, fmt.Errorf("%w: unexpected burn object", ErrSignAttemptCorrupt)
	}
	record, err := tss.DecodeBinaryValue[SignAttemptRecord](raw)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: decode attempt: %w", ErrSignAttemptCorrupt, err)
	}
	if keyID != s.signAttemptFileObjectKeyID(kind, record) {
		return SignAttemptRecord{}, fmt.Errorf("%w: %s AAD binding mismatch", ErrSignAttemptCorrupt, kind)
	}
	return record, nil
}

func (s *FileSignAttemptStore) decryptObject(encrypted []byte) ([]byte, string, error) {
	raw, keyID, err := tss.DecryptSignAttemptWithPassphraseAndKeyID(encrypted, s.passphrase)
	if err != nil {
		return nil, "", fmt.Errorf("%w: decrypt attempt: %w", ErrSignAttemptCorrupt, err)
	}
	return raw, keyID, nil
}

func (s *FileSignAttemptStore) signAttemptFileObjectKeyID(kind string, record SignAttemptRecord) string {
	t := transcript.New(signAttemptFileObjectKeyLabel)
	t.AppendString("kind", kind)
	t.AppendBytes("store_key", s.storeKey(record.PresignContentID))
	t.AppendString("protocol", string(record.Protocol))
	t.AppendBytes("presign_content_id", record.PresignContentID)
	t.AppendBytes("attempt_hash", record.AttemptHash)
	t.AppendBytes("intent_hash", record.IntentHash)
	t.AppendBytes("session_id", record.SessionID[:])
	t.AppendUint32("party", record.Party)
	t.AppendUint16("record_version", record.RecordVersion)
	return "cggmp21-sign-attempt:" + kind + ":" + hex.EncodeToString(t.Sum())
}

func (s *FileSignAttemptStore) signAttemptBurnObjectKeyID(burn SignAttemptBurn) string {
	t := transcript.New(signAttemptFileObjectKeyLabel)
	t.AppendString("kind", "burn")
	t.AppendBytes("store_key", s.storeKey(burn.PresignContentID))
	t.AppendBytes("presign_content_id", burn.PresignContentID)
	t.AppendString("reason", burn.Reason)
	return "cggmp21-sign-attempt:burn:" + hex.EncodeToString(t.Sum())
}

func isSignAttemptBurnObject(raw []byte) bool {
	return bytes.HasPrefix(raw, []byte(signAttemptBurnMagic))
}

func removeFileStoreObject(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + ".meta")
}

func (s *FileSignAttemptStore) burnExists(presignContentID []byte) bool {
	_, err := os.Stat(s.burnPath(presignContentID))
	return err == nil
}

func (s *FileSignAttemptStore) claimPath(presignContentID []byte) string {
	return filepath.Join(s.claims, hex.EncodeToString(s.storeKey(presignContentID)))
}

func (s *FileSignAttemptStore) ackPath(presignContentID []byte, party tss.PartyID) string {
	return filepath.Join(s.deliveryAcks, fmt.Sprintf("%s-%010d", hex.EncodeToString(s.storeKey(presignContentID)), party))
}

func (s *FileSignAttemptStore) certificatePath(presignContentID []byte) string {
	return filepath.Join(s.deliveryCertificates, hex.EncodeToString(s.storeKey(presignContentID)))
}

func (s *FileSignAttemptStore) completionPath(presignContentID []byte) string {
	return filepath.Join(s.completions, hex.EncodeToString(s.storeKey(presignContentID)))
}

func (s *FileSignAttemptStore) burnPath(presignContentID []byte) string {
	return filepath.Join(s.burns, hex.EncodeToString(s.storeKey(presignContentID)))
}

func (s *FileSignAttemptStore) storeKey(contentID []byte) []byte {
	mac := hmac.New(sha256.New, s.storeSecret)
	_, _ = mac.Write([]byte(signAttemptStoreKeyLabel))
	_, _ = mac.Write(contentID)
	return mac.Sum(nil)
}

func deriveSignAttemptStoreSecret(passphrase, salt []byte, params *tss.PassphraseParams) ([]byte, error) {
	if len(passphrase) == 0 || len(salt) != signAttemptStoreSaltSize {
		return nil, errors.New("invalid sign attempt store key material")
	}
	if err := validateSignAttemptStoreKDFParams(params); err != nil {
		return nil, err
	}
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, sha256.Size), nil
}

func validateSignAttemptStoreKDFParams(params *tss.PassphraseParams) error {
	if params == nil || params.Time == 0 || params.Memory == 0 || params.Threads == 0 {
		return errors.New("invalid sign attempt store KDF parameters")
	}
	if params.Time > signAttemptStoreMaxKDFTime || params.Memory > signAttemptStoreMaxKDFMemory || params.Threads > signAttemptStoreMaxKDFThreads {
		return fmt.Errorf("sign attempt store KDF parameters exceed limits: time=%d memory=%d threads=%d", params.Time, params.Memory, params.Threads)
	}
	return nil
}

func secureSignAttemptStoreRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve sign attempt store root: %w", err)
	}
	if info, statErr := os.Lstat(abs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("sign attempt store root is a symlink %q", abs)
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return "", fmt.Errorf("inspect sign attempt store root %q: %w", abs, statErr)
	}
	if err := rejectSignAttemptStoreSymlinkAncestors(abs); err != nil {
		return "", err
	}

	// Resolve the existing trusted path once and retain only the canonical target
	// path. Volume-root aliases such as macOS /var are administrator-controlled;
	// all lower symlink ancestors were rejected above.
	current := abs
	var suffix []string
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			break
		}
		if !errors.Is(statErr, fs.ErrNotExist) {
			return "", fmt.Errorf("inspect sign attempt store path %q: %w", current, statErr)
		}
		suffix = append(suffix, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for sign attempt store root %q", abs)
		}
		current = parent
	}
	if err := validateSignAttemptStoreTrustedAncestorChain(current); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", fmt.Errorf("resolve sign attempt store ancestor %q: %w", current, err)
	}
	// A trusted volume-root alias is only an indirection mechanism; its target
	// chain must independently satisfy the same ownership and replacement
	// rules before any missing suffix is appended.
	if err := validateSignAttemptStoreTrustedAncestorChain(resolved); err != nil {
		return "", fmt.Errorf("validate canonical sign attempt store ancestor: %w", err)
	}
	for i := len(suffix) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, suffix[i])
	}
	return filepath.Clean(resolved), nil
}

// validateSignAttemptStoreTrustedAncestorChain ensures that no untrusted local
// principal can replace an existing path component or insert the missing
// suffix between inspection and creation. A writable sticky directory is safe
// only for an already-existing child whose ownership was independently
// accepted; the nearest existing ancestor itself must never be writable by
// group or other because the store creates entries inside it.
func validateSignAttemptStoreTrustedAncestorChain(path string) error {
	volumeRoot := filepath.Clean(filepath.VolumeName(path) + string(os.PathSeparator))
	first := true
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect sign attempt store trusted ancestor %q: %w", current, err)
		}
		isVolumeAlias := info.Mode()&os.ModeSymlink != 0 && filepath.Clean(filepath.Dir(current)) == volumeRoot
		if !isVolumeAlias && !info.IsDir() {
			return fmt.Errorf("sign attempt store trusted ancestor %q is not a directory", current)
		}
		if !signAttemptStoreTrustedOwner(info) {
			return fmt.Errorf("sign attempt store ancestor %q is not owned by the current user or administrator", current)
		}
		if !isVolumeAlias && info.Mode().Perm()&0o022 != 0 {
			if first || info.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("sign attempt store ancestor %q permits untrusted path replacement", current)
			}
		}
		if current == volumeRoot {
			return nil
		}
		first = false
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("sign attempt store path %q has no filesystem volume root", path)
		}
	}
}

// rejectSignAttemptStoreSymlinkAncestors rejects caller-controlled indirection
// while permitting conventional aliases directly below a filesystem volume
// root, such as macOS /var -> /private/var.
func rejectSignAttemptStoreSymlinkAncestors(path string) error {
	volumeRoot := filepath.Clean(filepath.VolumeName(path) + string(os.PathSeparator))
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 && filepath.Clean(filepath.Dir(current)) != volumeRoot {
				return fmt.Errorf("sign attempt store ancestor is a symlink %q", current)
			}
		case errors.Is(err, fs.ErrNotExist):
			// A missing suffix is created only after every existing ancestor is
			// inspected and the trusted prefix is canonicalized.
		default:
			return fmt.Errorf("inspect sign attempt store ancestor %q: %w", current, err)
		}
		if current == volumeRoot {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("sign attempt store path %q has no filesystem volume root", path)
		}
	}
}

func validateSecureSignAttemptStoreDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect sign attempt store directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("sign attempt store path %q is not a real directory", path)
	}
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // directories intentionally require owner traversal
		return fmt.Errorf("secure sign attempt store directory %q: %w", path, err)
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("reinspect sign attempt store directory %q after chmod: %w", path, err)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("unsafe sign attempt store directory permissions on %q: %04o, want 0700", path, info.Mode().Perm())
	}
	return nil
}

func loadOrCreateSignAttemptStoreSalt(root string) ([]byte, error) {
	path := filepath.Join(root, signAttemptStoreSaltFile)
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("sign attempt store salt is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("unsafe sign attempt store salt permissions: %04o", info.Mode().Perm())
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect sign attempt store salt: %w", statErr)
	}
	salt, err := os.ReadFile(path) //nolint:gosec // fixed store-local salt path under caller-selected root
	if err == nil {
		if len(salt) != signAttemptStoreSaltSize {
			clear(salt)
			return nil, errors.New("invalid sign attempt store salt")
		}
		return salt, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read sign attempt store salt: %w", err)
	}
	salt = make([]byte, signAttemptStoreSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate sign attempt store salt: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed store-local salt path under caller-selected root
	if errors.Is(err, fs.ErrExist) {
		clear(salt)
		return loadOrCreateSignAttemptStoreSalt(root)
	}
	if err != nil {
		clear(salt)
		return nil, fmt.Errorf("create sign attempt store salt: %w", err)
	}
	if _, err := file.Write(salt); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		clear(salt)
		return nil, fmt.Errorf("write sign attempt store salt: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		clear(salt)
		return nil, fmt.Errorf("sync sign attempt store salt: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		clear(salt)
		return nil, fmt.Errorf("close sign attempt store salt: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		clear(salt)
		return nil, fmt.Errorf("sync sign attempt store root: %w", err)
	}
	return salt, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) //nolint:gosec // caller-selected store root
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
