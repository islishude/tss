package secp256k1

import (
	"bytes"
	"context"
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
)

const (
	signAttemptFileObjectKeyLabel = "cggmp21-secp256k1-sign-attempt-file-object-v1"
	signAttemptBurnMagic          = "cggmp21-sign-attempt-burn-v1\n"
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
	params               *tss.PassphraseParams
}

// NewFileSignAttemptStore creates an encrypted append-only file store. All
// directories must reside on one filesystem because atomic hard links establish
// presign claims and durable delivery/completion objects. A nil params value
// selects [tss.DefaultPassphraseParams].
func NewFileSignAttemptStore(directory string, passphrase []byte, params *tss.PassphraseParams) (*FileSignAttemptStore, error) {
	if directory == "" {
		return nil, errors.New("empty sign attempt store directory")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("empty sign attempt store passphrase")
	}
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
	if params != nil {
		copied := *params
		store.params = &copied
	}
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
}

// LoadSignAttempt loads the immutable claim and merges append-only delivery and
// completion objects. A burn tombstone returns ErrSignAttemptBurned.
func (s *FileSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	if err := validateFileStoreCall(ctx, s, presignID); err != nil {
		return SignAttemptRecord{}, err
	}
	base, err := s.readClaimRecord(presignID)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if !bytes.Equal(base.PresignID, presignID) {
		return SignAttemptRecord{}, fmt.Errorf("%w: claim key mismatch", ErrSignAttemptCorrupt)
	}
	record := base.Clone()
	if err := s.mergeDeliveryAcks(&record, presignID); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := s.mergeDeliveryCertificate(&record, presignID); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := s.mergeCompletion(&record, presignID); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := validateSignAttemptRecord(record); err != nil {
		return SignAttemptRecord{}, err
	}
	return record, nil
}

// CommitSignAttempt atomically creates the only claim for candidate.PresignID.
// An existing exact attempt is returned idempotently; the same intent with a
// different attempt is ErrSignAttemptNonDeterminism.
func (s *FileSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	if ctx == nil {
		return SignAttemptCommit{}, errors.New("nil context")
	}
	if err := validateSignAttemptCandidate(candidate); err != nil {
		return SignAttemptCommit{}, err
	}
	if err := validateFileStoreCall(ctx, s, candidate.PresignID); err != nil {
		return SignAttemptCommit{}, err
	}
	objectPath, err := s.writeEncryptedObject(candidate, "base-attempt")
	if err != nil {
		return SignAttemptCommit{}, err
	}
	claimPath := s.claimPath(candidate.PresignID)
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

// UpdateSignAttemptDelivery atomically persists a structurally valid delivery
// ACK or final broadcast certificate for the exact attempt hash.
func (s *FileSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if len(update.PresignID) != sha256.Size {
		return SignAttemptRecord{}, errors.New("invalid delivery update presign ID")
	}
	if err := validateFileStoreCall(ctx, s, update.PresignID); err != nil {
		return SignAttemptRecord{}, err
	}
	record, err := s.LoadSignAttempt(ctx, update.PresignID)
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
		if err := s.persistDeliveryCertificate(ctx, record, update.Certificate.Clone()); err != nil {
			return SignAttemptRecord{}, err
		}
	}
	return s.LoadSignAttempt(context.WithoutCancel(ctx), update.PresignID)
}

// CompleteSignAttempt atomically persists the final signature for an existing
// attempt. Repeating the same result is idempotent.
func (s *FileSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := result.validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	if err := validateFileStoreCall(ctx, s, result.PresignID); err != nil {
		return SignAttemptRecord{}, err
	}
	record, err := s.LoadSignAttempt(ctx, result.PresignID)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if !bytes.Equal(record.AttemptHash, result.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if record.Completed {
		if bytes.Equal(record.SignatureR, result.Signature.R) && bytes.Equal(record.SignatureS, result.Signature.S) {
			return record, nil
		}
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	completed := record.Clone()
	completed.Completed = true
	completed.SignatureR = slices.Clone(result.Signature.R)
	completed.SignatureS = slices.Clone(result.Signature.S)
	if err := validateSignAttemptRecord(completed); err != nil {
		return SignAttemptRecord{}, err
	}
	objectPath, err := s.writeEncryptedObject(completed, "completion")
	if err != nil {
		return SignAttemptRecord{}, err
	}
	completionPath := s.completionPath(result.PresignID)
	if err := os.Link(objectPath, completionPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			existing, loadErr := s.LoadSignAttempt(context.WithoutCancel(ctx), result.PresignID)
			if loadErr != nil {
				return SignAttemptRecord{}, loadErr
			}
			if existing.Completed &&
				bytes.Equal(existing.AttemptHash, result.AttemptHash) &&
				bytes.Equal(existing.SignatureR, result.Signature.R) &&
				bytes.Equal(existing.SignatureS, result.Signature.S) {
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
	if err := validateFileStoreCall(ctx, s, burn.PresignID); err != nil {
		return err
	}
	objectPath, err := s.writeBurnObject(burn)
	if err != nil {
		return err
	}
	claimPath := s.claimPath(burn.PresignID)
	if err := os.Link(objectPath, claimPath); err != nil {
		removeFileStoreObject(objectPath)
		if errors.Is(err, fs.ErrExist) {
			_, loadErr := s.LoadSignAttempt(context.WithoutCancel(ctx), burn.PresignID)
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
	burnPath := s.burnPath(burn.PresignID)
	if err := os.Link(objectPath, burnPath); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("link sign attempt burn tombstone: %w", err)
	}
	if err := syncDirectory(s.burns); err != nil {
		return fmt.Errorf("sync sign attempt burns: %w", err)
	}
	return nil
}

func (s *FileSignAttemptStore) existingCommit(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	existing, loadErr := s.LoadSignAttempt(context.WithoutCancel(ctx), candidate.PresignID)
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

func (s *FileSignAttemptStore) mergeDeliveryAcks(record *SignAttemptRecord, presignID []byte) error {
	pattern := filepath.Join(s.deliveryAcks, hex.EncodeToString(presignID)+"-*")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob sign attempt delivery acks: %w", err)
	}
	slices.Sort(paths)
	for _, path := range paths {
		ackRecord, err := s.readRecord(path)
		if err != nil {
			return err
		}
		if !record.SameBaseAttempt(ackRecord) || len(ackRecord.DeliveryState.Acks) == 0 ||
			ackRecord.DeliveryState.Certificate != nil || ackRecord.DeliveryState.DeliveryComplete {
			return fmt.Errorf("%w: delivery ack does not match claim", ErrSignAttemptCorrupt)
		}
		for _, ack := range ackRecord.DeliveryState.Acks {
			updated, err := applySignAttemptDeliveryUpdate(*record, SignAttemptDeliveryUpdate{
				PresignID:   presignID,
				AttemptHash: record.AttemptHash,
				Ack:         &ack,
			})
			if err != nil {
				return err
			}
			*record = updated
		}
	}
	return nil
}

func (s *FileSignAttemptStore) mergeDeliveryCertificate(record *SignAttemptRecord, presignID []byte) error {
	certRecord, err := s.readRecord(s.certificatePath(presignID))
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
		PresignID:   presignID,
		AttemptHash: record.AttemptHash,
		Certificate: certRecord.DeliveryState.Certificate,
	})
	if err != nil {
		return err
	}
	*record = updated
	return nil
}

func (s *FileSignAttemptStore) mergeCompletion(record *SignAttemptRecord, presignID []byte) error {
	completed, err := s.readRecord(s.completionPath(presignID))
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
	ackRecord.DeliveryState = SignAttemptDeliveryState{Acks: []tss.BroadcastAck{ack.Clone()}}
	if err := validateSignAttemptRecord(ackRecord); err != nil {
		return err
	}
	objectPath, err := s.writeEncryptedObject(ackRecord, "delivery-ack")
	if err != nil {
		return err
	}
	ackPath := s.ackPath(base.PresignID, ack.Party)
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
	certRecord.DeliveryState = SignAttemptDeliveryState{
		Acks:             cloneSignAttemptAcks(cert.Acks),
		Certificate:      cert.Clone(),
		DeliveryComplete: true,
	}
	if err := validateSignAttemptRecord(certRecord); err != nil {
		return err
	}
	objectPath, err := s.writeEncryptedObject(certRecord, "delivery-certificate")
	if err != nil {
		return err
	}
	certPath := s.certificatePath(base.PresignID)
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

func validateFileStoreCall(ctx context.Context, store *FileSignAttemptStore, presignID []byte) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if store == nil {
		return errors.New("nil file sign attempt store")
	}
	if len(store.passphrase) == 0 {
		return errors.New("file sign attempt store is destroyed")
	}
	if len(presignID) != sha256.Size {
		return errors.New("invalid presign ID")
	}
	return ctx.Err()
}

func (s *FileSignAttemptStore) writeEncryptedObject(record SignAttemptRecord, kind string) (string, error) {
	raw, err := record.MarshalBinary()
	if err != nil {
		return "", err
	}
	rawHash := sha256.Sum256(raw)
	keyID := signAttemptFileObjectKeyID(kind, record)
	encrypted, err := tss.EncryptSignAttemptWithPassphrase(raw, s.passphrase, keyID, s.params)
	clear(raw)
	if err != nil {
		return "", err
	}
	path, err := writeSyncedTempFile(s.objects, "attempt-*", encrypted)
	clear(encrypted)
	if err != nil {
		return "", err
	}
	meta := fmt.Appendf(nil, "kind=%s\nplaintext_sha256=%x\n", kind, rawHash[:])
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
	raw := append([]byte(signAttemptBurnMagic), []byte(burn.Reason)...)
	rawHash := sha256.Sum256(raw)
	path, err := writeSyncedTempFile(s.objects, "burn-*", raw)
	clear(raw)
	if err != nil {
		return "", err
	}
	meta := fmt.Appendf(nil, "kind=burn\nplaintext_sha256=%x\n", rawHash[:])
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

func (s *FileSignAttemptStore) readClaimRecord(presignID []byte) (SignAttemptRecord, error) {
	raw, err := os.ReadFile(s.claimPath(presignID))
	if errors.Is(err, fs.ErrNotExist) {
		if s.burnExists(presignID) {
			return SignAttemptRecord{}, ErrSignAttemptBurned
		}
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	if err != nil {
		return SignAttemptRecord{}, err
	}
	if isSignAttemptBurnObject(raw) {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	return s.decryptRecord(raw)
}

func (s *FileSignAttemptStore) readRecord(path string) (SignAttemptRecord, error) {
	encrypted, err := os.ReadFile(path) //nolint:gosec // fixed-width hex names under caller-selected root
	if err != nil {
		return SignAttemptRecord{}, err
	}
	return s.decryptRecord(encrypted)
}

func (s *FileSignAttemptStore) decryptRecord(encrypted []byte) (SignAttemptRecord, error) {
	raw, err := tss.DecryptSignAttemptWithPassphrase(encrypted, s.passphrase)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: decrypt attempt: %w", ErrSignAttemptCorrupt, err)
	}
	defer clear(raw)
	record, err := UnmarshalSignAttemptRecord(raw)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: decode attempt: %w", ErrSignAttemptCorrupt, err)
	}
	return record, nil
}

func signAttemptFileObjectKeyID(kind string, record SignAttemptRecord) string {
	t := transcript.New(signAttemptFileObjectKeyLabel)
	t.AppendString("kind", kind)
	t.AppendString("protocol", string(record.Protocol))
	t.AppendBytes("presign_id", record.PresignID)
	t.AppendBytes("attempt_hash", record.AttemptHash)
	t.AppendBytes("session_id", record.SessionID[:])
	t.AppendUint32("party", uint32(record.Party))
	t.AppendUint16("record_version", record.RecordVersion)
	return "cggmp21-sign-attempt:" + kind + ":" + hex.EncodeToString(t.Sum())
}

func isSignAttemptBurnObject(raw []byte) bool {
	return bytes.HasPrefix(raw, []byte(signAttemptBurnMagic))
}

func removeFileStoreObject(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + ".meta")
}

func (s *FileSignAttemptStore) burnExists(presignID []byte) bool {
	_, err := os.Stat(s.burnPath(presignID))
	return err == nil
}

func (s *FileSignAttemptStore) claimPath(presignID []byte) string {
	return filepath.Join(s.claims, hex.EncodeToString(presignID))
}

func (s *FileSignAttemptStore) ackPath(presignID []byte, party tss.PartyID) string {
	return filepath.Join(s.deliveryAcks, fmt.Sprintf("%s-%010d", hex.EncodeToString(presignID), party))
}

func (s *FileSignAttemptStore) certificatePath(presignID []byte) string {
	return filepath.Join(s.deliveryCertificates, hex.EncodeToString(presignID))
}

func (s *FileSignAttemptStore) completionPath(presignID []byte) string {
	return filepath.Join(s.completions, hex.EncodeToString(presignID))
}

func (s *FileSignAttemptStore) burnPath(presignID []byte) string {
	return filepath.Join(s.burns, hex.EncodeToString(presignID))
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
