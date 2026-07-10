package tss

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// storageVersion is the current envelope format version.
	storageVersion = 1

	// kdfArgon2id identifies the Argon2id KDF algorithm.
	kdfArgon2id = 0x00

	// recordTypeKeyShare identifies an encrypted key-share record.
	recordTypeKeyShare = 0x00
	// recordTypePresign identifies an encrypted presign record.
	recordTypePresign = 0x01
	// recordTypeSignAttempt identifies an encrypted CGGMP21 sign-attempt record.
	recordTypeSignAttempt = 0x02

	saltLen  = 32
	nonceLen = 12
	keyLen   = 32 // ChaCha20-Poly1305

	// minHeaderLen is the fixed header size before the variable key_id field:
	// version(1) + algo(1) + time(4) + mem(4) + threads(1) + record_type(1) +
	// key_id_len(1) + salt_len(1) + salt(32) = 46
	minHeaderLen = 46

	// maxKeyIDLen is the maximum length of a caller-assigned key identifier.
	maxKeyIDLen = 255

	// Argon2id upper bounds for decrypting unauthenticated input.
	// Defaults remain within these limits; callers that need larger costs should
	// use a storage backend that authenticates metadata before KDF evaluation.
	maxKDFTime    = 4
	maxKDFMemory  = 128 * 1024 // 128 MiB
	maxKDFThreads = 8

	// Default Argon2id parameters as recommended by RFC 9106 §7.3 for
	// non-interactive passphrase-based key derivation.
	defaultKDFTime    = 3
	defaultKDFMemory  = 64 * 1024 // 64 MiB
	defaultKDFThreads = 4
)

// PassphraseParams holds Argon2id parameters for passphrase-based key derivation.
// The zero value is not valid; use [DefaultPassphraseParams] or populate every field.
type PassphraseParams struct {
	// Time is the number of Argon2id iterations (passes).
	// RFC 9106 §7.3 recommends 3 for non-interactive use.
	Time uint32
	// Memory is the memory cost in kibibytes.
	// RFC 9106 §7.3 recommends at least 65536 (64 MiB) for non-interactive use.
	Memory uint32
	// Threads is the degree of parallelism.
	// RFC 9106 §7.3 recommends 4 for non-interactive use.
	Threads uint8
}

// ErrStorageKeyIDMismatch is returned when an authenticated storage record is
// valid but is bound to a different caller-assigned key ID.
var ErrStorageKeyIDMismatch = errors.New("storage key id mismatch")

// DefaultPassphraseParams returns RFC 9106 recommended Argon2id parameters for
// non-interactive passphrase-based key derivation (time=3, memory=64 MiB, threads=4).
func DefaultPassphraseParams() *PassphraseParams {
	return &PassphraseParams{
		Time:    defaultKDFTime,
		Memory:  defaultKDFMemory,
		Threads: defaultKDFThreads,
	}
}

// EncryptKeyShareWithPassphrase encrypts a key-share with a passphrase using
// Argon2id key derivation and ChaCha20-Poly1305. keyID is an optional caller-assigned
// identifier that is authenticated as AAD (empty string is allowed).
//
// This is a reference/demo implementation. Production deployments should use
// a KMS or HSM for key material protection.
func EncryptKeyShareWithPassphrase(plaintext, passphrase []byte, keyID string, params *PassphraseParams) ([]byte, error) {
	return encrypt(plaintext, passphrase, recordTypeKeyShare, keyID, params)
}

// DecryptKeyShareWithPassphrase decrypts an encoding produced by
// [EncryptKeyShareWithPassphrase] and requires its authenticated key ID to
// match expectedKeyID.
func DecryptKeyShareWithPassphrase(encoded, passphrase []byte, expectedKeyID string) ([]byte, error) {
	return decryptExpectedKeyID(encoded, passphrase, recordTypeKeyShare, expectedKeyID)
}

// EncryptPresignWithPassphrase encrypts a presign record with a passphrase using
// Argon2id key derivation and ChaCha20-Poly1305. keyID is an optional caller-assigned
// identifier that is authenticated as AAD (empty string is allowed).
//
// This is a reference/demo implementation. Production deployments should use
// a KMS or HSM for key material protection.
func EncryptPresignWithPassphrase(plaintext, passphrase []byte, keyID string, params *PassphraseParams) ([]byte, error) {
	return encrypt(plaintext, passphrase, recordTypePresign, keyID, params)
}

// DecryptPresignWithPassphrase decrypts an encoding produced by
// [EncryptPresignWithPassphrase] and requires its authenticated key ID to match
// expectedKeyID.
func DecryptPresignWithPassphrase(encoded, passphrase []byte, expectedKeyID string) ([]byte, error) {
	return decryptExpectedKeyID(encoded, passphrase, recordTypePresign, expectedKeyID)
}

// EncryptSignAttemptWithPassphrase encrypts a sign-attempt record with a
// passphrase using Argon2id key derivation and ChaCha20-Poly1305. keyID is an
// optional caller-assigned identifier that is authenticated as AAD.
//
// This is a reference/demo implementation. Production deployments should use
// a KMS or HSM for confidential signing-outbox records.
func EncryptSignAttemptWithPassphrase(plaintext, passphrase []byte, keyID string, params *PassphraseParams) ([]byte, error) {
	return encrypt(plaintext, passphrase, recordTypeSignAttempt, keyID, params)
}

// DecryptSignAttemptWithPassphrase decrypts an encoding produced by
// [EncryptSignAttemptWithPassphrase] and requires its authenticated key ID to
// match expectedKeyID.
func DecryptSignAttemptWithPassphrase(encoded, passphrase []byte, expectedKeyID string) ([]byte, error) {
	return decryptExpectedKeyID(encoded, passphrase, recordTypeSignAttempt, expectedKeyID)
}

// DecryptSignAttemptWithPassphraseAndKeyID decrypts a sign-attempt encoding and
// returns its authenticated caller-assigned key ID. Callers that use keyID to
// bind object kind or storage identity must compare the returned value with the
// expected value after decoding the plaintext record.
func DecryptSignAttemptWithPassphraseAndKeyID(encoded, passphrase []byte) ([]byte, string, error) {
	hdr, err := parseHeader(encoded)
	if err != nil {
		return nil, "", err
	}
	plaintext, err := decrypt(encoded, passphrase, recordTypeSignAttempt)
	if err != nil {
		return nil, "", err
	}
	return plaintext, hdr.keyID, nil
}

func decryptExpectedKeyID(encoded, passphrase []byte, recordType uint8, expectedKeyID string) ([]byte, error) {
	hdr, err := parseHeader(encoded)
	if err != nil {
		return nil, err
	}
	plaintext, err := decrypt(encoded, passphrase, recordType)
	if err != nil {
		return nil, err
	}
	if hdr.keyID != expectedKeyID {
		clear(plaintext)
		return nil, fmt.Errorf("%w: got %q, want %q", ErrStorageKeyIDMismatch, hdr.keyID, expectedKeyID)
	}
	return plaintext, nil
}

func encrypt(plaintext, passphrase []byte, recordType uint8, keyID string, params *PassphraseParams) ([]byte, error) {
	if params == nil {
		params = DefaultPassphraseParams()
	}
	if err := validateParams(params); err != nil {
		return nil, err
	}
	if len(keyID) > maxKeyIDLen {
		return nil, fmt.Errorf("tss encrypt: keyID too long (%d > %d)", len(keyID), maxKeyIDLen)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("tss encrypt: salt: %w", err)
	}

	key, err := deriveKeyArgon2id(passphrase, salt, params.Time, params.Memory, params.Threads)
	if err != nil {
		return nil, fmt.Errorf("tss encrypt: %w", err)
	}
	defer clear(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("tss encrypt: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("tss encrypt: nonce: %w", err)
	}

	// Build AAD: version || algo || time || memory || threads || record_type ||
	//            key_id_len || key_id || salt_len || salt
	aad := buildAAD(recordType, keyID, salt, params)

	// Encode: aad || nonce || ciphertext
	out := make([]byte, 0, len(aad)+nonceLen+len(plaintext)+aead.Overhead())
	out = append(out, aad...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

func decrypt(encoded, passphrase []byte, expectedRecordType uint8) ([]byte, error) {
	// Loose lower bound: the minimum valid encoding (no key_id, empty plaintext)
	// is minHeaderLen + nonceLen + AEAD tag (16 bytes). A non-empty key_id makes
	// the actual minimum larger; the real validation happens in parseHeader.
	if len(encoded) < minHeaderLen+nonceLen+16 {
		return nil, errors.New("tss decrypt: encoded data too short")
	}

	hdr, err := parseHeader(encoded)
	if err != nil {
		return nil, err
	}
	if hdr.version != storageVersion {
		return nil, fmt.Errorf("tss decrypt: unknown version %d", hdr.version)
	}
	if hdr.kdfAlgorithm != kdfArgon2id {
		return nil, fmt.Errorf("tss decrypt: unknown KDF algorithm %d", hdr.kdfAlgorithm)
	}
	if hdr.recordType != expectedRecordType {
		return nil, fmt.Errorf("tss decrypt: unexpected record type %d (expected %d)", hdr.recordType, expectedRecordType)
	}

	nonceStart := hdr.payloadStart
	if len(encoded) < nonceStart+nonceLen {
		return nil, errors.New("tss decrypt: encoded data too short for nonce")
	}
	nonce := encoded[nonceStart : nonceStart+nonceLen]
	ciphertext := encoded[nonceStart+nonceLen:]
	aad := encoded[:nonceStart]

	key, err := deriveKeyArgon2id(passphrase, hdr.salt, hdr.kdfTime, hdr.kdfMemory, hdr.kdfThreads)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}
	defer clear(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}
	return plaintext, nil
}

// header holds the parsed storage envelope header fields.
type header struct {
	version      uint8
	kdfAlgorithm uint8
	kdfTime      uint32
	kdfMemory    uint32
	kdfThreads   uint8
	recordType   uint8
	keyID        string
	salt         []byte
	payloadStart int // byte offset where nonce begins
}

// parseHeader decodes the storage envelope header from encoded bytes.
// It returns the parsed header without validating version or algorithm.
func parseHeader(encoded []byte) (*header, error) {
	if len(encoded) < minHeaderLen {
		return nil, errors.New("tss decrypt: encoded data too short for header")
	}

	pos := 0
	h := &header{}

	h.version = encoded[pos]
	pos++
	h.kdfAlgorithm = encoded[pos]
	pos++
	h.kdfTime = binary.BigEndian.Uint32(encoded[pos : pos+4])
	pos += 4
	h.kdfMemory = binary.BigEndian.Uint32(encoded[pos : pos+4])
	pos += 4
	h.kdfThreads = encoded[pos]
	pos++
	h.recordType = encoded[pos]
	pos++

	keyIDLen := int(encoded[pos])
	pos++
	if keyIDLen > 0 {
		if len(encoded) < pos+keyIDLen {
			return nil, errors.New("tss decrypt: encoded data too short for key_id")
		}
		h.keyID = string(encoded[pos : pos+keyIDLen])
		pos += keyIDLen
	}

	saltLenByte := int(encoded[pos])
	pos++
	if saltLenByte != saltLen {
		return nil, fmt.Errorf("tss decrypt: unexpected salt length %d (expected %d)", saltLenByte, saltLen)
	}
	if len(encoded) < pos+saltLen {
		return nil, errors.New("tss decrypt: encoded data too short for salt")
	}
	h.salt = make([]byte, saltLen)
	copy(h.salt, encoded[pos:pos+saltLen])
	pos += saltLen

	h.payloadStart = pos
	return h, nil
}

// buildAAD constructs the authenticated additional data for AEAD.
// Layout: version || algo || time || memory || threads || record_type ||
//
//	key_id_len || key_id || salt_len || salt
func buildAAD(recordType uint8, keyID string, salt []byte, params *PassphraseParams) []byte {
	keyIDBytes := []byte(keyID)
	aadLen := minHeaderLen + len(keyIDBytes)

	aad := make([]byte, aadLen)
	pos := 0

	aad[pos] = storageVersion
	pos++
	aad[pos] = kdfArgon2id
	pos++
	binary.BigEndian.PutUint32(aad[pos:pos+4], params.Time)
	pos += 4
	binary.BigEndian.PutUint32(aad[pos:pos+4], params.Memory)
	pos += 4
	aad[pos] = params.Threads
	pos++
	aad[pos] = recordType
	pos++
	aad[pos] = uint8(len(keyIDBytes))
	pos++
	if len(keyIDBytes) > 0 {
		copy(aad[pos:], keyIDBytes)
		pos += len(keyIDBytes)
	}
	aad[pos] = saltLen
	pos++
	copy(aad[pos:], salt)

	return aad
}

// validateParams checks that PassphraseParams fields are within supported bounds.
func validateParams(params *PassphraseParams) error {
	return validateKDFParams(params.Time, params.Memory, params.Threads)
}

// deriveKeyArgon2id derives a 32-byte key from a passphrase and salt using Argon2id.
// It rejects zero parameters and values exceeding fixed upper bounds
// to prevent resource-exhaustion attacks when decrypting untrusted input.
func deriveKeyArgon2id(passphrase, salt []byte, time, memory uint32, threads uint8) ([]byte, error) {
	if err := validateKDFParams(time, memory, threads); err != nil {
		return nil, err
	}
	return argon2.IDKey(passphrase, salt, time, memory, threads, keyLen), nil
}

func validateKDFParams(time, memory uint32, threads uint8) error {
	if time == 0 || memory == 0 || threads == 0 {
		return errors.New("tss: invalid argon2id parameters: zero value")
	}
	if time > maxKDFTime {
		return fmt.Errorf("tss: argon2id time %d exceeds maximum %d", time, maxKDFTime)
	}
	if memory > maxKDFMemory {
		return fmt.Errorf("tss: argon2id memory %d KiB exceeds maximum %d KiB", memory, maxKDFMemory)
	}
	if threads > maxKDFThreads {
		return fmt.Errorf("tss: argon2id threads %d exceeds maximum %d", threads, maxKDFThreads)
	}
	return nil
}
