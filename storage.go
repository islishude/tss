package tss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/argon2"
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

	saltLen  = 32
	nonceLen = 12
	keyLen   = 32 // AES-256

	// minHeaderLen is the fixed header size before the variable key_id field:
	// version(1) + algo(1) + time(4) + mem(4) + threads(1) + record_type(1) +
	// key_id_len(1) + salt_len(1) + salt(32) = 46
	minHeaderLen = 46

	// maxKeyIDLen is the maximum length of a caller-assigned key identifier.
	maxKeyIDLen = 255

	// Argon2id upper bounds for decrypting untrusted input.
	// These are generous enough for any legitimate use while preventing DOS.
	maxKDFTime    = 1000
	maxKDFMemory  = 1024 * 1024 // 1 GiB
	maxKDFThreads = math.MaxUint8

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
// Argon2id key derivation and AES-256-GCM. keyID is an optional caller-assigned
// identifier that is authenticated as AAD (empty string is allowed).
//
// This is a reference/demo implementation. Production deployments should use
// a KMS or HSM for key material protection.
func EncryptKeyShareWithPassphrase(plaintext, passphrase []byte, keyID string, params *PassphraseParams) ([]byte, error) {
	return encrypt(plaintext, passphrase, recordTypeKeyShare, keyID, params)
}

// DecryptKeyShareWithPassphrase decrypts an encoding produced by
// [EncryptKeyShareWithPassphrase]. A wrong passphrase causes GCM
// authentication failure.
func DecryptKeyShareWithPassphrase(encoded, passphrase []byte) ([]byte, error) {
	return decrypt(encoded, passphrase, recordTypeKeyShare)
}

// EncryptPresignWithPassphrase encrypts a presign record with a passphrase using
// Argon2id key derivation and AES-256-GCM. keyID is an optional caller-assigned
// identifier that is authenticated as AAD (empty string is allowed).
//
// This is a reference/demo implementation. Production deployments should use
// a KMS or HSM for key material protection.
func EncryptPresignWithPassphrase(plaintext, passphrase []byte, keyID string, params *PassphraseParams) ([]byte, error) {
	return encrypt(plaintext, passphrase, recordTypePresign, keyID, params)
}

// DecryptPresignWithPassphrase decrypts an encoding produced by
// [EncryptPresignWithPassphrase]. A wrong passphrase causes GCM
// authentication failure.
func DecryptPresignWithPassphrase(encoded, passphrase []byte) ([]byte, error) {
	return decrypt(encoded, passphrase, recordTypePresign)
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

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tss encrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
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
	out := make([]byte, 0, len(aad)+nonceLen+len(plaintext)+gcm.Overhead())
	out = append(out, aad...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

func decrypt(encoded, passphrase []byte, expectedRecordType uint8) ([]byte, error) {
	// Loose lower bound: the minimum valid encoding (no key_id, empty plaintext)
	// is minHeaderLen + nonceLen + GCM tag (16 bytes). A non-empty key_id makes
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

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
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

// buildAAD constructs the authenticated additional data for GCM.
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

// validateParams checks that PassphraseParams fields are non-zero.
func validateParams(params *PassphraseParams) error {
	if params.Time == 0 {
		return errors.New("tss: PassphraseParams.Time must be non-zero")
	}
	if params.Memory == 0 {
		return errors.New("tss: PassphraseParams.Memory must be non-zero")
	}
	if params.Threads == 0 {
		return errors.New("tss: PassphraseParams.Threads must be non-zero")
	}
	return nil
}

// deriveKeyArgon2id derives an AES-256 key from a passphrase and salt using Argon2id.
// It rejects zero parameters and values exceeding generous upper bounds
// to prevent resource-exhaustion attacks when decrypting untrusted input.
func deriveKeyArgon2id(passphrase, salt []byte, time, memory uint32, threads uint8) ([]byte, error) {
	if time == 0 || memory == 0 || threads == 0 {
		return nil, errors.New("tss: invalid argon2id parameters: zero value")
	}
	if time > maxKDFTime {
		return nil, fmt.Errorf("tss: argon2id time %d exceeds maximum %d", time, maxKDFTime)
	}
	if memory > maxKDFMemory {
		return nil, fmt.Errorf("tss: argon2id memory %d KiB exceeds maximum %d KiB", memory, maxKDFMemory)
	}
	if threads > maxKDFThreads {
		return nil, fmt.Errorf("tss: argon2id threads %d exceeds maximum %d", threads, maxKDFThreads)
	}
	return argon2.IDKey(passphrase, salt, time, memory, threads, keyLen), nil
}
