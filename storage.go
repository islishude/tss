package tss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"crypto/hkdf"
)

const (
	keyShareHKDFInfo = "tss-key-share-encryption-v1"
	presignHKDFInfo  = "tss-presign-encryption-v1"

	saltLen  = 32
	nonceLen = 12
	keyLen   = 32 // AES-256
)

// EncryptKeyShare encrypts plaintext with passphrase using AES-256-GCM.
// The returned encoding is salt || nonce || ciphertext. Different passphrases
// produce incompatible ciphertexts, and the same plaintext encrypted twice
// produces different output due to random salt and nonce.
//
// This is a reference implementation. Production deployments should prefer
// a KMS or HSM for key material protection.
func EncryptKeyShare(plaintext, passphrase []byte) ([]byte, error) {
	return encrypt(plaintext, passphrase, keyShareHKDFInfo)
}

// DecryptKeyShare decrypts an encoding produced by EncryptKeyShare.
// A wrong passphrase causes GCM authentication failure.
func DecryptKeyShare(encoded, passphrase []byte) ([]byte, error) {
	return decrypt(encoded, passphrase, keyShareHKDFInfo)
}

// EncryptPresign encrypts a presign record with passphrase.
// The returned encoding is salt || nonce || ciphertext.
func EncryptPresign(plaintext, passphrase []byte) ([]byte, error) {
	return encrypt(plaintext, passphrase, presignHKDFInfo)
}

// DecryptPresign decrypts an encoding produced by EncryptPresign.
func DecryptPresign(encoded, passphrase []byte) ([]byte, error) {
	return decrypt(encoded, passphrase, presignHKDFInfo)
}

func encrypt(plaintext, passphrase []byte, info string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("tss encrypt: salt: %w", err)
	}
	key := deriveKey(passphrase, salt, info)
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
	out := make([]byte, 0, saltLen+nonceLen+len(plaintext)+gcm.Overhead())
	out = append(out, salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

func decrypt(encoded, passphrase []byte, info string) ([]byte, error) {
	if len(encoded) < saltLen+nonceLen {
		return nil, errors.New("tss decrypt: encoded data too short")
	}
	salt := encoded[:saltLen]
	nonce := encoded[saltLen : saltLen+nonceLen]
	ciphertext := encoded[saltLen+nonceLen:]
	key := deriveKey(passphrase, salt, info)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("tss decrypt: %w", err)
	}
	return plaintext, nil
}

func deriveKey(passphrase, salt []byte, info string) []byte {
	key, err := hkdf.Key(sha256.New, passphrase, salt, info, keyLen)
	if err != nil {
		panic("tss: hkdf key derivation failed: " + err.Error())
	}
	return key
}
