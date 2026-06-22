package tss

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestEncryptDecryptKeyShareWithPassphrase(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test key share data for encryption round trip")
	passphrase := []byte("super-secret-passphrase")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "key-1", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	decrypted, err := DecryptKeyShareWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShareWithPassphrase: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("round trip: decrypted plaintext does not match original")
	}
}

func TestEncryptDecryptKeyShareWithPassphraseWrongPassphrase(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test key share data")
	passphrase := []byte("correct-passphrase")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	_, err = DecryptKeyShareWithPassphrase(encrypted, []byte("wrong-passphrase"))
	if err == nil {
		t.Fatal("expected decryption to fail with wrong passphrase")
	}
}

func TestEncryptKeyShareWithPassphraseIsNonDeterministic(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test key share data")
	passphrase := []byte("passphrase")

	enc1, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "key-1", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase 1: %v", err)
	}
	enc2, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "key-1", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase 2: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same plaintext produced identical output")
	}
}

func TestEncryptDecryptPresignWithPassphrase(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test presign data for encryption round trip")
	passphrase := []byte("presign-passphrase")

	encrypted, err := EncryptPresignWithPassphrase(plaintext, passphrase, "presign-1", nil)
	if err != nil {
		t.Fatalf("EncryptPresignWithPassphrase: %v", err)
	}

	decrypted, err := DecryptPresignWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptPresignWithPassphrase: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("presign round trip: decrypted plaintext does not match original")
	}
}

func TestEncryptDecryptPresignWithPassphraseWrongPassphrase(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test presign data")
	passphrase := []byte("correct")

	encrypted, err := EncryptPresignWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptPresignWithPassphrase: %v", err)
	}

	_, err = DecryptPresignWithPassphrase(encrypted, []byte("wrong"))
	if err == nil {
		t.Fatal("expected presign decryption to fail with wrong passphrase")
	}
}

func TestEncryptDecryptSignAttemptWithPassphrase(t *testing.T) {
	t.Parallel()
	plaintext := []byte("confidential sign attempt outbox")
	passphrase := []byte("sign-attempt-passphrase")
	params := &PassphraseParams{Time: 1, Memory: 1024, Threads: 1}

	encrypted, err := EncryptSignAttemptWithPassphrase(plaintext, passphrase, "attempt-1", params)
	if err != nil {
		t.Fatalf("EncryptSignAttemptWithPassphrase: %v", err)
	}
	decrypted, err := DecryptSignAttemptWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptSignAttemptWithPassphrase: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("sign attempt round trip mismatch")
	}
	decrypted, keyID, err := DecryptSignAttemptWithPassphraseAndKeyID(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptSignAttemptWithPassphraseAndKeyID: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) || keyID != "attempt-1" {
		t.Fatal("sign attempt authenticated key ID mismatch")
	}
	if _, err := DecryptPresignWithPassphrase(encrypted, passphrase); err == nil {
		t.Fatal("sign attempt ciphertext accepted as a presign record")
	}
}

func TestDecryptWithPassphraseTooShort(t *testing.T) {
	t.Parallel()
	_, err := DecryptKeyShareWithPassphrase([]byte("short"), []byte("pw"))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestEncryptDecryptWithPassphraseEmpty(t *testing.T) {
	t.Parallel()
	plaintext := []byte{}
	passphrase := []byte("pw")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase empty: %v", err)
	}

	decrypted, err := DecryptKeyShareWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShareWithPassphrase empty: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("empty round trip failed")
	}
}

func TestEncryptDecryptWithPassphraseLargePayload(t *testing.T) {
	t.Parallel()
	plaintext := make([]byte, 1024*1024) // 1 MiB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("big-payload-pw")
	// Use reduced params so the test stays fast — key derivation dominates for large payloads.
	fastParams := &PassphraseParams{Time: 1, Memory: 8 * 1024, Threads: 1}

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "large", fastParams)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase large: %v", err)
	}

	decrypted, err := DecryptKeyShareWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShareWithPassphrase large: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("large payload round trip failed")
	}
}

func TestEncryptKeyShareWithPassphraseKeyID(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")
	keyID := "my-key-id"

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, keyID, nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	decrypted, err := DecryptKeyShareWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShareWithPassphrase: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("round trip with keyID failed")
	}
}

func TestDecryptWithPassphraseUnknownVersion(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	// Corrupt the version byte (offset 0).
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[0] = 99

	_, err = DecryptKeyShareWithPassphrase(tampered, passphrase)
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
}

func TestDecryptWithPassphraseUnknownAlgorithm(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	// Corrupt the algorithm byte (offset 1).
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[1] = 99

	_, err = DecryptKeyShareWithPassphrase(tampered, passphrase)
	if err == nil {
		t.Fatal("expected error for unknown KDF algorithm")
	}
}

func TestDecryptWithPassphraseWrongRecordType(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	// Encrypt as key share, try to decrypt as presign.
	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	_, err = DecryptPresignWithPassphrase(encrypted, passphrase)
	if err == nil {
		t.Fatal("expected error for wrong record type")
	}
}

func TestDecryptWithPassphraseTamperedAAD(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "key-1", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	// Flip a bit in the salt (offset after version(1)+algo(1)+time(4)+mem(4)+threads(1)+record(1)+keyIDLen(1)+keyID(5)+saltLen(1) = 19)
	// keyID "key-1" is 5 bytes.
	saltOffset := 1 + 1 + 4 + 4 + 1 + 1 + 1 + 5 + 1
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[saltOffset] ^= 0x01

	_, err = DecryptKeyShareWithPassphrase(tampered, passphrase)
	if err == nil {
		t.Fatal("expected AEAD authentication failure for tampered AAD (salt)")
	}
}

func TestDecryptWithPassphraseTamperedKeyID(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "key-1", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	// Flip a bit in the key_id field.
	// keyIDLen is at offset 12, key_id starts at offset 13.
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[13] ^= 0x01

	_, err = DecryptKeyShareWithPassphrase(tampered, passphrase)
	if err == nil {
		t.Fatal("expected AEAD authentication failure for tampered AAD (keyID)")
	}
}

func TestEncryptDecryptWithPassphraseCustomParams(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")
	params := &PassphraseParams{Time: 2, Memory: 32 * 1024, Threads: 2}

	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "custom", params)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	decrypted, err := DecryptKeyShareWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShareWithPassphrase: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("custom params round trip failed")
	}
}

func TestEncryptWithPassphraseZeroParams(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	_, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", &PassphraseParams{})
	if err == nil {
		t.Fatal("expected error for zero Time")
	}

	_, err = EncryptKeyShareWithPassphrase(plaintext, passphrase, "", &PassphraseParams{Time: 1})
	if err == nil {
		t.Fatal("expected error for zero Memory")
	}

	_, err = EncryptKeyShareWithPassphrase(plaintext, passphrase, "", &PassphraseParams{Time: 1, Memory: 1024})
	if err == nil {
		t.Fatal("expected error for zero Threads")
	}
}

func TestEncryptWithPassphraseKeyIDTooLong(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")
	longKeyID := string(make([]byte, maxKeyIDLen+1))

	_, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, longKeyID, nil)
	if err == nil {
		t.Fatal("expected error for keyID exceeding max length")
	}
}

func TestDefaultPassphraseParams(t *testing.T) {
	t.Parallel()
	p := DefaultPassphraseParams()
	if p.Time != 3 {
		t.Errorf("expected Time=3, got %d", p.Time)
	}
	if p.Memory != 64*1024 {
		t.Errorf("expected Memory=65536, got %d", p.Memory)
	}
	if p.Threads != 4 {
		t.Errorf("expected Threads=4, got %d", p.Threads)
	}
}

func TestEncryptDecryptPresignWithPassphraseKeyID(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test presign data")
	passphrase := []byte("passphrase")
	keyID := "presign-k1"

	encrypted, err := EncryptPresignWithPassphrase(plaintext, passphrase, keyID, nil)
	if err != nil {
		t.Fatalf("EncryptPresignWithPassphrase: %v", err)
	}

	decrypted, err := DecryptPresignWithPassphrase(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptPresignWithPassphrase: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("presign round trip with keyID failed")
	}
}

func TestDecryptWithPassphraseRejectsExcessiveParams(t *testing.T) {
	t.Parallel()
	plaintext := []byte("test data")
	passphrase := []byte("passphrase")

	// Encrypt with valid params to get a well-formed encoding.
	encrypted, err := EncryptKeyShareWithPassphrase(plaintext, passphrase, "", nil)
	if err != nil {
		t.Fatalf("EncryptKeyShareWithPassphrase: %v", err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	// Corrupt kdf_time (offset 2) to exceed maxKDFTime (1000).
	binary.BigEndian.PutUint32(tampered[2:6], 1001)

	_, err = DecryptKeyShareWithPassphrase(tampered, passphrase)
	if err == nil {
		t.Fatal("expected error for excessive kdf_time")
	}

	copy(tampered, encrypted)
	// Corrupt kdf_memory (offset 6) to exceed maxKDFMemory (1 GiB).
	binary.BigEndian.PutUint32(tampered[6:10], 1024*1024+1)

	_, err = DecryptKeyShareWithPassphrase(tampered, passphrase)
	if err == nil {
		t.Fatal("expected error for excessive kdf_memory")
	}

	copy(tampered, encrypted)
	// Corrupt kdf_threads (offset 10) to exceed maxKDFThreads (255).
	tampered[10] = 255 // uint8 max is already the limit — use 255+1 overflow: wraps to 0
	// Since maxKDFThreads == 255 (uint8 max), we can't exceed it via uint8 wire field.
	// But any tampering of the header causes AEAD auth failure. So this sub-case
	// is covered by the general AAD tampering tests.
}
