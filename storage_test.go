package tss

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptKeyShare(t *testing.T) {
	plaintext := []byte("test key share data for encryption round trip")
	passphrase := []byte("super-secret-passphrase")

	encrypted, err := EncryptKeyShare(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptKeyShare: %v", err)
	}

	decrypted, err := DecryptKeyShare(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShare: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("round trip: decrypted plaintext does not match original")
	}
}

func TestEncryptDecryptKeyShareWrongPassphrase(t *testing.T) {
	plaintext := []byte("test key share data")
	passphrase := []byte("correct-passphrase")

	encrypted, err := EncryptKeyShare(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptKeyShare: %v", err)
	}

	_, err = DecryptKeyShare(encrypted, []byte("wrong-passphrase"))
	if err == nil {
		t.Fatal("expected decryption to fail with wrong passphrase")
	}
}

func TestEncryptKeyShareIsNonDeterministic(t *testing.T) {
	plaintext := []byte("test key share data")
	passphrase := []byte("passphrase")

	enc1, err := EncryptKeyShare(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptKeyShare 1: %v", err)
	}
	enc2, err := EncryptKeyShare(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptKeyShare 2: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same plaintext produced identical output")
	}
}

func TestEncryptDecryptPresign(t *testing.T) {
	plaintext := []byte("test presign data for encryption round trip")
	passphrase := []byte("presign-passphrase")

	encrypted, err := EncryptPresign(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptPresign: %v", err)
	}

	decrypted, err := DecryptPresign(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptPresign: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("presign round trip: decrypted plaintext does not match original")
	}
}

func TestEncryptDecryptPresignWrongPassphrase(t *testing.T) {
	plaintext := []byte("test presign data")
	passphrase := []byte("correct")

	encrypted, err := EncryptPresign(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptPresign: %v", err)
	}

	_, err = DecryptPresign(encrypted, []byte("wrong"))
	if err == nil {
		t.Fatal("expected presign decryption to fail with wrong passphrase")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := DecryptKeyShare([]byte("short"), []byte("pw"))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	plaintext := []byte{}
	passphrase := []byte("pw")

	encrypted, err := EncryptKeyShare(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptKeyShare empty: %v", err)
	}

	decrypted, err := DecryptKeyShare(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShare empty: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("empty round trip failed")
	}
}

func TestEncryptDecryptLargePayload(t *testing.T) {
	plaintext := make([]byte, 1024*1024) // 1 MiB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("big-payload-pw")

	encrypted, err := EncryptKeyShare(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptKeyShare large: %v", err)
	}

	decrypted, err := DecryptKeyShare(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptKeyShare large: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("large payload round trip failed")
	}
}
