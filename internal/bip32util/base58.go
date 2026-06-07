package bip32util

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58CheckEncode encodes a payload with a 4-byte SHA256d checksum and
// returns the Base58Check-encoded string.
func Base58CheckEncode(payload []byte) string {
	// Checksum = first 4 bytes of SHA256(SHA256(payload)).
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	extended := make([]byte, len(payload)+4)
	copy(extended, payload)
	copy(extended[len(payload):], h2[:4])

	// Count leading zero bytes for base58 leading '1' padding.
	leadingZeros := 0
	for _, b := range extended {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Encode the extended payload as a big integer in base 58.
	n := new(big.Int).SetBytes(extended)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var chars []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		chars = append(chars, base58Alphabet[mod.Int64()])
	}
	// Reverse (big-endian to base58 order).
	for i, j := 0, len(chars)-1; i < j; i, j = i+1, j-1 {
		chars[i], chars[j] = chars[j], chars[i]
	}

	// Prepend leading '1's.
	return strings.Repeat("1", leadingZeros) + string(chars)
}

// Base58CheckDecode decodes a Base58Check-encoded string and verifies the
// checksum. It returns the payload without the checksum.
func Base58CheckDecode(s string) ([]byte, error) {
	// Count leading '1's — each represents a leading zero byte.
	leadingZeros := 0
	for _, c := range s {
		if c == '1' {
			leadingZeros++
		} else {
			break
		}
	}

	// Decode base58.
	n := new(big.Int)
	base := big.NewInt(58)
	tmp := new(big.Int)
	for _, c := range s {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx == -1 {
			return nil, errors.New("invalid base58 character")
		}
		n.Mul(n, base)
		n.Add(n, tmp.SetInt64(int64(idx)))
	}

	raw := n.Bytes()

	// Prepend leading zeros.
	decoded := make([]byte, leadingZeros+len(raw))
	copy(decoded[leadingZeros:], raw)

	// xpub/xprv payload is always 78 bytes + 4 bytes checksum = 82 total.
	// big.Int.Bytes() drops leading zeros within the numeric value. For
	// xpub version 0x0488B21E, the 0x04 byte is dropped, giving 81 bytes.
	// Pad to 82 if needed.
	for len(decoded) < 82 {
		decoded = append([]byte{0}, decoded...)
	}

	if len(decoded) < 4 {
		return nil, errors.New("decoded data too short for checksum")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	if !bytes.Equal(h2[:4], checksum) {
		return nil, errors.New("base58 checksum mismatch")
	}

	return payload, nil
}
