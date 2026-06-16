package bip32util

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
)

const (
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// BIP32ExtendedKeyPayloadLen is the payload length, excluding the 4-byte
	// Base58Check checksum, for serialized BIP32 extended public/private keys.
	BIP32ExtendedKeyPayloadLen = 78
)

var (
	base58Radix     = big.NewInt(58)
	base58DecodeMap = newBase58DecodeMap()

	// ErrInvalidBase58Character indicates that the input contains a byte
	// outside the Bitcoin Base58 alphabet.
	ErrInvalidBase58Character = errors.New("invalid base58 character")

	// ErrInvalidChecksum indicates that the decoded payload checksum does not
	// match the expected Base58Check checksum.
	ErrInvalidChecksum = errors.New("base58 checksum mismatch")

	// ErrDataTooShort indicates that the decoded data is shorter than the
	// required 4-byte Base58Check checksum.
	ErrDataTooShort = errors.New("decoded data too short for checksum")
)

func newBase58DecodeMap() [256]int {
	var decodeMap [256]int
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i := range len(base58Alphabet) {
		decodeMap[base58Alphabet[i]] = i
	}
	return decodeMap
}

// Base58CheckEncode encodes payload with a 4-byte double-SHA256 checksum and
// returns the Base58Check-encoded string.
func Base58CheckEncode(payload []byte) string {
	checksum := checksum4(payload)

	data := make([]byte, len(payload)+len(checksum))
	copy(data, payload)
	copy(data[len(payload):], checksum)

	leadingZeros := countLeadingZeroBytes(data)

	n := new(big.Int).SetBytes(data)
	mod := new(big.Int)
	chars := make([]byte, 0, len(data)*138/100+1)

	for n.Sign() > 0 {
		n.DivMod(n, base58Radix, mod)
		chars = append(chars, base58Alphabet[mod.Int64()])
	}

	for i, j := 0, len(chars)-1; i < j; i, j = i+1, j-1 {
		chars[i], chars[j] = chars[j], chars[i]
	}

	encoded := make([]byte, leadingZeros+len(chars))
	for i := range leadingZeros {
		encoded[i] = base58Alphabet[0]
	}
	copy(encoded[leadingZeros:], chars)

	return string(encoded)
}

// Base58CheckDecode decodes a Base58Check-encoded string and verifies the
// checksum. It returns the original payload without the 4-byte checksum.
func Base58CheckDecode(s string) ([]byte, error) {
	leadingZeros := countLeadingBase58Zeros(s)

	n := new(big.Int)
	tmp := new(big.Int)

	for i := 0; i < len(s); i++ {
		idx := base58DecodeMap[s[i]]
		if idx < 0 {
			return nil, ErrInvalidBase58Character
		}

		n.Mul(n, base58Radix)
		n.Add(n, tmp.SetInt64(int64(idx)))
	}

	raw := n.Bytes()
	decoded := make([]byte, leadingZeros+len(raw))
	copy(decoded[leadingZeros:], raw)

	if len(decoded) < 4 {
		return nil, ErrDataTooShort
	}

	payloadLen := len(decoded) - 4
	payload := decoded[:payloadLen]
	checksum := decoded[payloadLen:]

	if !bytes.Equal(checksum4(payload), checksum) {
		return nil, ErrInvalidChecksum
	}

	return payload, nil
}

func checksum4(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return second[:4]
}

func countLeadingZeroBytes(data []byte) int {
	count := 0
	for count < len(data) && data[count] == 0 {
		count++
	}
	return count
}

func countLeadingBase58Zeros(s string) int {
	count := 0
	for count < len(s) && s[count] == base58Alphabet[0] {
		count++
	}
	return count
}
