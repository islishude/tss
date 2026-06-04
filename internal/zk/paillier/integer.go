package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Signed integer encoding uses a canonical signed-magnitude format:
//
//	byte 0: 0x00 = non-negative, 0x01 = negative
//	byte 1+: minimal big-endian magnitude (no leading zeroes)
//
// Zero is encoded as sign=0x00 with empty magnitude: [0x00].
// Negative zero (sign=0x01, magnitude empty or zero) is invalid.
// Leading zeroes in the magnitude are invalid.

// EncodeSigned encodes x as a canonical signed-magnitude byte sequence.
func EncodeSigned(x *big.Int) []byte {
	if x == nil {
		return []byte{0x00}
	}
	sign := x.Sign()
	if sign == 0 {
		return []byte{0x00}
	}
	mag := x.Bytes() // absolute value, minimal big-endian
	if sign < 0 {
		return append([]byte{0x01}, mag...)
	}
	return append([]byte{0x00}, mag...)
}

// DecodeSigned parses a canonical signed-magnitude encoding and returns the
// integer. Non-canonical encodings (negative zero, leading zeroes, empty) are
// rejected.
func DecodeSigned(b []byte) (*big.Int, error) {
	if len(b) == 0 {
		return nil, errors.New("signed integer: empty encoding")
	}
	sign := b[0]
	if sign != 0x00 && sign != 0x01 {
		return nil, fmt.Errorf("signed integer: invalid sign byte 0x%02x", sign)
	}
	mag := b[1:]

	// Zero: sign must be 0x00, magnitude empty.
	if len(mag) == 0 {
		if sign == 0x00 {
			return new(big.Int), nil
		}
		return nil, errors.New("signed integer: negative zero is invalid")
	}

	// Magnitude must be minimal: no leading zero byte.
	if mag[0] == 0 {
		return nil, errors.New("signed integer: non-minimal magnitude (leading zero)")
	}

	val := new(big.Int).SetBytes(mag)
	if sign == 0x01 {
		val.Neg(val)
	}
	return val, nil
}

// DecodePositive parses a canonical positive big-endian integer. Empty
// encodings, zero, and leading-zero alternate encodings are rejected.
func DecodePositive(b []byte) (*big.Int, error) {
	if len(b) == 0 {
		return nil, errors.New("positive integer: empty encoding")
	}
	if b[0] == 0 {
		return nil, errors.New("positive integer: non-minimal encoding")
	}
	x := new(big.Int).SetBytes(b)
	if x.Sign() <= 0 {
		return nil, errors.New("positive integer: value must be positive")
	}
	return x, nil
}

// InSignedPowerOfTwo reports whether x is in the range [-2^bits, 2^bits].
func InSignedPowerOfTwo(x *big.Int, bits uint) bool {
	if x == nil {
		return false // nil is not a valid signed integer
	}
	bound := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
	negBound := new(big.Int).Neg(bound)
	return x.Cmp(negBound) >= 0 && x.Cmp(bound) <= 0
}

// InUnsignedPowerOfTwo reports whether x is in [0, 2^bits).
func InUnsignedPowerOfTwo(x *big.Int, bits uint) bool {
	if x == nil || x.Sign() < 0 {
		return false
	}
	bound := new(big.Int).Lsh(big.NewInt(1), bits)
	return x.Cmp(bound) < 0
}

// BoundSignedPowerOfTwo returns 2^bits (the upper bound for the signed range).
func BoundSignedPowerOfTwo(bits uint) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), bits)
}

// BoundUnsignedPowerOfTwo returns 2^bits (the upper bound for the unsigned range).
func BoundUnsignedPowerOfTwo(bits uint) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), bits)
}

// SampleSignedPowerOfTwo samples a uniformly random integer from [-2^bits, 2^bits].
func SampleSignedPowerOfTwo(rng io.Reader, bits uint) (*big.Int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	// Range size is 2*2^bits + 1 = 2^(bits+1) + 1
	// Sample from [0, 2^(bits+1)+1), then shift by -2^bits.
	rangeSize := new(big.Int).Lsh(big.NewInt(1), bits+1) // 2^(bits+1)
	rangeSize.Add(rangeSize, big.NewInt(1))              // 2^(bits+1) + 1

	v, err := rand.Int(rng, rangeSize)
	if err != nil {
		return nil, err
	}
	offset := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
	return v.Sub(v, offset), nil
}

// SampleUnsignedPowerOfTwo samples a uniformly random integer from [0, 2^bits).
func SampleUnsignedPowerOfTwo(rng io.Reader, bits uint) (*big.Int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	bound := new(big.Int).Lsh(big.NewInt(1), bits)
	return rand.Int(rng, bound)
}

// SampleZNStar samples a uniformly random element of Z*_N.
func SampleZNStar(rng io.Reader, n *big.Int) (*big.Int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if n == nil || n.Sign() <= 0 {
		return nil, errors.New("invalid modulus")
	}
	one := big.NewInt(1)
	for {
		x, err := rand.Int(rng, n)
		if err != nil {
			return nil, err
		}
		if x.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, x, n).Cmp(one) == 0 {
			return x, nil
		}
	}
}

// SampleMultRange samples a random integer from ±(bound * N) where bound is
// a power-of-two bound and N is the modulus. This is used for Ring-Pedersen
// commitment nonces (mu, gamma, m, delta).
func SampleMultRange(rng io.Reader, boundBits uint, n *big.Int) (*big.Int, error) {
	if rng == nil {
		rng = rand.Reader
	}
	bound := new(big.Int).Lsh(big.NewInt(1), boundBits) // 2^boundBits
	rangeSize := new(big.Int).Mul(bound, n)             // N * 2^boundBits
	// Double for signed range: ±(N * 2^boundBits)
	twice := new(big.Int).Lsh(rangeSize, 1) // 2 * N * 2^boundBits
	twice.Add(twice, big.NewInt(1))         // 2*N*2^boundBits + 1

	v, err := rand.Int(rng, twice)
	if err != nil {
		return nil, err
	}
	return v.Sub(v, rangeSize), nil // shift to [-N*2^boundBits, N*2^boundBits]
}

// inMultRange checks whether x is in ±(N * 2^bits).
func inMultRange(x, n *big.Int, bits uint) bool {
	bound := new(big.Int).Lsh(big.NewInt(1), bits) // 2^bits
	bound.Mul(bound, n)                            // N * 2^bits
	negBound := new(big.Int).Neg(bound)
	return x.Cmp(negBound) >= 0 && x.Cmp(bound) <= 0
}

func signedPowerOfTwoBytes(bits uint) int {
	return int((bits + 8) / 8)
}

func multRangeBytes(n *big.Int, bits uint) int {
	if n == nil || n.Sign() <= 0 {
		return 0
	}
	bound := new(big.Int).Lsh(big.NewInt(1), bits)
	bound.Mul(bound, n)
	return (bound.BitLen() + 7) / 8
}
