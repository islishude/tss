package wire

import (
	"encoding/binary"
	"errors"
)

type uint32Value interface {
	~uint32
}

// MaxInt is the largest value representable by int on this platform.
const MaxInt = int(^uint(0) >> 1)

// Uint16 encodes v as big-endian uint16.
func Uint16(v uint16) []byte {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], v)
	return out[:]
}

// Uint32 encodes v as big-endian uint32.
func Uint32(v uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return out[:]
}

// Bool encodes v as one canonical byte.
func Bool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// DecodeUint16 decodes an exact-length big-endian uint16.
func DecodeUint16(in []byte) (uint16, error) {
	if len(in) != 2 {
		return 0, errors.New("uint16 must be 2 bytes")
	}
	return binary.BigEndian.Uint16(in), nil
}

// DecodeUint32 decodes an exact-length big-endian uint32.
func DecodeUint32(in []byte) (uint32, error) {
	if len(in) != 4 {
		return 0, errors.New("uint32 must be 4 bytes")
	}
	return binary.BigEndian.Uint32(in), nil
}

// DecodeBool decodes one canonical bool byte.
func DecodeBool(in []byte) (bool, error) {
	if len(in) != 1 {
		return false, errors.New("bool must be 1 byte")
	}
	switch in[0] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("bool must be 0 or 1")
	}
}
