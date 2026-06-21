package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// NonNilBytes returns an empty byte slice when in is nil.
func NonNilBytes(in []byte) []byte {
	if in == nil {
		return []byte{}
	}
	return in
}

// ReadUint16 reads a big-endian uint16 at offset and returns the next offset.
func ReadUint16(in []byte, offset int) (uint16, int, error) {
	if offset < 0 {
		return 0, offset, errors.New("invalid uint16 offset")
	}
	if len(in)-offset < 2 {
		return 0, offset, errors.New("truncated uint16")
	}
	return binary.BigEndian.Uint16(in[offset : offset+2]), offset + 2, nil
}

// ReadUint32 reads a big-endian uint32 at offset and returns the next offset.
func ReadUint32(in []byte, offset int) (uint32, int, error) {
	if offset < 0 {
		return 0, offset, errors.New("invalid uint32 offset")
	}
	if len(in)-offset < 4 {
		return 0, offset, errors.New("truncated uint32")
	}
	return binary.BigEndian.Uint32(in[offset : offset+4]), offset + 4, nil
}

// ReadBytes reads a uint32 length-prefixed byte string at offset.
func ReadBytes(in []byte, offset int) ([]byte, int, error) {
	return ReadBytesWithLimit(in, offset, 0)
}

// ReadBytesWithLimit reads a uint32 length-prefixed byte string at offset.
// When maxItemBytes > 0, it rejects lengths that exceed the cap before allocating.
// When maxItemBytes <= 0, the check is skipped (callers should prefer a real cap).
func ReadBytesWithLimit(in []byte, offset int, maxItemBytes int) ([]byte, int, error) {
	length, offset, err := ReadUint32(in, offset)
	if err != nil {
		return nil, offset, err
	}
	if maxItemBytes > 0 && uint64(length) > uint64(maxItemBytes) {
		return nil, offset, fmt.Errorf("byte field too large: %d > %d", length, maxItemBytes)
	}
	if uint64(len(in)-offset) < uint64(length) {
		return nil, offset, errors.New("truncated byte field")
	}
	lengthInt := int(length)
	out := make([]byte, lengthInt)
	copy(out, in[offset:offset+lengthInt])
	return out, offset + lengthInt, nil
}

// AppendUint16 appends a big-endian uint16 to out.
func AppendUint16(out []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(out, buf[:]...)
}

// AppendUint32 appends a big-endian uint32 to out.
func AppendUint32(out []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(out, buf[:]...)
}

// AppendBytesChecked appends a uint32 length-prefixed byte string to out.
func AppendBytesChecked(out, value []byte) ([]byte, error) {
	if uint64(len(value)) > math.MaxUint32 {
		return nil, fmt.Errorf("byte field length %d exceeds uint32", len(value))
	}
	out = append(out, Uint32(uint32(len(value)))...)
	return append(out, value...), nil
}

// AppendBytes appends a uint32 length-prefixed byte string to out.
// It panics when value exceeds the wire uint32 length domain. Production wire
// codecs should use AppendBytesChecked so oversized input returns an error.
func AppendBytes(out, value []byte) []byte {
	out, err := AppendBytesChecked(out, value)
	if err != nil {
		panic(err)
	}
	return out
}
