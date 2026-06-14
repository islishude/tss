// Package transcript provides canonical labeled SHA-256 transcripts.
package transcript

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"

	"github.com/islishude/tss/internal/wire"
)

// Builder incrementally constructs a labeled SHA-256 transcript.
type Builder struct {
	h hash.Hash
}

// New creates a transcript whose first entry binds domain.
func New(domain string) *Builder {
	if domain == "" {
		panic("transcript: empty domain")
	}
	b := &Builder{h: sha256.New()}
	b.AppendString("domain", domain)
	return b
}

// AppendBytes appends a labeled byte string.
func (b *Builder) AppendBytes(label string, value []byte) {
	b.append(label, value)
}

// AppendString appends a labeled UTF-8 string.
func (b *Builder) AppendString(label, value string) {
	b.append(label, []byte(value))
}

// AppendUint8 appends a labeled uint8.
func (b *Builder) AppendUint8(label string, value uint8) {
	b.append(label, []byte{value})
}

// AppendUint16 appends a labeled big-endian uint16.
func (b *Builder) AppendUint16(label string, value uint16) {
	b.append(label, wire.Uint16(value))
}

// AppendUint32 appends a labeled big-endian uint32.
func (b *Builder) AppendUint32(label string, value uint32) {
	b.append(label, wire.Uint32(value))
}

// AppendUint64 appends a labeled big-endian uint64.
func (b *Builder) AppendUint64(label string, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	b.append(label, encoded[:])
}

// AppendBool appends a labeled canonical bool.
func (b *Builder) AppendBool(label string, value bool) {
	b.append(label, wire.Bool(value))
}

// AppendUint32List appends a labeled canonical uint32 list.
func (b *Builder) AppendUint32List(label string, values []uint32) {
	b.append(label, wire.EncodeUint32List(values))
}

// AppendBytesList appends a labeled canonical byte-string list.
func (b *Builder) AppendBytesList(label string, values [][]byte) {
	b.append(label, wire.EncodeBytesList(values))
}

// Sum returns the current 32-byte digest without modifying the transcript.
func (b *Builder) Sum() []byte {
	return b.h.Sum(nil)
}

// Sum32 returns the current digest as an array.
func (b *Builder) Sum32() [sha256.Size]byte {
	var out [sha256.Size]byte
	b.h.Sum(out[:0])
	return out
}

func (b *Builder) append(label string, value []byte) {
	if label == "" {
		panic("transcript: empty field label")
	}
	writeLength(b.h, len(label))
	_, _ = b.h.Write([]byte(label))
	writeLength(b.h, len(value))
	_, _ = b.h.Write(value)
}

func writeLength(h hash.Hash, size int) {
	if uint64(size) > math.MaxUint32 {
		panic("transcript: field length exceeds uint32")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(size))
	_, _ = h.Write(encoded[:])
}
