package wire

import (
	"bytes"
	"testing"
)

func TestWriteHashPart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		part []byte
		want []byte
	}{
		{
			name: "empty",
			part: nil,
			want: []byte{0, 0, 0, 0},
		},
		{
			name: "single byte",
			part: []byte{0xab},
			want: []byte{0, 0, 0, 1, 0xab},
		},
		{
			name: "four bytes",
			part: []byte{0x01, 0x02, 0x03, 0x04},
			want: []byte{0, 0, 0, 4, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "max 16-bit length",
			part: make([]byte, 0xffff),
			want: append([]byte{0, 0, 0xff, 0xff}, make([]byte, 0xffff)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			WriteHashPart(&buf, tt.part)
			if !bytes.Equal(buf.Bytes(), tt.want) {
				t.Fatalf("WriteHashPart(%x) = %x, want %x", tt.part, buf.Bytes(), tt.want)
			}
		})
	}
}

func TestWritePartyID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   uint32
		want []byte
	}{
		{
			name: "zero",
			id:   0,
			want: []byte{0, 0, 0, 4, 0, 0, 0, 0},
		},
		{
			name: "one",
			id:   1,
			want: []byte{0, 0, 0, 4, 0, 0, 0, 1},
		},
		{
			name: "max uint32",
			id:   0xffffffff,
			want: []byte{0, 0, 0, 4, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "typical party id",
			id:   0x12345678,
			want: []byte{0, 0, 0, 4, 0x12, 0x34, 0x56, 0x78},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			WritePartyID(&buf, tt.id)
			if !bytes.Equal(buf.Bytes(), tt.want) {
				t.Fatalf("WritePartyID(%d) = %x, want %x", tt.id, buf.Bytes(), tt.want)
			}
		})
	}
}

func TestWritePartySet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		parties []uint32
		want    []byte
	}{
		{
			name:    "empty",
			parties: nil,
			want: []byte{
				0, 0, 0, 4, 0, 0, 0, 0, // length=4 + count=0
			},
		},
		{
			name:    "single party",
			parties: []uint32{1},
			want: []byte{
				0, 0, 0, 4, 0, 0, 0, 1, // length=4 + count=1
				0, 0, 0, 4, 0, 0, 0, 1, // length=4 + party 1
			},
		},
		{
			name:    "three parties",
			parties: []uint32{10, 20, 30},
			want: []byte{
				0, 0, 0, 4, 0, 0, 0, 3, // length=4 + count=3
				0, 0, 0, 4, 0, 0, 0, 10, // length=4 + party 10
				0, 0, 0, 4, 0, 0, 0, 20, // length=4 + party 20
				0, 0, 0, 4, 0, 0, 0, 30, // length=4 + party 30
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			WritePartySet(&buf, tt.parties)
			if !bytes.Equal(buf.Bytes(), tt.want) {
				t.Fatalf("WritePartySet(%v) = %x, want %x", tt.parties, buf.Bytes(), tt.want)
			}
		})
	}
}

func TestWriteHashPartRoundTrip(t *testing.T) {
	t.Parallel()
	// Verify that writing then reading the expected frame reconstructs the original.
	original := []byte("test round-trip data")
	var buf bytes.Buffer
	WriteHashPart(&buf, original)
	raw := buf.Bytes()
	if len(raw) < 4 {
		t.Fatal("output too short")
	}
	size := int(uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3]))
	if size != len(original) {
		t.Fatalf("encoded size %d != original len %d", size, len(original))
	}
	if !bytes.Equal(raw[4:], original) {
		t.Fatalf("payload %x != original %x", raw[4:], original)
	}
}
