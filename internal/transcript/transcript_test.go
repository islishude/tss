package transcript

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestBuilderFixedEncodingAndDigest(t *testing.T) {
	t.Parallel()

	b := New("test-domain")
	b.AppendBytes("bytes", []byte{0xaa, 0xbb})
	b.AppendString("string", "value")
	b.AppendUint8("u8", 7)
	b.AppendUint16("u16", 0x1234)
	b.AppendUint32("u32", 0x12345678)
	b.AppendBool("bool", true)
	b.AppendUint32List("ids", []uint32{1, 2})
	b.AppendBytesList("items", [][]byte{{0x01}, {0x02, 0x03}})

	var preimage []byte
	appendEntry := func(label string, value []byte) {
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(label)))
		preimage = append(preimage, label...)
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(value)))
		preimage = append(preimage, value...)
	}
	appendEntry("domain", []byte("test-domain"))
	appendEntry("bytes", []byte{0xaa, 0xbb})
	appendEntry("string", []byte("value"))
	appendEntry("u8", []byte{7})
	appendEntry("u16", []byte{0x12, 0x34})
	appendEntry("u32", []byte{0x12, 0x34, 0x56, 0x78})
	appendEntry("bool", []byte{1})
	appendEntry("ids", []byte{0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2})
	appendEntry("items", []byte{0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 2, 2, 3})

	want := sha256.Sum256(preimage)
	if got := b.Sum32(); got != want {
		t.Fatalf("Sum32() = %x, want %x", got, want)
	}
	if got := b.Sum(); !bytes.Equal(got, want[:]) {
		t.Fatalf("Sum() = %x, want %x", got, want)
	}
}

func TestBuilderBindsLabelsAndOrder(t *testing.T) {
	t.Parallel()

	a := New("domain")
	a.AppendString("first", "same")
	a.AppendString("second", "same")

	differentLabel := New("domain")
	differentLabel.AppendString("other", "same")
	differentLabel.AppendString("second", "same")
	if a.Sum32() == differentLabel.Sum32() {
		t.Fatal("different field labels produced the same digest")
	}

	differentOrder := New("domain")
	differentOrder.AppendString("second", "same")
	differentOrder.AppendString("first", "same")
	if a.Sum32() == differentOrder.Sum32() {
		t.Fatal("different field order produced the same digest")
	}

	differentDomain := New("other-domain")
	differentDomain.AppendString("first", "same")
	differentDomain.AppendString("second", "same")
	if a.Sum32() == differentDomain.Sum32() {
		t.Fatal("different domains produced the same digest")
	}
}

func TestBuilderSumDoesNotFinalize(t *testing.T) {
	t.Parallel()

	b := New("domain")
	before := b.Sum32()
	b.AppendString("field", "value")
	after := b.Sum32()
	if before == after {
		t.Fatal("appending after Sum32 did not change the digest")
	}
	if got := b.Sum32(); got != after {
		t.Fatal("repeated Sum32 calls were not deterministic")
	}
}

func TestBuilderRejectsEmptyDomainAndLabel(t *testing.T) {
	t.Parallel()

	assertPanic := func(t *testing.T, want string, fn func()) {
		t.Helper()
		defer func() {
			if got := recover(); got != want {
				t.Fatalf("panic = %v, want %q", got, want)
			}
		}()
		fn()
	}

	t.Run("domain", func(t *testing.T) {
		assertPanic(t, "transcript: empty domain", func() {
			New("")
		})
	})
	t.Run("label", func(t *testing.T) {
		assertPanic(t, "transcript: empty field label", func() {
			New("domain").AppendBytes("", []byte("secret"))
		})
	})
}
