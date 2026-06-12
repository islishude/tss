package wireutil

import (
	"bytes"
	"testing"
)

func TestCloneByteSlices_NilInput(t *testing.T) {
	t.Parallel()
	if got := CloneByteSlices(nil); got != nil {
		t.Fatalf("CloneByteSlices(nil) = %v, want nil", got)
	}
}

func TestCloneByteSlices_EmptySlice(t *testing.T) {
	t.Parallel()
	in := [][]byte{}
	got := CloneByteSlices(in)
	if got == nil {
		t.Fatal("CloneByteSlices({}) returned nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("CloneByteSlices({}) has length %d, want 0", len(got))
	}
}

func TestCloneByteSlices_SingleElement(t *testing.T) {
	t.Parallel()
	in := [][]byte{{0x01, 0x02, 0x03}}
	got := CloneByteSlices(in)
	if len(got) != 1 {
		t.Fatalf("got %d elements, want 1", len(got))
	}
	if !bytes.Equal(got[0], in[0]) {
		t.Fatalf("cloned element %x != original %x", got[0], in[0])
	}
	// Mutation to original must not affect clone.
	in[0][0] = 0xff
	if bytes.Equal(got[0], in[0]) {
		t.Fatal("original mutation leaked into clone")
	}
}

func TestCloneByteSlices_MultipleElements(t *testing.T) {
	t.Parallel()
	in := [][]byte{{0xaa}, {0xbb, 0xcc}, {0xdd, 0xee, 0xff}}
	got := CloneByteSlices(in)
	if len(got) != len(in) {
		t.Fatalf("got %d elements, want %d", len(got), len(in))
	}
	for i := range in {
		if !bytes.Equal(got[i], in[i]) {
			t.Fatalf("element %d: clone %x != original %x", i, got[i], in[i])
		}
	}
}

func TestCloneByteSlices_ContentEquality(t *testing.T) {
	t.Parallel()
	in := [][]byte{{0x01, 0x02}, {0x03}}
	clone := CloneByteSlices(in)
	// Slice headers are independent.
	if &clone[0] == &in[0] {
		t.Fatal("clone shares outer slice with original")
	}
	if &clone[0][0] == &in[0][0] {
		t.Fatal("clone inner slice shares backing array with original")
	}
	// Content is equal.
	for i := range in {
		if !bytes.Equal(clone[i], in[i]) {
			t.Fatalf("element %d: clone %x != original %x", i, clone[i], in[i])
		}
	}
}

func TestCloneByteSlices_MutateCloneLeavesOriginalIntact(t *testing.T) {
	t.Parallel()
	in := [][]byte{{0x10, 0x20}}
	clone := CloneByteSlices(in)
	clone[0][0] = 0x99
	if !bytes.Equal(in[0], []byte{0x10, 0x20}) {
		t.Fatal("clone mutation leaked into original")
	}
}

func TestCloneByteSlices_NilInnerSlice(t *testing.T) {
	t.Parallel()
	in := [][]byte{nil, {0x01}}
	got := CloneByteSlices(in)
	if len(got) != 2 {
		t.Fatalf("got %d elements, want 2", len(got))
	}
	if got[0] != nil {
		t.Fatalf("cloned nil inner slice is %v, want nil", got[0])
	}
	if !bytes.Equal(got[1], in[1]) {
		t.Fatalf("non-nil element: clone %x != original %x", got[1], in[1])
	}
}

func TestCloneByteSlices_Deterministic(t *testing.T) {
	t.Parallel()
	in := [][]byte{{0xca, 0xfe}, {0xba, 0xbe}}
	a := CloneByteSlices(in)
	b := CloneByteSlices(in)
	if !bytes.Equal(a[0], b[0]) || !bytes.Equal(a[1], b[1]) {
		t.Fatal("same input produced different clones")
	}
}

func TestIsAllZero_NilSlice(t *testing.T) {
	t.Parallel()
	if !IsAllZero(nil) {
		t.Fatal("IsAllZero(nil) = false, want true")
	}
}

func TestIsAllZero_EmptySlice(t *testing.T) {
	t.Parallel()
	if !IsAllZero([]byte{}) {
		t.Fatal("IsAllZero({}) = false, want true")
	}
}

func TestIsAllZero_AllZero(t *testing.T) {
	t.Parallel()
	if !IsAllZero([]byte{0, 0, 0, 0}) {
		t.Fatal("IsAllZero(all zeros) = false, want true")
	}
}

func TestIsAllZero_SingleNonZero_First(t *testing.T) {
	t.Parallel()
	if IsAllZero([]byte{1, 0, 0, 0}) {
		t.Fatal("IsAllZero(leading non-zero) = true, want false")
	}
}

func TestIsAllZero_SingleNonZero_Last(t *testing.T) {
	t.Parallel()
	if IsAllZero([]byte{0, 0, 0, 1}) {
		t.Fatal("IsAllZero(trailing non-zero) = true, want false")
	}
}

func TestIsAllZero_SingleNonZero_Middle(t *testing.T) {
	t.Parallel()
	if IsAllZero([]byte{0, 0, 1, 0}) {
		t.Fatal("IsAllZero(middle non-zero) = true, want false")
	}
}

func TestIsAllZero_AllNonZero(t *testing.T) {
	t.Parallel()
	if IsAllZero([]byte{0xff, 0xff, 0xff}) {
		t.Fatal("IsAllZero(all 0xff) = true, want false")
	}
}

func TestIsAllZero_FullByteRange(t *testing.T) {
	t.Parallel()
	// Every non-zero byte value must be detected.
	for b := 1; b <= 255; b++ {
		if IsAllZero([]byte{byte(b)}) {
			t.Fatalf("IsAllZero({0x%02x}) = true, want false", b)
		}
	}
}

func TestIsAllZero_LargeAllZero(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 1024)
	if !IsAllZero(buf) {
		t.Fatal("IsAllZero(1024 zeros) = false, want true")
	}
}

func TestIsAllZero_LargeAllNonZero(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 1024)
	for i := range buf {
		buf[i] = 0xff
	}
	if IsAllZero(buf) {
		t.Fatal("IsAllZero(1024×0xff) = true, want false")
	}
}

func TestIsAllZero_Deterministic(t *testing.T) {
	t.Parallel()
	buf := []byte{0, 1, 0, 2, 0}
	a := IsAllZero(buf)
	b := IsAllZero(buf)
	if a != b {
		t.Fatal("same input produced different results")
	}
}
