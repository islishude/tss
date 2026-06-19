package wireutil

import "testing"

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
