package bip32util

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// ---------------------------------------------------------------------------
// AggregateChainCode — basic correctness
// ---------------------------------------------------------------------------

func TestAggregateChainCode_SingleParty(t *testing.T) {
	parties := []tss.PartyID{1}
	chainCodes := map[tss.PartyID][]byte{
		1: bytes.Repeat([]byte{0xAB}, 32),
	}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chainCodes[1]) {
		t.Errorf("single-party output should equal input:\n  got:  %x\n  want: %x", got, chainCodes[1])
	}
}

func TestAggregateChainCode_TwoParties(t *testing.T) {
	a := bytes.Repeat([]byte{0xAB}, 32)
	b := bytes.Repeat([]byte{0xCD}, 32)
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = a[i] ^ b[i]
	}

	parties := []tss.PartyID{1, 2}
	chainCodes := map[tss.PartyID][]byte{1: a, 2: b}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("unexpected result:\n  got:  %x\n  want: %x", got, expected)
	}
}

func TestAggregateChainCode_ThreeParties(t *testing.T) {
	a := bytes.Repeat([]byte{0x11}, 32)
	b := bytes.Repeat([]byte{0x22}, 32)
	c := bytes.Repeat([]byte{0x33}, 32)
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = a[i] ^ b[i] ^ c[i]
	}

	parties := []tss.PartyID{1, 2, 3}
	chainCodes := map[tss.PartyID][]byte{1: a, 2: b, 3: c}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("unexpected result:\n  got:  %x\n  want: %x", got, expected)
	}
}

func TestAggregateChainCode_RandomChainCodes(t *testing.T) {
	// Use cryptographically random chain codes to verify XOR aggregation.
	parties := []tss.PartyID{0, 1, 2, 3, 4}
	chainCodes := make(map[tss.PartyID][]byte, len(parties))
	expected := make([]byte, 32)
	for _, id := range parties {
		chainCodes[id] = make([]byte, 32)
		newRandomBytes(t, chainCodes[id])
		for i := range expected {
			expected[i] ^= chainCodes[id][i]
		}
	}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("random chain code aggregation mismatch")
	}
}

// ---------------------------------------------------------------------------
// AggregateChainCode — data consistency
// ---------------------------------------------------------------------------

func TestAggregateChainCode_Commutative(t *testing.T) {
	// XOR is commutative: the result should be the same regardless of party order.
	a := testutil.MustDecodeHex(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff01")
	b := testutil.MustDecodeHex(t, "1a2b3c4d5e6f708192a3b4c5d6e7f809102132435465768798a9bacbdcedfe0f")
	c := testutil.MustDecodeHex(t, "deadbeefcafebabedecafbadc0ffeeeebabe1234abcd5678ef901234fedcba98")

	chainCodes := map[tss.PartyID][]byte{1: a, 2: b, 3: c}

	// Compute result with order [1, 2, 3].
	result1, err := AggregateChainCode([]tss.PartyID{1, 2, 3}, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	// Compute result with order [3, 1, 2].
	result2, err := AggregateChainCode([]tss.PartyID{3, 1, 2}, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result1, result2) {
		t.Errorf("AggregateChainCode should be commutative (order-independent)")
	}
}

func TestAggregateChainCode_Associative(t *testing.T) {
	// XOR is associative: (a ^ b) ^ c == a ^ (b ^ c).
	a := testutil.MustDecodeHex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := testutil.MustDecodeHex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	c := testutil.MustDecodeHex(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

	// Aggregate all three.
	chainCodes := map[tss.PartyID][]byte{1: a, 2: b, 3: c}
	allThree, err := AggregateChainCode([]tss.PartyID{1, 2, 3}, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	// Aggregate first two, then with third.
	firstTwo, err := AggregateChainCode([]tss.PartyID{1, 2}, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	thenThird, err := AggregateChainCode(
		[]tss.PartyID{0, 3},
		map[tss.PartyID][]byte{0: firstTwo, 3: c},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(allThree, thenThird) {
		t.Errorf("AggregateChainCode should be associative")
	}
}

func TestAggregateChainCode_DoubleXORIdentity(t *testing.T) {
	// Double XOR with the same value returns the original: a ^ a = 0, a ^ a ^ b = b.
	a := testutil.MustDecodeHex(t, "42f08ba1c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddee")
	b := testutil.MustDecodeHex(t, "f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff42")

	chainCodes := map[tss.PartyID][]byte{1: a, 2: a, 3: b}
	result, err := AggregateChainCode([]tss.PartyID{1, 2, 3}, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	// a ^ a ^ b = b.
	if !bytes.Equal(result, b) {
		t.Errorf("double-XOR identity: a ^ a ^ b should equal b")
	}
}

func TestAggregateChainCode_AllZeroChainCodes(t *testing.T) {
	// All-zero chain codes should XOR to all-zero.
	z := make([]byte, 32)
	parties := []tss.PartyID{1, 2, 3}
	chainCodes := map[tss.PartyID][]byte{1: z, 2: z, 3: z}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, z) {
		t.Errorf("all-zero chain codes should XOR to all-zero, got %x", got)
	}
}

func TestAggregateChainCode_SameValueEveryParty(t *testing.T) {
	// For an even number of parties with the same chain code, the result is zero.
	// For an odd number, the result is the chain code itself.
	for _, n := range []int{1, 2, 3, 4, 6, 10} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			v := testutil.MustDecodeHex(t, "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344")
			parties := make([]tss.PartyID, n)
			chainCodes := make(map[tss.PartyID][]byte, n)
			for i := range n {
				parties[i] = tss.PartyID(i)
				chainCodes[parties[i]] = v
			}
			got, err := AggregateChainCode(parties, chainCodes)
			if err != nil {
				t.Fatal(err)
			}
			if n%2 == 0 {
				zero := make([]byte, 32)
				if !bytes.Equal(got, zero) {
					t.Errorf("even (%d) identical chain codes should XOR to zero", n)
				}
			} else {
				if !bytes.Equal(got, v) {
					t.Errorf("odd (%d) identical chain codes should XOR to the value itself", n)
				}
			}
		})
	}
}

func TestAggregateChainCode_Deterministic(t *testing.T) {
	a := testutil.MustDecodeHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	b := testutil.MustDecodeHex(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff01")
	parties := []tss.PartyID{1, 2}
	chainCodes := map[tss.PartyID][]byte{1: a, 2: b}

	first, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		got, err := AggregateChainCode(parties, chainCodes)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("AggregateChainCode is not deterministic: iteration %d", i)
		}
	}
}

func TestAggregateChainCode_NonOverlappingBytes(t *testing.T) {
	// Each party contributes to non-overlapping byte ranges, making XOR equivalent
	// to concatenation for those ranges.
	p1 := make([]byte, 32)
	p2 := make([]byte, 32)
	p3 := make([]byte, 32)
	for i := range 32 {
		switch {
		case i < 8:
			p1[i] = byte(i + 1)
		case i < 16:
			p2[i] = byte(i + 1)
		default:
			p3[i] = byte(i + 1)
		}
	}
	expected := make([]byte, 32)
	for i := range 32 {
		expected[i] = p1[i] ^ p2[i] ^ p3[i]
		// Verify the non-overlap assumption: only one party has non-zero at each byte.
		active := 0
		if p1[i] != 0 {
			active++
		}
		if p2[i] != 0 {
			active++
		}
		if p3[i] != 0 {
			active++
		}
		if active > 1 {
			t.Errorf("test setup violated: byte %d has %d non-zero values", i, active)
		}
	}

	parties := []tss.PartyID{1, 2, 3}
	chainCodes := map[tss.PartyID][]byte{1: p1, 2: p2, 3: p3}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("non-overlapping aggregation mismatch")
	}
}

// ---------------------------------------------------------------------------
// AggregateChainCode — error cases
// ---------------------------------------------------------------------------

func TestAggregateChainCode_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"zero length", 0},
		{"one byte", 1},
		{"31 bytes", 31},
		{"33 bytes", 33},
		{"64 bytes", 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parties := []tss.PartyID{1, 2}
			chainCodes := map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xAA}, 32),
				2: make([]byte, tt.length),
			}
			_, err := AggregateChainCode(parties, chainCodes)
			if err == nil {
				t.Error("expected error for wrong chain code length")
			}
		})
	}
}

func TestAggregateChainCode_MissingParty(t *testing.T) {
	// When a party in the parties slice has no entry in chainCodes,
	// the zero-value []byte (nil, len 0) should cause a length error.
	parties := []tss.PartyID{1, 2}
	chainCodes := map[tss.PartyID][]byte{1: bytes.Repeat([]byte{0xBB}, 32)}
	_, err := AggregateChainCode(parties, chainCodes)
	if err == nil {
		t.Error("expected error for missing party chain code")
	}
}

func TestAggregateChainCode_EmptyParties(t *testing.T) {
	// No parties means the output is all-zero (no XOR operations performed).
	got, err := AggregateChainCode(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32-byte output, got %d", len(got))
	}
	zero := make([]byte, 32)
	if !bytes.Equal(got, zero) {
		t.Errorf("empty parties should return all-zero, got %x", got)
	}
}

func TestAggregateChainCode_LargePartyID(t *testing.T) {
	// PartyID is uint32 — test with large values.
	parties := []tss.PartyID{1 << 20, 1<<20 + 1}
	a := bytes.Repeat([]byte{0x0F}, 32)
	b := bytes.Repeat([]byte{0xF0}, 32)
	chainCodes := map[tss.PartyID][]byte{1 << 20: a, 1<<20 + 1: b}
	got, err := AggregateChainCode(parties, chainCodes)
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = a[i] ^ b[i]
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("large PartyID aggregation mismatch")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newRandomBytes(t *testing.T, buf []byte) {
	t.Helper()
	n, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("short read: %d < %d", n, len(buf))
	}
}
