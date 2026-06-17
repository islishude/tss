package bip32util

import (
	"bytes"
	"io"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestAggregateChainCode_AggregatesInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte)
	}{
		{
			name: "single party equals input",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				cc := bytes.Repeat([]byte{0xAB}, 32)
				return tss.NewPartySet(1), map[tss.PartyID][]byte{1: cc}, cc
			},
		},
		{
			name: "two parties xor bytewise",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				a := bytes.Repeat([]byte{0xAB}, 32)
				b := bytes.Repeat([]byte{0xCD}, 32)
				return tss.NewPartySet(1, 2), map[tss.PartyID][]byte{1: a, 2: b}, xorChainCodes(a, b)
			},
		},
		{
			name: "three parties xor bytewise",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				a := bytes.Repeat([]byte{0x11}, 32)
				b := bytes.Repeat([]byte{0x22}, 32)
				c := bytes.Repeat([]byte{0x33}, 32)
				return tss.NewPartySet(1, 2, 3), map[tss.PartyID][]byte{1: a, 2: b, 3: c}, xorChainCodes(a, b, c)
			},
		},
		{
			name: "deterministic pseudo-random chain codes",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				parties := tss.NewPartySet(0, 1, 2, 3, 4)
				chainCodes := make(map[tss.PartyID][]byte, len(parties))
				inputs := make([][]byte, 0, len(parties))
				for _, id := range parties {
					cc := deterministicChainCode(t, int64(100+id))
					chainCodes[id] = cc
					inputs = append(inputs, cc)
				}
				return parties, chainCodes, xorChainCodes(inputs...)
			},
		},
		{
			name: "all zero chain codes",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				z := make([]byte, 32)
				return tss.NewPartySet(1, 2, 3), map[tss.PartyID][]byte{1: z, 2: z, 3: z}, z
			},
		},
		{
			name: "empty party set",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				return nil, nil, make([]byte, 32)
			},
		},
		{
			name: "large party IDs",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
				parties := tss.NewPartySet(1<<20, 1<<20+1)
				a := bytes.Repeat([]byte{0x0F}, 32)
				b := bytes.Repeat([]byte{0xF0}, 32)
				return parties, map[tss.PartyID][]byte{parties[0]: a, parties[1]: b}, xorChainCodes(a, b)
			},
		},
		{
			name: "non-overlapping byte contributors",
			setup: func(t *testing.T) (tss.PartySet, map[tss.PartyID][]byte, []byte) {
				t.Helper()
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
				return tss.NewPartySet(1, 2, 3), map[tss.PartyID][]byte{1: p1, 2: p2, 3: p3}, xorChainCodes(p1, p2, p3)
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parties, chainCodes, want := tc.setup(t)
			got, err := AggregateChainCode(parties, chainCodes)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("AggregateChainCode() = %x, want %x", got, want)
			}
		})
	}
}

func TestAggregateChainCode_PreservesXORProperties(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		assert func(t *testing.T)
	}{
		{
			name: "commutative party order",
			assert: func(t *testing.T) {
				t.Helper()
				a := testutil.MustDecodeHex(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff01")
				b := testutil.MustDecodeHex(t, "1a2b3c4d5e6f708192a3b4c5d6e7f809102132435465768798a9bacbdcedfe0f")
				c := testutil.MustDecodeHex(t, "deadbeefcafebabedecafbadc0ffeeeebabe1234abcd5678ef901234fedcba98")
				chainCodes := map[tss.PartyID][]byte{1: a, 2: b, 3: c}

				result1, err := AggregateChainCode(tss.NewPartySet(1, 2, 3), chainCodes)
				if err != nil {
					t.Fatal(err)
				}
				result2, err := AggregateChainCode(tss.NewPartySet(3, 1, 2), chainCodes)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(result1, result2) {
					t.Fatal("party order changed aggregate chain code")
				}
			},
		},
		{
			name: "associative regrouping",
			assert: func(t *testing.T) {
				t.Helper()
				a := testutil.MustDecodeHex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				b := testutil.MustDecodeHex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
				c := testutil.MustDecodeHex(t, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
				chainCodes := map[tss.PartyID][]byte{1: a, 2: b, 3: c}

				allThree, err := AggregateChainCode(tss.NewPartySet(1, 2, 3), chainCodes)
				if err != nil {
					t.Fatal(err)
				}
				firstTwo, err := AggregateChainCode(tss.NewPartySet(1, 2), chainCodes)
				if err != nil {
					t.Fatal(err)
				}
				thenThird, err := AggregateChainCode(tss.NewPartySet(0, 3), map[tss.PartyID][]byte{0: firstTwo, 3: c})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(allThree, thenThird) {
					t.Fatal("regrouping changed aggregate chain code")
				}
			},
		},
		{
			name: "double xor cancels",
			assert: func(t *testing.T) {
				t.Helper()
				a := testutil.MustDecodeHex(t, "42f08ba1c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddee")
				b := testutil.MustDecodeHex(t, "f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff42")
				result, err := AggregateChainCode(tss.NewPartySet(1, 2, 3), map[tss.PartyID][]byte{1: a, 2: a, 3: b})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(result, b) {
					t.Fatal("a ^ a ^ b did not equal b")
				}
			},
		},
		{
			name: "same value parity",
			assert: func(t *testing.T) {
				t.Helper()
				v := testutil.MustDecodeHex(t, "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344")
				for _, n := range []int{1, 2, 3, 4, 6, 10} {
					parties := make(tss.PartySet, n)
					chainCodes := make(map[tss.PartyID][]byte, n)
					for i := range n {
						parties[i] = tss.PartyID(i)
						chainCodes[parties[i]] = v
					}

					got, err := AggregateChainCode(parties, chainCodes)
					if err != nil {
						t.Fatal(err)
					}
					want := v
					if n%2 == 0 {
						want = make([]byte, 32)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("n=%d: got %x, want %x", n, got, want)
					}
				}
			},
		},
		{
			name: "deterministic output",
			assert: func(t *testing.T) {
				t.Helper()
				a := testutil.MustDecodeHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
				b := testutil.MustDecodeHex(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff01")
				parties := tss.NewPartySet(1, 2)
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
						t.Fatalf("iteration %d: got %x, want %x", i, got, first)
					}
				}
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

func TestAggregateChainCode_RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parties    tss.PartySet
		chainCodes map[tss.PartyID][]byte
	}{
		{
			name:    "zero length chain code",
			parties: tss.NewPartySet(1, 2),
			chainCodes: map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xAA}, 32),
				2: nil,
			},
		},
		{
			name:    "one byte chain code",
			parties: tss.NewPartySet(1, 2),
			chainCodes: map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xAA}, 32),
				2: bytes.Repeat([]byte{0xBB}, 1),
			},
		},
		{
			name:    "31 byte chain code",
			parties: tss.NewPartySet(1, 2),
			chainCodes: map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xAA}, 32),
				2: bytes.Repeat([]byte{0xBB}, 31),
			},
		},
		{
			name:    "33 byte chain code",
			parties: tss.NewPartySet(1, 2),
			chainCodes: map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xAA}, 32),
				2: bytes.Repeat([]byte{0xBB}, 33),
			},
		},
		{
			name:    "64 byte chain code",
			parties: tss.NewPartySet(1, 2),
			chainCodes: map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xAA}, 32),
				2: bytes.Repeat([]byte{0xBB}, 64),
			},
		},
		{
			name:    "missing party chain code",
			parties: tss.NewPartySet(1, 2),
			chainCodes: map[tss.PartyID][]byte{
				1: bytes.Repeat([]byte{0xBB}, 32),
			},
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := AggregateChainCode(tc.parties, tc.chainCodes); err == nil {
				t.Fatal("expected invalid aggregate chain code input to be rejected")
			}
		})
	}
}

func xorChainCodes(inputs ...[]byte) []byte {
	out := make([]byte, 32)
	for _, in := range inputs {
		for i := range out {
			out[i] ^= in[i]
		}
	}
	return out
}

func deterministicChainCode(t *testing.T, seed int64) []byte {
	t.Helper()
	out := make([]byte, 32)
	n, err := io.ReadFull(testutil.DeterministicReader(seed), out)
	if err != nil {
		t.Fatalf("deterministic reader failed: %v", err)
	}
	if n != len(out) {
		t.Fatalf("short deterministic read: %d < %d", n, len(out))
	}
	return out
}
