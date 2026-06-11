package wireutil

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
)

func TestPartySetHash_SameSetDifferentOrderProducesSameHash(t *testing.T) {
	t.Parallel()
	a := PartySetHash([]tss.PartyID{1, 2, 3}, "test-v1")
	b := PartySetHash([]tss.PartyID{3, 1, 2}, "test-v1")
	if !bytes.Equal(a, b) {
		t.Fatal("same party set in different order produced different hashes")
	}
}

func TestPartySetHash_DifferentSetsProduceDifferentHashes(t *testing.T) {
	t.Parallel()
	a := PartySetHash([]tss.PartyID{1, 2}, "test-v1")
	b := PartySetHash([]tss.PartyID{1, 2, 3}, "test-v1")
	if bytes.Equal(a, b) {
		t.Fatal("different party sets produced identical hashes")
	}
}

func TestPartySetHash_DifferentLabelsProduceDifferentHashes(t *testing.T) {
	t.Parallel()
	a := PartySetHash([]tss.PartyID{1, 2}, "keygen-v1")
	b := PartySetHash([]tss.PartyID{1, 2}, "signing-v1")
	if bytes.Equal(a, b) {
		t.Fatal("different labels produced identical hashes")
	}
}

func TestPartySetHash_EmptySlice(t *testing.T) {
	t.Parallel()
	h := PartySetHash(nil, "test-v1")
	if len(h) != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(h))
	}
}

func TestPartySetHash_SingleParty(t *testing.T) {
	t.Parallel()
	h := PartySetHash([]tss.PartyID{42}, "test-v1")
	if len(h) != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(h))
	}
}

func TestPartySetHash_Deterministic(t *testing.T) {
	t.Parallel()
	parties := []tss.PartyID{5, 1, 9}
	a := PartySetHash(parties, "test-v1")
	b := PartySetHash(parties, "test-v1")
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs produced different hashes")
	}
}

func TestByteSlicesHash_DifferentLabelsProduceDifferentHashes(t *testing.T) {
	t.Parallel()
	values := [][]byte{{0x01, 0x02}, {0x03}}
	a := ByteSlicesHash("commitments-v1", values)
	b := ByteSlicesHash("public-keys-v1", values)
	if bytes.Equal(a, b) {
		t.Fatal("different labels produced identical hashes")
	}
}

func TestByteSlicesHash_DifferentValuesProduceDifferentHashes(t *testing.T) {
	t.Parallel()
	a := ByteSlicesHash("test-v1", [][]byte{{0x01}, {0x02}})
	b := ByteSlicesHash("test-v1", [][]byte{{0x02}, {0x01}})
	if bytes.Equal(a, b) {
		t.Fatal("different values produced identical hashes")
	}
}

func TestByteSlicesHash_LengthPrefixPreventsCollision(t *testing.T) {
	t.Parallel()
	// "ab" + "c" must NOT collide with "a" + "bc"
	a := ByteSlicesHash("test-v1", [][]byte{[]byte("ab"), []byte("c")})
	b := ByteSlicesHash("test-v1", [][]byte{[]byte("a"), []byte("bc")})
	if bytes.Equal(a, b) {
		t.Fatal("length-prefix collision: [ab,c] and [a,bc] produced identical hashes")
	}
}

func TestByteSlicesHash_EmptySlice(t *testing.T) {
	t.Parallel()
	h := ByteSlicesHash("test-v1", nil)
	if len(h) != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(h))
	}
}

func TestByteSlicesHash_SingleSlice(t *testing.T) {
	t.Parallel()
	h := ByteSlicesHash("test-v1", [][]byte{{0xaa, 0xbb}})
	if len(h) != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(h))
	}
}

func TestByteSlicesHash_Deterministic(t *testing.T) {
	t.Parallel()
	values := [][]byte{{0xde, 0xad}, {0xbe, 0xef}}
	a := ByteSlicesHash("test-v1", values)
	b := ByteSlicesHash("test-v1", values)
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs produced different hashes")
	}
}
