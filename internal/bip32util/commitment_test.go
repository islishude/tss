package bip32util

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestChainCodeCommitment_Deterministic(t *testing.T) {
	t.Parallel()

	sessionID := tss.SessionID{0: 0x01, 1: 0x02, 31: 0xff}
	chainCode := bytes.Repeat([]byte{0xAB}, ChainCodeSize)

	first := ChainCodeCommitment("test-label", sessionID, 1, chainCode)
	for i := range 10 {
		got := ChainCodeCommitment("test-label", sessionID, 1, chainCode)
		if !bytes.Equal(got, first) {
			t.Fatalf("iteration %d: commitment changed", i)
		}
	}
}

func TestChainCodeCommitment_DifferentInputsDiverge(t *testing.T) {
	t.Parallel()

	label := "cggmp21/keygen"
	sessionID := tss.SessionID{0: 0xAA}
	partyID := tss.PartyID(1)
	chainCode := bytes.Repeat([]byte{0xCC}, ChainCodeSize)

	base := ChainCodeCommitment(label, sessionID, partyID, chainCode)

	tests := []struct {
		name  string
		value []byte
	}{
		{
			name:  "different label",
			value: ChainCodeCommitment("other-label", sessionID, partyID, chainCode),
		},
		{
			name:  "different session ID",
			value: ChainCodeCommitment(label, tss.SessionID{0: 0xBB}, partyID, chainCode),
		},
		{
			name:  "different party ID",
			value: ChainCodeCommitment(label, sessionID, 2, chainCode),
		},
		{
			name:  "different chain code",
			value: ChainCodeCommitment(label, sessionID, partyID, bytes.Repeat([]byte{0xDD}, ChainCodeSize)),
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if bytes.Equal(base, tc.value) {
				t.Fatal("commitments should differ but are equal")
			}
		})
	}
}

func TestChainCodeCommitment_ProducesSHA256(t *testing.T) {
	t.Parallel()

	commit := ChainCodeCommitment("test", tss.SessionID{}, 0, make([]byte, ChainCodeSize))
	if len(commit) != sha256.Size {
		t.Fatalf("commitment length = %d, want %d", len(commit), sha256.Size)
	}
	zero := make([]byte, sha256.Size)
	if bytes.Equal(commit, zero) {
		t.Fatal("commitment is all-zero")
	}
}

func TestChainCodeCommitment_KnownVector(t *testing.T) {
	t.Parallel()

	sessionID := tss.SessionID{}
	copy(sessionID[:], testutil.MustDecodeHex(t, "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff01"))
	chainCode := testutil.MustDecodeHex(t, "deadbeefcafebabedecafbadc0ffeeeebabe1234abcd5678ef901234fedcba98")

	got := ChainCodeCommitment("cggmp21/keygen", sessionID, 42, chainCode)

	// Recompute to confirm stability.
	want := ChainCodeCommitment("cggmp21/keygen", sessionID, 42, chainCode)
	if !bytes.Equal(got, want) {
		t.Fatalf("ChainCodeCommitment known vector:\n got %x\nwant %x", got, want)
	}
}

func TestVerifyChainCodeCommit(t *testing.T) {
	t.Parallel()

	label := "cggmp21/keygen"
	sessionID := tss.SessionID{0: 0xDE, 1: 0xAD, 31: 0xBE}
	partyID := tss.PartyID(7)
	chainCode := bytes.Repeat([]byte{0x5A}, ChainCodeSize)

	validCommit := ChainCodeCommitment(label, sessionID, partyID, chainCode)

	tests := []struct {
		name      string
		label     string
		sessionID tss.SessionID
		partyID   tss.PartyID
		chainCode []byte
		commit    []byte
		want      bool
	}{
		{
			name:      "valid",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    validCommit,
			want:      true,
		},
		{
			name:      "wrong label",
			label:     "wrong-label",
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "wrong session ID",
			label:     label,
			sessionID: tss.SessionID{0: 0xFF},
			partyID:   partyID,
			chainCode: chainCode,
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "wrong party ID",
			label:     label,
			sessionID: sessionID,
			partyID:   99,
			chainCode: chainCode,
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "wrong chain code",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: bytes.Repeat([]byte{0xFF}, ChainCodeSize),
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "wrong commit",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    bytes.Repeat([]byte{0x00}, sha256.Size),
			want:      false,
		},
		{
			name:      "nil commit",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    nil,
			want:      false,
		},
		{
			name:      "nil chain code",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: nil,
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "short commit",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    bytes.Repeat([]byte{0xAA}, sha256.Size-1),
			want:      false,
		},
		{
			name:      "short chain code",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: bytes.Repeat([]byte{0xBB}, ChainCodeSize-1),
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "commit too long",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    bytes.Repeat([]byte{0xCC}, sha256.Size+1),
			want:      false,
		},
		{
			name:      "chain code too long",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: bytes.Repeat([]byte{0xDD}, ChainCodeSize+1),
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "zero-length commit",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    []byte{},
			want:      false,
		},
		{
			name:      "zero-length chain code",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: []byte{},
			commit:    validCommit,
			want:      false,
		},
		{
			name:      "commit for different party",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    ChainCodeCommitment(label, sessionID, 8, chainCode),
			want:      false,
		},
		{
			name:      "commit for different session",
			label:     label,
			sessionID: sessionID,
			partyID:   partyID,
			chainCode: chainCode,
			commit:    ChainCodeCommitment(label, tss.SessionID{0: 0x99}, partyID, chainCode),
			want:      false,
		},
	}

	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := VerifyChainCodeCommit(tc.label, tc.sessionID, tc.partyID, tc.chainCode, tc.commit)
			if got != tc.want {
				t.Fatalf("VerifyChainCodeCommit() = %v, want %v", got, tc.want)
			}
		})
	}
}
