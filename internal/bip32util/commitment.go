package bip32util

import (
	"bytes"
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

// ChainCodeCommitment produces a hash commitment for a party's HD chain code.
func ChainCodeCommitment(label string, sessionID tss.SessionID, partyID tss.PartyID, chainCode []byte) []byte {
	t := transcript.New(label)
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint32("party_id", partyID)
	t.AppendBytes("chain_code", chainCode)
	return t.Sum()
}

// VerifyChainCodeCommit checks that a revealed chain code matches its round 1 commit.
func VerifyChainCodeCommit(label string, sessionID tss.SessionID, partyID tss.PartyID, chainCode, commit []byte) bool {
	if len(commit) != sha256.Size || len(chainCode) != ChainCodeSize {
		return false
	}
	expected := ChainCodeCommitment(label, sessionID, partyID, chainCode)
	return bytes.Equal(expected, commit)
}
