package ed25519

import (
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

// RFC 9591 Section 5.4.1 defines the Ed25519 ciphersuite context string.
const rfc9591ContextString = "FROST-ED25519-SHA512-v1"

const (
	frostKeygenTranscriptLabel  = "frost-ed25519-keygen-transcript-v1"
	frostReshareTranscriptLabel = "frost-ed25519-reshare-transcript-v1"
)

func frostKeygenTranscriptHash(sessionID tss.SessionID, threshold int, parties []tss.PartyID, chainCode, planHash []byte, dealerCommitments map[tss.PartyID][][]byte, groupCommitments [][]byte, verificationShares []VerificationShare) []byte {
	t := transcript.New(frostKeygenTranscriptLabel)
	t.AppendString("ciphersuite_context", rfc9591ContextString)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint32("threshold", uint32(threshold))
	sortedParties := tss.SortParties(parties)
	t.AppendUint32List("parties", transcript.Uint32s(sortedParties))
	t.AppendBytes("chain_code", chainCode)
	t.AppendBytes("plan_hash", planHash)
	for _, id := range sortedParties {
		t.AppendUint32("dealer", uint32(id))
		t.AppendBytesList("dealer_commitments", dealerCommitments[id])
	}
	t.AppendBytesList("group_commitments", groupCommitments)
	appendVerificationShares(t, verificationShares)
	return t.Sum()
}

func frostReshareTranscriptHash(sessionID tss.SessionID, oldParties, newParties []tss.PartyID, newThreshold int, oldPublicKey, chainCode, planHash []byte, refreshMode bool, dealerCommitments map[tss.PartyID][][]byte, newCommitments [][]byte, verificationShares []VerificationShare) []byte {
	t := transcript.New(frostReshareTranscriptLabel)
	t.AppendString("ciphersuite_context", rfc9591ContextString)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendBytes("session_id", sessionID[:])
	sortedOldParties := tss.SortParties(oldParties)
	sortedNewParties := tss.SortParties(newParties)
	t.AppendUint32List("old_parties", transcript.Uint32s(sortedOldParties))
	t.AppendUint32List("new_parties", transcript.Uint32s(sortedNewParties))
	t.AppendUint32("new_threshold", uint32(newThreshold))
	t.AppendBytes("old_public_key", oldPublicKey)
	t.AppendBytes("chain_code", chainCode)
	t.AppendBytes("plan_hash", planHash)
	t.AppendBool("refresh_mode", refreshMode)
	for _, dealer := range sortedOldParties {
		t.AppendUint32("dealer", uint32(dealer))
		t.AppendBytesList("dealer_commitments", dealerCommitments[dealer])
	}
	t.AppendBytesList("new_commitments", newCommitments)
	appendVerificationShares(t, verificationShares)
	return t.Sum()
}

func appendVerificationShares(t *transcript.Builder, verificationShares []VerificationShare) {
	sorted := slices.Clone(verificationShares)
	slices.SortFunc(sorted, func(a, b VerificationShare) int {
		return int(a.Party) - int(b.Party)
	})
	for _, share := range sorted {
		t.AppendUint32("verification_share_party", uint32(share.Party))
		t.AppendBytes("verification_share_public_key", share.PublicKey)
	}
}
