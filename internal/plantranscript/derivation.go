// Package plantranscript centralizes transcript fragments shared by protocol
// plans without sharing protocol-specific transcript domains or field order.
package plantranscript

import (
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

// AppendDerivationResult appends the canonical public derivation result fields.
// Callers remain responsible for selecting the surrounding transcript domain
// and for placing this fragment at the protocol-defined position.
func AppendDerivationResult(t *transcript.Builder, result *tss.DerivationResult) {
	if result == nil {
		t.AppendString("derivation_scheme", "")
		return
	}
	t.AppendString("derivation_scheme", string(result.Scheme))
	t.AppendUint32List("requested_path", result.RequestedPath)
	t.AppendUint32List("resolved_path", result.ResolvedPath)
	t.AppendBytes("child_public_key", result.ChildPublicKey)
	t.AppendBytes("child_chain_code", result.ChildChainCode)
	t.AppendUint32("derivation_depth", uint32(result.Depth))
	t.AppendBytes("parent_fingerprint", result.ParentFingerprint[:])
	t.AppendUint32("child_number", result.ChildNumber)
	t.AppendBytes("additive_shift", result.AdditiveShift)
}
