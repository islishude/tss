package ed25519

import (
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

const signContextHashLabel = "frost-ed25519-sign-context-v1"

func prepareSignContext(key *KeyShare, ctx tss.SigningContext) (tss.SigningContext, []byte, *tss.DerivationResult, error) {
	if err := ctx.Validate(); err != nil {
		return tss.SigningContext{}, nil, nil, err
	}
	if ctx.Derivation.Scheme != tss.DerivationSchemeEd25519KhovratovichLaw {
		return tss.SigningContext{}, nil, nil, fmt.Errorf("signing context derivation scheme must be %q", tss.DerivationSchemeEd25519KhovratovichLaw)
	}
	if key == nil || key.state == nil {
		return tss.SigningContext{}, nil, nil, errors.New("nil key share")
	}
	derivation, err := key.Derive(ctx.Derivation.Path, tss.WithInvalidChildMode(ctx.Derivation.InvalidChildMode))
	if err != nil {
		return tss.SigningContext{}, nil, nil, err
	}
	if len(ctx.Derivation.ResolvedPath) > 0 && !slices.Equal(ctx.Derivation.ResolvedPath, derivation.ResolvedPath) {
		return tss.SigningContext{}, nil, nil, errors.New("signing context resolved path mismatch")
	}
	ctx = ctx.Clone()
	ctx.Derivation.Path = derivation.RequestedPath.Clone()
	ctx.Derivation.ResolvedPath = derivation.ResolvedPath.Clone()
	return ctx, signContextHash(ctx), derivation.Clone(), nil
}

func signContextHash(ctx tss.SigningContext) []byte {
	resolvedPath := ctx.Derivation.ResolvedPath
	if len(resolvedPath) == 0 {
		resolvedPath = ctx.Derivation.Path
	}
	t := transcript.New(signContextHashLabel)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendString("curve", "ed25519")
	t.AppendString("key_id", ctx.KeyID)
	t.AppendString("chain_id", ctx.ChainID)
	t.AppendString("derivation_scheme", string(ctx.Derivation.Scheme))
	t.AppendUint32List("requested_path", ctx.Derivation.Path)
	t.AppendUint32List("resolved_path", resolvedPath)
	t.AppendUint32("invalid_child_mode", uint32(ctx.Derivation.InvalidChildMode))
	t.AppendString("policy_domain", ctx.PolicyDomain)
	t.AppendString("message_domain", ctx.MessageDomain)
	return t.Sum()
}

func appendDerivationResultTranscript(t *transcript.Builder, result *tss.DerivationResult) {
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
