package secp256k1

import (
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/transcript"
)

func validatePresignContext(ctx tss.SigningContext) error {
	if err := ctx.Validate(); err != nil {
		return err
	}
	if ctx.Derivation.Scheme != tss.DerivationSchemeBIP32Secp256k1 {
		return fmt.Errorf("presign context derivation scheme must be %q", tss.DerivationSchemeBIP32Secp256k1)
	}
	return nil
}

func preparePresignContext(key *KeyShare, ctx tss.SigningContext) (tss.SigningContext, []byte, *tss.DerivationResult, error) {
	if err := validatePresignContext(ctx); err != nil {
		return tss.SigningContext{}, nil, nil, err
	}
	if key == nil || key.state == nil {
		return tss.SigningContext{}, nil, nil, errors.New("nil key share")
	}
	derivation, err := key.Derive(
		ctx.Derivation.Path,
		tss.WithInvalidChildMode(ctx.Derivation.InvalidChildMode),
	)
	if err != nil {
		return tss.SigningContext{}, nil, nil, err
	}
	if len(ctx.Derivation.ResolvedPath) > 0 && !slices.Equal(ctx.Derivation.ResolvedPath, derivation.ResolvedPath) {
		return tss.SigningContext{}, nil, nil, errors.New("presign context resolved path mismatch")
	}
	ctx = ctx.Clone()
	ctx.Derivation.Path = derivation.RequestedPath.Clone()
	ctx.Derivation.ResolvedPath = derivation.ResolvedPath.Clone()
	return ctx, presignContextHash(ctx), derivation.Clone(), nil
}

func presignContextHash(ctx tss.SigningContext) []byte {
	resolvedPath := ctx.Derivation.ResolvedPath
	if len(resolvedPath) == 0 {
		resolvedPath = ctx.Derivation.Path
	}
	t := transcript.New(presignContextHashLabel)
	t.AppendString("protocol", string(tss.ProtocolCGGMP21Secp256k1))
	t.AppendUint32("version", uint32(tss.ProtocolVersion))
	t.AppendString("curve", "secp256k1")
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

func validateDerivationResult(result *tss.DerivationResult, scheme tss.DerivationScheme) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid derivation result: %w", err)
	}
	if result.Scheme != scheme {
		return fmt.Errorf("derivation scheme must be %q", scheme)
	}
	if len(result.AdditiveShift) != secp.ScalarSize {
		return errors.New("additive shift must be 32 bytes")
	}
	if _, err := secp.PointFromBytes(result.ChildPublicKey); err != nil {
		return fmt.Errorf("invalid child public key: %w", err)
	}
	return nil
}

func validateSecp256k1DerivationBinding(parent *secp.Point, result *tss.DerivationResult) error {
	if parent == nil || result == nil {
		return errors.New("nil secp256k1 derivation binding")
	}
	shift, err := secp.ScalarFromBytesAllowZero(result.AdditiveShift)
	if err != nil {
		return fmt.Errorf("invalid additive shift: %w", err)
	}
	child, err := secp.PointFromBytes(result.ChildPublicKey)
	if err != nil {
		return fmt.Errorf("invalid child public key: %w", err)
	}
	expected := secp.Clone(parent)
	if !shift.IsZero() {
		expected = secp.Add(expected, secp.ScalarBaseMult(shift))
	}
	if !secp.Equal(expected, child) {
		return errors.New("child public key does not match parent key and additive shift")
	}
	return nil
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

func signMessageDigest(contextHash []byte, messageDomain string, message []byte) []byte {
	t := transcript.New(signMessageDigestLabel)
	t.AppendString("protocol", string(tss.ProtocolCGGMP21Secp256k1))
	t.AppendUint32("version", uint32(tss.ProtocolVersion))
	t.AppendString("curve", "secp256k1")
	t.AppendBytes("context_hash", contextHash)
	t.AppendString("message_domain", messageDomain)
	t.AppendBytes("message", message)
	return t.Sum()
}

func mtaResponseHash(label string, response mta.ResponseMessage) []byte {
	t := transcript.New(mtaResponseEvidenceLabel)
	proofBytes, _ := response.Proof.MarshalBinary()
	t.AppendString("response_label", label)
	t.AppendBytes("ciphertext", response.Ciphertext)
	t.AppendBytes("proof", proofBytes)
	return t.Sum()
}
