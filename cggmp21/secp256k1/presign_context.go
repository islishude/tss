package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/transcript"
)

func validatePresignContext(ctx PresignContext) error {
	if ctx.KeyID == "" {
		return errors.New("presign context key id is required")
	}
	if ctx.ChainID == "" {
		return errors.New("presign context chain id is required")
	}
	if ctx.PolicyDomain == "" {
		return errors.New("presign context policy domain is required")
	}
	if ctx.MessageDomain == "" {
		return errors.New("presign context message domain is required")
	}
	for _, index := range ctx.DerivationPath {
		if index >= bip32util.HardenedKeyStart {
			return fmt.Errorf("hardened derivation index %d is not supported", index)
		}
	}
	return nil
}

func preparePresignContext(key *KeyShare, ctx PresignContext) (PresignContext, []byte, []byte, error) {
	if err := validatePresignContext(ctx); err != nil {
		return PresignContext{}, nil, nil, err
	}
	ctx.DerivationPath = append([]uint32(nil), ctx.DerivationPath...)
	var additiveShift []byte
	if len(ctx.DerivationPath) > 0 {
		result, err := DeriveNonHardenedBIP32Extended(key.state.publicKey, key.state.chainCode, ctx.DerivationPath)
		if err != nil {
			return PresignContext{}, nil, nil, err
		}
		additiveShift = result.AdditiveShift
	}
	return ctx, presignContextHash(ctx), additiveShift, nil
}

func presignContextHash(ctx PresignContext) []byte {
	t := transcript.New(presignContextHashLabel)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendString("curve", "secp256k1")
	t.AppendString("key_id", ctx.KeyID)
	t.AppendString("chain_id", ctx.ChainID)
	t.AppendUint32List("derivation_path", ctx.DerivationPath)
	t.AppendString("policy_domain", ctx.PolicyDomain)
	t.AppendString("message_domain", ctx.MessageDomain)
	return t.Sum()
}

func signMessageDigest(contextHash []byte, messageDomain string, message []byte) []byte {
	t := transcript.New(signMessageDigestLabel)
	t.AppendString("protocol", string(protocol))
	t.AppendUint32("version", uint32(tss.Version))
	t.AppendString("curve", "secp256k1")
	t.AppendBytes("context_hash", contextHash)
	t.AppendString("message_domain", messageDomain)
	t.AppendBytes("message", message)
	return t.Sum()
}

func mtaResponseHash(label string, response mta.ResponseMessage) []byte {
	t := transcript.New(mtaResponseEvidenceLabel)
	t.AppendString("response_label", label)
	t.AppendBytes("ciphertext", response.Ciphertext)
	t.AppendBytes("proof", response.Proof)
	return t.Sum()
}
