package secp256k1

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/wire"
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
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignContextHashLabel))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, []byte("secp256k1"))
	wire.WriteHashPart(h, []byte(ctx.KeyID))
	wire.WriteHashPart(h, []byte(ctx.ChainID))
	wire.WriteHashPart(h, wire.EncodeUint32List(ctx.DerivationPath))
	wire.WriteHashPart(h, []byte(ctx.PolicyDomain))
	wire.WriteHashPart(h, []byte(ctx.MessageDomain))
	return h.Sum(nil)
}

func signMessageDigest(contextHash []byte, messageDomain string, message []byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(signMessageDigestLabel))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, []byte("secp256k1"))
	wire.WriteHashPart(h, contextHash)
	wire.WriteHashPart(h, []byte(messageDomain))
	wire.WriteHashPart(h, message)
	return h.Sum(nil)
}

func mtaResponseHash(label string, response mta.ResponseMessage) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(mtaResponseEvidenceLabel))
	wire.WriteHashPart(h, []byte(label))
	wire.WriteHashPart(h, response.Ciphertext)
	wire.WriteHashPart(h, response.Proof)
	return h.Sum(nil)
}
