package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/islishude/tss/tssrun"
)

// GenerationBindingForKeyShare derives the canonical durable binding for a
// fully confirmed CGGMP21 key share.
func GenerationBindingForKeyShare(key *KeyShare, keyID string, generation tssrun.KeyGeneration) (tssrun.GenerationBinding, error) {
	return generationBindingForKeyShareWithLimits(key, keyID, generation, DefaultLimits())
}

func generationBindingForKeyShareWithLimits(key *KeyShare, keyID string, generation tssrun.KeyGeneration, limits Limits) (tssrun.GenerationBinding, error) {
	if key == nil {
		return tssrun.GenerationBinding{}, errors.New("nil CGGMP21 key share")
	}
	if err := key.ValidateWithLimits(limits); err != nil {
		return tssrun.GenerationBinding{}, fmt.Errorf("validate CGGMP21 key share for lifecycle install: %w", err)
	}
	metadata, ok := key.PublicMetadata()
	if !ok || metadata.Epoch == nil {
		return tssrun.GenerationBinding{}, errors.New("CGGMP21 key share has no authorization epoch")
	}
	epochID, err := tssrun.NewEpochID(metadata.EpochID)
	if err != nil {
		return tssrun.GenerationBinding{}, err
	}
	binding := tssrun.GenerationBinding{KeyID: keyID, KeyGeneration: generation, EpochID: epochID}
	if err := binding.Validate(); err != nil {
		return tssrun.GenerationBinding{}, err
	}
	return binding, nil
}

// InstallKeyShare canonically validates and installs the first durable CGGMP21 generation.
func InstallKeyShare(ctx context.Context, store tssrun.LifecycleStore, keyID string, generation tssrun.KeyGeneration, key *KeyShare) (tssrun.GenerationRecord, error) {
	return InstallKeyShareWithLimits(ctx, store, keyID, generation, key, DefaultLimits())
}

// InstallKeyShareWithLimits is [InstallKeyShare] with explicit local validation limits.
func InstallKeyShareWithLimits(ctx context.Context, store tssrun.LifecycleStore, keyID string, generation tssrun.KeyGeneration, key *KeyShare, limits Limits) (tssrun.GenerationRecord, error) {
	if ctx == nil || store == nil {
		return tssrun.GenerationRecord{}, tssrun.ErrInvalidLifecycleRecord
	}
	if err := ctx.Err(); err != nil {
		return tssrun.GenerationRecord{}, err
	}
	binding, err := generationBindingForKeyShareWithLimits(key, keyID, generation, limits)
	if err != nil {
		return tssrun.GenerationRecord{}, err
	}
	blob, err := key.MarshalBinaryWithLimits(limits)
	if err != nil {
		return tssrun.GenerationRecord{}, err
	}
	defer clear(blob)
	metadata, ok := key.PublicMetadata()
	if !ok {
		return tssrun.GenerationRecord{}, errors.New("CGGMP21 key share has no public metadata")
	}
	publicMetadata := bytes.Clone(metadata.PlanHash)
	defer clear(publicMetadata)
	return store.InstallInitialGeneration(ctx, binding, blob, publicMetadata)
}
