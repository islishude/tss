package ed25519

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/tssrun"
)

// GenerationBindingForKeyShare derives the canonical durable binding for a
// fully confirmed FROST key share.
func GenerationBindingForKeyShare(key *KeyShare, keyID string, generation tssrun.KeyGeneration) (tssrun.GenerationBinding, error) {
	return generationBindingForKeyShareWithLimits(key, keyID, generation, DefaultLimits())
}

func generationBindingForKeyShareWithLimits(key *KeyShare, keyID string, generation tssrun.KeyGeneration, limits Limits) (tssrun.GenerationBinding, error) {
	if key == nil {
		return tssrun.GenerationBinding{}, errors.New("nil FROST key share")
	}
	if err := key.ValidateWithLimits(limits); err != nil {
		return tssrun.GenerationBinding{}, fmt.Errorf("validate FROST key share for lifecycle install: %w", err)
	}
	metadata, ok := key.PublicMetadata()
	if !ok {
		return tssrun.GenerationBinding{}, errors.New("FROST key share has no public metadata")
	}
	publicKey := metadata.PublicKey.Bytes()
	defer clear(publicKey)
	t := transcript.New("frost-ed25519-generation-epoch")
	t.AppendString("protocol", string(tss.ProtocolFROSTEd25519))
	t.AppendUint32("protocol_version", uint32(tss.ProtocolVersion))
	t.AppendBytes("keygen_session_id", metadata.KeygenSessionID[:])
	t.AppendUint32("threshold", uint32(metadata.Threshold))
	t.AppendUint32List("parties", metadata.Parties)
	t.AppendBytes("public_key", publicKey)
	t.AppendBytes("chain_code", metadata.ChainCode)
	t.AppendBytesList("group_commitments", metadata.GroupCommitments)
	t.AppendBytes("keygen_transcript_hash", metadata.KeygenTranscriptHash)
	t.AppendBytes("plan_hash", metadata.PlanHash)
	epochID, err := tssrun.NewEpochID(t.Sum())
	if err != nil {
		return tssrun.GenerationBinding{}, err
	}
	binding := tssrun.GenerationBinding{KeyID: keyID, KeyGeneration: generation, EpochID: epochID}
	if err := binding.Validate(); err != nil {
		return tssrun.GenerationBinding{}, err
	}
	return binding, nil
}

// InstallKeyShare canonically validates and installs the first durable FROST generation.
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
		return tssrun.GenerationRecord{}, errors.New("FROST key share has no public metadata")
	}
	publicMetadata := bytes.Clone(metadata.PlanHash)
	defer clear(publicMetadata)
	return store.InstallInitialGeneration(ctx, binding, blob, publicMetadata)
}
