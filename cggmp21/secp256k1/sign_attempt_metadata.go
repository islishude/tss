package secp256k1

import (
	"context"
	"errors"
)

// LoadSignAttemptMetadata loads and validates non-secret metadata for the
// durable attempt bound to presign. Use it during recovery to construct the
// session-scoped EnvelopeGuard before calling ResumeSign.
func LoadSignAttemptMetadata(ctx context.Context, presign *Presign, store SignAttemptStore) (SignAttemptMetadata, error) {
	return LoadSignAttemptMetadataWithLimits(ctx, presign, store, DefaultLimits())
}

// LoadSignAttemptMetadataWithLimits is LoadSignAttemptMetadata with explicit
// local validation and decoding limits.
func LoadSignAttemptMetadataWithLimits(ctx context.Context, presign *Presign, store SignAttemptStore, limits Limits) (SignAttemptMetadata, error) {
	if ctx == nil {
		return SignAttemptMetadata{}, errors.New("nil context")
	}
	if presign == nil || presign.state == nil {
		return SignAttemptMetadata{}, errors.New("nil presign")
	}
	if store == nil {
		return SignAttemptMetadata{}, errors.New("nil sign attempt store")
	}
	handle, err := newPresignHandle(presign, limits)
	if err != nil {
		return SignAttemptMetadata{}, err
	}
	coordinator, err := newSignAttemptCoordinator(store, handle, DefaultSignAttemptStoreTimeout, limits)
	if err != nil {
		return SignAttemptMetadata{}, err
	}
	record, err := coordinator.load(ctx)
	if err != nil {
		return SignAttemptMetadata{}, err
	}
	return record.Metadata(), nil
}
