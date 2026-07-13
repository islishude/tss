package secp256k1

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/tssrun"
)

func TestFast_PresignSlotIDIsCanonicalAndStrict(t *testing.T) {
	t.Parallel()

	id := bytes.Repeat([]byte{0xab}, 32)
	slot, err := PresignSlotID(id)
	if err != nil {
		t.Fatal(err)
	}
	want := presignLifecycleSlotPrefix + strings.Repeat("ab", 32)
	if slot != want {
		t.Fatalf("slot = %q, want %q", slot, want)
	}
	for _, invalid := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if _, err := PresignSlotID(invalid); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
			t.Fatalf("PresignSlotID(%d bytes) = %v, want ErrInvalidLifecycleRecord", len(invalid), err)
		}
	}
}

func TestFast_PersistPresignFromLeaseUsesCanonicalSlotAndIsIdempotent(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	store, binding, lease := newPresignPersistenceFixture(t, presign, 0x11)

	wantSlot, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := PersistPresignFromLeaseWithLimits(context.Background(), store, lease, presign, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if slot != wantSlot {
		t.Fatalf("slot = %q, want %q", slot, wantSlot)
	}
	candidate, err := store.PreparePresignCandidate(context.Background(), binding, slot)
	if err != nil {
		t.Fatal(err)
	}
	wantBlob, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wantBlob)
	wantMetadata, err := presign.LifecycleMetadataWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wantMetadata)
	if !bytes.Equal(candidate.Blob, wantBlob) || !bytes.Equal(candidate.Metadata, wantMetadata) {
		t.Fatal("persisted candidate differs from canonical presign artifact")
	}
	if IsPresignConsumed(presign) {
		t.Fatal("durable availability commit consumed the local presign handle")
	}

	retriedSlot, err := PersistPresignFromLeaseWithLimits(context.Background(), store, lease, presign, testLimits())
	if err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if retriedSlot != slot {
		t.Fatalf("retry slot = %q, want %q", retriedSlot, slot)
	}
}

func TestFast_PersistPresignFromLeaseRejectsSameArtifactInAnotherSlot(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	store, binding, lease := newPresignPersistenceFixture(t, presign, 0x22)
	blob, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	metadata, err := presign.LifecycleMetadataWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	if err := commitTestAvailablePresignFromLease(context.Background(), store, binding, "non-canonical-slot", blob, metadata, "non-canonical-slot"); err != nil {
		t.Fatal(err)
	}
	if _, err := PersistPresignFromLeaseWithLimits(context.Background(), store, lease, presign, testLimits()); !errors.Is(err, tssrun.ErrPresignUnavailable) {
		t.Fatalf("PersistPresignFromLease = %v, want ErrPresignUnavailable", err)
	}
}

func TestFast_PresignPersistenceRejectsBindingAndPublicMetadataMismatch(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	_, binding, lease := newPresignPersistenceFixture(t, presign, 0x33)
	slot, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := presign.LifecycleMetadataWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)

	wrongKey := binding
	wrongKey.KeyID = "wrong-key"
	if err := validatePresignPersistenceArtifact(presign, wrongKey, slot, metadata, testLimits()); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("wrong key binding = %v, want ErrInvalidLifecycleRecord", err)
	}
	wrongEpoch := binding
	wrongEpoch.EpochID[0] ^= 0xff
	if err := validatePresignPersistenceArtifact(presign, wrongEpoch, slot, metadata, testLimits()); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("wrong epoch binding = %v, want ErrInvalidLifecycleRecord", err)
	}
	if err := validatePresignPersistenceArtifact(presign, binding, "wrong-slot", metadata, testLimits()); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("wrong slot = %v, want ErrInvalidLifecycleRecord", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*signAttemptPublicContext)
	}{
		{name: "protocol presign id", mutate: func(c *signAttemptPublicContext) {
			c.ProtocolPresignID = bytes.Repeat([]byte{0x72}, 32)
			c.PresignSlot, _ = PresignSlotID(c.ProtocolPresignID)
		}},
		{name: "key id", mutate: func(c *signAttemptPublicContext) {
			c.KeyID = "different-valid-key"
		}},
		{name: "Gamma", mutate: func(c *signAttemptPublicContext) {
			c.Gamma = secp.ScalarBaseMult(secp.ScalarFromUint64(2))
			c.LittleR = secp.ScalarFromFieldElement(c.Gamma.X)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicContext, err := unmarshalSignAttemptPublicContext(metadata, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&publicContext)
			mutated, err := marshalSignAttemptPublicContext(publicContext, testLimits())
			publicContext.destroy()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(mutated)
			if err := validatePresignPersistenceArtifact(presign, binding, slot, mutated, testLimits()); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
				t.Fatalf("mutated metadata = %v, want ErrInvalidLifecycleRecord", err)
			}
		})
	}

	badLease := lease
	badLease.Kind = tssrun.RunSign
	if err := validatePresignPersistenceLease(badLease); !errors.Is(err, tssrun.ErrInvalidLifecycleRecord) {
		t.Fatalf("wrong lease kind = %v, want ErrInvalidLifecycleRecord", err)
	}
}

func TestFast_SignRecoveryAndBurnRejectNonCanonicalPresignSlot(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	store, binding, _ := newPresignPersistenceFixture(t, presign, 0x44)
	blob, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	metadata, err := presign.LifecycleMetadataWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	canonicalSlot, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitTestAvailablePresignFromLease(context.Background(), store, binding, canonicalSlot, blob, metadata, "canonical-burn-slot"); err != nil {
		t.Fatal(err)
	}

	record := tssrun.SignAttemptRecord{PresignID: "non-canonical-slot", PresignMetadata: bytes.Clone(metadata)}
	if err := validateLifecycleRecordPresignSlot(record, testLimits()); !errors.Is(err, ErrSignAttemptCorrupt) {
		t.Fatalf("recovery slot validation = %v, want ErrSignAttemptCorrupt", err)
	}
	if err := BurnPresign(context.Background(), store, binding, "non-canonical-slot", presign.state.PresignID, "operator discard"); !errors.Is(err, ErrSignAttemptCorrupt) {
		t.Fatalf("non-canonical burn = %v, want ErrSignAttemptCorrupt", err)
	}
	if _, err := store.PreparePresignCandidate(context.Background(), binding, canonicalSlot); err != nil {
		t.Fatalf("rejected burn mutated canonical presign: %v", err)
	}
	if err := BurnPresign(context.Background(), store, binding, canonicalSlot, presign.state.PresignID, "operator discard"); err != nil {
		t.Fatalf("canonical burn: %v", err)
	}
	if _, err := store.PreparePresignCandidate(context.Background(), binding, canonicalSlot); !errors.Is(err, tssrun.ErrPresignBurned) {
		t.Fatalf("burned candidate = %v, want ErrPresignBurned", err)
	}
}

func TestFast_PresignPublicMetadataCarriesCanonicalEpochAndSlot(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	defer presign.Destroy()
	metadata, ok := presign.PublicMetadata()
	if !ok {
		t.Fatal("missing presign public metadata")
	}
	wantSlot, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Epoch == nil || metadata.SID != metadata.Epoch.SID || metadata.RID != metadata.Epoch.RID ||
		!sameEpochPartyIdentifiers(metadata.Identifiers, metadata.Epoch.Identifiers) || metadata.LifecycleSlot != wantSlot {
		t.Fatal("presign public metadata omitted or mismatched canonical epoch fields")
	}
	publicKey, err := secp.PointBytes(presign.state.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	parties := make(tss.PartySet, len(metadata.Epoch.Identifiers))
	for i := range metadata.Epoch.Identifiers {
		parties[i] = metadata.Epoch.Identifiers[i].Party
	}
	key := &KeyShare{state: &keyShareState{
		Party: presign.state.Party, Threshold: presign.state.Threshold, Parties: parties,
		PublicKey: publicKey, ChainCode: bytes.Clone(presign.state.Derivation.ChildChainCode),
		KeygenTranscriptHash: bytes.Clone(presign.state.KeygenTranscriptHash),
		SecurityParams:       presign.state.SecurityParams, Epoch: presign.state.Epoch.Clone(),
	}}
	if err := validatePresignPublicMetadata(key, metadata, testLimits()); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*PresignPublicMetadata)
	}{
		{name: "sid", mutate: func(m *PresignPublicMetadata) { m.SID[0] ^= 0xff }},
		{name: "rid", mutate: func(m *PresignPublicMetadata) { m.RID[0] ^= 0xff }},
		{name: "identifier", mutate: func(m *PresignPublicMetadata) { m.Identifiers[0].Identifier[0] ^= 0xff }},
		{name: "source epoch", mutate: func(m *PresignPublicMetadata) { m.SourceEpochID = bytes.Repeat([]byte{0x91}, 32) }},
		{name: "slot", mutate: func(m *PresignPublicMetadata) { m.LifecycleSlot = "wrong-slot" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := metadata.Clone()
			tc.mutate(&mutated)
			if err := validatePresignPublicMetadata(key, mutated, testLimits()); err == nil {
				t.Fatal("mismatched explicit public metadata was accepted")
			}
		})
	}

	metadata.Identifiers[0].Identifier[0] ^= 0xff
	metadata.Epoch.EpochID[0] ^= 0xff
	if bytes.Equal(metadata.Identifiers[0].Identifier, presign.state.Epoch.Identifiers[0].Identifier) ||
		bytes.Equal(metadata.Epoch.EpochID, presign.state.Epoch.EpochID) {
		t.Fatal("presign public epoch metadata aliases artifact state")
	}
}

func newPresignPersistenceFixture(t testing.TB, presign *Presign, sessionByte byte) (*tssrun.MemoryLifecycleStore, tssrun.GenerationBinding, tssrun.RunLease) {
	t.Helper()
	epochID, err := tssrun.NewEpochID(presign.state.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	binding := tssrun.GenerationBinding{
		KeyID:         presign.state.Context.KeyID,
		KeyGeneration: tssrun.KeyGeneration("presign-persistence-generation"),
		EpochID:       epochID,
	}
	store := tssrun.NewMemoryLifecycleStore()
	if _, err := store.InstallInitialGeneration(context.Background(), binding, []byte("generation-secret"), nil); err != nil {
		t.Fatal(err)
	}
	var sessionID tss.SessionID
	sessionID[0] = sessionByte
	lease, err := store.AcquireRunLease(context.Background(), binding, tssrun.RunPresign, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return store, binding, lease
}
