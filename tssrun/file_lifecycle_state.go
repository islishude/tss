package tssrun

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

type fileLifecycleLeaseEffect struct {
	LeaseToken   uint64                `json:"lease_token"`
	Kind         storedLeaseEffectKind `json:"kind"`
	PresignID    string                `json:"presign_id,omitempty"`
	Target       GenerationBinding     `json:"target"`
	Digest       []byte                `json:"digest,omitempty"`
	Reason       string                `json:"reason,omitempty"`
	CutoverToken uint64                `json:"cutover_token,omitempty"`
}

func validateMemoryLifecycleStateForKey(memory *MemoryLifecycleStore, keyID string) error {
	if memory == nil || keyID != fileLifecycleGlobalKeyID {
		return ErrLifecycleCorrupt
	}
	if err := validateMemoryLifecycleGenerations(memory); err != nil {
		return err
	}
	if err := validateMemoryLifecycleLeases(memory); err != nil {
		return err
	}
	if err := validateMemoryLifecycleLeaseEffects(memory); err != nil {
		return err
	}
	if err := validateMemoryLifecycleRefreshDisabled(memory); err != nil {
		return err
	}
	if err := validateMemoryLifecyclePresigns(memory); err != nil {
		return err
	}
	if err := validateMemoryLifecycleAttempts(memory); err != nil {
		return err
	}
	if err := validateMemoryLifecycleCutovers(memory); err != nil {
		return err
	}
	return validateMemoryLifecycleTombstones(memory)
}

func validateMemoryLifecycleTombstones(memory *MemoryLifecycleStore) error {
	for key, tombstone := range memory.tombstones {
		if !validLifecycleTombstoneNamespace(tombstone.Namespace) || len(tombstone.IdentifierHash) != sha256.Size*2 ||
			validateLifecycleIdentifier(tombstone.KeyID) != nil || len(tombstone.Digest) != sha256.Size || tombstone.State == "" ||
			key != lifecycleTombstoneMapKey(tombstone.Namespace, tombstone.IdentifierHash) {
			return fmt.Errorf("%w: invalid lifecycle tombstone", ErrLifecycleCorrupt)
		}
	}
	return nil
}

func validateMemoryLifecycleGenerations(memory *MemoryLifecycleStore) error {
	currentCounts := make(map[string]int, len(memory.current))
	for indexedKeyID, binding := range memory.current {
		if indexedKeyID != binding.KeyID || binding.Validate() != nil {
			return fmt.Errorf("%w: invalid current generation index", ErrLifecycleCorrupt)
		}
	}
	for binding, generation := range memory.generations {
		if binding.Validate() != nil || generation == nil || generation.record.Binding != binding {
			return fmt.Errorf("%w: invalid generation record", ErrLifecycleCorrupt)
		}
		if generation.record.Status != GenerationCurrent && generation.record.Status != GenerationRetired {
			return fmt.Errorf("%w: invalid generation status", ErrLifecycleCorrupt)
		}
		if generation.record.Status == GenerationCurrent {
			currentCounts[binding.KeyID]++
			if current, ok := memory.current[binding.KeyID]; !ok || current != binding || len(generation.record.Blob) == 0 {
				return fmt.Errorf("%w: current generation mismatch", ErrLifecycleCorrupt)
			}
		} else if len(generation.record.Blob) != 0 || len(generation.record.Metadata) != 0 {
			return fmt.Errorf("%w: retired generation retained secret blob", ErrLifecycleCorrupt)
		}
	}
	for indexedKeyID := range memory.current {
		if currentCounts[indexedKeyID] != 1 {
			return fmt.Errorf("%w: invalid current generation count", ErrLifecycleCorrupt)
		}
	}
	return nil
}

func validateMemoryLifecycleLeases(memory *MemoryLifecycleStore) error {
	if len(memory.leasesByToken) != len(memory.leaseBySession) {
		return fmt.Errorf("%w: lease index mismatch", ErrLifecycleCorrupt)
	}
	activeLeaseCounts := make(map[string]int)
	hasActiveExclusiveLease := make(map[string]bool)
	validatedReceiverAnchors := 0
	for token, stored := range memory.leasesByToken {
		if err := validateStoredLease(memory, token, stored); err != nil {
			return err
		}
		receiverAnchor, receiverJoin := memory.reshareReceivers[token]
		if stored.lease.State != RunLeaseActive {
			if receiverJoin {
				return fmt.Errorf("%w: terminal lease retained reshare receiver anchor", ErrLifecycleCorrupt)
			}
			continue
		}
		leaseKeyID := stored.lease.Binding.KeyID
		activeLeaseCounts[leaseKeyID]++
		if receiverJoin {
			validatedReceiverAnchors++
			if err := validateReceiverLease(memory, stored.lease, receiverAnchor); err != nil {
				return err
			}
		} else if stored.lease.Kind == RunKeygen {
			if _, hasCurrent := memory.current[leaseKeyID]; hasCurrent || memory.hasGenerationForKeyLocked(leaseKeyID) {
				return fmt.Errorf("%w: active keygen lease has generation state", ErrLifecycleCorrupt)
			}
		} else if !memory.isCurrentLocked(stored.lease.Binding) {
			return fmt.Errorf("%w: active lease is not bound to current generation", ErrLifecycleCorrupt)
		}
		if exclusiveLeaseRunKind(stored.lease.Kind) {
			hasActiveExclusiveLease[leaseKeyID] = true
		}
	}
	if validatedReceiverAnchors != len(memory.reshareReceivers) {
		return fmt.Errorf("%w: reshare receiver anchor missing active lease", ErrLifecycleCorrupt)
	}
	for leaseKeyID := range hasActiveExclusiveLease {
		if activeLeaseCounts[leaseKeyID] != 1 {
			return fmt.Errorf("%w: active exclusive lease overlaps another lease", ErrLifecycleCorrupt)
		}
	}
	return nil
}

func validateMemoryLifecycleLeaseEffects(memory *MemoryLifecycleStore) error {
	for token, effect := range memory.leaseEffects {
		lease := memory.leasesByToken[token]
		if effect == nil || effect.LeaseToken != token || lease == nil || lease.lease.State == RunLeaseActive {
			return fmt.Errorf("%w: invalid lease effect", ErrLifecycleCorrupt)
		}
		switch effect.Kind {
		case storedLeaseEffectPresign:
			if lease.lease.Kind != RunPresign || lease.lease.State != RunLeaseCompleted ||
				validateLifecycleIdentifier(effect.PresignID) != nil || len(effect.Digest) != sha256.Size || memory.presigns[effect.PresignID] == nil {
				return fmt.Errorf("%w: invalid presign lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectCutover:
			cutover := memory.cutoversByToken[effect.CutoverToken]
			if !cutoverLeaseRunKind(lease.lease.Kind) || lease.lease.State != RunLeaseCompleted ||
				effect.Target.KeyID != lease.lease.Binding.KeyID || cutover == nil || cutover.fence.Source != lease.lease.Binding || cutover.fence.Target != effect.Target {
				return fmt.Errorf("%w: invalid cutover lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectRefreshFailed:
			disabled, ok := memory.refreshDisabled[lease.lease.Binding.KeyID]
			if lease.lease.Kind != RunRefresh || lease.lease.State != RunLeaseAborted ||
				!ok || disabled.SessionID != lease.lease.SessionID || disabled.Reason != effect.Reason {
				return fmt.Errorf("%w: invalid refresh-failed lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectChildGeneration:
			child := memory.generations[effect.Target]
			if lease.lease.Kind != RunChildDerivation || lease.lease.State != RunLeaseCompleted ||
				effect.Target.KeyID == lease.lease.Binding.KeyID || effect.Target.EpochID == lease.lease.Binding.EpochID ||
				effect.Target.Validate() != nil || len(effect.Digest) != sha256.Size || child == nil {
				return fmt.Errorf("%w: invalid child-generation lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectReshareReceiverGeneration:
			target := memory.generations[effect.Target]
			if lease.lease.Kind != RunReshare || lease.lease.State != RunLeaseCompleted ||
				effect.Target.KeyID != lease.lease.Binding.KeyID ||
				effect.Target.KeyGeneration == lease.lease.Binding.KeyGeneration ||
				effect.Target.EpochID == lease.lease.Binding.EpochID ||
				effect.Target.Validate() != nil || len(effect.Digest) != sha256.Size || target == nil {
				return fmt.Errorf("%w: invalid reshare receiver generation lease effect", ErrLifecycleCorrupt)
			}
		case storedLeaseEffectRetirement:
			source := memory.generations[lease.lease.Binding]
			if lease.lease.Kind != RunReshare || lease.lease.State != RunLeaseCompleted ||
				validateCutoverBindings(lease.lease.Binding, effect.Target) != nil ||
				source == nil || source.record.Status != GenerationRetired ||
				len(source.record.Blob) != 0 || len(source.record.Metadata) != 0 {
				return fmt.Errorf("%w: invalid retirement lease effect", ErrLifecycleCorrupt)
			}
		default:
			return fmt.Errorf("%w: unknown lease effect", ErrLifecycleCorrupt)
		}
	}
	return nil
}

func validateMemoryLifecycleRefreshDisabled(memory *MemoryLifecycleStore) error {
	for disabledKeyID, disabled := range memory.refreshDisabled {
		if disabled.KeyID != disabledKeyID || !disabled.SessionID.Valid() || validateLifecycleReason(disabled.Reason) != nil {
			return fmt.Errorf("%w: invalid refresh-disabled record", ErrLifecycleCorrupt)
		}
		token, ok := memory.leaseBySession[disabled.SessionID]
		if !ok && memory.tombstonedLocked("session", disabled.SessionID[:]) {
			continue
		}
		if !ok || memory.leaseEffects[token] == nil || memory.leaseEffects[token].Kind != storedLeaseEffectRefreshFailed {
			return fmt.Errorf("%w: refresh-disabled record missing lease effect", ErrLifecycleCorrupt)
		}
	}
	return nil
}

func validLifecycleTombstoneNamespace(namespace string) bool {
	switch namespace {
	case "generation", "generation-name", "session", "presign", "presign-artifact", "attempt", "cutover":
		return true
	default:
		return false
	}
}

func validateMemoryLifecyclePresigns(memory *MemoryLifecycleStore) error {
	artifactOwners := make(map[string]string, len(memory.presigns))
	for presignID, presign := range memory.presigns {
		if presign == nil || validateLifecycleIdentifier(presignID) != nil || presign.binding.Validate() != nil || len(presign.artifactDigest) != sha256.Size {
			return fmt.Errorf("%w: invalid presign record", ErrLifecycleCorrupt)
		}
		artifactKey := string(presign.artifactDigest)
		if owner, duplicate := artifactOwners[artifactKey]; duplicate && owner != presignID {
			return fmt.Errorf("%w: duplicate presign public artifact", ErrLifecycleCorrupt)
		}
		artifactOwners[artifactKey] = presignID
		if err := validateStoredPresign(memory, presignID, presign); err != nil {
			return err
		}
	}
	return nil
}

func validateMemoryLifecycleAttempts(memory *MemoryLifecycleStore) error {
	for attemptID, attempt := range memory.attempts {
		if attempt == nil || attempt.record.Intent.AttemptID != attemptID {
			return fmt.Errorf("%w: invalid attempt index", ErrLifecycleCorrupt)
		}
		record := attempt.record
		if record.Binding.Validate() != nil || record.Intent.Validate() != nil || validateLifecycleIdentifier(record.PresignID) != nil || len(record.OutboxDigest) != sha256.Size {
			return fmt.Errorf("%w: invalid attempt record", ErrLifecycleCorrupt)
		}
		leaseToken, ok := memory.leaseBySession[record.Intent.SessionID]
		lease := memory.leasesByToken[leaseToken]
		if !ok || lease == nil || lease.lease.Binding != record.Binding || lease.lease.Kind != RunSign {
			return fmt.Errorf("%w: attempt sign lease mismatch", ErrLifecycleCorrupt)
		}
		if !record.Terminal() && !memory.isCurrentLocked(record.Binding) {
			return fmt.Errorf("%w: nonterminal attempt is not current", ErrLifecycleCorrupt)
		}
		presign := memory.presigns[record.PresignID]
		if presign == nil || presign.binding != record.Binding || presign.attemptID != attemptID {
			return fmt.Errorf("%w: attempt presign index mismatch", ErrLifecycleCorrupt)
		}
		if record.Aborted {
			if presign.state != storedPresignBurned || validateLifecycleReason(record.AbortReason) != nil {
				return fmt.Errorf("%w: invalid aborted attempt", ErrLifecycleCorrupt)
			}
		} else if record.AbortReason != "" ||
			(presign.state != storedPresignClaimed && (!record.Terminal() || presign.state != storedPresignBurned)) {
			return fmt.Errorf("%w: invalid claimed attempt", ErrLifecycleCorrupt)
		}
		if err := validateStoredAttemptProgress(record); err != nil {
			return err
		}
	}
	return nil
}

func validateMemoryLifecycleCutovers(memory *MemoryLifecycleStore) error {
	activeCutovers := 0
	for token, cutover := range memory.cutoversByToken {
		if cutover == nil || cutover.fence.Token != token || token > memory.nextCutoverToken || validateCutoverFence(cutover.fence) != nil {
			return fmt.Errorf("%w: invalid cutover record", ErrLifecycleCorrupt)
		}
		cutoverKeyID := cutover.fence.Source.KeyID
		switch cutover.state {
		case storedCutoverActive:
			activeCutovers++
			_, targetExists := memory.generations[cutover.fence.Target]
			if memory.cutoverByKey[cutoverKeyID] != token || !memory.isCurrentLocked(cutover.fence.Source) || targetExists ||
				memory.hasActiveLeaseForKeyLocked(cutoverKeyID) || memory.hasNonTerminalAttemptLocked(cutover.fence.Source) ||
				len(cutover.targetBlobDigest) != 0 || len(cutover.targetMetadataDigest) != 0 || cutover.reason != "" {
				return fmt.Errorf("%w: invalid active cutover", ErrLifecycleCorrupt)
			}
		case storedCutoverCommitted:
			if err := validateCommittedCutover(memory, cutover); err != nil {
				return err
			}
		case storedCutoverAborted:
			if len(cutover.targetBlobDigest) != 0 || len(cutover.targetMetadataDigest) != 0 || validateLifecycleReason(cutover.reason) != nil {
				return fmt.Errorf("%w: invalid aborted cutover", ErrLifecycleCorrupt)
			}
		default:
			return fmt.Errorf("%w: invalid cutover state", ErrLifecycleCorrupt)
		}
	}
	if activeCutovers != len(memory.cutoverByKey) {
		return fmt.Errorf("%w: active cutover index mismatch", ErrLifecycleCorrupt)
	}
	return nil
}

func clearMemoryLifecycleState(memory *MemoryLifecycleStore) {
	if memory == nil {
		return
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	for _, generation := range memory.generations {
		if generation != nil {
			clear(generation.record.Blob)
			clear(generation.record.Metadata)
			generation.record.Blob = nil
			generation.record.Metadata = nil
		}
	}
	for _, presign := range memory.presigns {
		if presign != nil {
			clear(presign.blob)
			clear(presign.metadata)
			clear(presign.artifactDigest)
			presign.blob = nil
			presign.metadata = nil
			presign.artifactDigest = nil
		}
	}
	for _, attempt := range memory.attempts {
		if attempt != nil {
			clearSignAttemptRecord(&attempt.record)
		}
	}
	for _, effect := range memory.leaseEffects {
		if effect != nil {
			clear(effect.Digest)
			effect.Digest = nil
		}
	}
	for token, anchor := range memory.reshareReceivers {
		clear(anchor.PlanDigest)
		clear(anchor.SourceEpochDigest)
		anchor.PlanDigest = nil
		anchor.SourceEpochDigest = nil
		memory.reshareReceivers[token] = anchor
	}
	for _, cutover := range memory.cutoversByToken {
		if cutover != nil {
			clear(cutover.targetBlobDigest)
			clear(cutover.targetMetadataDigest)
			cutover.targetBlobDigest = nil
			cutover.targetMetadataDigest = nil
		}
	}
	for key, tombstone := range memory.tombstones {
		clear(tombstone.Digest)
		tombstone.Digest = nil
		memory.tombstones[key] = tombstone
	}
}

func clearSignAttemptRecord(record *SignAttemptRecord) {
	if record == nil {
		return
	}
	clear(record.Intent.IntentDigest)
	clear(record.PresignMetadata)
	clear(record.ExactOutbox)
	clear(record.OutboxDigest)
	clear(record.Delivery)
	clear(record.Completion)
	record.Intent.IntentDigest = nil
	record.PresignMetadata = nil
	record.ExactOutbox = nil
	record.OutboxDigest = nil
	record.Delivery = nil
	record.Completion = nil
}

func writeLifecycleFile(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func syncLifecycleDirectory(path string) error {
	// #nosec G304 G703 -- callers provide only constructor-validated store-owned
	// directories.
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func validateReceiverLease(memory *MemoryLifecycleStore, lease RunLease, receiverAnchor ReshareReceiverAnchor) error {
	leaseKeyID := lease.Binding.KeyID
	if receiverAnchor.Validate() != nil || lease.Kind != RunReshare ||
		receiverAnchor.Source != lease.Binding || receiverAnchor.SessionID != lease.SessionID {
		return fmt.Errorf("%w: invalid reshare receiver anchor", ErrLifecycleCorrupt)
	}
	if _, hasCurrent := memory.current[leaseKeyID]; hasCurrent ||
		memory.hasKeyGenerationLocked(leaseKeyID, receiverAnchor.TargetKeyGeneration) ||
		memory.hasNonTerminalAttemptForKeyLocked(leaseKeyID) {
		return fmt.Errorf("%w: reshare receiver anchor conflicts with local state", ErrLifecycleCorrupt)
	}
	if _, fenced := memory.cutoverByKey[leaseKeyID]; fenced {
		return fmt.Errorf("%w: reshare receiver anchor overlaps cutover", ErrLifecycleCorrupt)
	}
	return nil
}

func validateStoredPresign(memory *MemoryLifecycleStore, presignID string, presign *storedPresign) error {
	switch presign.state {
	case storedPresignAvailable:
		if !memory.isCurrentLocked(presign.binding) || len(presign.blob) == 0 || presign.attemptID != "" || presign.reason != "" {
			return fmt.Errorf("%w: invalid available presign", ErrLifecycleCorrupt)
		}
		metadataDigest := sha256.Sum256(presign.metadata)
		if !bytes.Equal(presign.artifactDigest, metadataDigest[:]) {
			return fmt.Errorf("%w: presign public artifact digest mismatch", ErrLifecycleCorrupt)
		}
	case storedPresignClaimed:
		attempt := memory.attempts[presign.attemptID]
		if !memory.isCurrentLocked(presign.binding) || len(presign.blob) != 0 || len(presign.metadata) != 0 || presign.attemptID == "" || presign.reason != "" ||
			attempt == nil || attempt.record.Binding != presign.binding || attempt.record.PresignID != presignID || attempt.record.Aborted {
			return fmt.Errorf("%w: invalid claimed presign", ErrLifecycleCorrupt)
		}
	case storedPresignBurned:
		if len(presign.blob) != 0 || len(presign.metadata) != 0 || validateLifecycleReason(presign.reason) != nil {
			return fmt.Errorf("%w: invalid burned presign", ErrLifecycleCorrupt)
		}
		if presign.attemptID != "" {
			attempt := memory.attempts[presign.attemptID]
			if attempt == nil || attempt.record.Binding != presign.binding || attempt.record.PresignID != presignID || (!attempt.record.Aborted && !attempt.record.Terminal()) {
				return fmt.Errorf("%w: invalid attempted burned presign", ErrLifecycleCorrupt)
			}
		}
	default:
		return fmt.Errorf("%w: invalid presign state", ErrLifecycleCorrupt)
	}
	return nil
}

func validateStoredAttemptProgress(record SignAttemptRecord) error {
	if record.Delivered != (len(record.Delivery) != 0) || record.Completed != (len(record.Completion) != 0) {
		return fmt.Errorf("%w: attempt progress mismatch", ErrLifecycleCorrupt)
	}
	if !record.Terminal() && !record.Aborted && len(record.ExactOutbox) == 0 {
		return fmt.Errorf("%w: pending attempt missing exact outbox", ErrLifecycleCorrupt)
	}
	if (record.Terminal() || record.Aborted) && len(record.ExactOutbox) != 0 {
		return fmt.Errorf("%w: terminal outbox retained", ErrLifecycleCorrupt)
	}
	if len(record.ExactOutbox) != 0 {
		digest := sha256.Sum256(record.ExactOutbox)
		if !bytes.Equal(record.OutboxDigest, digest[:]) {
			return fmt.Errorf("%w: exact outbox digest mismatch", ErrLifecycleCorrupt)
		}
	}
	if len(record.PresignMetadata) == 0 {
		return fmt.Errorf("%w: attempt missing public presign metadata", ErrLifecycleCorrupt)
	}
	return nil
}

func validateCommittedCutover(memory *MemoryLifecycleStore, cutover *storedCutover) error {
	if len(cutover.targetBlobDigest) != sha256.Size || len(cutover.targetMetadataDigest) != sha256.Size || cutover.reason != "" {
		return fmt.Errorf("%w: invalid committed cutover", ErrLifecycleCorrupt)
	}
	source := memory.generations[cutover.fence.Source]
	target := memory.generations[cutover.fence.Target]
	if source == nil || source.record.Status != GenerationRetired || target == nil {
		return fmt.Errorf("%w: committed cutover generation mismatch", ErrLifecycleCorrupt)
	}
	if target.record.Status == GenerationCurrent {
		blobDigest := sha256.Sum256(target.record.Blob)
		metadataDigest := sha256.Sum256(target.record.Metadata)
		if !bytes.Equal(cutover.targetBlobDigest, blobDigest[:]) || !bytes.Equal(cutover.targetMetadataDigest, metadataDigest[:]) {
			return fmt.Errorf("%w: committed cutover target digest mismatch", ErrLifecycleCorrupt)
		}
	}
	return nil
}

func validateStoredLease(memory *MemoryLifecycleStore, token uint64, stored *storedRunLease) error {
	if stored == nil || stored.lease.Token != token || validateRunLease(stored.lease) != nil || token > memory.nextLeaseToken {
		return fmt.Errorf("%w: invalid run lease", ErrLifecycleCorrupt)
	}
	if memory.leaseBySession[stored.lease.SessionID] != token {
		return fmt.Errorf("%w: lease session index mismatch", ErrLifecycleCorrupt)
	}
	if stored.lease.State != RunLeaseActive && stored.lease.State != RunLeaseCompleted && stored.lease.State != RunLeaseAborted {
		return fmt.Errorf("%w: invalid run lease state", ErrLifecycleCorrupt)
	}
	return nil
}
