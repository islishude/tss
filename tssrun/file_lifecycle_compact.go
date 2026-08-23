package tssrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sort"
)

var _ LifecycleCompactor = (*FileLifecycleStore)(nil)

// CompactLifecycle replaces old terminal records with fixed public tombstones
// and makes their superseded encrypted snapshots eligible for orphan recovery.
func (s *FileLifecycleStore) CompactLifecycle(ctx context.Context, request LifecycleCompactionRequest) (LifecycleCompactionReport, error) {
	if ctx == nil {
		return LifecycleCompactionReport{}, errors.New("nil lifecycle compaction context")
	}
	if err := ctx.Err(); err != nil {
		return LifecycleCompactionReport{}, err
	}
	if validateLifecycleIdentifier(request.KeyID) != nil || request.ExpectedCurrent.Validate() != nil || request.ExpectedCurrent.KeyID != request.KeyID {
		return LifecycleCompactionReport{}, ErrInvalidLifecycleRecord
	}
	report, err := mutateFileLifecycleState(ctx, s, []string{request.KeyID}, func(memory *MemoryLifecycleStore) (LifecycleCompactionReport, error) {
		if !memory.isCurrentLocked(request.ExpectedCurrent) {
			return LifecycleCompactionReport{}, ErrGenerationNotCurrent
		}
		report := compactMemoryLifecycleState(memory, request.KeyID, int(request.RetainRecentTerminal))
		if err := validateMemoryLifecycleStateForKey(memory, fileLifecycleGlobalKeyID); err != nil {
			return LifecycleCompactionReport{}, err
		}
		return report, nil
	})
	if err != nil {
		return LifecycleCompactionReport{}, err
	}
	// Compaction is the explicit ordinary-operation exception that also
	// reclaims immutable ciphertexts no longer referenced by the committed root.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return report, ErrFileLifecycleStoreClosed
	}
	if err := recoverFileLifecycleSnapshotArtifacts(s); err != nil {
		return report, err
	}
	return report, nil
}

type compactAttemptCandidate struct {
	id    string
	order uint64
}

func compactMemoryLifecycleState(memory *MemoryLifecycleStore, keyID string, retain int) LifecycleCompactionReport {
	var report LifecycleCompactionReport
	generationOrders := make(map[GenerationBinding]uint64)
	for token, effect := range memory.leaseEffects {
		if effect != nil && effect.Target.KeyID == keyID && token > generationOrders[effect.Target] {
			generationOrders[effect.Target] = token
		}
	}
	var attempts []compactAttemptCandidate
	for id, attempt := range memory.attempts {
		if attempt.record.Binding.KeyID == keyID && attempt.record.Terminal() {
			attempts = append(attempts, compactAttemptCandidate{id: id, order: leaseOrderForSession(memory, attempt.record.Intent.SessionID)})
		}
	}
	sort.Slice(attempts, func(i, j int) bool { return attempts[i].order > attempts[j].order })
	for i, candidate := range attempts {
		if i < retain {
			continue
		}
		attempt := memory.attempts[candidate.id]
		if attempt == nil {
			continue
		}
		presign := memory.presigns[attempt.record.PresignID]
		if presign == nil || presign.state == storedPresignAvailable {
			continue
		}
		addAttemptTombstones(memory, keyID, attempt.record, presign)
		clearSignAttemptRecord(&attempt.record)
		delete(memory.attempts, candidate.id)
		clear(presign.blob)
		clear(presign.metadata)
		clear(presign.artifactDigest)
		delete(memory.presigns, attempt.record.PresignID)
		report.Attempts++
		report.Presigns++
	}

	compactUnlinkedBurnedPresigns(memory, keyID, retain, &report)
	compactTerminalLeases(memory, keyID, retain, &report)
	compactTerminalCutovers(memory, keyID, retain, &report)
	compactRetiredGenerations(memory, keyID, retain, generationOrders, &report)
	return report
}

func compactUnlinkedBurnedPresigns(memory *MemoryLifecycleStore, keyID string, retain int, report *LifecycleCompactionReport) {
	var candidates []compactAttemptCandidate
	for id, presign := range memory.presigns {
		if presign.binding.KeyID == keyID && presign.state == storedPresignBurned && presign.attemptID == "" {
			candidates = append(candidates, compactAttemptCandidate{id: id, order: leaseOrderForPresign(memory, id)})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].order != candidates[j].order {
			return candidates[i].order > candidates[j].order
		}
		return candidates[i].id > candidates[j].id
	})
	for i, candidate := range candidates {
		if i < retain {
			continue
		}
		presign := memory.presigns[candidate.id]
		addPresignTombstones(memory, keyID, candidate.id, presign)
		clear(presign.artifactDigest)
		delete(memory.presigns, candidate.id)
		report.Presigns++
	}
}

func compactTerminalLeases(memory *MemoryLifecycleStore, keyID string, retain int, report *LifecycleCompactionReport) {
	var tokens []uint64
	for token, lease := range memory.leasesByToken {
		if lease.lease.Binding.KeyID != keyID || lease.lease.State == RunLeaseActive {
			continue
		}
		if leaseReferencedByAttempt(memory, lease.lease.SessionID) {
			continue
		}
		if effect := memory.leaseEffects[token]; effect != nil && effect.Kind == storedLeaseEffectPresign {
			if _, stillPresent := memory.presigns[effect.PresignID]; stillPresent {
				continue
			}
		}
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i] > tokens[j] })
	for i, token := range tokens {
		if i < retain {
			continue
		}
		lease := memory.leasesByToken[token]
		addLeaseTombstone(memory, keyID, lease.lease, memory.leaseEffects[token])
		delete(memory.leaseBySession, lease.lease.SessionID)
		delete(memory.reshareReceivers, token)
		if effect := memory.leaseEffects[token]; effect != nil {
			clear(effect.Digest)
			delete(memory.leaseEffects, token)
		}
		delete(memory.leasesByToken, token)
		report.Leases++
	}
}

func compactTerminalCutovers(memory *MemoryLifecycleStore, keyID string, retain int, report *LifecycleCompactionReport) {
	var tokens []uint64
	for token, cutover := range memory.cutoversByToken {
		if cutover.fence.Source.KeyID == keyID && cutover.state != storedCutoverActive && !cutoverReferencedByLeaseEffect(memory, token) {
			tokens = append(tokens, token)
		}
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i] > tokens[j] })
	for i, token := range tokens {
		if i < retain {
			continue
		}
		cutover := memory.cutoversByToken[token]
		addLifecycleTombstone(memory, "cutover", cutoverTombstoneIdentifier(token), keyID, "terminal", cutover.targetBlobDigest)
		clear(cutover.targetBlobDigest)
		clear(cutover.targetMetadataDigest)
		delete(memory.cutoversByToken, token)
		report.Cutovers++
	}
}

func compactRetiredGenerations(memory *MemoryLifecycleStore, keyID string, retain int, orders map[GenerationBinding]uint64, report *LifecycleCompactionReport) {
	var bindings []GenerationBinding
	for binding, generation := range memory.generations {
		if binding.KeyID == keyID && generation.record.Status == GenerationRetired && !generationReferencedByLeaseEffect(memory, binding) {
			bindings = append(bindings, binding)
		}
	}
	sort.Slice(bindings, func(i, j int) bool {
		if orders[bindings[i]] != orders[bindings[j]] {
			return orders[bindings[i]] > orders[bindings[j]]
		}
		return bindings[i].KeyGeneration > bindings[j].KeyGeneration
	})
	for i, binding := range bindings {
		if i < retain {
			continue
		}
		record := memory.generations[binding].record
		addLifecycleTombstone(memory, "generation", generationTombstoneIdentifier(binding), keyID, "retired", record.Metadata)
		addLifecycleTombstone(memory, "generation-name", []byte(binding.KeyID+"\x00"+string(binding.KeyGeneration)), keyID, "retired", record.Metadata)
		clear(record.Blob)
		clear(record.Metadata)
		delete(memory.generations, binding)
		report.Generations++
	}
}

func addAttemptTombstones(memory *MemoryLifecycleStore, keyID string, record SignAttemptRecord, presign *storedPresign) {
	addLifecycleTombstone(memory, "attempt", []byte(record.Intent.AttemptID), keyID, "terminal", bytes.Join([][]byte{record.Intent.IntentDigest, record.OutboxDigest}, nil))
	addPresignTombstones(memory, keyID, record.PresignID, presign)
}

func addPresignTombstones(memory *MemoryLifecycleStore, keyID, id string, presign *storedPresign) {
	if presign == nil {
		return
	}
	addLifecycleTombstone(memory, "presign", []byte(id), keyID, "terminal", presign.artifactDigest)
	addLifecycleTombstone(memory, "presign-artifact", presign.artifactDigest, keyID, "terminal", []byte(id))
}

func addLeaseTombstone(memory *MemoryLifecycleStore, keyID string, lease RunLease, effect *storedLeaseEffect) {
	var digest []byte
	if effect != nil {
		digest = effect.Digest
	}
	addLifecycleTombstone(memory, "session", lease.SessionID[:], keyID, "terminal", digest)
}

func addLifecycleTombstone(memory *MemoryLifecycleStore, namespace string, identifier []byte, keyID, state string, digestInput []byte) {
	identifierHash := lifecycleTombstoneHash(namespace, identifier)
	digest := sha256.Sum256(digestInput)
	tombstone := storedLifecycleTombstone{
		Namespace: namespace, IdentifierHash: identifierHash, KeyID: keyID,
		Digest: bytes.Clone(digest[:]), State: state,
	}
	memory.tombstones[lifecycleTombstoneMapKey(namespace, identifierHash)] = tombstone
}

func leaseOrderForSession(memory *MemoryLifecycleStore, sessionID [32]byte) uint64 {
	if token, ok := memory.leaseBySession[sessionID]; ok {
		return token
	}
	return 0
}

func leaseOrderForPresign(memory *MemoryLifecycleStore, presignID string) uint64 {
	var order uint64
	for token, effect := range memory.leaseEffects {
		if effect != nil && effect.Kind == storedLeaseEffectPresign && effect.PresignID == presignID && token > order {
			order = token
		}
	}
	return order
}

func leaseReferencedByAttempt(memory *MemoryLifecycleStore, sessionID [32]byte) bool {
	for _, attempt := range memory.attempts {
		if attempt != nil && attempt.record.Intent.SessionID == sessionID {
			return true
		}
	}
	return false
}

func cutoverReferencedByLeaseEffect(memory *MemoryLifecycleStore, token uint64) bool {
	for _, effect := range memory.leaseEffects {
		if effect.CutoverToken == token {
			return true
		}
	}
	return false
}

func generationReferencedByLeaseEffect(memory *MemoryLifecycleStore, binding GenerationBinding) bool {
	for _, effect := range memory.leaseEffects {
		if effect.Target == binding {
			return true
		}
		lease := memory.leasesByToken[effect.LeaseToken]
		if lease != nil && lease.lease.Binding == binding {
			return true
		}
	}
	return false
}
