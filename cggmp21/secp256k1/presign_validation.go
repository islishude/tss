package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
)

func validatePresignPublicMetadata(key *KeyShare, metadata PresignPublicMetadata, limits Limits) error {
	if key == nil || key.state == nil {
		return errors.New("nil key share")
	}
	if metadata.Party != key.state.Party {
		return errors.New("presign party mismatch")
	}
	if metadata.Threshold != key.state.Threshold {
		return errors.New("presign threshold mismatch")
	}
	if !validSecurityParams(metadata.SecurityParams) {
		return errors.New("invalid presign security parameters")
	}
	if validSecurityParams(key.state.SecurityParams) && metadata.SecurityParams != key.state.SecurityParams {
		return errors.New("presign security params mismatch")
	}
	if err := validateSignerSet(key, metadata.Signers, limits); err != nil {
		return fmt.Errorf("invalid presign signer set: %w", err)
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{name: "presign id", value: metadata.PresignID},
		{name: "epoch id", value: metadata.EpochID},
		{name: "presign transcript hash", value: metadata.TranscriptHash},
		{name: "context hash", value: metadata.ContextHash},
		{name: "presign plan hash", value: metadata.PlanHash},
		{name: "keygen transcript hash", value: metadata.KeygenTranscriptHash},
		{name: "parties hash", value: metadata.PartiesHash},
	} {
		if err := validateRequiredPlanID(field.name, field.value); err != nil {
			return err
		}
	}
	if key.state.Epoch == nil || !bytes.Equal(metadata.EpochID, key.state.Epoch.EpochID) {
		return errors.New("presign epoch binding mismatch")
	}
	if metadata.Epoch == nil {
		return errors.New("missing presign epoch context")
	}
	if err := metadata.Epoch.ValidateWithLimits(limits); err != nil {
		return fmt.Errorf("invalid presign epoch context: %w", err)
	}
	if !bytes.Equal(metadata.EpochID, metadata.Epoch.EpochID) || !bytes.Equal(metadata.Epoch.EpochID, key.state.Epoch.EpochID) {
		return errors.New("presign epoch context mismatch")
	}
	sourceEpochID, _ := metadata.Epoch.SourceEpochIDBytes()
	if metadata.SID != metadata.Epoch.SID || metadata.RID != metadata.Epoch.RID ||
		!sameEpochPartyIdentifiers(metadata.Identifiers, metadata.Epoch.Identifiers) ||
		!bytes.Equal(metadata.SourceEpochID, sourceEpochID) {
		return errors.New("presign explicit epoch metadata does not match full epoch context")
	}
	wantSlot, err := PresignSlotID(metadata.PresignID)
	if err != nil {
		return err
	}
	if metadata.LifecycleSlot != wantSlot {
		return errors.New("presign lifecycle slot mismatch")
	}
	if _, err := secp.PointFromBytes(metadata.Gamma); err != nil {
		return fmt.Errorf("invalid presign gamma: %w", err)
	}
	if !bytes.Equal(metadata.R, metadata.Gamma) {
		return errors.New("presign R and gamma mismatch")
	}
	if _, err := secp.ScalarFromBytes(metadata.LittleR); err != nil {
		return fmt.Errorf("invalid presign little-r: %w", err)
	}
	if _, err := secp.PointFromBytes(metadata.VerificationKey); err != nil {
		return fmt.Errorf("invalid presign verification key: %w", err)
	}
	if _, err := secp.PointFromBytes(metadata.PublicKey); err != nil {
		return fmt.Errorf("invalid presign public key: %w", err)
	}
	if !bytes.Equal(metadata.PublicKey, key.state.PublicKey) {
		return errors.New("presign public key binding mismatch")
	}
	if !bytes.Equal(metadata.KeygenTranscriptHash, key.state.KeygenTranscriptHash) {
		return errors.New("presign keygen transcript binding mismatch")
	}
	if !bytes.Equal(metadata.PartiesHash, tss.PartySetHash(key.state.Parties, partySetHashLabel)) {
		return errors.New("presign participant set binding mismatch")
	}
	if err := validatePresignContext(metadata.Context); err != nil {
		return fmt.Errorf("invalid presign context: %w", err)
	}
	if !bytes.Equal(metadata.ContextHash, presignContextHash(metadata.Context)) {
		return errors.New("presign context hash mismatch")
	}
	if metadata.Derivation == nil {
		return errors.New("missing presign generation derivation binding")
	}
	if err := validateDerivationResult(metadata.Derivation); err != nil {
		return err
	}
	shift, err := secp.ScalarFromBytesAllowZero(metadata.Derivation.AdditiveShift)
	if err != nil || !shift.IsZero() || len(metadata.Derivation.RequestedPath) != 0 || len(metadata.Derivation.ResolvedPath) != 0 {
		return errors.New("presign derivation must bind the current generation with an empty path and zero shift")
	}
	if !bytes.Equal(metadata.Derivation.ChildPublicKey, metadata.VerificationKey) ||
		!bytes.Equal(metadata.Derivation.ChildPublicKey, key.state.PublicKey) ||
		!bytes.Equal(metadata.Derivation.ChildChainCode, key.state.ChainCode) {
		return errors.New("presign derivation generation binding mismatch")
	}
	epochPublicKey, _, err := epochContextGroupPublicKey(metadata.Epoch)
	if err != nil {
		return fmt.Errorf("invalid presign epoch group key: %w", err)
	}
	wantPublicKey, err := secp.PointFromBytes(metadata.PublicKey)
	if err != nil || !secp.Equal(epochPublicKey, wantPublicKey) {
		return errors.New("presign epoch public shares do not reconstruct the group key")
	}
	return nil
}

func validatePresign(key *KeyShare, presign *Presign, limits Limits) error {
	if err := presign.ValidateWithLimits(limits); err != nil {
		return err
	}
	if presign.state.Party != key.state.Party {
		return errors.New("presign party mismatch")
	}
	if presign.state.Threshold != key.state.Threshold {
		return errors.New("presign threshold mismatch")
	}
	if validSecurityParams(key.state.SecurityParams) && presign.state.SecurityParams != key.state.SecurityParams {
		return errors.New("presign security params mismatch")
	}
	presignPublicKey, err := secp.PointBytes(presign.state.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(presignPublicKey, key.state.PublicKey) {
		return errors.New("presign public key binding mismatch")
	}
	if !bytes.Equal(presign.state.KeygenTranscriptHash, key.state.KeygenTranscriptHash) {
		return errors.New("presign keygen transcript binding mismatch")
	}
	if !bytes.Equal(presign.state.PartiesHash, tss.PartySetHash(key.state.Parties, partySetHashLabel)) {
		return errors.New("presign participant set binding mismatch")
	}
	contextHash := presignContextHash(presign.state.Context)
	if !bytes.Equal(contextHash, presign.state.ContextHash) {
		return errors.New("presign context hash mismatch")
	}
	if len(presign.state.EpochID) != sha256.Size || key.state.Epoch == nil || !bytes.Equal(presign.state.EpochID, key.state.Epoch.EpochID) {
		return errors.New("presign epoch binding mismatch")
	}
	if presign.state.Epoch == nil || !bytes.Equal(presign.state.Epoch.EpochID, key.state.Epoch.EpochID) {
		return errors.New("presign epoch context binding mismatch")
	}
	if presign.state.Derivation == nil ||
		!bytes.Equal(presign.state.Derivation.ChildPublicKey, key.state.PublicKey) ||
		!bytes.Equal(presign.state.Derivation.ChildChainCode, key.state.ChainCode) {
		return errors.New("presign generation derivation binding mismatch")
	}
	if len(presign.state.Signers) < key.state.Threshold || !tss.ContainsParty(presign.state.Signers, key.state.Party) {
		return errors.New("invalid presign signer set")
	}
	return nil
}

func sameEpochPartyIdentifiers(a, b []EpochPartyIdentifier) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Party != b[i].Party || !bytes.Equal(a[i].Identifier, b[i].Identifier) {
			return false
		}
	}
	return true
}

func validatePresignGenerationBinding(state *presignState, limits Limits) error {
	if state == nil {
		return errors.New("nil presign state")
	}
	if state.Derivation == nil {
		return errors.New("missing presign generation derivation binding")
	}
	if err := validateDerivationResult(state.Derivation); err != nil {
		return err
	}
	shift, err := secp.ScalarFromBytesAllowZero(state.Derivation.AdditiveShift)
	if err != nil || !shift.IsZero() || len(state.Derivation.RequestedPath) != 0 || len(state.Derivation.ResolvedPath) != 0 {
		return errors.New("presign derivation must use an empty path and zero shift")
	}
	publicKey, err := secp.PointBytes(state.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid presign public key: %w", err)
	}
	if !bytes.Equal(state.Derivation.ChildPublicKey, publicKey) {
		return errors.New("presign derivation public key binding mismatch")
	}
	if state.Epoch == nil {
		return errors.New("missing presign epoch context")
	}
	if err := state.Epoch.ValidateWithLimits(limits); err != nil {
		return fmt.Errorf("invalid presign epoch context: %w", err)
	}
	if !bytes.Equal(state.EpochID, state.Epoch.EpochID) || state.Epoch.Threshold != state.Threshold {
		return errors.New("presign epoch identity or threshold mismatch")
	}
	parties := make(tss.PartySet, len(state.Epoch.Identifiers))
	for i := range state.Epoch.Identifiers {
		parties[i] = state.Epoch.Identifiers[i].Party
	}
	for _, signer := range state.Signers {
		if !parties.Contains(signer) {
			return fmt.Errorf("presign signer %d is outside epoch", signer)
		}
	}
	if !parties.Contains(state.Party) {
		return errors.New("presign party is outside epoch")
	}
	if !bytes.Equal(state.PartiesHash, tss.PartySetHash(parties, partySetHashLabel)) {
		return errors.New("presign participant hash does not match epoch")
	}
	epochPublicKey, _, err := epochContextGroupPublicKey(state.Epoch)
	if err != nil {
		return fmt.Errorf("invalid presign epoch public shares: %w", err)
	}
	if !secp.Equal(epochPublicKey, state.PublicKey) {
		return errors.New("presign epoch public shares do not reconstruct the group key")
	}
	return nil
}

func epochContextGroupPublicKey(epoch *EpochContext) (*secp.Point, tss.PartySet, error) {
	if epoch == nil {
		return nil, nil, errors.New("missing epoch context")
	}
	parties := make(tss.PartySet, len(epoch.Identifiers))
	for i := range epoch.Identifiers {
		parties[i] = epoch.Identifiers[i].Party
	}
	terms := make([]*secp.Point, 0, len(parties))
	for i, party := range parties {
		if i >= len(epoch.PublicShares) || epoch.PublicShares[i].Party != party {
			return nil, nil, errors.New("epoch public shares are not in identifier order")
		}
		point, err := secp.PointFromBytes(epoch.PublicShares[i].PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("decode epoch public share %d: %w", party, err)
		}
		coefficient, err := epochLagrangeCoefficient(epoch, party, parties)
		if err != nil {
			return nil, nil, err
		}
		terms = append(terms, secp.ScalarMult(point, coefficient))
	}
	return secp.AddPoints(terms...), parties, nil
}

func validateSignerSet(key *KeyShare, signers tss.PartySet, limits Limits) error {
	return tss.ValidateSignerSet(key.state.Parties, key.state.Threshold, signers, limits.ThresholdLimits())
}

func normalizedCommitmentFor(presign *Presign, party tss.PartyID) (normalizedPresignCommitment, bool) {
	if presign == nil || presign.state == nil {
		return normalizedPresignCommitment{}, false
	}
	for i := range presign.state.Commitments {
		if presign.state.Commitments[i].Party == party {
			return presign.state.Commitments[i].clone(), true
		}
	}
	return normalizedPresignCommitment{}, false
}
