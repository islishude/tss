package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
)

func compareKeygenConfirmationBindingFields(local, confirmation *KeygenConfirmation) error {
	if confirmation.SessionID != local.SessionID {
		return fmt.Errorf("keygen confirmation session mismatch from party %d", confirmation.Sender)
	}
	if confirmation.Threshold != local.Threshold {
		return fmt.Errorf("keygen confirmation threshold mismatch from party %d: got %d, want %d", confirmation.Sender, confirmation.Threshold, local.Threshold)
	}
	if !slices.Equal(confirmation.Parties, local.Parties) {
		return fmt.Errorf("keygen confirmation party set mismatch from party %d", confirmation.Sender)
	}
	if !confirmation.PublicKey.Equal(local.PublicKey) {
		return fmt.Errorf("keygen confirmation public key mismatch from party %d", confirmation.Sender)
	}
	if !bytes.Equal(confirmation.TranscriptHash, local.TranscriptHash) {
		return fmt.Errorf("keygen confirmation transcript mismatch from party %d", confirmation.Sender)
	}
	if !bytes.Equal(confirmation.CommitmentsHash, local.CommitmentsHash) {
		return fmt.Errorf("keygen confirmation commitments mismatch from party %d", confirmation.Sender)
	}
	if !bytes.Equal(confirmation.PlanHash, local.PlanHash) {
		return fmt.Errorf("keygen confirmation from party %d: %w", confirmation.Sender, errPlanHashMismatch)
	}
	return nil
}

func verifyKeygenConfirmationSetBinding(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	reference, err := local.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}
	return verifyKeygenConfirmationBindingList(local.state.Parties, reference, confirmations)
}

func verifyKeygenConfirmationSetAggregateChainCode(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := verifyKeygenConfirmationSetBinding(local, confirmations); err != nil {
		return err
	}
	chainCodes := make(map[tss.PartyID][]byte, len(confirmations))
	for _, confirmation := range confirmations {
		chainCodes[confirmation.Sender] = slices.Clone(confirmation.ChainCode)
	}
	aggregate, err := bip32util.AggregateChainCode(local.state.Parties, chainCodes)
	if err != nil {
		return fmt.Errorf("keygen confirmation chain code set: %w", err)
	}
	if !bytes.Equal(aggregate, local.state.ChainCode) {
		return errors.New("keygen confirmation aggregate chain code mismatch")
	}
	return nil
}

func verifyKeygenConfirmationBindingList(parties tss.PartySet, reference *KeygenConfirmation, confirmations []*KeygenConfirmation) error {
	if len(confirmations) != len(parties) {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(confirmations), len(parties))
	}
	seen := make(map[tss.PartyID]struct{}, len(parties))
	for i, confirmation := range confirmations {
		expected := parties[i]
		if confirmation == nil {
			return fmt.Errorf("nil keygen confirmation at index %d for party %d", i, expected)
		}
		if confirmation.Sender != expected {
			return fmt.Errorf("keygen confirmation order mismatch at index %d: got party %d, want %d", i, confirmation.Sender, expected)
		}
		if _, ok := seen[confirmation.Sender]; ok {
			return fmt.Errorf("duplicate keygen confirmation from party %d", confirmation.Sender)
		}
		seen[confirmation.Sender] = struct{}{}
		if err := compareKeygenConfirmationBindingFields(reference, confirmation); err != nil {
			return err
		}
	}
	return nil
}

func verifyKeygenConfirmationForPending(pending *frostPendingKeyShare, confirmation *KeygenConfirmation) error {
	if pending == nil {
		return errors.New("nil pending key share")
	}
	if confirmation == nil {
		return errors.New("nil keygen confirmation")
	}
	reference, err := pending.confirmationReference(pending.party, pending.localChainCode)
	if err != nil {
		return err
	}
	return compareKeygenConfirmationBindingFields(reference, confirmation)
}

func verifyKeygenConfirmationSetForPending(pending *frostPendingKeyShare, confirmations []*KeygenConfirmation) error {
	if pending == nil {
		return errors.New("nil pending key share")
	}
	reference, err := pending.confirmationReference(pending.party, pending.localChainCode)
	if err != nil {
		return err
	}
	return verifyKeygenConfirmationBindingList(pending.parties, reference, confirmations)
}

func verifyFROSTKeygenCommitRevealChainCode(sessionID tss.SessionID, sender tss.PartyID, revealed, commitment []byte) error {
	if !bip32util.VerifyChainCodeCommit(frostChainCodeCommitLabel, sessionID, sender, revealed, commitment) {
		return fmt.Errorf("keygen confirmation chain code does not match round 1 commit from party %d", sender)
	}
	return nil
}

func validateKeygenConfirmationSetForShare(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := local.validateWithoutConfirmations(); err != nil {
		return fmt.Errorf("invalid local key share: %w", err)
	}
	return verifyKeygenConfirmationSetBinding(local, confirmations)
}

func attachKeygenConfirmations(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil || local.state == nil {
		return errors.New("nil local key share")
	}
	for _, confirmation := range confirmations {
		data, ok := local.state.PartyData[confirmation.Sender]
		if !ok {
			return fmt.Errorf("keygen confirmation from unknown party %d", confirmation.Sender)
		}
		data.KeygenConfirmation = confirmation.Clone()
		local.state.PartyData[confirmation.Sender] = data
	}
	return nil
}

func applyKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if err := validateKeygenConfirmationSetForShare(local, confirmations); err != nil {
		return err
	}
	return attachKeygenConfirmations(local, confirmations)
}
