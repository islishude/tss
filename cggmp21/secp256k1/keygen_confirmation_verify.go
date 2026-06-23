package secp256k1

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
	if !bytes.Equal(confirmation.PublicKey, local.PublicKey) {
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
	n := len(local.state.Parties)
	if len(confirmations) != n {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(confirmations), n)
	}
	localConfirmation, err := local.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}
	seen := make(map[tss.PartyID]struct{}, n)
	for i, confirmation := range confirmations {
		expectedSender := local.state.Parties[i]
		if confirmation == nil {
			return fmt.Errorf("nil keygen confirmation at index %d for party %d", i, expectedSender)
		}
		if confirmation.Sender != expectedSender {
			return fmt.Errorf("keygen confirmation order mismatch at index %d: got party %d, want %d", i, confirmation.Sender, expectedSender)
		}
		if _, ok := seen[confirmation.Sender]; ok {
			return fmt.Errorf("duplicate keygen confirmation from party %d", confirmation.Sender)
		}
		seen[confirmation.Sender] = struct{}{}
		if err := compareKeygenConfirmationBindingFields(localConfirmation, confirmation); err != nil {
			return err
		}
	}
	return nil
}

func verifyConfirmationBinding(local *KeyShare, confirmation *KeygenConfirmation) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if confirmation == nil {
		return errors.New("nil keygen confirmation")
	}
	localConfirmation, err := local.keygenConfirmationReferenceUnchecked()
	if err != nil {
		return fmt.Errorf("local confirmation: %w", err)
	}
	return compareKeygenConfirmationBindingFields(localConfirmation, confirmation)
}

func verifyKeygenConfirmationSetPreservedChainCodeStruct(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if err := verifyKeygenConfirmationSetBinding(local, confirmations); err != nil {
		return err
	}
	for _, confirmation := range confirmations {
		if err := verifyConfirmationPreservedChainCode(local.state.ChainCode, confirmation); err != nil {
			return err
		}
	}
	return nil
}

func verifyKeygenConfirmationForPreservedChainCode(local *KeyShare, confirmation *KeygenConfirmation) error {
	if err := verifyConfirmationBinding(local, confirmation); err != nil {
		return err
	}
	return verifyConfirmationPreservedChainCode(local.state.ChainCode, confirmation)
}

func verifyConfirmationCommitRevealChainCode(
	sessionID tss.SessionID,
	sender tss.PartyID,
	revealed []byte,
	commitment []byte,
) error {
	if !bip32util.VerifyChainCodeCommit(cggmpChainCodeCommitLabel, sessionID, sender, revealed, commitment) {
		return fmt.Errorf("keygen confirmation chain code does not match round 1 commit from party %d", sender)
	}
	return nil
}

func verifyConfirmationPreservedChainCode(expected []byte, confirmation *KeygenConfirmation) error {
	if confirmation == nil {
		return errors.New("nil keygen confirmation")
	}
	if !bytes.Equal(confirmation.ChainCode, expected) {
		return fmt.Errorf("keygen confirmation chain code mismatch from party %d", confirmation.Sender)
	}
	return nil
}

func validateKeygenConfirmationSetForShare(local *KeyShare, confirmations []*KeygenConfirmation, limits Limits) error {
	if local == nil {
		return errors.New("nil local key share")
	}
	if err := local.validateWithoutConfirmations(limits); err != nil {
		return fmt.Errorf("invalid local key share: %w", err)
	}
	if len(confirmations) != len(local.state.Parties) {
		return fmt.Errorf("got %d keygen confirmations, want %d", len(confirmations), len(local.state.Parties))
	}
	for i, confirmation := range confirmations {
		if confirmation == nil {
			return fmt.Errorf("nil keygen confirmation at index %d", i)
		}
		if confirmation.Sender != local.state.Parties[i] {
			return fmt.Errorf("keygen confirmation order mismatch at index %d: got party %d, want %d", i, confirmation.Sender, local.state.Parties[i])
		}
	}
	return verifyKeygenConfirmationSetBinding(local, confirmations)
}

func attachKeygenConfirmations(local *KeyShare, confirmations []*KeygenConfirmation) error {
	if local == nil || local.state == nil {
		return errors.New("nil local key share")
	}
	for _, confirmation := range confirmations {
		if confirmation == nil {
			return errors.New("nil keygen confirmation")
		}
		if _, ok := local.state.PartyData[confirmation.Sender]; !ok {
			return fmt.Errorf("missing party data for confirmation sender %d", confirmation.Sender)
		}
		data := local.state.PartyData[confirmation.Sender]
		data.KeygenConfirmation = confirmation.Clone()
		local.state.PartyData[confirmation.Sender] = data
	}
	return nil
}

func applyKeygenConfirmationSet(local *KeyShare, confirmations []*KeygenConfirmation, limits Limits) error {
	if err := validateKeygenConfirmationSetForShare(local, confirmations, limits); err != nil {
		return err
	}
	return attachKeygenConfirmations(local, confirmations)
}
