package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

// Algorithm returns the common algorithm identifier.
func (k *KeyShare) Algorithm() tss.Algorithm {
	return tss.AlgorithmFROSTEd25519
}

// PartyID returns the owner party of this key share.
func (k *KeyShare) PartyID() tss.PartyID {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.Party
}

// Threshold returns the signing threshold.
func (k *KeyShare) Threshold() int {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.Threshold
}

// PublicMetadata returns a caller-owned snapshot of non-secret key-share
// metadata that is not scoped to a single participant.
func (k *KeyShare) PublicMetadata() (KeySharePublicMetadata, bool) {
	if k == nil || k.state == nil {
		return KeySharePublicMetadata{}, false
	}
	return KeySharePublicMetadata{
		Party:                k.state.Party,
		Threshold:            k.state.Threshold,
		Parties:              k.state.Parties.Clone(),
		PublicKey:            k.state.PublicKey.Clone(),
		ChainCode:            bytes.Clone(k.state.ChainCode),
		GroupCommitments:     k.state.GroupCommitments.BytesList(),
		KeygenSessionID:      k.state.KeygenSessionID,
		KeygenTranscriptHash: bytes.Clone(k.state.KeygenTranscriptHash),
		PlanHash:             bytes.Clone(k.state.PlanHash),
	}, true
}

// Derive resolves a non-hardened Ed25519-BIP32 derivation path from this key share.
func (k *KeyShare) Derive(path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	return DeriveNonHardenedBIP32(k.state.PublicKey.Bytes(), k.state.ChainCode, path.Clone(), opts...)
}

// VerificationShare returns a caller-owned public verification share for party.
func (k *KeyShare) VerificationShare(party tss.PartyID) (VerificationShare, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || data.VerificationShare.IsZero() {
		return VerificationShare{}, false
	}
	return VerificationShare{Party: party, PublicKey: data.VerificationShare.Clone()}, true
}

// KeygenSessionID returns the DKG or resharing session that produced the share.
func (k *KeyShare) KeygenSessionID() tss.SessionID {
	if k == nil || k.state == nil {
		return tss.SessionID{}
	}
	return k.state.KeygenSessionID
}

// KeygenConfirmation returns a caller-owned lifecycle confirmation for party.
func (k *KeyShare) KeygenConfirmation(party tss.PartyID) (*KeygenConfirmation, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || data.KeygenConfirmation == nil {
		return nil, false
	}
	return data.KeygenConfirmation.Clone(), true
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return k.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the share using canonical TLV wire format
// with explicit local resource limits.
func (k *KeyShare) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := k.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return k.MarshalWireMessage(wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// MarshalJSON rejects default JSON encoding of secret-bearing key shares.
func (k KeyShare) MarshalJSON() ([]byte, error) {
	return nil, errors.New("frost ed25519 key share contains secret material; use MarshalBinary")
}

// String returns a redacted representation of the key share.
func (k KeyShare) String() string {
	return k.redactedString()
}

// GoString returns a redacted representation of the key share.
func (k KeyShare) GoString() string {
	return k.redactedString()
}

// Format writes a redacted representation of the key share.
func (k *KeyShare) Format(state fmt.State, verb rune) {
	if k == nil || k.state == nil {
		_, _ = fmt.Fprint(state, "<nil>")
		return
	}
	_, _ = fmt.Fprint(state, k.redactedString())
}

func (k KeyShare) redactedString() string {
	if k.state == nil {
		return "<nil>"
	}
	confirmationCount := 0
	for _, data := range k.state.PartyData {
		if data.KeygenConfirmation != nil {
			confirmationCount++
		}
	}
	return fmt.Sprintf(
		"KeyShare{Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d PartyData:%d KeygenSessionID:%s KeygenTranscriptHash:%x PlanHash:%d bytes KeygenConfirmations:%d}",
		k.state.Party,
		k.state.Threshold,
		k.state.Parties,
		k.state.PublicKey.Bytes(),
		len(k.state.ChainCode),
		k.state.GroupCommitments.Len(),
		len(k.state.PartyData),
		k.state.KeygenSessionID,
		k.state.KeygenTranscriptHash,
		len(k.state.PlanHash),
		confirmationCount,
	)
}

// UnmarshalKeyShareWithLimits decodes a canonical FROST key-share record using
// explicit local resource limits.
func UnmarshalKeyShareWithLimits(in []byte, limits Limits) (*KeyShare, error) {
	return tss.DecodeBinaryWithLimits[KeyShare](in, limits)
}

// UnmarshalBinary decodes a canonical FROST key-share record with size caps.
func (k *KeyShare) UnmarshalBinary(in []byte) error {
	return k.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical FROST key-share record into the
// receiver using explicit local resource limits.
func (k *KeyShare) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if len(in) == 0 {
		return errors.New("empty key share")
	}
	if len(in) > limits.State.MaxSerializedKeyShareBytes {
		return fmt.Errorf("key share too large: %d > %d", len(in), limits.State.MaxSerializedKeyShareBytes)
	}
	var decoded KeyShare
	if err := decoded.UnmarshalWireMessage(in,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	k.state = decoded.state
	return nil
}

func (k *KeyShare) validateWithoutConfirmations() error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if !k.state.KeygenSessionID.Valid() {
		return errors.New("key share has no keygen/lifecycle session id")
	}
	if k.state.Threshold <= 0 || k.state.Threshold > len(k.state.Parties) {
		return errors.New("invalid threshold")
	}
	if err := wire.ValidateStrictSortedIDs(k.state.Parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.state.Parties, k.state.Party) {
		return errors.New("key share party is not in participant set")
	}
	if k.state.PartyData == nil {
		return errors.New("missing party data")
	}
	if err := k.state.checkPartyDataKeys(); err != nil {
		return err
	}
	if err := k.state.PublicKey.Validate(); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.state.ChainCode) != 32 {
		return errors.New("chain code must be 32 bytes")
	}
	if len(k.state.KeygenTranscriptHash) == 0 {
		return errors.New("key share has no keygen transcript hash")
	}
	if len(k.state.PlanHash) != sha256.Size {
		return errors.New("key share has no lifecycle plan hash")
	}
	if !k.state.ConfirmationMode.valid() {
		return errors.New("key share has invalid completion confirmation mode")
	}
	if _, err := edScalarFromSecret(k.state.Secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if k.state.GroupCommitments.Len() != k.state.Threshold {
		return errors.New("group commitments length must equal threshold")
	}
	if err := k.state.GroupCommitments.Validate(); err != nil {
		return fmt.Errorf("invalid group commitments: %w", err)
	}
	for _, id := range k.state.Parties {
		data := k.state.PartyData[id]
		if err := data.VerificationShare.Validate(); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", id, err)
		}
	}
	return nil
}

// Validate checks share structure, canonical scalar/point encodings, and the
// mandatory complete lifecycle confirmation set.
func (k *KeyShare) Validate() error {
	if err := k.validateWithoutConfirmations(); err != nil {
		return err
	}
	confirmationCount := 0
	for _, data := range k.state.PartyData {
		if data.KeygenConfirmation != nil {
			confirmationCount++
		}
	}
	if confirmationCount != len(k.state.Parties) {
		return fmt.Errorf("lifecycle confirmation count %d != party count %d", confirmationCount, len(k.state.Parties))
	}
	confirmations, err := k.orderedKeygenConfirmations()
	if err != nil {
		return err
	}
	if err := verifyKeygenConfirmationSetAggregateChainCode(k, confirmations); err != nil {
		return fmt.Errorf("invalid keygen confirmations: %w", err)
	}
	return nil
}

// ValidateConsistency checks that the key share's cryptographic invariants hold:
// the public key matches the group commitments, each verification share is derived
// from those commitments, and the local secret share is consistent with its
// verification share. Call this after UnmarshalKeyShare or before using a key
// share recovered from persistent storage.
func (k *KeyShare) ValidateConsistency() error {
	if err := k.Validate(); err != nil {
		return err
	}
	return k.validateConsistencyWithoutConfirmations()
}

func (k *KeyShare) validateConsistencyWithoutConfirmations() error {
	if err := k.validateWithoutConfirmations(); err != nil {
		return err
	}
	if !k.state.GroupCommitments.PublicKey().Equal(k.state.PublicKey) {
		return errors.New("group public key does not match first group commitment")
	}
	for _, id := range k.state.Parties {
		expected, err := k.state.GroupCommitments.Eval(id)
		if err != nil {
			return fmt.Errorf("cannot evaluate commitments for party %d: %w", id, err)
		}
		if !expected.Equal(k.state.PartyData[id].VerificationShare) {
			return fmt.Errorf("verification share for party %d does not match group commitments", id)
		}
	}
	secretScalar, err := k.secretScalar()
	if err != nil {
		return fmt.Errorf("cannot decode secret share: %w", err)
	}
	wantPub, ok := k.verificationSharePoint(k.state.Party)
	if !ok {
		return errors.New("missing verification share for local party")
	}
	secretPub := fed.NewIdentityPoint().ScalarBaseMult(secretScalar)
	if !pointEqual(secretPub, wantPub.Point()) {
		return errors.New("secret share inconsistent with verification share")
	}
	return nil
}

// Destroy zeros the local secret scalar and chain code in place. After Destroy,
// the KeyShare is permanently unusable for MPC operations.
//
// # Go zeroization boundaries
//
// Destroy zeroes the fields that this package controls: secret (fixed-length
// secret scalar) and ChainCode. It does not zero GroupCommitments,
// VerificationShares, or other public material. A shallow Go copy is another
// handle to the same lifecycle state. Callers that extracted metadata before
// Destroy own independent copies that must be zeroed separately.
func (k *KeyShare) Destroy() {
	if k == nil || k.state == nil {
		return
	}
	clear(k.state.ChainCode)
	if k.state.Secret != nil {
		k.state.Secret.Destroy()
	}
}

func (k *KeyShare) secretScalar() (*fed.Scalar, error) {
	return edScalarFromSecret(k.state.Secret)
}

func (k *KeyShare) partyDataFor(id tss.PartyID) (keySharePartyData, error) {
	if k == nil || k.state == nil {
		return keySharePartyData{}, errors.New("nil key share")
	}
	if !tss.ContainsParty(k.state.Parties, id) {
		return keySharePartyData{}, fmt.Errorf("party %d is not a participant", id)
	}
	data, ok := k.state.PartyData[id]
	if !ok {
		return keySharePartyData{}, fmt.Errorf("missing party data for participant %d", id)
	}
	return data, nil
}

func (k *KeyShare) verificationSharePoint(id tss.PartyID) (verificationSharePoint, bool) {
	data, err := k.partyDataFor(id)
	if err != nil || data.VerificationShare.IsZero() {
		return verificationSharePoint{}, false
	}
	return data.VerificationShare.Clone(), true
}

func (k *KeyShare) orderedVerificationShares() ([]VerificationShare, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]VerificationShare, 0, len(k.state.Parties))
	for _, id := range k.state.Parties {
		data, err := k.partyDataFor(id)
		if err != nil {
			return nil, err
		}
		out = append(out, VerificationShare{Party: id, PublicKey: data.VerificationShare.Clone()})
	}
	return out, nil
}

func (k *KeyShare) orderedKeygenConfirmations() ([]*KeygenConfirmation, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]*KeygenConfirmation, 0, len(k.state.Parties))
	for _, id := range k.state.Parties {
		data, err := k.partyDataFor(id)
		if err != nil {
			return nil, err
		}
		if data.KeygenConfirmation == nil {
			return nil, fmt.Errorf("missing keygen confirmation for party %d", id)
		}
		if data.KeygenConfirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.KeygenConfirmation.Sender, id)
		}
		out = append(out, data.KeygenConfirmation.Clone())
	}
	return out, nil
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil || k.state == nil {
		return nil
	}
	return &KeyShare{state: &keyShareState{
		Party:                k.state.Party,
		Threshold:            k.state.Threshold,
		Parties:              slices.Clone(k.state.Parties),
		PublicKey:            k.state.PublicKey.Clone(),
		ChainCode:            slices.Clone(k.state.ChainCode),
		Secret:               k.state.Secret.Clone(),
		GroupCommitments:     k.state.GroupCommitments.Clone(),
		PartyData:            tss.CloneMap(k.state.PartyData),
		KeygenSessionID:      k.state.KeygenSessionID,
		KeygenTranscriptHash: slices.Clone(k.state.KeygenTranscriptHash),
		PlanHash:             slices.Clone(k.state.PlanHash),
		ConfirmationMode:     k.state.ConfirmationMode,
	}}
}
