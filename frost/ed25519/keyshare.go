package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
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
	return k.state.party
}

// Threshold returns the signing threshold.
func (k *KeyShare) Threshold() int {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.threshold
}

// PublicMetadata returns a caller-owned snapshot of non-secret key-share
// metadata that is not scoped to a single participant.
func (k *KeyShare) PublicMetadata() (KeySharePublicMetadata, bool) {
	if k == nil || k.state == nil {
		return KeySharePublicMetadata{}, false
	}
	return KeySharePublicMetadata{
		Party:                k.state.party,
		Threshold:            k.state.threshold,
		Parties:              k.state.parties.Clone(),
		PublicKey:            bytes.Clone(k.state.publicKey),
		ChainCode:            bytes.Clone(k.state.chainCode),
		GroupCommitments:     tss.CloneByteSlices(k.state.groupCommitments),
		KeygenSessionID:      k.state.keygenSessionID,
		KeygenTranscriptHash: bytes.Clone(k.state.keygenTranscriptHash),
		PlanHash:             bytes.Clone(k.state.planHash),
	}, true
}

// Derive resolves a non-hardened Ed25519-BIP32 derivation path from this key share.
func (k *KeyShare) Derive(path tss.DerivationPath, opts ...tss.DeriveOption) (*tss.DerivationResult, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	return DeriveNonHardenedBIP32(k.state.publicKey, k.state.chainCode, path.Clone(), opts...)
}

// VerificationShare returns a caller-owned public verification share for party.
func (k *KeyShare) VerificationShare(party tss.PartyID) (VerificationShare, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || len(data.verificationShare) == 0 {
		return VerificationShare{}, false
	}
	return VerificationShare{Party: party, PublicKey: bytes.Clone(data.verificationShare)}, true
}

// KeygenSessionID returns the DKG or resharing session that produced the share.
func (k *KeyShare) KeygenSessionID() tss.SessionID {
	if k == nil || k.state == nil {
		return tss.SessionID{}
	}
	return k.state.keygenSessionID
}

// KeygenConfirmation returns a caller-owned keygen confirmation for party.
func (k *KeyShare) KeygenConfirmation(party tss.PartyID) (*KeygenConfirmation, bool) {
	data, err := k.partyDataFor(party)
	if err != nil || data.keygenConfirmation == nil {
		return nil, false
	}
	return data.keygenConfirmation.Clone(), true
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
	for _, data := range k.state.partyData {
		if data.keygenConfirmation != nil {
			confirmationCount++
		}
	}
	return fmt.Sprintf(
		"KeyShare{Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d PartyData:%d KeygenSessionID:%s KeygenTranscriptHash:%x PlanHash:%d bytes KeygenConfirmations:%d}",
		k.state.party,
		k.state.threshold,
		k.state.parties,
		k.state.publicKey,
		len(k.state.chainCode),
		len(k.state.groupCommitments),
		len(k.state.partyData),
		k.state.keygenSessionID,
		k.state.keygenTranscriptHash,
		len(k.state.planHash),
		confirmationCount,
	)
}

// UnmarshalKeyShare decodes a canonical FROST key-share record with size caps.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	return tss.DecodeBinary[KeyShare](in)
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
	if k.state.threshold <= 0 || k.state.threshold > len(k.state.parties) {
		return errors.New("invalid threshold")
	}
	if err := wire.ValidateStrictSortedIDs(k.state.parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.state.parties, k.state.party) {
		return errors.New("key share party is not in participant set")
	}
	if k.state.partyData == nil {
		return errors.New("missing party data")
	}
	if len(k.state.partyData) != len(k.state.parties) {
		return fmt.Errorf("party data count %d != party count %d", len(k.state.partyData), len(k.state.parties))
	}
	for _, id := range k.state.parties {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		if _, ok := k.state.partyData[id]; !ok {
			return fmt.Errorf("missing party data for participant %d", id)
		}
	}
	for id := range k.state.partyData {
		if id == tss.BroadcastPartyId {
			return errors.New("broadcast party cannot have key share party data")
		}
		if !tss.ContainsParty(k.state.parties, id) {
			return fmt.Errorf("party data for non-participant %d", id)
		}
	}
	if _, err := edcurve.PointFromBytes(k.state.publicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.state.chainCode) != 32 {
		return errors.New("chain code must be 32 bytes")
	}
	if len(k.state.keygenTranscriptHash) == 0 {
		return errors.New("key share has no keygen transcript hash")
	}
	if len(k.state.planHash) != sha256.Size {
		return errors.New("key share has no lifecycle plan hash")
	}
	if _, err := edScalarFromSecret(k.state.secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.state.groupCommitments) != k.state.threshold {
		return errors.New("group commitments length must equal threshold")
	}
	for i, commitment := range k.state.groupCommitments {
		if i == 0 {
			if _, err := edcurve.PointFromBytes(commitment); err != nil {
				return fmt.Errorf("invalid group commitment %d: %w", i, err)
			}
			continue
		}
		if _, err := edcurve.PointFromBytesAllowIdentity(commitment); err != nil {
			return fmt.Errorf("invalid group commitment %d: %w", i, err)
		}
	}
	for _, id := range k.state.parties {
		data := k.state.partyData[id]
		if _, err := edcurve.PointFromBytesAllowIdentity(data.verificationShare); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", id, err)
		}
		if data.keygenConfirmation != nil && data.keygenConfirmation.Sender != id {
			return fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.keygenConfirmation.Sender, id)
		}
	}
	return nil
}

// Validate checks share structure and canonical scalar/point encodings. When a
// share carries keygen confirmation evidence, the complete confirmation set is
// verified as well.
func (k *KeyShare) Validate() error {
	if err := k.validateWithoutConfirmations(); err != nil {
		return err
	}
	confirmationCount := 0
	for _, data := range k.state.partyData {
		if data.keygenConfirmation != nil {
			confirmationCount++
		}
	}
	if confirmationCount == 0 {
		return nil
	}
	if confirmationCount != len(k.state.parties) {
		return fmt.Errorf("keygen confirmation count %d != party count %d", confirmationCount, len(k.state.parties))
	}
	confirmations, err := k.orderedKeygenConfirmations()
	if err != nil {
		return err
	}
	if err := verifyFinalizedKeygenConfirmationSet(k, confirmations, false); err != nil {
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
	commit0, err := edcurve.EvalCommitments(k.state.groupCommitments, 0)
	if err != nil {
		return fmt.Errorf("cannot evaluate group commitments at 0: %w", err)
	}
	if !bytes.Equal(commit0, k.state.publicKey) {
		return errors.New("group public key does not match first group commitment")
	}
	for _, id := range k.state.parties {
		expected, err := edcurve.EvalCommitments(k.state.groupCommitments, id)
		if err != nil {
			return fmt.Errorf("cannot evaluate commitments for party %d: %w", id, err)
		}
		if !bytes.Equal(expected, k.state.partyData[id].verificationShare) {
			return fmt.Errorf("verification share for party %d does not match group commitments", id)
		}
	}
	secretScalar, err := k.secretScalar()
	if err != nil {
		return fmt.Errorf("cannot decode secret share: %w", err)
	}
	wantPub, ok := k.verificationShare(k.state.party)
	if !ok {
		return errors.New("missing verification share for local party")
	}
	secretPub := fed.NewIdentityPoint().ScalarBaseMult(secretScalar)
	if !bytes.Equal(secretPub.Bytes(), wantPub) {
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
	clear(k.state.chainCode)
	if k.state.secret != nil {
		k.state.secret.Destroy()
	}
}

func (k *KeyShare) secretScalar() (*fed.Scalar, error) {
	return edScalarFromSecret(k.state.secret)
}

func (k *KeyShare) partyDataFor(id tss.PartyID) (keySharePartyData, error) {
	if k == nil || k.state == nil {
		return keySharePartyData{}, errors.New("nil key share")
	}
	if !tss.ContainsParty(k.state.parties, id) {
		return keySharePartyData{}, fmt.Errorf("party %d is not a participant", id)
	}
	data, ok := k.state.partyData[id]
	if !ok {
		return keySharePartyData{}, fmt.Errorf("missing party data for participant %d", id)
	}
	return data, nil
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	data, err := k.partyDataFor(id)
	if err != nil || len(data.verificationShare) == 0 {
		return nil, false
	}
	return data.verificationShare, true
}

func (k *KeyShare) orderedVerificationShares() ([]VerificationShare, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]VerificationShare, 0, len(k.state.parties))
	for _, id := range k.state.parties {
		data, err := k.partyDataFor(id)
		if err != nil {
			return nil, err
		}
		out = append(out, VerificationShare{Party: id, PublicKey: bytes.Clone(data.verificationShare)})
	}
	return out, nil
}

func (k *KeyShare) orderedKeygenConfirmations() ([]*KeygenConfirmation, error) {
	if k == nil || k.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]*KeygenConfirmation, 0, len(k.state.parties))
	for _, id := range k.state.parties {
		data, err := k.partyDataFor(id)
		if err != nil {
			return nil, err
		}
		if data.keygenConfirmation == nil {
			return nil, fmt.Errorf("missing keygen confirmation for party %d", id)
		}
		if data.keygenConfirmation.Sender != id {
			return nil, fmt.Errorf("keygen confirmation sender %d does not match party data key %d", data.keygenConfirmation.Sender, id)
		}
		out = append(out, data.keygenConfirmation.Clone())
	}
	return out, nil
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil || k.state == nil {
		return nil
	}
	return &KeyShare{state: &keyShareState{
		party:                k.state.party,
		threshold:            k.state.threshold,
		parties:              slices.Clone(k.state.parties),
		publicKey:            slices.Clone(k.state.publicKey),
		chainCode:            slices.Clone(k.state.chainCode),
		secret:               k.state.secret.Clone(),
		groupCommitments:     tss.CloneByteSlices(k.state.groupCommitments),
		partyData:            cloneKeySharePartyDataMap(k.state.partyData),
		keygenSessionID:      k.state.keygenSessionID,
		keygenTranscriptHash: slices.Clone(k.state.keygenTranscriptHash),
		planHash:             slices.Clone(k.state.planHash),
	}}
}
