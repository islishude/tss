package ed25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"

	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/secret"
)

const protocol = tss.ProtocolFROSTEd25519

const (
	payloadKeygenCommitments  tss.PayloadType = "frost.ed25519.keygen.commitments"
	payloadKeygenShare        tss.PayloadType = "frost.ed25519.keygen.share"
	payloadKeygenConfirmation tss.PayloadType = "frost.ed25519.keygen.confirmation"
	payloadSignCommitment     tss.PayloadType = "frost.ed25519.sign.commitment"
	payloadSignPartial        tss.PayloadType = "frost.ed25519.sign.partial"
)

// VerificationShare is a caller-owned snapshot of a participant public share
// derived from DKG commitments.
type VerificationShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
}

// KeyShare is one local FROST Ed25519 signing share.
//
// Its fields are intentionally opaque. Accessors that return slices or nested
// records return caller-owned copies.
//
// A shallow Go copy of KeyShare is another handle to the same lifecycle state:
// destroying either handle destroys the shared secret material. Session
// completion accessors instead return independently owned key shares.
type KeyShare struct {
	state *keyShareState
}

type keyShareState struct {
	version              uint16
	party                tss.PartyID
	threshold            int
	parties              []tss.PartyID
	publicKey            []byte
	chainCode            []byte
	secret               *secret.Scalar
	groupCommitments     [][]byte
	verificationShares   []VerificationShare
	keygenSessionID      tss.SessionID
	keygenTranscriptHash []byte
	planHash             []byte
	keygenConfirmations  [][]byte
}

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

// Version returns the key-share wire version.
func (k *KeyShare) Version() uint16 {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.version
}

// Threshold returns the signing threshold.
func (k *KeyShare) Threshold() int {
	if k == nil || k.state == nil {
		return 0
	}
	return k.state.threshold
}

// Parties returns a copy of the canonical participant set.
func (k *KeyShare) Parties() []tss.PartyID {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.parties)
}

// PublicKeyBytes returns a copy of the group Ed25519 public key.
func (k *KeyShare) PublicKeyBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.publicKey)
}

// ChainCodeBytes returns a copy of the HD chain code. The chain code is
// cleared by [KeyShare.Destroy]; callers that need the value after Destroy
// must capture it first.
func (k *KeyShare) ChainCodeBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.chainCode)
}

// GroupCommitments returns a deep copy of the public polynomial commitments.
func (k *KeyShare) GroupCommitments() [][]byte {
	if k == nil || k.state == nil {
		return nil
	}
	return wireutil.CloneByteSlices(k.state.groupCommitments)
}

// VerificationShares returns a deep copy of the participant verification shares.
func (k *KeyShare) VerificationShares() []VerificationShare {
	if k == nil || k.state == nil {
		return nil
	}
	return cloneVerificationShares(k.state.verificationShares)
}

// KeygenSessionID returns the DKG or resharing session that produced the share.
func (k *KeyShare) KeygenSessionID() tss.SessionID {
	if k == nil || k.state == nil {
		return tss.SessionID{}
	}
	return k.state.keygenSessionID
}

// KeygenTranscriptHashBytes returns a copy of the keygen transcript hash.
func (k *KeyShare) KeygenTranscriptHashBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.keygenTranscriptHash)
}

// PlanHashBytes returns a copy of the lifecycle plan hash that produced this
// key share.
func (k *KeyShare) PlanHashBytes() []byte {
	if k == nil || k.state == nil {
		return nil
	}
	return slices.Clone(k.state.planHash)
}

// KeygenConfirmations returns a deep copy of the keygen confirmation set.
func (k *KeyShare) KeygenConfirmations() [][]byte {
	if k == nil || k.state == nil {
		return nil
	}
	return wireutil.CloneByteSlices(k.state.keygenConfirmations)
}

// MarshalBinary encodes the share using canonical TLV wire format.
func (k *KeyShare) MarshalBinary() ([]byte, error) {
	return marshalKeyShare(k)
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
	return fmt.Sprintf(
		"KeyShare{Version:%d Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d VerificationShares:%d KeygenSessionID:%s KeygenTranscriptHash:%x PlanHash:%d bytes KeygenConfirmations:%d}",
		k.state.version,
		k.state.party,
		k.state.threshold,
		k.state.parties,
		k.state.publicKey,
		len(k.state.chainCode),
		len(k.state.groupCommitments),
		len(k.state.verificationShares),
		k.state.keygenSessionID,
		k.state.keygenTranscriptHash,
		len(k.state.planHash),
		len(k.state.keygenConfirmations),
	)
}

// UnmarshalKeyShare decodes a canonical FROST key-share record with size caps.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	limits := DefaultLimits()
	if len(in) == 0 {
		return nil, errors.New("empty key share")
	}
	if len(in) > limits.State.MaxSerializedKeyShareBytes {
		return nil, fmt.Errorf("key share too large: %d > %d", len(in), limits.State.MaxSerializedKeyShareBytes)
	}
	return unmarshalKeyShareWithLimits(in, limits)
}

func (k *KeyShare) validateWithoutConfirmations() error {
	if k == nil || k.state == nil {
		return errors.New("nil key share")
	}
	if k.state.version != tss.Version {
		return fmt.Errorf("unexpected key share version %d", k.state.version)
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
	if _, err := edcurve.PointFromBytes(k.state.publicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.state.chainCode) != 0 && len(k.state.chainCode) != 32 {
		return errors.New("chain code must be empty or 32 bytes")
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
	if len(k.state.verificationShares) != len(k.state.parties) {
		return errors.New("verification share count must equal party count")
	}
	seen := make(map[tss.PartyID]struct{}, len(k.state.verificationShares))
	for i, vs := range k.state.verificationShares {
		if vs.Party != k.state.parties[i] {
			return errors.New("verification shares must follow party order")
		}
		if !tss.ContainsParty(k.state.parties, vs.Party) {
			return fmt.Errorf("verification share for non-participant %d", vs.Party)
		}
		if _, ok := seen[vs.Party]; ok {
			return fmt.Errorf("duplicate verification share for %d", vs.Party)
		}
		seen[vs.Party] = struct{}{}
		if _, err := edcurve.PointFromBytesAllowIdentity(vs.PublicKey); err != nil {
			return fmt.Errorf("invalid verification share for %d: %w", vs.Party, err)
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
	if len(k.state.keygenConfirmations) > 0 {
		if err := verifyKeygenConfirmationSet(k, k.state.keygenConfirmations); err != nil {
			return fmt.Errorf("invalid keygen confirmations: %w", err)
		}
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
	// PublicKey must equal GroupCommitments evaluated at 0.
	commit0, err := edcurve.EvalCommitments(k.state.groupCommitments, 0)
	if err != nil {
		return fmt.Errorf("cannot evaluate group commitments at 0: %w", err)
	}
	if !bytes.Equal(commit0, k.state.publicKey) {
		return errors.New("group public key does not match first group commitment")
	}
	// Verification shares must equal commitments evaluated at each party's ID.
	for _, vs := range k.state.verificationShares {
		expected, err := edcurve.EvalCommitments(k.state.groupCommitments, uint32(vs.Party))
		if err != nil {
			return fmt.Errorf("cannot evaluate commitments for party %d: %w", vs.Party, err)
		}
		if !bytes.Equal(expected, vs.PublicKey) {
			return fmt.Errorf("verification share for party %d does not match group commitments", vs.Party)
		}
	}
	// Secret share * B must equal the local verification share.
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
// [fed.Scalar]) and ChainCode. It does not zero GroupCommitments,
// VerificationShares, or other public material — those fields contain no secret
// data. Callers that copied the chain code via [KeyShare.ChainCodeBytes] before
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

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	for _, vs := range k.state.verificationShares {
		if vs.Party == id {
			return vs.PublicKey, true
		}
	}
	return nil, false
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil || k.state == nil {
		return nil
	}
	return &KeyShare{state: &keyShareState{
		version:              k.state.version,
		party:                k.state.party,
		threshold:            k.state.threshold,
		parties:              slices.Clone(k.state.parties),
		publicKey:            slices.Clone(k.state.publicKey),
		chainCode:            slices.Clone(k.state.chainCode),
		secret:               k.state.secret.Clone(),
		groupCommitments:     wireutil.CloneByteSlices(k.state.groupCommitments),
		verificationShares:   cloneVerificationShares(k.state.verificationShares),
		keygenSessionID:      k.state.keygenSessionID,
		keygenTranscriptHash: slices.Clone(k.state.keygenTranscriptHash),
		planHash:             slices.Clone(k.state.planHash),
		keygenConfirmations:  wireutil.CloneByteSlices(k.state.keygenConfirmations),
	}}
}

func cloneVerificationShares(in []VerificationShare) []VerificationShare {
	if in == nil {
		return nil
	}
	out := slices.Clone(in)
	for i := range out {
		out[i].PublicKey = slices.Clone(out[i].PublicKey)
	}
	return out
}

func scalarBytes(x *big.Int) ([]byte, error) {
	s, err := edcurve.ScalarFromBig(x)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// KeygenOptions controls optional DKG behavior.
type KeygenOptions struct {
	// EnableHD generates a random 32-byte chain code during keygen for BIP32 derivation.
	EnableHD bool

	// Limits overrides the default protocol limits. When nil, DefaultLimits is used.
	Limits *Limits
}

// SignOptions controls optional signing behavior.
type SignOptions struct {
	// AdditiveShift is the cumulative HD tweak applied as an additive scalar shift.
	// Each signer adds lambda_i * c * AdditiveShift to their partial, and the
	// group public key is effectively A' = A + AdditiveShift * B.
	AdditiveShift []byte

	// NonceReader supplies fresh randomness for FROST signing nonces. If nil,
	// crypto/rand.Reader is used.
	NonceReader io.Reader

	// Limits overrides the default protocol limits. When nil, DefaultLimits is used.
	Limits *Limits
}

// DerivePublicKey returns the child Ed25519 public key produced by adding
// the additive scalar shift times the base point to publicKey.
func DerivePublicKey(publicKey, additiveShift []byte) ([]byte, error) {
	base, err := edcurve.PointFromBytes(publicKey)
	if err != nil {
		return nil, err
	}
	if len(additiveShift) == 0 {
		return base.Bytes(), nil
	}
	shift, err := edcurve.ScalarFromCanonical(additiveShift)
	if err != nil {
		return nil, fmt.Errorf("invalid additive shift: %w", err)
	}
	shifted := edcurve.AddPoints(base, fed.NewIdentityPoint().ScalarBaseMult(shift))
	if edcurve.IsIdentity(shifted) {
		return nil, errors.New("derived public key is identity")
	}
	return shifted.Bytes(), nil
}
