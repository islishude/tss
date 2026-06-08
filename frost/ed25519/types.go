package ed25519

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"

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

// VerificationShare is a participant public share derived from DKG commitments.
type VerificationShare struct {
	Party     tss.PartyID `json:"party"`
	PublicKey []byte      `json:"public_key"`
}

// KeyShare is one local FROST Ed25519 signing share.
type KeyShare struct {
	Version              uint16        `json:"version"`
	Party                tss.PartyID   `json:"party"`
	Threshold            int           `json:"threshold"`
	Parties              []tss.PartyID `json:"parties"`
	PublicKey            []byte        `json:"public_key"`
	ChainCode            []byte        `json:"chain_code,omitempty"`
	secret               *secret.Scalar
	GroupCommitments     [][]byte            `json:"group_commitments"`
	VerificationShares   []VerificationShare `json:"verification_shares"`
	KeygenSessionID      tss.SessionID       `json:"keygen_session_id"`
	KeygenTranscriptHash []byte              `json:"keygen_transcript_hash,omitempty"`
	KeygenConfirmations  [][]byte            `json:"keygen_confirmations,omitempty"`
}

// Algorithm returns the common algorithm identifier.
func (k *KeyShare) Algorithm() tss.Algorithm {
	return tss.AlgorithmFROSTEd25519
}

// PartyID returns the owner party of this key share.
func (k *KeyShare) PartyID() tss.PartyID {
	if k == nil {
		return 0
	}
	return k.Party
}

// PublicKeyBytes returns a copy of the group Ed25519 public key.
func (k *KeyShare) PublicKeyBytes() []byte {
	if k == nil {
		return nil
	}
	return slices.Clone(k.PublicKey)
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
	if k == nil {
		_, _ = fmt.Fprint(state, "<nil>")
		return
	}
	_, _ = fmt.Fprint(state, k.redactedString())
}

func (k KeyShare) redactedString() string {
	return fmt.Sprintf(
		"KeyShare{Version:%d Party:%d Threshold:%d Parties:%v PublicKey:%x ChainCode:%d bytes Secret:<redacted> GroupCommitments:%d VerificationShares:%d KeygenSessionID:%s KeygenTranscriptHash:%x KeygenConfirmations:%d}",
		k.Version,
		k.Party,
		k.Threshold,
		k.Parties,
		k.PublicKey,
		len(k.ChainCode),
		len(k.GroupCommitments),
		len(k.VerificationShares),
		k.KeygenSessionID,
		k.KeygenTranscriptHash,
		len(k.KeygenConfirmations),
	)
}

// UnmarshalKeyShare decodes a canonical FROST key-share record with size caps.
func UnmarshalKeyShare(in []byte) (*KeyShare, error) {
	limits := DefaultLimits()
	if len(in) == 0 {
		return nil, errors.New("empty key share")
	}
	if len(in) > limits.MaxSerializedKeyShareBytes {
		return nil, fmt.Errorf("key share too large: %d > %d", len(in), limits.MaxSerializedKeyShareBytes)
	}
	return unmarshalKeyShareWithLimits(in, limits)
}

func (k *KeyShare) validateWithoutConfirmations() error {
	if k == nil {
		return errors.New("nil key share")
	}
	if k.Version != tss.Version {
		return fmt.Errorf("unexpected key share version %d", k.Version)
	}
	if k.Threshold <= 0 || k.Threshold > len(k.Parties) {
		return errors.New("invalid threshold")
	}
	if err := wire.ValidateStrictSortedIDs(k.Parties); err != nil {
		return err
	}
	if !tss.ContainsParty(k.Parties, k.Party) {
		return errors.New("key share party is not in participant set")
	}
	if _, err := edcurve.PointFromBytes(k.PublicKey); err != nil {
		return fmt.Errorf("invalid group public key: %w", err)
	}
	if len(k.ChainCode) != 0 && len(k.ChainCode) != 32 {
		return errors.New("chain code must be empty or 32 bytes")
	}
	if len(k.KeygenTranscriptHash) == 0 {
		return errors.New("key share has no keygen transcript hash")
	}
	if _, err := edScalarFromSecret(k.secret); err != nil {
		return fmt.Errorf("invalid secret scalar: %w", err)
	}
	if len(k.GroupCommitments) != k.Threshold {
		return errors.New("group commitments length must equal threshold")
	}
	for i, commitment := range k.GroupCommitments {
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
	if len(k.VerificationShares) != len(k.Parties) {
		return errors.New("verification share count must equal party count")
	}
	seen := make(map[tss.PartyID]struct{}, len(k.VerificationShares))
	for i, vs := range k.VerificationShares {
		if vs.Party != k.Parties[i] {
			return errors.New("verification shares must follow party order")
		}
		if !tss.ContainsParty(k.Parties, vs.Party) {
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
	if len(k.KeygenConfirmations) > 0 {
		if err := verifyKeygenConfirmationSet(k, k.KeygenConfirmations); err != nil {
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
	commit0, err := edcurve.EvalCommitments(k.GroupCommitments, 0)
	if err != nil {
		return fmt.Errorf("cannot evaluate group commitments at 0: %w", err)
	}
	if !bytes.Equal(commit0, k.PublicKey) {
		return errors.New("group public key does not match first group commitment")
	}
	// Verification shares must equal commitments evaluated at each party's ID.
	for _, vs := range k.VerificationShares {
		expected, err := edcurve.EvalCommitments(k.GroupCommitments, uint32(vs.Party))
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
	wantPub, ok := k.verificationShare(k.Party)
	if !ok {
		return errors.New("missing verification share for local party")
	}
	secretPub := fed.NewIdentityPoint().ScalarBaseMult(secretScalar)
	if !bytes.Equal(secretPub.Bytes(), wantPub) {
		return errors.New("secret share inconsistent with verification share")
	}
	return nil
}

// Destroy zeros the local scalar share bytes in place.
func (k *KeyShare) Destroy() {
	if k == nil {
		return
	}
	clear(k.ChainCode)
	k.secret.Destroy()
}

func (k *KeyShare) secretScalar() (*fed.Scalar, error) {
	return edScalarFromSecret(k.secret)
}

func (k *KeyShare) verificationShare(id tss.PartyID) ([]byte, bool) {
	for _, vs := range k.VerificationShares {
		if vs.Party == id {
			return vs.PublicKey, true
		}
	}
	return nil, false
}

func cloneKeyShareValue(k *KeyShare) *KeyShare {
	if k == nil {
		return nil
	}
	out := *k
	out.Parties = slices.Clone(k.Parties)
	out.PublicKey = slices.Clone(k.PublicKey)
	out.ChainCode = slices.Clone(k.ChainCode)
	out.secret = k.secret.Clone()
	out.GroupCommitments = cloneKeyShareByteSlices(k.GroupCommitments)
	out.VerificationShares = cloneVerificationShares(k.VerificationShares)
	out.KeygenSessionID = k.KeygenSessionID
	out.KeygenTranscriptHash = slices.Clone(k.KeygenTranscriptHash)
	out.KeygenConfirmations = cloneKeyShareByteSlices(k.KeygenConfirmations)
	return &out
}

func cloneKeyShareByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = slices.Clone(item)
	}
	return out
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
	return shifted.Bytes(), nil
}

func requireDirectConfidential(env tss.Envelope, self tss.PartyID, payloadType tss.PayloadType) error {
	if env.To != self {
		return fmt.Errorf("%s must be addressed to receiver", payloadType)
	}
	// Secret-bearing direct messages must be delivered over a confidential transport.
	// This check is defense-in-depth: EnvelopeGuard already enforces confidentiality
	// per the protocol policy when a guard is configured. When no guard is set
	// (test-only path), we always check the confidential flag regardless of whether
	// the transport has set an authenticated security context.
	if !env.Security.Confidential {
		return fmt.Errorf("%s must be delivered over a confidential transport", payloadType)
	}
	return nil
}
