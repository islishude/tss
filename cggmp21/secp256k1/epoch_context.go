package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	epochContextWireType                = "cggmp21.secp256k1.epoch-context"
	epochContextWireVersion      uint16 = 1
	epochIdentifierHashLabel            = "cggmp21-secp256k1-epoch-shamir-id"
	epochContextIDLabel                 = "cggmp21-secp256k1-epoch-context-id"
	epochAuxiliaryDigestLabel           = "cggmp21-secp256k1-epoch-auxiliary-digest"
	maxEpochIdentifierCandidates        = 256
)

var (
	errEpochIdentifierZero      = errors.New("derive epoch identifier: hash candidate is zero")
	errEpochIdentifierExhausted = errors.New("derive epoch identifier: rejection sampling exhausted")
)

// EpochSourceID is the fixed-width identity of the epoch from which a new
// epoch was derived. It is carried as an optional exact-width custom wire
// value so absence cannot be confused with an empty byte string.
type EpochSourceID [sha256.Size]byte

// Bytes returns a caller-owned fixed-width encoding of id.
func (id EpochSourceID) Bytes() []byte {
	return bytes.Clone(id[:])
}

// Clone returns a caller-owned copy of id.
func (id *EpochSourceID) Clone() *EpochSourceID {
	if id == nil {
		return nil
	}
	out := *id
	return &out
}

// MarshalWireValue returns the canonical fixed-width wire value.
func (id EpochSourceID) MarshalWireValue() ([]byte, error) {
	return id.Bytes(), nil
}

// UnmarshalWireValue decodes one canonical fixed-width source epoch ID.
func (id *EpochSourceID) UnmarshalWireValue(in []byte) error {
	if id == nil {
		return errors.New("nil epoch source id")
	}
	if len(in) != sha256.Size {
		return fmt.Errorf("epoch source id must be %d bytes", sha256.Size)
	}
	var zero [sha256.Size]byte
	if bytes.Equal(in, zero[:]) {
		return errors.New("epoch source id must be non-zero")
	}
	copy(id[:], in)
	return nil
}

func newEpochSourceID(in []byte) (*EpochSourceID, error) {
	if len(in) == 0 {
		return nil, nil //nolint:nilnil // An empty source ID canonically represents the initial epoch.
	}
	if len(in) != sha256.Size {
		return nil, fmt.Errorf("epoch source id must be %d bytes", sha256.Size)
	}
	var zero [sha256.Size]byte
	if bytes.Equal(in, zero[:]) {
		return nil, errors.New("epoch source id must be non-zero")
	}
	var out EpochSourceID
	copy(out[:], in)
	return &out, nil
}

// EpochPartyIdentifier binds one transport party identity to its non-zero
// Shamir evaluation point for an epoch.
type EpochPartyIdentifier struct {
	Party      tss.PartyID `wire:"1,u32"`
	Identifier []byte      `wire:"2,bytes,len=32"`
}

// Clone returns a caller-owned copy of the party identifier.
func (i EpochPartyIdentifier) Clone() EpochPartyIdentifier {
	return EpochPartyIdentifier{Party: i.Party, Identifier: bytes.Clone(i.Identifier)}
}

// EpochPublicShare binds one party to its public Shamir share in an epoch.
type EpochPublicShare struct {
	Party     tss.PartyID `wire:"1,u32"`
	PublicKey []byte      `wire:"2,bytes,max_bytes=point"`
}

// Clone returns a caller-owned copy of the epoch public share.
func (s EpochPublicShare) Clone() EpochPublicShare {
	return EpochPublicShare{Party: s.Party, PublicKey: bytes.Clone(s.PublicKey)}
}

// EpochContext is the canonical public identity of one CGGMP21 auxiliary-key
// epoch. Identifiers and public shares are ordered by strictly increasing party
// ID. SourceEpochID is absent only for the first epoch established after
// keygen.
type EpochContext struct {
	SID             tss.SessionID          `wire:"1,bytes,len=32"`
	RID             tss.SessionID          `wire:"2,bytes,len=32"`
	Threshold       int                    `wire:"3,u32"`
	EpochID         []byte                 `wire:"4,bytes,len=32"`
	Identifiers     []EpochPartyIdentifier `wire:"5,recordlist,max_items=parties"`
	PublicShares    []EpochPublicShare     `wire:"6,recordlist,max_items=parties"`
	AuxiliaryDigest []byte                 `wire:"7,bytes,len=32"`
	SourceEpochID   *EpochSourceID         `wire:"8,custom,len=32,optional"`
}

// EpochContextOption contains the public inputs used to construct an epoch.
type EpochContextOption struct {
	SID             tss.SessionID
	RID             tss.SessionID
	Threshold       int
	Parties         tss.PartySet
	PublicShares    []EpochPublicShare
	AuxiliaryDigest []byte
	SourceEpochID   []byte
}

// NewEpochContext derives dynamic Shamir identifiers and the canonical epoch
// ID from option. Inputs must already use canonical party order.
func NewEpochContext(option EpochContextOption) (*EpochContext, error) {
	if !option.SID.Valid() {
		return nil, errors.New("epoch context: invalid sid")
	}
	if !option.RID.Valid() {
		return nil, errors.New("epoch context: invalid rid")
	}
	if err := wire.ValidateStrictSortedIDs(option.Parties); err != nil {
		return nil, fmt.Errorf("epoch context: invalid parties: %w", err)
	}
	if option.Threshold <= 0 || option.Threshold > len(option.Parties) {
		return nil, fmt.Errorf("epoch context: threshold %d outside [1, %d]", option.Threshold, len(option.Parties))
	}
	if len(option.PublicShares) != len(option.Parties) {
		return nil, fmt.Errorf("epoch context: public share count %d != party count %d", len(option.PublicShares), len(option.Parties))
	}
	if len(option.AuxiliaryDigest) != sha256.Size {
		return nil, fmt.Errorf("epoch context: auxiliary digest must be %d bytes", sha256.Size)
	}
	sourceEpochID, err := newEpochSourceID(option.SourceEpochID)
	if err != nil {
		return nil, fmt.Errorf("epoch context: %w", err)
	}

	ctx := &EpochContext{
		SID:             option.SID,
		RID:             option.RID,
		Threshold:       option.Threshold,
		Identifiers:     make([]EpochPartyIdentifier, len(option.Parties)),
		PublicShares:    make([]EpochPublicShare, len(option.PublicShares)),
		AuxiliaryDigest: bytes.Clone(option.AuxiliaryDigest),
		SourceEpochID:   sourceEpochID,
	}
	seenIdentifiers := make(map[[secp.ScalarSize]byte]struct{}, len(option.Parties))
	for i, party := range option.Parties {
		if option.PublicShares[i].Party != party {
			return nil, fmt.Errorf("epoch context: public share party %d at index %d, want %d", option.PublicShares[i].Party, i, party)
		}
		identifier, err := DeriveEpochIdentifier(option.SID, option.RID, party)
		if err != nil {
			return nil, err
		}
		var identifierKey [secp.ScalarSize]byte
		copy(identifierKey[:], identifier)
		if _, ok := seenIdentifiers[identifierKey]; ok {
			return nil, errors.New("epoch context: duplicate Shamir identifier")
		}
		seenIdentifiers[identifierKey] = struct{}{}
		ctx.Identifiers[i] = EpochPartyIdentifier{Party: party, Identifier: identifier}
		ctx.PublicShares[i] = option.PublicShares[i].Clone()
	}
	ctx.EpochID = ctx.computeID()
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	return ctx, nil
}

// WireType returns the canonical epoch-context wire type.
func (EpochContext) WireType() string { return epochContextWireType }

// WireVersion returns the canonical epoch-context wire version.
func (EpochContext) WireVersion() uint16 { return epochContextWireVersion }

// MarshalBinary encodes the epoch context using canonical TLV.
func (e EpochContext) MarshalBinary() ([]byte, error) {
	return e.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the epoch context with explicit limits.
func (e EpochContext) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := e.ValidateWithLimits(limits); err != nil {
		return nil, err
	}
	return wire.Marshal(e, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes a canonical epoch context.
func (e *EpochContext) UnmarshalBinary(in []byte) error {
	return e.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical epoch context with explicit
// limits without retaining references to in.
func (e *EpochContext) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if e == nil {
		return errors.New("nil epoch context")
	}
	var decoded EpochContext
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedKeyShareBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := decoded.ValidateWithLimits(limits); err != nil {
		return err
	}
	*e = *decoded.Clone()
	return nil
}

// Clone returns a deep caller-owned copy of the epoch context.
func (e *EpochContext) Clone() *EpochContext {
	if e == nil {
		return nil
	}
	out := &EpochContext{
		SID:             e.SID,
		RID:             e.RID,
		Threshold:       e.Threshold,
		EpochID:         bytes.Clone(e.EpochID),
		Identifiers:     make([]EpochPartyIdentifier, len(e.Identifiers)),
		PublicShares:    make([]EpochPublicShare, len(e.PublicShares)),
		AuxiliaryDigest: bytes.Clone(e.AuxiliaryDigest),
		SourceEpochID:   e.SourceEpochID.Clone(),
	}
	for i := range e.Identifiers {
		out.Identifiers[i] = e.Identifiers[i].Clone()
	}
	for i := range e.PublicShares {
		out.PublicShares[i] = e.PublicShares[i].Clone()
	}
	return out
}

// SourceEpochIDBytes returns the optional source epoch identity as a
// caller-owned byte slice. The second result reports whether it was present.
func (e *EpochContext) SourceEpochIDBytes() ([]byte, bool) {
	if e == nil || e.SourceEpochID == nil {
		return nil, false
	}
	return e.SourceEpochID.Bytes(), true
}

// Identifier returns a caller-owned epoch identifier for party.
func (e *EpochContext) Identifier(party tss.PartyID) ([]byte, bool) {
	if e == nil {
		return nil, false
	}
	for i := range e.Identifiers {
		if e.Identifiers[i].Party == party {
			return bytes.Clone(e.Identifiers[i].Identifier), true
		}
	}
	return nil, false
}

// PublicShare returns a caller-owned epoch public share for party.
func (e *EpochContext) PublicShare(party tss.PartyID) (EpochPublicShare, bool) {
	if e == nil {
		return EpochPublicShare{}, false
	}
	for i := range e.PublicShares {
		if e.PublicShares[i].Party == party {
			return e.PublicShares[i].Clone(), true
		}
	}
	return EpochPublicShare{}, false
}

// Validate checks canonical epoch identity and field bindings.
func (e EpochContext) Validate() error {
	return e.ValidateWithLimits(DefaultLimits())
}

// ValidateWithLimits checks canonical epoch identity and resource bounds.
func (e EpochContext) ValidateWithLimits(limits Limits) error {
	if !e.SID.Valid() {
		return errors.New("epoch context: invalid sid")
	}
	if !e.RID.Valid() {
		return errors.New("epoch context: invalid rid")
	}
	if len(e.EpochID) != sha256.Size {
		return fmt.Errorf("epoch context: epoch id must be %d bytes", sha256.Size)
	}
	var zeroEpochID [sha256.Size]byte
	if bytes.Equal(e.EpochID, zeroEpochID[:]) {
		return errors.New("epoch context: epoch id must be non-zero")
	}
	if len(e.AuxiliaryDigest) != sha256.Size {
		return fmt.Errorf("epoch context: auxiliary digest must be %d bytes", sha256.Size)
	}
	if e.Threshold <= 0 || e.Threshold > len(e.Identifiers) {
		return fmt.Errorf("epoch context: threshold %d outside [1, %d]", e.Threshold, len(e.Identifiers))
	}
	if e.Threshold > limits.Threshold.MaxThreshold {
		return fmt.Errorf("epoch context: threshold %d exceeds limit %d", e.Threshold, limits.Threshold.MaxThreshold)
	}
	if e.SourceEpochID != nil {
		var zeroSourceEpochID EpochSourceID
		if *e.SourceEpochID == zeroSourceEpochID {
			return errors.New("epoch context: source epoch id must be non-zero")
		}
	}
	if e.SourceEpochID != nil && bytes.Equal(e.SourceEpochID[:], e.EpochID) {
		return errors.New("epoch context: source epoch id equals epoch id")
	}
	if len(e.Identifiers) == 0 || len(e.Identifiers) != len(e.PublicShares) {
		return errors.New("epoch context: identifier and public-share vectors must be non-empty and equal length")
	}
	if len(e.Identifiers) > limits.Threshold.MaxParties {
		return fmt.Errorf("epoch context: too many parties: %d > %d", len(e.Identifiers), limits.Threshold.MaxParties)
	}

	seenIdentifiers := make(map[[secp.ScalarSize]byte]struct{}, len(e.Identifiers))
	var last tss.PartyID
	for i := range e.Identifiers {
		identifier := e.Identifiers[i]
		publicShare := e.PublicShares[i]
		if identifier.Party == tss.BroadcastPartyId || publicShare.Party == tss.BroadcastPartyId {
			return errors.New("epoch context: party id 0 is reserved")
		}
		if i > 0 && identifier.Party <= last {
			return errors.New("epoch context: parties must be strictly increasing")
		}
		if publicShare.Party != identifier.Party {
			return fmt.Errorf("epoch context: public share party %d does not match identifier party %d", publicShare.Party, identifier.Party)
		}
		if len(publicShare.PublicKey) > limits.Curve.MaxPointBytes {
			return fmt.Errorf("epoch context: public share for party %d too large", publicShare.Party)
		}
		if _, err := secp.PointFromBytes(publicShare.PublicKey); err != nil {
			return fmt.Errorf("epoch context: invalid public share for party %d: %w", publicShare.Party, err)
		}
		parsed, err := shamir.IdentifierFromBytes(identifier.Identifier)
		if err != nil {
			return fmt.Errorf("epoch context: party %d: %w", identifier.Party, err)
		}
		parsedBytes := parsed.Bytes()
		var identifierKey [secp.ScalarSize]byte
		copy(identifierKey[:], parsedBytes)
		clear(parsedBytes)
		if _, ok := seenIdentifiers[identifierKey]; ok {
			return errors.New("epoch context: duplicate Shamir identifier")
		}
		seenIdentifiers[identifierKey] = struct{}{}
		expected, err := DeriveEpochIdentifier(e.SID, e.RID, identifier.Party)
		if err != nil {
			return err
		}
		if !bytes.Equal(expected, identifier.Identifier) {
			return fmt.Errorf("epoch context: identifier mismatch for party %d", identifier.Party)
		}
		last = identifier.Party
	}
	expectedEpochID := e.computeID()
	if !bytes.Equal(expectedEpochID, e.EpochID) {
		return errors.New("epoch context: epoch id mismatch")
	}
	return nil
}

// DeriveEpochIdentifier hashes sid, rid, and party into a canonical non-zero
// secp256k1 scalar. A zero candidate is terminal; candidates at or above the
// scalar order are retried with a domain-bound counter at most 256 times.
func DeriveEpochIdentifier(sid, rid tss.SessionID, party tss.PartyID) ([]byte, error) {
	if !sid.Valid() {
		return nil, errors.New("derive epoch identifier: invalid sid")
	}
	if !rid.Valid() {
		return nil, errors.New("derive epoch identifier: invalid rid")
	}
	if party == tss.BroadcastPartyId {
		return nil, errors.New("derive epoch identifier: party id 0 is reserved")
	}
	return deriveEpochIdentifierWithDigest(func(counter uint32) []byte {
		t := transcript.New(epochIdentifierHashLabel)
		t.AppendBytes("sid", sid[:])
		t.AppendBytes("rid", rid[:])
		t.AppendUint32("party", party)
		t.AppendUint32("counter", counter)
		return t.Sum()
	})
}

func deriveEpochIdentifierWithDigest(digest func(uint32) []byte) ([]byte, error) {
	if digest == nil {
		return nil, errors.New("derive epoch identifier: nil digest function")
	}
	for counter := range uint32(maxEpochIdentifierCandidates) {
		candidate := digest(counter)
		if len(candidate) != sha256.Size {
			return nil, fmt.Errorf("derive epoch identifier: hash candidate must be %d bytes", sha256.Size)
		}
		var zero [sha256.Size]byte
		if bytes.Equal(candidate, zero[:]) {
			return nil, errEpochIdentifierZero
		}
		identifier, err := shamir.IdentifierFromBytes(candidate)
		if err == nil {
			return identifier.Bytes(), nil
		}
	}
	return nil, errEpochIdentifierExhausted
}

func (e EpochContext) computeID() []byte {
	t := transcript.New(epochContextIDLabel)
	t.AppendBytes("sid", e.SID[:])
	t.AppendBytes("rid", e.RID[:])
	t.AppendUint32("threshold", uint32(e.Threshold))
	t.AppendBool("has_source_epoch_id", e.SourceEpochID != nil)
	if e.SourceEpochID != nil {
		t.AppendBytes("source_epoch_id", e.SourceEpochID[:])
	}
	t.AppendBytes("auxiliary_digest", e.AuxiliaryDigest)
	for i := range e.Identifiers {
		t.AppendUint32("identifier_party", e.Identifiers[i].Party)
		t.AppendBytes("identifier", e.Identifiers[i].Identifier)
		t.AppendUint32("public_share_party", e.PublicShares[i].Party)
		t.AppendBytes("public_share", e.PublicShares[i].PublicKey)
	}
	return t.Sum()
}

func computeEpochAuxiliaryDigest(parties tss.PartySet, partyData map[tss.PartyID]keySharePartyData) ([]byte, error) {
	if err := wire.ValidateStrictSortedIDs(parties); err != nil {
		return nil, fmt.Errorf("epoch auxiliary digest: invalid parties: %w", err)
	}
	t := transcript.New(epochAuxiliaryDigestLabel)
	t.AppendUint32("party_count", uint32(len(parties)))
	for _, party := range parties {
		data, ok := partyData[party]
		if !ok {
			return nil, fmt.Errorf("epoch auxiliary digest: missing party %d", party)
		}
		if data.PaillierPublicKey == nil {
			return nil, fmt.Errorf("epoch auxiliary digest: missing Paillier public key for party %d", party)
		}
		if data.RingPedersenParams == nil {
			return nil, fmt.Errorf("epoch auxiliary digest: missing Ring-Pedersen parameters for party %d", party)
		}
		paillierPublicKey, err := data.PaillierPublicKey.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("epoch auxiliary digest: encode Paillier public key for party %d: %w", party, err)
		}
		ringPedersenParams, err := data.RingPedersenParams.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("epoch auxiliary digest: encode Ring-Pedersen parameters for party %d: %w", party, err)
		}
		t.AppendUint32("party", party)
		t.AppendBytes("paillier_public_key", paillierPublicKey)
		t.AppendBytes("ring_pedersen_params", ringPedersenParams)
	}
	return t.Sum(), nil
}

func evaluateCommitmentPointsAtIdentifier(commitments []*secp.Point, identifier []byte) (*secp.Point, error) {
	x, err := secp.ScalarFromBytes(identifier)
	if err != nil {
		return nil, fmt.Errorf("invalid commitment evaluation identifier: %w", err)
	}
	power := secp.ScalarOne()
	acc := secp.NewInfinity()
	for _, commitment := range commitments {
		if commitment != nil {
			acc = secp.Add(acc, secp.ScalarMult(commitment, power))
		}
		power = secp.ScalarMul(power, x)
	}
	return acc, nil
}

func (state *keyShareState) validateEpochBinding(limits Limits) error {
	if state == nil || state.Epoch == nil {
		return errors.New("missing epoch context")
	}
	if err := state.Epoch.ValidateWithLimits(limits); err != nil {
		return err
	}
	// Epoch.SID is the stable lineage identity. PaillierProofSessionID is the
	// concrete run session that created this epoch. They are equal only for an
	// initial keygen/import epoch; refresh, reshare, and child derivation must
	// preserve the former while using a fresh authenticated run session for the
	// latter.
	if !state.PaillierProofSessionID.Valid() {
		return errors.New("missing key-share auxiliary proof run session")
	}
	if state.Epoch.Threshold != state.Threshold {
		return errors.New("epoch threshold does not match key share")
	}
	if len(state.Epoch.Identifiers) != len(state.Parties) {
		return errors.New("epoch context party count does not match key share")
	}
	auxiliaryDigest, err := computeEpochAuxiliaryDigest(state.Parties, state.PartyData)
	if err != nil {
		return err
	}
	if !bytes.Equal(auxiliaryDigest, state.Epoch.AuxiliaryDigest) {
		return errors.New("epoch auxiliary digest does not match key share")
	}
	for i, party := range state.Parties {
		identifier := state.Epoch.Identifiers[i]
		publicShare := state.Epoch.PublicShares[i]
		if identifier.Party != party || publicShare.Party != party {
			return fmt.Errorf("epoch context party at index %d does not match key-share party %d", i, party)
		}
		partyData, ok := state.PartyData[party]
		if !ok {
			return fmt.Errorf("missing party data for epoch participant %d", party)
		}
		if !bytes.Equal(publicShare.PublicKey, partyData.VerificationShare) {
			return fmt.Errorf("epoch public share for party %d does not match key-share party data", party)
		}
		expected, err := evaluateCommitmentPointsAtIdentifier(state.GroupCommitments, identifier.Identifier)
		if err != nil {
			return fmt.Errorf("evaluate epoch public share for party %d: %w", party, err)
		}
		expectedBytes, err := secp.PointBytes(expected)
		if err != nil {
			return fmt.Errorf("encode epoch public share for party %d: %w", party, err)
		}
		if !bytes.Equal(expectedBytes, publicShare.PublicKey) {
			return fmt.Errorf("epoch public share for party %d does not match group commitments", party)
		}
	}
	return nil
}
