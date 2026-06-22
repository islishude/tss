package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
)

const (
	signAttemptRecordVersion       uint16 = 1
	signAttemptWireVersion         uint16 = 1
	signAttemptWireType                   = "cggmp21.secp256k1.sign-attempt"
	signAttemptIntentLabel                = "cggmp21-secp256k1-sign-attempt-intent-v1"
	signAttemptHashLabel                  = "cggmp21-secp256k1-sign-attempt-hash-v1"
	signAttemptSignerSetLabel             = "cggmp21-secp256k1-sign-attempt-signers-v1"
	signAttemptDeliveryPolicyLabel        = "cggmp21-secp256k1-sign-attempt-delivery-policy-v1"
)

// SignAttemptCommitStatus reports whether CommitSignAttempt created or reused
// the durable record.
type SignAttemptCommitStatus uint8

const (
	// SignAttemptCreated reports that CommitSignAttempt created a new attempt.
	SignAttemptCreated SignAttemptCommitStatus = iota
	// SignAttemptExistingSame reports that CommitSignAttempt found the same attempt.
	SignAttemptExistingSame
)

// SignAttemptCommit is the result of a successful durable attempt commit.
type SignAttemptCommit struct {
	Status SignAttemptCommitStatus
	Record SignAttemptRecord
}

// SignAttemptDeliveryPolicy snapshots the delivery policy that applies to the
// committed outbound signing envelope.
type SignAttemptDeliveryPolicy struct {
	Mode                 tss.DeliveryMode               `wire:"1,u8"`
	Confidentiality      tss.ConfidentialityPolicy      `wire:"2,u8"`
	BroadcastConsistency tss.BroadcastConsistencyPolicy `wire:"3,u8"`
	Recipients           tss.PartySet                   `wire:"4,u32list,max_items=parties"`
}

// Clone returns an independent copy of the delivery policy snapshot.
func (p SignAttemptDeliveryPolicy) Clone() SignAttemptDeliveryPolicy {
	return SignAttemptDeliveryPolicy{
		Mode:                 p.Mode,
		Confidentiality:      p.Confidentiality,
		BroadcastConsistency: p.BroadcastConsistency,
		Recipients:           slices.Clone(p.Recipients),
	}
}

// Equal reports whether p and other contain the same delivery policy snapshot.
func (p SignAttemptDeliveryPolicy) Equal(other SignAttemptDeliveryPolicy) bool {
	return p.Mode == other.Mode &&
		p.Confidentiality == other.Confidentiality &&
		p.BroadcastConsistency == other.BroadcastConsistency &&
		slices.Equal(p.Recipients, other.Recipients)
}

// SignAttemptDeliveryState tracks durable outbox delivery progress for one
// committed attempt.
type SignAttemptDeliveryState struct {
	Acks             []tss.BroadcastAck        `wire:"1,recordlist,max_items=parties"`
	Certificate      *tss.BroadcastCertificate `wire:"2,nested,optional,max_bytes=envelope"`
	DeliveryComplete bool                      `wire:"3,bool"`
}

// Clone returns an independent copy of the delivery state.
func (s SignAttemptDeliveryState) Clone() SignAttemptDeliveryState {
	return SignAttemptDeliveryState{
		Acks:             tss.CloneSlice(s.Acks),
		Certificate:      s.Certificate.Clone(),
		DeliveryComplete: s.DeliveryComplete,
	}
}

// Equal reports whether s and other contain the same durable delivery state.
func (s SignAttemptDeliveryState) Equal(other SignAttemptDeliveryState) bool {
	if s.DeliveryComplete != other.DeliveryComplete || len(s.Acks) != len(other.Acks) {
		return false
	}
	for i := range s.Acks {
		if !s.Acks[i].Equal(other.Acks[i]) {
			return false
		}
	}
	return s.Certificate.Equal(other.Certificate)
}

// SignAttemptDeliveryUpdate records one durable outbox delivery progress update.
type SignAttemptDeliveryUpdate struct {
	PresignContentID []byte
	AttemptHash      []byte
	Ack              *tss.BroadcastAck
	Certificate      *tss.BroadcastCertificate
}

// SignAttemptBurn is a durable tombstone for a presign that must not be used.
type SignAttemptBurn struct {
	PresignContentID []byte
	Reason           string
}

func validateSignAttemptBurn(burn SignAttemptBurn) error {
	if len(burn.PresignContentID) != sha256.Size {
		return errors.New("invalid burn presign content ID")
	}
	if burn.Reason == "" {
		return errors.New("empty burn reason")
	}
	if len(burn.Reason) > 256 || !utf8.ValidString(burn.Reason) {
		return errors.New("invalid burn reason")
	}
	for _, r := range burn.Reason {
		if r < 0x20 || r == 0x7f {
			return errors.New("burn reason contains control characters")
		}
	}
	return nil
}

// SignAttemptRecord is the canonical durable binding between one presign and
// one online signing intent. CanonicalBaseEnvelopeBytes contains a confidential
// partial signature and must be encrypted at rest. PresignContentID is
// secret-tainted and must not be logged or used directly as a public storage key.
type SignAttemptRecord struct {
	RecordVersion    uint16         `wire:"1,u16"`
	Protocol         tss.ProtocolID `wire:"2,string,max_bytes=protocol_name"`
	ProtocolVersion  uint16         `wire:"3,u16"`
	PresignContentID []byte         `wire:"4,bytes,len=32"` // Secret-derived presign content commitment.
	AttemptHash      []byte         `wire:"5,bytes,len=32"`
	IntentHash       []byte         `wire:"6,bytes,len=32"`

	SessionID     tss.SessionID `wire:"7,bytes,len=32"`
	Party         tss.PartyID   `wire:"8,u32"`
	SignerSetHash []byte        `wire:"9,bytes,len=32"`
	SignPlanHash  []byte        `wire:"10,bytes,len=32"`

	ContextHash       []byte `wire:"11,bytes,len=32"`
	Digest            []byte `wire:"12,bytes,len=32"`
	DigestBindingHash []byte `wire:"13,bytes,len=32"`

	CanonicalBaseEnvelopeBytes []byte `wire:"14,bytes,max_bytes=envelope"`
	CanonicalBaseEnvelopeHash  []byte `wire:"15,bytes,len=32"`
	EnvelopeDigest             []byte `wire:"16,bytes,len=32"`
	PayloadHash                []byte `wire:"17,bytes,len=32"`

	DeliveryPolicy SignAttemptDeliveryPolicy `wire:"18,record"`
	DeliveryState  SignAttemptDeliveryState  `wire:"19,record"`

	Completed           bool   `wire:"20,bool"`
	SignatureR          []byte `wire:"21,bytes,max_bytes=scalar"`
	SignatureS          []byte `wire:"22,bytes,max_bytes=scalar"`
	SignatureRecoveryID uint8  `wire:"23,u8"`
}

// Clone returns an independent copy of the sign-attempt record.
func (r SignAttemptRecord) Clone() SignAttemptRecord {
	return SignAttemptRecord{
		RecordVersion:              r.RecordVersion,
		Protocol:                   r.Protocol,
		ProtocolVersion:            r.ProtocolVersion,
		PresignContentID:           slices.Clone(r.PresignContentID),
		AttemptHash:                slices.Clone(r.AttemptHash),
		IntentHash:                 slices.Clone(r.IntentHash),
		SessionID:                  r.SessionID,
		Party:                      r.Party,
		SignerSetHash:              slices.Clone(r.SignerSetHash),
		SignPlanHash:               slices.Clone(r.SignPlanHash),
		ContextHash:                slices.Clone(r.ContextHash),
		Digest:                     slices.Clone(r.Digest),
		DigestBindingHash:          slices.Clone(r.DigestBindingHash),
		CanonicalBaseEnvelopeBytes: slices.Clone(r.CanonicalBaseEnvelopeBytes),
		CanonicalBaseEnvelopeHash:  slices.Clone(r.CanonicalBaseEnvelopeHash),
		EnvelopeDigest:             slices.Clone(r.EnvelopeDigest),
		PayloadHash:                slices.Clone(r.PayloadHash),
		DeliveryPolicy:             r.DeliveryPolicy.Clone(),
		DeliveryState:              r.DeliveryState.Clone(),
		Completed:                  r.Completed,
		SignatureR:                 slices.Clone(r.SignatureR),
		SignatureS:                 slices.Clone(r.SignatureS),
		SignatureRecoveryID:        r.SignatureRecoveryID,
	}
}

// Equal reports whether r and other contain the same canonical durable record,
// including delivery and completion state. It compares fields directly and does
// not validate either record.
func (r SignAttemptRecord) Equal(other SignAttemptRecord) bool {
	return r.SameBaseAttempt(other) &&
		r.DeliveryState.Equal(other.DeliveryState) &&
		r.Completed == other.Completed &&
		bytes.Equal(r.SignatureR, other.SignatureR) &&
		bytes.Equal(r.SignatureS, other.SignatureS) &&
		r.SignatureRecoveryID == other.SignatureRecoveryID
}

// SameAttempt reports whether r and other identify the same committed attempt.
// It compares the presign, intent, and attempt hashes only.
func (r SignAttemptRecord) SameAttempt(other SignAttemptRecord) bool {
	return bytes.Equal(r.PresignContentID, other.PresignContentID) &&
		bytes.Equal(r.IntentHash, other.IntentHash) &&
		bytes.Equal(r.AttemptHash, other.AttemptHash)
}

// SameBaseAttempt reports whether r and other contain the same immutable base
// attempt, excluding delivery progress and completion state.
func (r SignAttemptRecord) SameBaseAttempt(other SignAttemptRecord) bool {
	return r.RecordVersion == other.RecordVersion &&
		r.Protocol == other.Protocol &&
		r.ProtocolVersion == other.ProtocolVersion &&
		r.SessionID == other.SessionID &&
		r.Party == other.Party &&
		bytes.Equal(r.PresignContentID, other.PresignContentID) &&
		bytes.Equal(r.AttemptHash, other.AttemptHash) &&
		bytes.Equal(r.IntentHash, other.IntentHash) &&
		bytes.Equal(r.SignerSetHash, other.SignerSetHash) &&
		bytes.Equal(r.SignPlanHash, other.SignPlanHash) &&
		bytes.Equal(r.ContextHash, other.ContextHash) &&
		bytes.Equal(r.Digest, other.Digest) &&
		bytes.Equal(r.DigestBindingHash, other.DigestBindingHash) &&
		bytes.Equal(r.CanonicalBaseEnvelopeBytes, other.CanonicalBaseEnvelopeBytes) &&
		bytes.Equal(r.CanonicalBaseEnvelopeHash, other.CanonicalBaseEnvelopeHash) &&
		bytes.Equal(r.EnvelopeDigest, other.EnvelopeDigest) &&
		bytes.Equal(r.PayloadHash, other.PayloadHash) &&
		r.DeliveryPolicy.Equal(other.DeliveryPolicy)
}

// MarshalJSON rejects JSON encoding of confidential sign-attempt records.
func (r SignAttemptRecord) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 sign attempt contains a confidential partial; use MarshalBinary")
}

// UnmarshalJSON rejects JSON decoding of confidential sign-attempt records.
func (r *SignAttemptRecord) UnmarshalJSON([]byte) error {
	return errors.New("cggmp21 secp256k1 sign attempt requires canonical binary decoding")
}

// MarshalBinary encodes the sign-attempt record using canonical TLV.
func (r SignAttemptRecord) MarshalBinary() ([]byte, error) {
	return r.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the sign-attempt record using explicit local
// resource limits.
func (r SignAttemptRecord) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	if err := validateSignAttemptRecordWithLimits(r, limits); err != nil {
		return nil, err
	}
	return wire.Marshal(r, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalBinary decodes and validates a canonical sign-attempt record.
func (r *SignAttemptRecord) UnmarshalBinary(in []byte) error {
	return r.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes a canonical sign-attempt record into the
// receiver using explicit local resource limits.
func (r *SignAttemptRecord) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	if r == nil {
		return errors.New("nil sign attempt")
	}
	if len(in) == 0 {
		return errors.New("empty sign attempt")
	}
	if len(in) > limits.State.MaxSerializedSignAttemptBytes {
		return fmt.Errorf("sign attempt too large: %d > %d", len(in), limits.State.MaxSerializedSignAttemptBytes)
	}
	var decoded SignAttemptRecord
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return err
	}
	if err := validateSignAttemptRecordWithLimits(decoded, limits); err != nil {
		return err
	}
	*r = decoded
	return nil
}

// WireType returns the canonical sign-attempt wire type.
func (SignAttemptRecord) WireType() string { return signAttemptWireType }

// WireVersion returns the sign-attempt wire version.
func (SignAttemptRecord) WireVersion() uint16 { return signAttemptWireVersion }

// Validate checks the sign-attempt record against default local limits.
func (r SignAttemptRecord) Validate() error {
	return validateSignAttemptRecordWithLimits(r, DefaultLimits())
}

// ValidateWithLimits checks the sign-attempt record against explicit local
// resource limits.
func (r SignAttemptRecord) ValidateWithLimits(limits Limits) error {
	return validateSignAttemptRecordWithLimits(r, limits)
}

// SignAttemptResult supplies the final signature for an existing durable attempt.
type SignAttemptResult struct {
	PresignContentID []byte
	AttemptHash      []byte
	Signature        Signature
}

// Validate checks structural invariants for a SignAttemptResult.
func (r SignAttemptResult) Validate() error {
	if len(r.PresignContentID) != sha256.Size {
		return errors.New("invalid result presign content ID")
	}
	if len(r.AttemptHash) != sha256.Size {
		return errors.New("invalid result attempt hash")
	}
	if _, err := secp.ScalarFromBytes(r.Signature.R); err != nil {
		return fmt.Errorf("invalid result signature r: %w", err)
	}
	s, err := secp.ScalarFromBytes(r.Signature.S)
	if err != nil {
		return fmt.Errorf("invalid result signature s: %w", err)
	}
	if !secp.IsLowS(s) {
		return errors.New("invalid result signature s: high-S signatures are not canonical")
	}
	if r.Signature.RecoveryID > 3 {
		return errors.New("invalid result signature recovery id")
	}
	return nil
}

func validateSignAttemptRecordWithLimits(r SignAttemptRecord, limits Limits) error {
	if r.RecordVersion != signAttemptRecordVersion {
		return fmt.Errorf("%w: unexpected sign attempt record version %d", ErrSignAttemptCorrupt, r.RecordVersion)
	}
	if r.Protocol != tss.ProtocolCGGMP21Secp256k1 {
		return fmt.Errorf("%w: unexpected protocol %q", ErrSignAttemptCorrupt, r.Protocol)
	}
	if r.ProtocolVersion != tss.ProtocolVersion {
		return fmt.Errorf("%w: unexpected protocol version %d", ErrSignAttemptCorrupt, r.ProtocolVersion)
	}
	if len(r.PresignContentID) != sha256.Size || len(r.AttemptHash) != sha256.Size ||
		len(r.IntentHash) != sha256.Size || len(r.SignerSetHash) != sha256.Size ||
		len(r.SignPlanHash) != sha256.Size ||
		len(r.ContextHash) != sha256.Size || len(r.Digest) != sha256.Size ||
		len(r.DigestBindingHash) != sha256.Size || len(r.CanonicalBaseEnvelopeHash) != sha256.Size ||
		len(r.EnvelopeDigest) != sha256.Size || len(r.PayloadHash) != sha256.Size {
		return fmt.Errorf("%w: invalid fixed-length field", ErrSignAttemptCorrupt)
	}
	if !r.SessionID.Valid() || r.Party == tss.BroadcastPartyId {
		return fmt.Errorf("%w: invalid session or party", ErrSignAttemptCorrupt)
	}
	env, payload, err := decodeSignAttemptEnvelopeWithLimits(r.CanonicalBaseEnvelopeBytes, limits)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	envelopeHash := sha256.Sum256(r.CanonicalBaseEnvelopeBytes)
	if !bytes.Equal(r.CanonicalBaseEnvelopeHash, envelopeHash[:]) {
		return fmt.Errorf("%w: envelope hash mismatch", ErrSignAttemptCorrupt)
	}
	payloadHash := tss.PayloadHashFromEnvelope(env)
	if !bytes.Equal(r.PayloadHash, payloadHash[:]) {
		return fmt.Errorf("%w: payload hash mismatch", ErrSignAttemptCorrupt)
	}
	envelopeDigest := env.Digest()
	if !bytes.Equal(r.EnvelopeDigest, envelopeDigest[:]) {
		return fmt.Errorf("%w: envelope digest mismatch", ErrSignAttemptCorrupt)
	}
	if env.Protocol != r.Protocol || env.SessionID != r.SessionID ||
		env.Round != signStartRound || env.From != r.Party || env.To != tss.BroadcastPartyId || env.PayloadType != payloadSignPartial {
		return fmt.Errorf("%w: envelope binding mismatch", ErrSignAttemptCorrupt)
	}
	expectedDigestBinding := digestHash(r.Digest, r.ContextHash)
	if !bytes.Equal(r.DigestBindingHash, expectedDigestBinding) || !bytes.Equal(payload.DigestHash, r.DigestBindingHash) {
		return fmt.Errorf("%w: digest binding hash mismatch", ErrSignAttemptCorrupt)
	}
	if !bytes.Equal(payload.PresignContext, r.ContextHash) {
		return fmt.Errorf("%w: payload context hash mismatch", ErrSignAttemptCorrupt)
	}
	if !bytes.Equal(payload.PlanHash, r.SignPlanHash) {
		return fmt.Errorf("%w: payload sign plan hash mismatch", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptDeliveryPolicy(r, env); err != nil {
		return err
	}
	if err := validateSignAttemptDeliveryState(r, env); err != nil {
		return err
	}
	expectedIntent := signAttemptIntentHash(r)
	if !bytes.Equal(r.IntentHash, expectedIntent) {
		return fmt.Errorf("%w: intent hash mismatch", ErrSignAttemptCorrupt)
	}
	expectedAttempt := signAttemptHash(r)
	if !bytes.Equal(r.AttemptHash, expectedAttempt) {
		return fmt.Errorf("%w: attempt hash mismatch", ErrSignAttemptCorrupt)
	}
	if r.Completed {
		if _, err := secp.ScalarFromBytes(r.SignatureR); err != nil {
			return fmt.Errorf("%w: invalid signature r", ErrSignAttemptCorrupt)
		}
		s, err := secp.ScalarFromBytes(r.SignatureS)
		if err != nil {
			return fmt.Errorf("%w: invalid signature s", ErrSignAttemptCorrupt)
		}
		if !secp.IsLowS(s) {
			return fmt.Errorf("%w: high-S signature is not canonical", ErrSignAttemptCorrupt)
		}
		if r.SignatureRecoveryID > 3 {
			return fmt.Errorf("%w: invalid signature recovery id", ErrSignAttemptCorrupt)
		}
	} else if len(r.SignatureR) != 0 || len(r.SignatureS) != 0 || r.SignatureRecoveryID != 0 {
		return fmt.Errorf("%w: incomplete record contains signature", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateSignAttemptCandidate(r SignAttemptRecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Completed {
		return errors.New("sign attempt commit candidate is already completed")
	}
	if len(r.DeliveryState.Acks) != 0 || r.DeliveryState.Certificate != nil || r.DeliveryState.DeliveryComplete {
		return errors.New("sign attempt commit candidate contains delivery state")
	}
	return nil
}

func validateSignAttemptDeliveryPolicy(r SignAttemptRecord, env tss.Envelope) error {
	policy, err := CGGMP21Policies().Match(r.Protocol, env.Round, env.PayloadType)
	if err != nil {
		return fmt.Errorf("%w: sign attempt delivery policy lookup: %w", ErrSignAttemptCorrupt, err)
	}
	if r.DeliveryPolicy.Mode != policy.Mode ||
		r.DeliveryPolicy.Confidentiality != policy.Confidentiality ||
		r.DeliveryPolicy.BroadcastConsistency != policy.BroadcastConsistency {
		return fmt.Errorf("%w: delivery policy snapshot mismatch", ErrSignAttemptCorrupt)
	}
	if len(r.DeliveryPolicy.Recipients) == 0 {
		return fmt.Errorf("%w: empty delivery recipients", ErrSignAttemptCorrupt)
	}
	if err := wire.ValidateStrictSortedIDs(r.DeliveryPolicy.Recipients); err != nil {
		return fmt.Errorf("%w: invalid delivery recipients: %w", ErrSignAttemptCorrupt, err)
	}
	if !bytes.Equal(r.SignerSetHash, signAttemptSignerSetHash(r.DeliveryPolicy.Recipients)) {
		return fmt.Errorf("%w: delivery recipients do not match signer set", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateSignAttemptDeliveryState(r SignAttemptRecord, env tss.Envelope) error {
	recipients := r.DeliveryPolicy.Recipients
	seen := make(map[tss.PartyID]struct{}, len(r.DeliveryState.Acks))
	order := signAttemptRecipientOrder(r.DeliveryPolicy.Recipients)
	prev := -1
	for _, ack := range r.DeliveryState.Acks {
		if err := validateSignAttemptDeliveryAck(ack, env, recipients); err != nil {
			return err
		}
		index := order[ack.Party]
		if index <= prev {
			return fmt.Errorf("%w: non-canonical delivery ack order", ErrSignAttemptCorrupt)
		}
		prev = index
		if _, ok := seen[ack.Party]; ok {
			return fmt.Errorf("%w: duplicate delivery ack", ErrSignAttemptCorrupt)
		}
		seen[ack.Party] = struct{}{}
	}
	if r.DeliveryState.Certificate != nil {
		if err := r.DeliveryState.Certificate.VerifyStructure(env, recipients); err != nil {
			return fmt.Errorf("%w: delivery certificate: %w", ErrSignAttemptCorrupt, err)
		}
		if err := wire.ValidateStrictSortedIDs(r.DeliveryState.Certificate.Recipients); err != nil ||
			!slices.Equal(r.DeliveryState.Certificate.Recipients, r.DeliveryPolicy.Recipients) {
			return fmt.Errorf("%w: non-canonical delivery certificate recipients: %w", ErrSignAttemptCorrupt, err)
		}
		prev := -1
		for _, ack := range r.DeliveryState.Certificate.Acks {
			index := order[ack.Party]
			if index <= prev {
				return fmt.Errorf("%w: non-canonical delivery certificate ack order", ErrSignAttemptCorrupt)
			}
			prev = index
		}
		if _, err := r.DeliveryState.Certificate.MarshalBinary(); err != nil {
			return fmt.Errorf("%w: delivery certificate encoding: %w", ErrSignAttemptCorrupt, err)
		}
	}
	if r.DeliveryState.DeliveryComplete {
		if r.DeliveryState.Certificate == nil {
			return fmt.Errorf("%w: complete delivery without certificate", ErrSignAttemptCorrupt)
		}
		if len(r.DeliveryState.Acks) != len(r.DeliveryPolicy.Recipients) {
			return fmt.Errorf("%w: complete delivery without all acks", ErrSignAttemptCorrupt)
		}
	}
	return nil
}

func validateSignAttemptDeliveryAck(ack tss.BroadcastAck, env tss.Envelope, recipients tss.PartySet) error {
	if !recipients.Contains(ack.Party) {
		return fmt.Errorf("%w: delivery ack from non-recipient", ErrSignAttemptCorrupt)
	}
	if ack.PayloadHash != tss.PayloadHashFromEnvelope(env) || ack.EnvelopeDigest != env.Digest() {
		return fmt.Errorf("%w: delivery ack binding mismatch", ErrSignAttemptCorrupt)
	}
	return nil
}

func applySignAttemptDeliveryUpdate(record SignAttemptRecord, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if err := record.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	if len(update.PresignContentID) != sha256.Size || len(update.AttemptHash) != sha256.Size {
		return SignAttemptRecord{}, errors.New("invalid delivery update identity")
	}
	if !bytes.Equal(update.PresignContentID, record.PresignContentID) || !bytes.Equal(update.AttemptHash, record.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if update.Ack == nil && update.Certificate == nil {
		return record.Clone(), nil
	}
	env, _, err := decodeSignAttemptEnvelope(record.CanonicalBaseEnvelopeBytes)
	if err != nil {
		return SignAttemptRecord{}, fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
	}
	recipients := record.DeliveryPolicy.Recipients
	updated := record.Clone()
	if update.Ack != nil {
		if err := addSignAttemptDeliveryAck(&updated, update.Ack.Clone(), env, recipients); err != nil {
			return SignAttemptRecord{}, err
		}
	}
	if update.Certificate != nil {
		cert := update.Certificate.Clone()
		if err := cert.VerifyStructure(env, recipients); err != nil {
			return SignAttemptRecord{}, fmt.Errorf("%w: delivery certificate: %w", ErrSignAttemptCorrupt, err)
		}
		cert.Recipients = updated.DeliveryPolicy.Recipients.Clone()
		orderSignAttemptCertificateAcks(cert, updated.DeliveryPolicy.Recipients)
		if _, err := cert.MarshalBinary(); err != nil {
			return SignAttemptRecord{}, fmt.Errorf("%w: delivery certificate encoding: %w", ErrSignAttemptCorrupt, err)
		}
		for _, ack := range cert.Acks {
			if err := addSignAttemptDeliveryAck(&updated, ack.Clone(), env, recipients); err != nil {
				return SignAttemptRecord{}, err
			}
		}
		updated.DeliveryState.Certificate = cert
		updated.DeliveryState.DeliveryComplete = true
	}
	orderSignAttemptDeliveryAcks(&updated)
	if err := updated.Validate(); err != nil {
		return SignAttemptRecord{}, err
	}
	return updated, nil
}

func addSignAttemptDeliveryAck(record *SignAttemptRecord, ack tss.BroadcastAck, env tss.Envelope, recipients tss.PartySet) error {
	if err := validateSignAttemptDeliveryAck(ack, env, recipients); err != nil {
		return err
	}
	for _, existing := range record.DeliveryState.Acks {
		if existing.Party == ack.Party {
			return nil
		}
	}
	record.DeliveryState.Acks = append(record.DeliveryState.Acks, ack.Clone())
	return nil
}

func orderSignAttemptDeliveryAcks(record *SignAttemptRecord) {
	if len(record.DeliveryState.Acks) <= 1 {
		return
	}
	order := signAttemptRecipientOrder(record.DeliveryPolicy.Recipients)
	slices.SortStableFunc(record.DeliveryState.Acks, func(a, b tss.BroadcastAck) int {
		return order[a.Party] - order[b.Party]
	})
}

func orderSignAttemptCertificateAcks(cert *tss.BroadcastCertificate, recipients tss.PartySet) {
	if cert == nil || len(cert.Acks) <= 1 {
		return
	}
	order := signAttemptRecipientOrder(recipients)
	slices.SortStableFunc(cert.Acks, func(a, b tss.BroadcastAck) int {
		return order[a.Party] - order[b.Party]
	})
}

func signAttemptRecipientOrder(recipients tss.PartySet) map[tss.PartyID]int {
	order := make(map[tss.PartyID]int, len(recipients))
	for i, id := range recipients {
		order[id] = i
	}
	return order
}

func decodeSignAttemptEnvelope(raw []byte) (tss.Envelope, signPartialPayload, error) {
	return decodeSignAttemptEnvelopeWithLimits(raw, DefaultLimits())
}

func decodeSignAttemptEnvelopeWithLimits(raw []byte, limits Limits) (tss.Envelope, signPartialPayload, error) {
	var env tss.Envelope
	if err := env.UnmarshalBinary(raw); err != nil {
		return tss.Envelope{}, signPartialPayload{}, err
	}
	canonical, err := env.MarshalBinary()
	if err != nil {
		return tss.Envelope{}, signPartialPayload{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return tss.Envelope{}, signPartialPayload{}, errors.New("non-canonical envelope")
	}
	payload, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](env.Payload, limits)
	if err != nil {
		return tss.Envelope{}, payload, err
	}
	return env, payload, nil
}

func signAttemptIntentHash(r SignAttemptRecord) []byte {
	t := transcript.New(signAttemptIntentLabel)
	t.AppendUint16("record_version", r.RecordVersion)
	t.AppendString("protocol", string(r.Protocol))
	t.AppendUint16("protocol_version", r.ProtocolVersion)
	t.AppendBytes("presign_content_id", r.PresignContentID)
	t.AppendBytes("session_id", r.SessionID[:])
	t.AppendUint32("party", r.Party)
	t.AppendBytes("signer_set_hash", r.SignerSetHash)
	t.AppendBytes("sign_plan_hash", r.SignPlanHash)
	t.AppendBytes("context_hash", r.ContextHash)
	t.AppendBytes("digest", r.Digest)
	t.AppendBytes("digest_binding_hash", r.DigestBindingHash)
	return t.Sum()
}

func signAttemptHash(r SignAttemptRecord) []byte {
	t := transcript.New(signAttemptHashLabel)
	t.AppendBytes("intent_hash", r.IntentHash)
	t.AppendBytes("canonical_base_envelope_hash", r.CanonicalBaseEnvelopeHash)
	t.AppendBytes("envelope_digest", r.EnvelopeDigest)
	t.AppendBytes("payload_hash", r.PayloadHash)
	t.AppendBytes("delivery_policy_hash", signAttemptDeliveryPolicyHash(r.DeliveryPolicy))
	return t.Sum()
}

func signAttemptDeliveryPolicyHash(p SignAttemptDeliveryPolicy) []byte {
	t := transcript.New(signAttemptDeliveryPolicyLabel)
	t.AppendUint8("mode", uint8(p.Mode))
	t.AppendUint8("confidentiality", uint8(p.Confidentiality))
	t.AppendUint8("broadcast_consistency", uint8(p.BroadcastConsistency))
	t.AppendUint32List("recipients", p.Recipients)
	return t.Sum()
}

func signAttemptSignerSetHash(signers tss.PartySet) []byte {
	return tss.PartySetHash(signers, signAttemptSignerSetLabel)
}
