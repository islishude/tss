package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const (
	signAttemptRecordVersion       uint16 = 1
	signAttemptWireType                   = "cggmp21.secp256k1.sign-attempt"
	signAttemptCertificateWireType        = "cggmp21.secp256k1.sign-attempt.certificate"
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
	Mode                 tss.DeliveryMode
	Confidentiality      tss.ConfidentialityPolicy
	BroadcastConsistency tss.BroadcastConsistencyPolicy
	Recipients           tss.PartySet
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
	Acks             []tss.BroadcastAck
	Certificate      *tss.BroadcastCertificate
	DeliveryComplete bool
}

// Clone returns an independent copy of the delivery state.
func (s SignAttemptDeliveryState) Clone() SignAttemptDeliveryState {
	return SignAttemptDeliveryState{
		Acks:             tss.CloneSlices(s.Acks),
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
		if !broadcastAckEqual(s.Acks[i], other.Acks[i]) {
			return false
		}
	}
	return broadcastCertificateEqual(s.Certificate, other.Certificate)
}

// SignAttemptDeliveryUpdate records one durable outbox delivery progress update.
type SignAttemptDeliveryUpdate struct {
	PresignID   []byte
	AttemptHash []byte
	Ack         *tss.BroadcastAck
	Certificate *tss.BroadcastCertificate
}

// SignAttemptBurn is a durable tombstone for a presign that must not be used.
type SignAttemptBurn struct {
	PresignID []byte
	Reason    string
}

// SignAttemptRecord is the canonical durable binding between one presign and
// one online signing intent. CanonicalBaseEnvelopeBytes contains a confidential
// partial signature and must be encrypted at rest.
type SignAttemptRecord struct {
	RecordVersion uint16
	Protocol      tss.ProtocolID
	Version       uint16
	PresignID     []byte
	AttemptHash   []byte
	IntentHash    []byte

	SessionID     tss.SessionID
	Party         tss.PartyID
	SignerSetHash []byte
	SignPlanHash  []byte

	ContextHash       []byte
	Digest            []byte
	DigestBindingHash []byte
	LowS              bool

	CanonicalBaseEnvelopeBytes []byte
	CanonicalBaseEnvelopeHash  []byte
	EnvelopeDigest             []byte
	PayloadHash                []byte

	DeliveryPolicy SignAttemptDeliveryPolicy
	DeliveryState  SignAttemptDeliveryState

	Completed           bool
	SignatureR          []byte
	SignatureS          []byte
	SignatureRecoveryID uint8
}

// Clone returns an independent copy of the sign-attempt record.
func (r SignAttemptRecord) Clone() SignAttemptRecord {
	return SignAttemptRecord{
		RecordVersion:              r.RecordVersion,
		Protocol:                   r.Protocol,
		Version:                    r.Version,
		PresignID:                  slices.Clone(r.PresignID),
		AttemptHash:                slices.Clone(r.AttemptHash),
		IntentHash:                 slices.Clone(r.IntentHash),
		SessionID:                  r.SessionID,
		Party:                      r.Party,
		SignerSetHash:              slices.Clone(r.SignerSetHash),
		SignPlanHash:               slices.Clone(r.SignPlanHash),
		ContextHash:                slices.Clone(r.ContextHash),
		Digest:                     slices.Clone(r.Digest),
		DigestBindingHash:          slices.Clone(r.DigestBindingHash),
		LowS:                       r.LowS,
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
	return bytes.Equal(r.PresignID, other.PresignID) &&
		bytes.Equal(r.IntentHash, other.IntentHash) &&
		bytes.Equal(r.AttemptHash, other.AttemptHash)
}

// SameBaseAttempt reports whether r and other contain the same immutable base
// attempt, excluding delivery progress and completion state.
func (r SignAttemptRecord) SameBaseAttempt(other SignAttemptRecord) bool {
	return r.RecordVersion == other.RecordVersion &&
		r.Protocol == other.Protocol &&
		r.Version == other.Version &&
		r.SessionID == other.SessionID &&
		r.Party == other.Party &&
		r.LowS == other.LowS &&
		bytes.Equal(r.PresignID, other.PresignID) &&
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
	return wire.Marshal(signAttemptWireFromRecord(r), wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

// UnmarshalSignAttemptRecord decodes and validates a canonical sign-attempt record.
func UnmarshalSignAttemptRecord(in []byte) (SignAttemptRecord, error) {
	return UnmarshalSignAttemptRecordWithLimits(in, DefaultLimits())
}

// UnmarshalSignAttemptRecordWithLimits decodes a canonical sign-attempt record
// using explicit local resource limits.
func UnmarshalSignAttemptRecordWithLimits(in []byte, limits Limits) (SignAttemptRecord, error) {
	if len(in) == 0 {
		return SignAttemptRecord{}, errors.New("empty sign attempt")
	}
	if len(in) > limits.State.MaxSerializedSignAttemptBytes {
		return SignAttemptRecord{}, fmt.Errorf("sign attempt too large: %d > %d", len(in), limits.State.MaxSerializedSignAttemptBytes)
	}
	var w signAttemptWire
	if err := wire.Unmarshal(in, &w,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return SignAttemptRecord{}, err
	}
	sessionID, err := tss.SessionIDFromBytes(w.SessionID)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	record := SignAttemptRecord{
		RecordVersion:              w.RecordVersion,
		Protocol:                   tss.ProtocolID(w.Protocol),
		Version:                    w.Version,
		PresignID:                  w.PresignID,
		AttemptHash:                w.AttemptHash,
		IntentHash:                 w.IntentHash,
		SessionID:                  sessionID,
		Party:                      w.Party,
		SignerSetHash:              w.SignerSetHash,
		SignPlanHash:               w.SignPlanHash,
		ContextHash:                w.ContextHash,
		Digest:                     w.Digest,
		DigestBindingHash:          w.DigestBindingHash,
		LowS:                       w.LowS,
		CanonicalBaseEnvelopeBytes: w.CanonicalBaseEnvelopeBytes,
		CanonicalBaseEnvelopeHash:  w.CanonicalBaseEnvelopeHash,
		EnvelopeDigest:             w.EnvelopeDigest,
		PayloadHash:                w.PayloadHash,
		DeliveryPolicy: SignAttemptDeliveryPolicy{
			Mode:                 tss.DeliveryMode(w.DeliveryMode),
			Confidentiality:      tss.ConfidentialityPolicy(w.Confidentiality),
			BroadcastConsistency: tss.BroadcastConsistencyPolicy(w.BroadcastConsistency),
			Recipients:           w.Recipients,
		},
		DeliveryState: SignAttemptDeliveryState{
			Acks:             signAttemptAcksFromWire(w.Acks),
			Certificate:      signAttemptCertificateFromWire(w.Certificate),
			DeliveryComplete: w.DeliveryComplete,
		},
		Completed:           w.Completed,
		SignatureR:          w.SignatureR,
		SignatureS:          w.SignatureS,
		SignatureRecoveryID: w.SignatureRecoveryID,
	}
	if err := validateSignAttemptRecordWithLimits(record, limits); err != nil {
		return SignAttemptRecord{}, err
	}
	return record, nil
}

// SignAttemptResult supplies the final signature for an existing durable attempt.
type SignAttemptResult struct {
	PresignID   []byte
	AttemptHash []byte
	Signature   Signature
}

func (r SignAttemptResult) validate() error {
	if len(r.PresignID) != sha256.Size {
		return errors.New("invalid result presign ID")
	}
	if len(r.AttemptHash) != sha256.Size {
		return errors.New("invalid result attempt hash")
	}
	if _, err := scalarBytesStrict(r.Signature.R); err != nil {
		return fmt.Errorf("invalid result signature r: %w", err)
	}
	if _, err := scalarBytesStrict(r.Signature.S); err != nil {
		return fmt.Errorf("invalid result signature s: %w", err)
	}
	if r.Signature.RecoveryID > 3 {
		return errors.New("invalid result signature recovery id")
	}
	return nil
}

type signAttemptWire struct {
	RecordVersion              uint16      `wire:"1,u16"`
	Protocol                   string      `wire:"2,string"`
	Version                    uint16      `wire:"3,u16"`
	PresignID                  []byte      `wire:"4,bytes,len=32"`
	AttemptHash                []byte      `wire:"5,bytes,len=32"`
	IntentHash                 []byte      `wire:"6,bytes,len=32"`
	SessionID                  []byte      `wire:"7,bytes,len=32"`
	Party                      tss.PartyID `wire:"8,u32"`
	SignerSetHash              []byte      `wire:"9,bytes,len=32"`
	SignPlanHash               []byte      `wire:"10,bytes,len=32"`
	ContextHash                []byte      `wire:"11,bytes,len=32"`
	Digest                     []byte      `wire:"12,bytes,len=32"`
	DigestBindingHash          []byte      `wire:"13,bytes,len=32"`
	LowS                       bool        `wire:"14,bool"`
	CanonicalBaseEnvelopeBytes []byte      `wire:"15,bytes,max_bytes=envelope"`
	CanonicalBaseEnvelopeHash  []byte      `wire:"16,bytes,len=32"`
	EnvelopeDigest             []byte      `wire:"17,bytes,len=32"`
	PayloadHash                []byte      `wire:"18,bytes,len=32"`
	DeliveryMode               uint8       `wire:"19,u8"`
	Confidentiality            uint8       `wire:"20,u8"`
	BroadcastConsistency       uint8       `wire:"21,u8"`
	Recipients                 []uint32    `wire:"22,u32list"`
	Acks                       []ackWire   `wire:"23,recordlist"`
	Certificate                []byte      `wire:"24,bytes,max_bytes=envelope"`
	DeliveryComplete           bool        `wire:"25,bool"`
	Completed                  bool        `wire:"26,bool"`
	SignatureR                 []byte      `wire:"27,bytes,max_bytes=scalar"`
	SignatureS                 []byte      `wire:"28,bytes,max_bytes=scalar"`
	SignatureRecoveryID        uint8       `wire:"29,u8"`
}

// WireType returns the canonical sign-attempt wire type.
func (signAttemptWire) WireType() string { return signAttemptWireType }

// WireVersion returns the sign-attempt wire version.
func (signAttemptWire) WireVersion() uint16 { return tss.Version }

type ackWire struct {
	Party          tss.PartyID `wire:"1,u32"`
	PayloadHash    []byte      `wire:"2,bytes,len=32"`
	EnvelopeDigest []byte      `wire:"3,bytes,len=32"`
	Signature      []byte      `wire:"4,bytes"`
}

type certWire struct {
	Protocol       string    `wire:"1,string"`
	SessionID      []byte    `wire:"2,bytes,len=32"`
	Round          uint8     `wire:"3,u8"`
	From           uint32    `wire:"4,u32"`
	PayloadType    string    `wire:"5,string"`
	PayloadHash    []byte    `wire:"6,bytes,len=32"`
	EnvelopeDigest []byte    `wire:"7,bytes,len=32"`
	Recipients     []uint32  `wire:"8,u32list"`
	Acks           []ackWire `wire:"9,recordlist"`
}

// WireType returns the canonical certificate wire type.
func (certWire) WireType() string { return signAttemptCertificateWireType }

// WireVersion returns the certificate wire version.
func (certWire) WireVersion() uint16 { return tss.Version }

func signAttemptWireFromRecord(r SignAttemptRecord) signAttemptWire {
	return signAttemptWire{
		RecordVersion:              r.RecordVersion,
		Protocol:                   string(r.Protocol),
		Version:                    r.Version,
		PresignID:                  r.PresignID,
		AttemptHash:                r.AttemptHash,
		IntentHash:                 r.IntentHash,
		SessionID:                  r.SessionID[:],
		Party:                      r.Party,
		SignerSetHash:              r.SignerSetHash,
		SignPlanHash:               r.SignPlanHash,
		ContextHash:                r.ContextHash,
		Digest:                     r.Digest,
		DigestBindingHash:          r.DigestBindingHash,
		LowS:                       r.LowS,
		CanonicalBaseEnvelopeBytes: r.CanonicalBaseEnvelopeBytes,
		CanonicalBaseEnvelopeHash:  r.CanonicalBaseEnvelopeHash,
		EnvelopeDigest:             r.EnvelopeDigest,
		PayloadHash:                r.PayloadHash,
		DeliveryMode:               uint8(r.DeliveryPolicy.Mode),
		Confidentiality:            uint8(r.DeliveryPolicy.Confidentiality),
		BroadcastConsistency:       uint8(r.DeliveryPolicy.BroadcastConsistency),
		Recipients:                 r.DeliveryPolicy.Recipients,
		Acks:                       signAttemptAcksToWire(r.DeliveryState.Acks),
		Certificate:                signAttemptCertificateToWire(r.DeliveryState.Certificate),
		DeliveryComplete:           r.DeliveryState.DeliveryComplete,
		Completed:                  r.Completed,
		SignatureR:                 r.SignatureR,
		SignatureS:                 r.SignatureS,
		SignatureRecoveryID:        r.SignatureRecoveryID,
	}
}

func validateSignAttemptRecord(r SignAttemptRecord) error {
	return validateSignAttemptRecordWithLimits(r, DefaultLimits())
}

func validateSignAttemptRecordWithLimits(r SignAttemptRecord, limits Limits) error {
	if r.RecordVersion != signAttemptRecordVersion {
		return fmt.Errorf("%w: unexpected sign attempt record version %d", ErrSignAttemptCorrupt, r.RecordVersion)
	}
	if r.Protocol != tss.ProtocolCGGMP21Secp256k1 {
		return fmt.Errorf("%w: unexpected protocol %q", ErrSignAttemptCorrupt, r.Protocol)
	}
	if r.Version != tss.Version {
		return fmt.Errorf("%w: unexpected version %d", ErrSignAttemptCorrupt, r.Version)
	}
	if len(r.PresignID) != sha256.Size || len(r.AttemptHash) != sha256.Size ||
		len(r.IntentHash) != sha256.Size || len(r.SignerSetHash) != sha256.Size ||
		len(r.SignPlanHash) != sha256.Size ||
		len(r.ContextHash) != sha256.Size || len(r.Digest) != sha256.Size ||
		len(r.DigestBindingHash) != sha256.Size || len(r.CanonicalBaseEnvelopeHash) != sha256.Size ||
		len(r.EnvelopeDigest) != sha256.Size || len(r.PayloadHash) != sha256.Size {
		return fmt.Errorf("%w: invalid fixed-length field", ErrSignAttemptCorrupt)
	}
	if !r.SessionID.Valid() || r.Party == 0 {
		return fmt.Errorf("%w: invalid session or party", ErrSignAttemptCorrupt)
	}
	if len(r.CanonicalBaseEnvelopeBytes) == 0 || len(r.CanonicalBaseEnvelopeBytes) > tss.DefaultMaxEnvelopeBytes {
		return fmt.Errorf("%w: invalid envelope length", ErrSignAttemptCorrupt)
	}
	env, err := decodeSignAttemptEnvelopeWithLimits(r.CanonicalBaseEnvelopeBytes, limits)
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
	if env.Protocol != r.Protocol || env.Version != r.Version || env.SessionID != r.SessionID ||
		env.Round != 1 || env.From != r.Party || env.To != 0 || env.PayloadType != payloadSignPartial {
		return fmt.Errorf("%w: envelope binding mismatch", ErrSignAttemptCorrupt)
	}
	payload, err := unmarshalSignPartialPayloadWithLimits(env.Payload, limits)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignAttemptCorrupt, err)
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
		if _, err := scalarBytesStrict(r.SignatureR); err != nil {
			return fmt.Errorf("%w: invalid signature r", ErrSignAttemptCorrupt)
		}
		if _, err := scalarBytesStrict(r.SignatureS); err != nil {
			return fmt.Errorf("%w: invalid signature s", ErrSignAttemptCorrupt)
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
	if err := validateSignAttemptRecord(r); err != nil {
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
		if _, err := marshalSignAttemptCertificate(r.DeliveryState.Certificate); err != nil {
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
	if err := validateSignAttemptRecord(record); err != nil {
		return SignAttemptRecord{}, err
	}
	if len(update.PresignID) != sha256.Size || len(update.AttemptHash) != sha256.Size {
		return SignAttemptRecord{}, errors.New("invalid delivery update identity")
	}
	if !bytes.Equal(update.PresignID, record.PresignID) || !bytes.Equal(update.AttemptHash, record.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if update.Ack == nil && update.Certificate == nil {
		return record.Clone(), nil
	}
	env, err := decodeSignAttemptEnvelope(record.CanonicalBaseEnvelopeBytes)
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
		if _, err := marshalSignAttemptCertificate(cert); err != nil {
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
	if err := validateSignAttemptRecord(updated); err != nil {
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

func scalarBytesStrict(in []byte) ([]byte, error) {
	if len(in) != 32 {
		return nil, errors.New("scalar must be 32 bytes")
	}
	if _, err := secp.ScalarFromBytes(in); err != nil {
		return nil, err
	}
	return in, nil
}

func decodeSignAttemptEnvelope(raw []byte) (tss.Envelope, error) {
	return decodeSignAttemptEnvelopeWithLimits(raw, DefaultLimits())
}

func decodeSignAttemptEnvelopeWithLimits(raw []byte, limits Limits) (tss.Envelope, error) {
	var env tss.Envelope
	if err := env.UnmarshalBinary(raw); err != nil {
		return tss.Envelope{}, err
	}
	canonical, err := env.MarshalBinary()
	if err != nil {
		return tss.Envelope{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return tss.Envelope{}, errors.New("non-canonical envelope")
	}
	if _, err := unmarshalSignPartialPayloadWithLimits(env.Payload, limits); err != nil {
		return tss.Envelope{}, err
	}
	return env, nil
}

func signAttemptIntentHash(r SignAttemptRecord) []byte {
	t := transcript.New(signAttemptIntentLabel)
	t.AppendUint16("record_version", r.RecordVersion)
	t.AppendString("protocol", string(r.Protocol))
	t.AppendUint16("protocol_version", r.Version)
	t.AppendBytes("presign_id", r.PresignID)
	t.AppendBytes("session_id", r.SessionID[:])
	t.AppendUint32("party", r.Party)
	t.AppendBytes("signer_set_hash", r.SignerSetHash)
	t.AppendBytes("sign_plan_hash", r.SignPlanHash)
	t.AppendBytes("context_hash", r.ContextHash)
	t.AppendBytes("digest", r.Digest)
	t.AppendBytes("digest_binding_hash", r.DigestBindingHash)
	t.AppendBool("low_s", r.LowS)
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
	return wireutil.PartySetHash(signers, signAttemptSignerSetLabel)
}

func signAttemptAcksToWire(acks []tss.BroadcastAck) []ackWire {
	if acks == nil {
		return nil
	}
	out := make([]ackWire, len(acks))
	for i, ack := range acks {
		out[i] = ackWire{
			Party:          ack.Party,
			PayloadHash:    ack.PayloadHash[:],
			EnvelopeDigest: ack.EnvelopeDigest[:],
			Signature:      ack.Signature,
		}
	}
	return out
}

func signAttemptAcksFromWire(acks []ackWire) []tss.BroadcastAck {
	if acks == nil {
		return nil
	}
	out := make([]tss.BroadcastAck, len(acks))
	for i, ack := range acks {
		out[i] = tss.BroadcastAck{
			Party:     ack.Party,
			Signature: slices.Clone(ack.Signature),
		}
		copy(out[i].PayloadHash[:], ack.PayloadHash)
		copy(out[i].EnvelopeDigest[:], ack.EnvelopeDigest)
	}
	return out
}

func signAttemptCertificateToWire(cert *tss.BroadcastCertificate) []byte {
	raw, err := marshalSignAttemptCertificate(cert)
	if err != nil {
		return []byte{0}
	}
	return raw
}

func marshalSignAttemptCertificate(cert *tss.BroadcastCertificate) ([]byte, error) {
	if cert == nil {
		return nil, nil
	}
	return wire.Marshal(certWire{
		Protocol:       string(cert.Protocol),
		SessionID:      cert.SessionID[:],
		Round:          cert.Round,
		From:           cert.From,
		PayloadType:    string(cert.PayloadType),
		PayloadHash:    cert.PayloadHash[:],
		EnvelopeDigest: cert.EnvelopeDigest[:],
		Recipients:     cert.Recipients,
		Acks:           signAttemptAcksToWire(cert.Acks),
	})
}

func signAttemptCertificateFromWire(raw []byte) *tss.BroadcastCertificate {
	if len(raw) == 0 {
		return nil
	}
	var w certWire
	if err := wire.Unmarshal(raw, &w); err != nil {
		return &tss.BroadcastCertificate{}
	}
	sessionID, err := tss.SessionIDFromBytes(w.SessionID)
	if err != nil {
		return &tss.BroadcastCertificate{}
	}
	cert := &tss.BroadcastCertificate{
		Protocol:    tss.ProtocolID(w.Protocol),
		SessionID:   sessionID,
		Round:       w.Round,
		From:        w.From,
		PayloadType: tss.PayloadType(w.PayloadType),
		Recipients:  w.Recipients,
		Acks:        signAttemptAcksFromWire(w.Acks),
	}
	copy(cert.PayloadHash[:], w.PayloadHash)
	copy(cert.EnvelopeDigest[:], w.EnvelopeDigest)
	return cert
}

func broadcastAckEqual(a, b tss.BroadcastAck) bool {
	return a.Party == b.Party &&
		a.PayloadHash == b.PayloadHash &&
		a.EnvelopeDigest == b.EnvelopeDigest &&
		bytes.Equal(a.Signature, b.Signature)
}

func broadcastCertificateEqual(a, b *tss.BroadcastCertificate) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Protocol != b.Protocol ||
		a.SessionID != b.SessionID ||
		a.Round != b.Round ||
		a.From != b.From ||
		a.PayloadType != b.PayloadType ||
		a.PayloadHash != b.PayloadHash ||
		a.EnvelopeDigest != b.EnvelopeDigest ||
		!slices.Equal(a.Recipients, b.Recipients) ||
		len(a.Acks) != len(b.Acks) {
		return false
	}
	for i := range a.Acks {
		if !broadcastAckEqual(a.Acks[i], b.Acks[i]) {
			return false
		}
	}
	return true
}
