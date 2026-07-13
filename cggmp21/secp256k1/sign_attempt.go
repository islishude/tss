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
	"github.com/islishude/tss/tssrun"
)

const (
	signAttemptOutboxVersion     uint16 = 1
	signAttemptDeliveryVersion   uint16 = 1
	signAttemptCompletionVersion uint16 = 1
	signAttemptMetadataVersion   uint16 = 1

	signAttemptOutboxWireType     = "cggmp21.secp256k1.sign-outbox"
	signAttemptDeliveryWireType   = "cggmp21.secp256k1.sign-delivery"
	signAttemptCompletionWireType = "cggmp21.secp256k1.sign-completion"
	signAttemptMetadataWireType   = "cggmp21.secp256k1.sign-public-context"

	signAttemptIntentLabel         = "cggmp21-secp256k1-sign-attempt-intent-v1"
	signAttemptSignerSetLabel      = "cggmp21-secp256k1-sign-attempt-signers-v1"
	signAttemptDeliveryPolicyLabel = "cggmp21-secp256k1-sign-attempt-delivery-policy-v1"
	maxSignLifecycleIdentifier     = 256
)

// signAttemptPublicContext is the public Figure 10 verification and exact
// generation/epoch/slot state retained after the available presign's secret
// tuple is destroyed at commit.
type signAttemptPublicContext struct {
	RecordVersion     uint16                        `wire:"1,u16"`
	Party             tss.PartyID                   `wire:"2,u32"`
	Threshold         int                           `wire:"3,u32"`
	Signers           tss.PartySet                  `wire:"4,u32list,max_items=signers"`
	ProtocolPresignID []byte                        `wire:"5,bytes,len=32"`
	EpochID           []byte                        `wire:"6,bytes,len=32"`
	Gamma             *secp.Point                   `wire:"7,custom,len=33"`
	LittleR           secp.Scalar                   `wire:"8,custom,len=32"`
	Commitments       []normalizedPresignCommitment `wire:"9,recordlist,max_items=signers"`
	TranscriptHash    []byte                        `wire:"10,bytes,len=32"`
	ContextHash       []byte                        `wire:"11,bytes,len=32"`
	VerificationKey   []byte                        `wire:"12,bytes,max_bytes=point"`
	KeyID             string                        `wire:"13,string"`
	Derivation        *tss.DerivationResult         `wire:"14,record"`
	Epoch             *EpochContext                 `wire:"15,record"`
	PresignSlot       string                        `wire:"16,string"`
}

func (c signAttemptPublicContext) clone() signAttemptPublicContext {
	clone := signAttemptPublicContext{
		RecordVersion:     c.RecordVersion,
		Party:             c.Party,
		Threshold:         c.Threshold,
		Signers:           c.Signers.Clone(),
		ProtocolPresignID: bytes.Clone(c.ProtocolPresignID),
		EpochID:           bytes.Clone(c.EpochID),
		Gamma:             secp.Clone(c.Gamma),
		LittleR:           c.LittleR,
		Commitments:       make([]normalizedPresignCommitment, len(c.Commitments)),
		TranscriptHash:    bytes.Clone(c.TranscriptHash),
		ContextHash:       bytes.Clone(c.ContextHash),
		VerificationKey:   bytes.Clone(c.VerificationKey),
		KeyID:             c.KeyID,
		Derivation:        c.Derivation.Clone(),
		Epoch:             c.Epoch.Clone(),
		PresignSlot:       c.PresignSlot,
	}
	for i := range c.Commitments {
		clone.Commitments[i] = c.Commitments[i].clone()
	}
	return clone
}

func (c *signAttemptPublicContext) destroy() {
	if c == nil {
		return
	}
	for i := range c.Commitments {
		c.Commitments[i].destroy()
	}
	clear(c.ProtocolPresignID)
	clear(c.EpochID)
	clear(c.TranscriptHash)
	clear(c.ContextHash)
	clear(c.VerificationKey)
	if c.Derivation != nil {
		c.Derivation.Destroy()
	}
	*c = signAttemptPublicContext{}
}

// SignAttemptDeliveryPolicy snapshots the delivery policy for the exact
// committed online-sign outbox.
type SignAttemptDeliveryPolicy struct {
	Mode                 tss.DeliveryMode               `wire:"1,u8"`
	Confidentiality      tss.ConfidentialityPolicy      `wire:"2,u8"`
	BroadcastConsistency tss.BroadcastConsistencyPolicy `wire:"3,u8"`
	Recipients           tss.PartySet                   `wire:"4,u32list,max_items=parties"`
}

// Clone returns an independent delivery policy.
func (p SignAttemptDeliveryPolicy) Clone() SignAttemptDeliveryPolicy {
	return SignAttemptDeliveryPolicy{
		Mode:                 p.Mode,
		Confidentiality:      p.Confidentiality,
		BroadcastConsistency: p.BroadcastConsistency,
		Recipients:           p.Recipients.Clone(),
	}
}

// Equal reports whether p and other are the same policy.
func (p SignAttemptDeliveryPolicy) Equal(other SignAttemptDeliveryPolicy) bool {
	return p.Mode == other.Mode &&
		p.Confidentiality == other.Confidentiality &&
		p.BroadcastConsistency == other.BroadcastConsistency &&
		slices.Equal(p.Recipients, other.Recipients)
}

// signAttemptOutbox is the exact immutable protocol outbox stored inside a
// tssrun signing attempt. It contains the canonical envelope and every
// non-secret value required to validate or replay that envelope.
type signAttemptOutbox struct {
	RecordVersion   uint16         `wire:"1,u16"`
	Protocol        tss.ProtocolID `wire:"2,string,max_bytes=protocol_name"`
	ProtocolVersion uint16         `wire:"3,u16"`

	KeyID         string `wire:"4,string"`
	KeyGeneration string `wire:"5,string"`
	EpochID       []byte `wire:"6,bytes,len=32"`
	PresignID     string `wire:"7,string"`
	AttemptID     string `wire:"8,string"`

	ProtocolPresignID []byte        `wire:"9,bytes,len=32"`
	SessionID         tss.SessionID `wire:"10,bytes,len=32"`
	Party             tss.PartyID   `wire:"11,u32"`
	SignerSetHash     []byte        `wire:"12,bytes,len=32"`
	SignPlanHash      []byte        `wire:"13,bytes,len=32"`
	ContextHash       []byte        `wire:"14,bytes,len=32"`
	Digest            []byte        `wire:"15,bytes,len=32"`
	DigestBindingHash []byte        `wire:"16,bytes,len=32"`

	CanonicalEnvelope     []byte                    `wire:"17,bytes,max_bytes=envelope"`
	CanonicalEnvelopeHash []byte                    `wire:"18,bytes,len=32"`
	EnvelopeDigest        []byte                    `wire:"19,bytes,len=32"`
	PayloadHash           []byte                    `wire:"20,bytes,len=32"`
	DeliveryPolicy        SignAttemptDeliveryPolicy `wire:"21,record"`
	IntentDigest          []byte                    `wire:"22,bytes,len=32"`
	VerificationKey       []byte                    `wire:"23,bytes,max_bytes=point"`
}

// signAttemptDelivery is persisted only after a complete authenticated
// broadcast certificate exists. It intentionally excludes the partial
// signature envelope while retaining non-secret recovery inputs.
type signAttemptDelivery struct {
	RecordVersion uint16 `wire:"1,u16"`

	KeyID         string `wire:"2,string"`
	KeyGeneration string `wire:"3,string"`
	EpochID       []byte `wire:"4,bytes,len=32"`
	PresignID     string `wire:"5,string"`
	AttemptID     string `wire:"6,string"`

	ProtocolPresignID []byte        `wire:"7,bytes,len=32"`
	SessionID         tss.SessionID `wire:"8,bytes,len=32"`
	Party             tss.PartyID   `wire:"9,u32"`
	SignerSetHash     []byte        `wire:"10,bytes,len=32"`
	SignPlanHash      []byte        `wire:"11,bytes,len=32"`
	ContextHash       []byte        `wire:"12,bytes,len=32"`
	Digest            []byte        `wire:"13,bytes,len=32"`
	DigestBindingHash []byte        `wire:"14,bytes,len=32"`

	CanonicalEnvelopeHash []byte                    `wire:"15,bytes,len=32"`
	EnvelopeDigest        []byte                    `wire:"16,bytes,len=32"`
	PayloadHash           []byte                    `wire:"17,bytes,len=32"`
	DeliveryPolicy        SignAttemptDeliveryPolicy `wire:"18,record"`
	IntentDigest          []byte                    `wire:"19,bytes,len=32"`
	Certificate           *tss.BroadcastCertificate `wire:"20,nested,max_bytes=envelope"`
	VerificationKey       []byte                    `wire:"21,bytes,max_bytes=point"`
}

type signAttemptCompletion struct {
	RecordVersion uint16 `wire:"1,u16"`
	IntentDigest  []byte `wire:"2,bytes,len=32"`
	SignatureR    []byte `wire:"3,bytes,max_bytes=scalar"`
	SignatureS    []byte `wire:"4,bytes,max_bytes=scalar"`
	RecoveryID    uint8  `wire:"5,u8"`
}

// WireType returns the canonical wire type for an exact sign outbox.
func (signAttemptOutbox) WireType() string { return signAttemptOutboxWireType }

// WireVersion returns the canonical wire version for an exact sign outbox.
func (signAttemptOutbox) WireVersion() uint16 { return signAttemptOutboxVersion }

// WireType returns the canonical wire type for sign delivery evidence.
func (signAttemptDelivery) WireType() string { return signAttemptDeliveryWireType }

// WireVersion returns the canonical wire version for sign delivery evidence.
func (signAttemptDelivery) WireVersion() uint16 { return signAttemptDeliveryVersion }

// WireType returns the canonical wire type for a sign completion record.
func (signAttemptCompletion) WireType() string { return signAttemptCompletionWireType }

// WireVersion returns the canonical wire version for a sign completion record.
func (signAttemptCompletion) WireVersion() uint16 { return signAttemptCompletionVersion }

// WireType returns the canonical wire type for public presign recovery state.
func (signAttemptPublicContext) WireType() string { return signAttemptMetadataWireType }

// WireVersion returns the canonical wire version for public presign recovery state.
func (signAttemptPublicContext) WireVersion() uint16 { return signAttemptMetadataVersion }

func signAttemptPublicContextFromPresign(presign *Presign) signAttemptPublicContext {
	presignSlot, _ := PresignSlotID(presign.state.PresignID)
	context := signAttemptPublicContext{
		RecordVersion:     signAttemptMetadataVersion,
		Party:             presign.state.Party,
		Threshold:         presign.state.Threshold,
		Signers:           presign.state.Signers.Clone(),
		ProtocolPresignID: bytes.Clone(presign.state.PresignID),
		EpochID:           bytes.Clone(presign.state.EpochID),
		Gamma:             secp.Clone(presign.state.Gamma),
		LittleR:           presign.state.LittleR,
		Commitments:       make([]normalizedPresignCommitment, len(presign.state.Commitments)),
		TranscriptHash:    bytes.Clone(presign.state.TranscriptHash),
		ContextHash:       bytes.Clone(presign.state.ContextHash),
		VerificationKey:   presign.verificationKey(),
		KeyID:             presign.state.Context.KeyID,
		Derivation:        presign.state.Derivation.Clone(),
		Epoch:             presign.state.Epoch.Clone(),
		PresignSlot:       presignSlot,
	}
	for i := range presign.state.Commitments {
		context.Commitments[i] = presign.state.Commitments[i].clone()
	}
	return context
}

func marshalSignAttemptPublicContext(context signAttemptPublicContext, limits Limits) ([]byte, error) {
	if err := validateSignAttemptPublicContext(context, limits); err != nil {
		return nil, err
	}
	return wire.Marshal(context, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalSignAttemptPublicContext(raw []byte, limits Limits) (signAttemptPublicContext, error) {
	if len(raw) == 0 || len(raw) > limits.State.MaxSerializedSignAttemptBytes {
		return signAttemptPublicContext{}, fmt.Errorf("%w: invalid sign public context size", ErrSignAttemptCorrupt)
	}
	var context signAttemptPublicContext
	if err := wire.Unmarshal(raw, &context,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return signAttemptPublicContext{}, fmt.Errorf("%w: decode sign public context: %w", ErrSignAttemptCorrupt, err)
	}
	if err := validateSignAttemptPublicContext(context, limits); err != nil {
		context.destroy()
		return signAttemptPublicContext{}, err
	}
	canonical, err := wire.Marshal(context, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil || !bytes.Equal(raw, canonical) {
		context.destroy()
		return signAttemptPublicContext{}, fmt.Errorf("%w: non-canonical sign public context", ErrSignAttemptCorrupt)
	}
	return context, nil
}

func (o signAttemptOutbox) binding() (tssrun.GenerationBinding, error) {
	epochID, err := tssrun.NewEpochID(o.EpochID)
	if err != nil {
		return tssrun.GenerationBinding{}, err
	}
	binding := tssrun.GenerationBinding{
		KeyID:         o.KeyID,
		KeyGeneration: tssrun.KeyGeneration(o.KeyGeneration),
		EpochID:       epochID,
	}
	if err := binding.Validate(); err != nil {
		return tssrun.GenerationBinding{}, err
	}
	return binding, nil
}

func (d signAttemptDelivery) outboxIdentity() signAttemptOutbox {
	return signAttemptOutbox{
		RecordVersion:         signAttemptOutboxVersion,
		Protocol:              tss.ProtocolCGGMP21Secp256k1,
		ProtocolVersion:       tss.ProtocolVersion,
		KeyID:                 d.KeyID,
		KeyGeneration:         d.KeyGeneration,
		EpochID:               bytes.Clone(d.EpochID),
		PresignID:             d.PresignID,
		AttemptID:             d.AttemptID,
		ProtocolPresignID:     bytes.Clone(d.ProtocolPresignID),
		SessionID:             d.SessionID,
		Party:                 d.Party,
		SignerSetHash:         bytes.Clone(d.SignerSetHash),
		SignPlanHash:          bytes.Clone(d.SignPlanHash),
		ContextHash:           bytes.Clone(d.ContextHash),
		Digest:                bytes.Clone(d.Digest),
		DigestBindingHash:     bytes.Clone(d.DigestBindingHash),
		CanonicalEnvelopeHash: bytes.Clone(d.CanonicalEnvelopeHash),
		EnvelopeDigest:        bytes.Clone(d.EnvelopeDigest),
		PayloadHash:           bytes.Clone(d.PayloadHash),
		DeliveryPolicy:        d.DeliveryPolicy.Clone(),
		IntentDigest:          bytes.Clone(d.IntentDigest),
		VerificationKey:       bytes.Clone(d.VerificationKey),
	}
}

func deliveryForOutbox(outbox signAttemptOutbox, certificate *tss.BroadcastCertificate) signAttemptDelivery {
	return signAttemptDelivery{
		RecordVersion:         signAttemptDeliveryVersion,
		KeyID:                 outbox.KeyID,
		KeyGeneration:         outbox.KeyGeneration,
		EpochID:               bytes.Clone(outbox.EpochID),
		PresignID:             outbox.PresignID,
		AttemptID:             outbox.AttemptID,
		ProtocolPresignID:     bytes.Clone(outbox.ProtocolPresignID),
		SessionID:             outbox.SessionID,
		Party:                 outbox.Party,
		SignerSetHash:         bytes.Clone(outbox.SignerSetHash),
		SignPlanHash:          bytes.Clone(outbox.SignPlanHash),
		ContextHash:           bytes.Clone(outbox.ContextHash),
		Digest:                bytes.Clone(outbox.Digest),
		DigestBindingHash:     bytes.Clone(outbox.DigestBindingHash),
		CanonicalEnvelopeHash: bytes.Clone(outbox.CanonicalEnvelopeHash),
		EnvelopeDigest:        bytes.Clone(outbox.EnvelopeDigest),
		PayloadHash:           bytes.Clone(outbox.PayloadHash),
		DeliveryPolicy:        outbox.DeliveryPolicy.Clone(),
		IntentDigest:          bytes.Clone(outbox.IntentDigest),
		Certificate:           certificate.Clone(),
		VerificationKey:       bytes.Clone(outbox.VerificationKey),
	}
}

func marshalSignAttemptOutbox(outbox signAttemptOutbox, limits Limits) ([]byte, error) {
	if err := validateSignAttemptOutbox(outbox, limits); err != nil {
		return nil, err
	}
	return wire.Marshal(outbox, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalSignAttemptOutbox(raw []byte, limits Limits) (signAttemptOutbox, error) {
	if len(raw) == 0 || len(raw) > limits.State.MaxSerializedSignAttemptBytes {
		return signAttemptOutbox{}, fmt.Errorf("%w: invalid sign outbox size", ErrSignAttemptCorrupt)
	}
	var outbox signAttemptOutbox
	if err := wire.Unmarshal(raw, &outbox,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return signAttemptOutbox{}, fmt.Errorf("%w: decode sign outbox: %w", ErrSignAttemptCorrupt, err)
	}
	if err := validateSignAttemptOutbox(outbox, limits); err != nil {
		return signAttemptOutbox{}, err
	}
	canonical, err := wire.Marshal(outbox, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil || !bytes.Equal(raw, canonical) {
		return signAttemptOutbox{}, fmt.Errorf("%w: non-canonical sign outbox", ErrSignAttemptCorrupt)
	}
	return outbox, nil
}

func marshalSignAttemptDelivery(delivery signAttemptDelivery, limits Limits, verifier tss.BroadcastAckVerifier) ([]byte, error) {
	if err := validateSignAttemptDelivery(delivery, verifier); err != nil {
		return nil, err
	}
	return wire.Marshal(delivery, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalSignAttemptDelivery(raw []byte, limits Limits, verifier tss.BroadcastAckVerifier) (signAttemptDelivery, error) {
	if len(raw) == 0 || len(raw) > limits.State.MaxSerializedSignAttemptBytes {
		return signAttemptDelivery{}, fmt.Errorf("%w: invalid sign delivery size", ErrSignAttemptCorrupt)
	}
	var delivery signAttemptDelivery
	if err := wire.Unmarshal(raw, &delivery,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return signAttemptDelivery{}, fmt.Errorf("%w: decode sign delivery: %w", ErrSignAttemptCorrupt, err)
	}
	if err := validateSignAttemptDelivery(delivery, verifier); err != nil {
		return signAttemptDelivery{}, err
	}
	canonical, err := wire.Marshal(delivery, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil || !bytes.Equal(raw, canonical) {
		return signAttemptDelivery{}, fmt.Errorf("%w: non-canonical sign delivery", ErrSignAttemptCorrupt)
	}
	return delivery, nil
}

func marshalSignAttemptCompletion(intentDigest []byte, signature Signature, limits Limits) ([]byte, error) {
	completion := signAttemptCompletion{
		RecordVersion: signAttemptCompletionVersion,
		IntentDigest:  bytes.Clone(intentDigest),
		SignatureR:    bytes.Clone(signature.R),
		SignatureS:    bytes.Clone(signature.S),
		RecoveryID:    signature.RecoveryID,
	}
	if err := validateSignAttemptCompletion(completion); err != nil {
		return nil, err
	}
	return wire.Marshal(completion, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func unmarshalSignAttemptCompletion(raw []byte, limits Limits) (signAttemptCompletion, error) {
	if len(raw) == 0 || len(raw) > limits.State.MaxSerializedSignAttemptBytes {
		return signAttemptCompletion{}, fmt.Errorf("%w: invalid sign completion size", ErrSignAttemptCorrupt)
	}
	var completion signAttemptCompletion
	if err := wire.Unmarshal(raw, &completion,
		wire.WithFrameLimits(limits.frameLimits(limits.State.MaxSerializedSignAttemptBytes)),
		wire.WithFieldLimits(limits.fieldLimits()),
	); err != nil {
		return signAttemptCompletion{}, fmt.Errorf("%w: decode sign completion: %w", ErrSignAttemptCorrupt, err)
	}
	if err := validateSignAttemptCompletion(completion); err != nil {
		return signAttemptCompletion{}, err
	}
	canonical, err := wire.Marshal(completion, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
	if err != nil || !bytes.Equal(raw, canonical) {
		return signAttemptCompletion{}, fmt.Errorf("%w: non-canonical sign completion", ErrSignAttemptCorrupt)
	}
	return completion, nil
}

func validateSignAttemptOutbox(outbox signAttemptOutbox, limits Limits) error {
	if outbox.RecordVersion != signAttemptOutboxVersion ||
		outbox.Protocol != tss.ProtocolCGGMP21Secp256k1 ||
		outbox.ProtocolVersion != tss.ProtocolVersion {
		return fmt.Errorf("%w: invalid sign outbox version or protocol", ErrSignAttemptCorrupt)
	}
	if _, err := outbox.binding(); err != nil ||
		validateSignLifecycleIdentifier(outbox.PresignID) != nil ||
		validateSignLifecycleIdentifier(outbox.AttemptID) != nil {
		return fmt.Errorf("%w: invalid sign outbox lifecycle binding", ErrSignAttemptCorrupt)
	}
	if len(outbox.ProtocolPresignID) != sha256.Size ||
		!outbox.SessionID.Valid() || outbox.Party == tss.BroadcastPartyId ||
		len(outbox.SignerSetHash) != sha256.Size ||
		len(outbox.SignPlanHash) != sha256.Size ||
		len(outbox.ContextHash) != sha256.Size ||
		len(outbox.Digest) != sha256.Size ||
		len(outbox.DigestBindingHash) != sha256.Size ||
		len(outbox.CanonicalEnvelopeHash) != sha256.Size ||
		len(outbox.EnvelopeDigest) != sha256.Size ||
		len(outbox.PayloadHash) != sha256.Size ||
		len(outbox.IntentDigest) != sha256.Size ||
		len(outbox.VerificationKey) == 0 {
		return fmt.Errorf("%w: invalid sign outbox fixed-width field", ErrSignAttemptCorrupt)
	}
	if err := validateCanonicalPresignSlot(outbox.PresignID, outbox.ProtocolPresignID); err != nil {
		return err
	}
	env, payload, err := decodeSignAttemptEnvelopeWithLimits(outbox.CanonicalEnvelope, limits)
	if err != nil {
		return fmt.Errorf("%w: invalid sign outbox envelope: %w", ErrSignAttemptCorrupt, err)
	}
	defer payload.S.Destroy()
	envelopeHash := sha256.Sum256(outbox.CanonicalEnvelope)
	payloadHash := tss.PayloadHashFromEnvelope(env)
	envelopeDigest := env.Digest()
	if !bytes.Equal(outbox.CanonicalEnvelopeHash, envelopeHash[:]) ||
		!bytes.Equal(outbox.PayloadHash, payloadHash[:]) ||
		!bytes.Equal(outbox.EnvelopeDigest, envelopeDigest[:]) {
		return fmt.Errorf("%w: sign outbox envelope hash mismatch", ErrSignAttemptCorrupt)
	}
	if env.Protocol != outbox.Protocol || env.SessionID != outbox.SessionID ||
		env.Round != signStartRound || env.From != outbox.Party ||
		env.To != tss.BroadcastPartyId || env.PayloadType != payloadSignPartial {
		return fmt.Errorf("%w: sign outbox envelope binding mismatch", ErrSignAttemptCorrupt)
	}
	if !bytes.Equal(payload.PresignID, outbox.ProtocolPresignID) ||
		!bytes.Equal(payload.EpochID, outbox.EpochID) ||
		!bytes.Equal(payload.PresignContext, outbox.ContextHash) ||
		!bytes.Equal(payload.PlanHash, outbox.SignPlanHash) {
		return fmt.Errorf("%w: sign outbox payload binding mismatch", ErrSignAttemptCorrupt)
	}
	expectedDigestBinding := digestHash(outbox.Digest, outbox.ContextHash)
	if !bytes.Equal(outbox.DigestBindingHash, expectedDigestBinding) ||
		!bytes.Equal(payload.DigestHash, expectedDigestBinding) {
		return fmt.Errorf("%w: sign outbox digest binding mismatch", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptDeliveryPolicy(outbox.DeliveryPolicy, outbox.Protocol, env, outbox.SignerSetHash); err != nil {
		return err
	}
	if !bytes.Equal(outbox.IntentDigest, signAttemptIntentDigest(outbox)) {
		return fmt.Errorf("%w: sign attempt intent digest mismatch", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateSignAttemptDelivery(delivery signAttemptDelivery, verifier tss.BroadcastAckVerifier) error {
	if delivery.RecordVersion != signAttemptDeliveryVersion || delivery.Certificate == nil {
		return fmt.Errorf("%w: invalid sign delivery record", ErrSignAttemptCorrupt)
	}
	identity := delivery.outboxIdentity()
	if _, err := identity.binding(); err != nil ||
		validateSignLifecycleIdentifier(identity.PresignID) != nil ||
		validateSignLifecycleIdentifier(identity.AttemptID) != nil {
		return fmt.Errorf("%w: invalid sign delivery lifecycle binding", ErrSignAttemptCorrupt)
	}
	if len(identity.ProtocolPresignID) != sha256.Size ||
		!identity.SessionID.Valid() || identity.Party == tss.BroadcastPartyId ||
		len(identity.SignerSetHash) != sha256.Size ||
		len(identity.SignPlanHash) != sha256.Size ||
		len(identity.ContextHash) != sha256.Size ||
		len(identity.Digest) != sha256.Size ||
		len(identity.DigestBindingHash) != sha256.Size ||
		len(identity.CanonicalEnvelopeHash) != sha256.Size ||
		len(identity.EnvelopeDigest) != sha256.Size ||
		len(identity.PayloadHash) != sha256.Size ||
		len(identity.IntentDigest) != sha256.Size ||
		len(identity.VerificationKey) == 0 {
		return fmt.Errorf("%w: invalid sign delivery fixed-width field", ErrSignAttemptCorrupt)
	}
	if err := validateCanonicalPresignSlot(identity.PresignID, identity.ProtocolPresignID); err != nil {
		return err
	}
	if !bytes.Equal(identity.DigestBindingHash, digestHash(identity.Digest, identity.ContextHash)) ||
		!bytes.Equal(identity.IntentDigest, signAttemptIntentDigest(identity)) {
		return fmt.Errorf("%w: invalid sign delivery intent binding", ErrSignAttemptCorrupt)
	}
	if err := validateSignAttemptDeliveryPolicy(identity.DeliveryPolicy, tss.ProtocolCGGMP21Secp256k1, tss.Envelope{
		Protocol: tss.ProtocolCGGMP21Secp256k1, Round: signStartRound, PayloadType: payloadSignPartial,
	}, identity.SignerSetHash); err != nil {
		return err
	}
	cert := delivery.Certificate
	var payloadHash [sha256.Size]byte
	var envelopeDigest tss.EnvelopeDigest
	copy(payloadHash[:], identity.PayloadHash)
	copy(envelopeDigest[:], identity.EnvelopeDigest)
	if cert.Protocol != tss.ProtocolCGGMP21Secp256k1 ||
		cert.SessionID != identity.SessionID ||
		cert.Round != signStartRound ||
		cert.From != identity.Party ||
		cert.PayloadType != payloadSignPartial ||
		cert.PayloadHash != payloadHash ||
		cert.EnvelopeDigest != envelopeDigest ||
		!slices.Equal(cert.Recipients, identity.DeliveryPolicy.Recipients) ||
		len(cert.Acks) != len(cert.Recipients) {
		return fmt.Errorf("%w: delivery certificate binding mismatch", ErrSignAttemptCorrupt)
	}
	if verifier == nil {
		return fmt.Errorf("%w: delivery certificate: %w", ErrSignAttemptCorrupt, tss.ErrMissingAckVerifier)
	}
	if err := wire.ValidateStrictSortedIDs(cert.Recipients); err != nil {
		return fmt.Errorf("%w: invalid delivery certificate recipients: %w", ErrSignAttemptCorrupt, err)
	}
	order := signAttemptRecipientOrder(cert.Recipients)
	previous := -1
	for _, ack := range cert.Acks {
		index, ok := order[ack.Party]
		if !ok || index <= previous ||
			ack.PayloadHash != cert.PayloadHash ||
			ack.EnvelopeDigest != cert.EnvelopeDigest {
			return fmt.Errorf("%w: invalid delivery certificate acknowledgements", ErrSignAttemptCorrupt)
		}
		previous = index
		digest := tss.AckDigest(cert.Protocol, cert.SessionID, cert.Round, cert.From, cert.PayloadType, cert.PayloadHash, cert.EnvelopeDigest)
		if err := verifier.VerifyAck(ack.Party, digest, ack.Signature); err != nil {
			return fmt.Errorf("%w: delivery certificate party %d: %w", ErrSignAttemptCorrupt, ack.Party, err)
		}
	}
	return nil
}

func validateSignAttemptCompletion(completion signAttemptCompletion) error {
	if completion.RecordVersion != signAttemptCompletionVersion ||
		len(completion.IntentDigest) != sha256.Size {
		return fmt.Errorf("%w: invalid sign completion record", ErrSignAttemptCorrupt)
	}
	if _, err := secp.ScalarFromBytes(completion.SignatureR); err != nil {
		return fmt.Errorf("%w: invalid sign completion r: %w", ErrSignAttemptCorrupt, err)
	}
	s, err := secp.ScalarFromBytes(completion.SignatureS)
	if err != nil {
		return fmt.Errorf("%w: invalid sign completion s: %w", ErrSignAttemptCorrupt, err)
	}
	if !secp.IsLowS(s) {
		return fmt.Errorf("%w: high-S sign completion", ErrSignAttemptCorrupt)
	}
	if completion.RecoveryID > 3 {
		return fmt.Errorf("%w: invalid sign completion recovery id", ErrSignAttemptCorrupt)
	}
	return nil
}

func validateSignAttemptPublicContext(context signAttemptPublicContext, limits Limits) error {
	if context.RecordVersion != signAttemptMetadataVersion ||
		context.Party == tss.BroadcastPartyId ||
		context.Threshold <= 0 || context.Threshold > len(context.Signers) ||
		len(context.Signers) > limits.Threshold.MaxSigners ||
		len(context.ProtocolPresignID) != sha256.Size ||
		len(context.EpochID) != sha256.Size ||
		len(context.TranscriptHash) != sha256.Size ||
		len(context.ContextHash) != sha256.Size ||
		len(context.VerificationKey) == 0 ||
		validateSignLifecycleIdentifier(context.KeyID) != nil ||
		context.Derivation == nil || context.Epoch == nil || context.PresignSlot == "" ||
		len(context.Commitments) != len(context.Signers) {
		return fmt.Errorf("%w: invalid sign public context", ErrSignAttemptCorrupt)
	}
	if err := limits.Threshold.ValidateThreshold(context.Threshold, len(context.Signers)); err != nil {
		return fmt.Errorf("%w: invalid sign public threshold: %w", ErrSignAttemptCorrupt, err)
	}
	if err := wire.ValidateStrictSortedIDs(context.Signers); err != nil || !context.Signers.Contains(context.Party) {
		return fmt.Errorf("%w: invalid sign public signer set", ErrSignAttemptCorrupt)
	}
	if _, err := secp.PointBytes(context.Gamma); err != nil {
		return fmt.Errorf("%w: invalid sign public Gamma: %w", ErrSignAttemptCorrupt, err)
	}
	if context.LittleR.IsZero() || !context.LittleR.Equal(secp.ScalarFromFieldElement(context.Gamma.X)) {
		return fmt.Errorf("%w: invalid sign public little r", ErrSignAttemptCorrupt)
	}
	publicKey, err := secp.PointFromBytes(context.VerificationKey)
	if err != nil {
		return fmt.Errorf("%w: invalid sign verification key: %w", ErrSignAttemptCorrupt, err)
	}
	if err := validateDerivationResult(context.Derivation); err != nil {
		return fmt.Errorf("%w: invalid sign generation derivation: %w", ErrSignAttemptCorrupt, err)
	}
	shift, err := secp.ScalarFromBytesAllowZero(context.Derivation.AdditiveShift)
	if err != nil || !shift.IsZero() || len(context.Derivation.RequestedPath) != 0 || len(context.Derivation.ResolvedPath) != 0 ||
		!bytes.Equal(context.Derivation.ChildPublicKey, context.VerificationKey) {
		return fmt.Errorf("%w: sign derivation is not the current generation binding", ErrSignAttemptCorrupt)
	}
	if err := context.Epoch.ValidateWithLimits(limits); err != nil {
		return fmt.Errorf("%w: invalid sign epoch context: %w", ErrSignAttemptCorrupt, err)
	}
	if !bytes.Equal(context.EpochID, context.Epoch.EpochID) || context.Epoch.Threshold != context.Threshold {
		return fmt.Errorf("%w: sign epoch identity or threshold mismatch", ErrSignAttemptCorrupt)
	}
	wantSlot, err := PresignSlotID(context.ProtocolPresignID)
	if err != nil || context.PresignSlot != wantSlot {
		return fmt.Errorf("%w: sign presign slot mismatch", ErrSignAttemptCorrupt)
	}
	epochPublicKey, epochParties, err := epochContextGroupPublicKey(context.Epoch)
	if err != nil || !secp.Equal(epochPublicKey, publicKey) {
		return fmt.Errorf("%w: sign epoch public-key binding mismatch", ErrSignAttemptCorrupt)
	}
	if !epochParties.Contains(context.Party) {
		return fmt.Errorf("%w: sign party is outside epoch", ErrSignAttemptCorrupt)
	}
	for _, signer := range context.Signers {
		if !epochParties.Contains(signer) {
			return fmt.Errorf("%w: sign signer %d is outside epoch", ErrSignAttemptCorrupt, signer)
		}
	}
	deltaPoints := make([]*secp.Point, 0, len(context.Commitments))
	sPoints := make([]*secp.Point, 0, len(context.Commitments))
	for i := range context.Commitments {
		commitment := context.Commitments[i]
		if commitment.Party != context.Signers[i] {
			return fmt.Errorf("%w: sign public commitment order mismatch", ErrSignAttemptCorrupt)
		}
		delta, err := decodePresignGroupElement(commitment.DeltaTilde)
		if err != nil {
			return fmt.Errorf("%w: invalid DeltaTilde for party %d: %w", ErrSignAttemptCorrupt, commitment.Party, err)
		}
		sPoint, err := decodePresignGroupElement(commitment.STilde)
		if err != nil {
			return fmt.Errorf("%w: invalid STilde for party %d: %w", ErrSignAttemptCorrupt, commitment.Party, err)
		}
		deltaPoints = append(deltaPoints, delta)
		sPoints = append(sPoints, sPoint)
	}
	if !secp.Equal(secp.AddPoints(deltaPoints...), secp.G) ||
		!secp.Equal(secp.AddPoints(sPoints...), publicKey) {
		return fmt.Errorf("%w: sign public commitments do not aggregate", ErrSignAttemptCorrupt)
	}
	return nil
}

func signAttemptPublicContextMatchesPresign(context signAttemptPublicContext, presign *Presign) bool {
	if presign == nil || presign.state == nil {
		return false
	}
	wantSlot, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		return false
	}
	if context.Party != presign.state.Party ||
		context.Threshold != presign.state.Threshold ||
		!slices.Equal(context.Signers, presign.state.Signers) ||
		!bytes.Equal(context.ProtocolPresignID, presign.state.PresignID) ||
		!bytes.Equal(context.EpochID, presign.state.EpochID) ||
		!secp.Equal(context.Gamma, presign.state.Gamma) ||
		!context.LittleR.Equal(presign.state.LittleR) ||
		!bytes.Equal(context.TranscriptHash, presign.state.TranscriptHash) ||
		!bytes.Equal(context.ContextHash, presign.state.ContextHash) ||
		!bytes.Equal(context.VerificationKey, presign.verificationKey()) ||
		context.KeyID != presign.state.Context.KeyID ||
		context.Derivation == nil || !context.Derivation.Equal(presign.state.Derivation) ||
		context.Epoch == nil || presign.state.Epoch == nil || !bytes.Equal(context.Epoch.EpochID, presign.state.Epoch.EpochID) ||
		context.PresignSlot != wantSlot ||
		len(context.Commitments) != len(presign.state.Commitments) {
		return false
	}
	for i := range context.Commitments {
		if context.Commitments[i].Party != presign.state.Commitments[i].Party ||
			!bytes.Equal(context.Commitments[i].DeltaTilde, presign.state.Commitments[i].DeltaTilde) ||
			!bytes.Equal(context.Commitments[i].STilde, presign.state.Commitments[i].STilde) {
			return false
		}
	}
	return true
}

func normalizedCommitmentForPublicContext(context *signAttemptPublicContext, party tss.PartyID) (normalizedPresignCommitment, bool) {
	if context == nil {
		return normalizedPresignCommitment{}, false
	}
	for i := range context.Commitments {
		if context.Commitments[i].Party == party {
			return context.Commitments[i].clone(), true
		}
	}
	return normalizedPresignCommitment{}, false
}

func validateSignAttemptDeliveryPolicy(policy SignAttemptDeliveryPolicy, protocol tss.ProtocolID, env tss.Envelope, signerSetHash []byte) error {
	expected, err := CGGMP21Policies().Match(protocol, env.Round, env.PayloadType)
	if err != nil {
		return fmt.Errorf("%w: sign delivery policy lookup: %w", ErrSignAttemptCorrupt, err)
	}
	if policy.Mode != expected.Mode ||
		policy.Confidentiality != expected.Confidentiality ||
		policy.BroadcastConsistency != expected.BroadcastConsistency ||
		len(policy.Recipients) == 0 {
		return fmt.Errorf("%w: sign delivery policy mismatch", ErrSignAttemptCorrupt)
	}
	if err := wire.ValidateStrictSortedIDs(policy.Recipients); err != nil {
		return fmt.Errorf("%w: invalid sign delivery recipients: %w", ErrSignAttemptCorrupt, err)
	}
	if !bytes.Equal(signerSetHash, signAttemptSignerSetHash(policy.Recipients)) {
		return fmt.Errorf("%w: sign delivery recipients do not match signer set", ErrSignAttemptCorrupt)
	}
	return nil
}

func signAttemptIntentDigest(outbox signAttemptOutbox) []byte {
	t := transcript.New(signAttemptIntentLabel)
	t.AppendUint16("record_version", outbox.RecordVersion)
	t.AppendString("protocol", string(outbox.Protocol))
	t.AppendUint16("protocol_version", outbox.ProtocolVersion)
	t.AppendString("key_id", outbox.KeyID)
	t.AppendString("key_generation", outbox.KeyGeneration)
	t.AppendBytes("epoch_id", outbox.EpochID)
	t.AppendString("presign_id", outbox.PresignID)
	t.AppendString("attempt_id", outbox.AttemptID)
	t.AppendBytes("protocol_presign_id", outbox.ProtocolPresignID)
	t.AppendBytes("session_id", outbox.SessionID[:])
	t.AppendUint32("party", outbox.Party)
	t.AppendBytes("signer_set_hash", outbox.SignerSetHash)
	t.AppendBytes("sign_plan_hash", outbox.SignPlanHash)
	t.AppendBytes("context_hash", outbox.ContextHash)
	t.AppendBytes("digest", outbox.Digest)
	t.AppendBytes("digest_binding_hash", outbox.DigestBindingHash)
	t.AppendBytes("canonical_envelope_hash", outbox.CanonicalEnvelopeHash)
	t.AppendBytes("envelope_digest", outbox.EnvelopeDigest)
	t.AppendBytes("payload_hash", outbox.PayloadHash)
	t.AppendBytes("delivery_policy_hash", signAttemptDeliveryPolicyHash(outbox.DeliveryPolicy))
	t.AppendBytes("verification_key", outbox.VerificationKey)
	return t.Sum()
}

func signAttemptDeliveryPolicyHash(policy SignAttemptDeliveryPolicy) []byte {
	t := transcript.New(signAttemptDeliveryPolicyLabel)
	t.AppendUint8("mode", uint8(policy.Mode))
	t.AppendUint8("confidentiality", uint8(policy.Confidentiality))
	t.AppendUint8("broadcast_consistency", uint8(policy.BroadcastConsistency))
	t.AppendUint32List("recipients", policy.Recipients)
	return t.Sum()
}

func signAttemptSignerSetHash(signers tss.PartySet) []byte {
	return tss.PartySetHash(signers, signAttemptSignerSetLabel)
}

func signAttemptRecipientOrder(recipients tss.PartySet) map[tss.PartyID]int {
	order := make(map[tss.PartyID]int, len(recipients))
	for index, party := range recipients {
		order[party] = index
	}
	return order
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
		return tss.Envelope{}, signPartialPayload{}, errors.New("non-canonical sign envelope")
	}
	payload, err := tss.DecodeBinaryValueWithLimits[signPartialPayload](env.Payload, limits)
	if err != nil {
		return tss.Envelope{}, signPartialPayload{}, err
	}
	return env, payload, nil
}

func validateSignLifecycleIdentifier(value string) error {
	if value == "" || len(value) > maxSignLifecycleIdentifier || !utf8.ValidString(value) {
		return errors.New("invalid lifecycle identifier")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("lifecycle identifier contains control characters")
		}
	}
	return nil
}

func clearSignAttemptOutbox(outbox *signAttemptOutbox) {
	if outbox == nil {
		return
	}
	clear(outbox.EpochID)
	clear(outbox.ProtocolPresignID)
	clear(outbox.SignerSetHash)
	clear(outbox.SignPlanHash)
	clear(outbox.ContextHash)
	clear(outbox.Digest)
	clear(outbox.DigestBindingHash)
	clear(outbox.CanonicalEnvelope)
	clear(outbox.CanonicalEnvelopeHash)
	clear(outbox.EnvelopeDigest)
	clear(outbox.PayloadHash)
	clear(outbox.IntentDigest)
	clear(outbox.VerificationKey)
	for i := range outbox.DeliveryPolicy.Recipients {
		outbox.DeliveryPolicy.Recipients[i] = 0
	}
	*outbox = signAttemptOutbox{}
}
