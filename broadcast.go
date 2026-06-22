package tss

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/islishude/tss/internal/transcript"
)

const broadcastAckDigestLabel = "github.com/islishude/tss/broadcast-ack/v1"

// BroadcastAckSigner produces a signature over a broadcast ack digest.
// Implementations bind an identity key to a PartyID.
type BroadcastAckSigner interface {
	// SignAck returns a cryptographic signature over the canonical ack digest.
	SignAck(digest [32]byte) (signature []byte, err error)
}

// BroadcastAckVerifier checks that a broadcast ack signature is valid for a party.
type BroadcastAckVerifier interface {
	// VerifyAck returns nil when signature is a valid signature by party over digest.
	VerifyAck(party PartyID, digest [32]byte, signature []byte) error
}

// AckDigest computes the canonical digest that parties sign for a broadcast ack.
// It binds the ack to the complete broadcast message identity.
func AckDigest(protocol ProtocolID, sessionID SessionID, round uint8, from PartyID, payloadType PayloadType, payloadHash [32]byte, envelopeDigest EnvelopeDigest) [32]byte {
	t := transcript.New(broadcastAckDigestLabel)
	t.AppendString("protocol", string(protocol))
	t.AppendBytes("session_id", sessionID[:])
	t.AppendUint8("round", round)
	t.AppendUint32("from", from)
	t.AppendString("payload_type", string(payloadType))
	t.AppendBytes("payload_hash", payloadHash[:])
	t.AppendBytes("envelope_digest", envelopeDigest[:])
	return t.Sum32()
}

// NewBroadcastCertificate constructs a certificate from an envelope and a complete
// set of signed acks. It verifies that every ack covers the same digest and that
// every party in recipients contributed exactly one ack.
//
// Callers must have already verified each individual ack signature via
// BroadcastAckVerifier before calling this constructor.
func NewBroadcastCertificate(env Envelope, recipients PartySet, acks []BroadcastAck) (*BroadcastCertificate, error) {
	if len(recipients) == 0 {
		return nil, errors.New("empty broadcast recipients")
	}
	if len(acks) != len(recipients) {
		return nil, fmt.Errorf("ack count %d does not match recipient count %d", len(acks), len(recipients))
	}
	payloadHash := PayloadHashFromEnvelope(env)
	envelopeDigest := env.Digest()
	cert := &BroadcastCertificate{
		Protocol:       env.Protocol,
		SessionID:      env.SessionID,
		Round:          env.Round,
		From:           env.From,
		PayloadType:    env.PayloadType,
		PayloadHash:    payloadHash,
		EnvelopeDigest: envelopeDigest,
		Recipients:     recipients.Clone(),
		Acks:           CloneSlice(acks),
	}

	// Verify internal consistency: every ack covers the same digest and recipient set.
	seen := make(map[PartyID]bool, len(acks))
	for _, ack := range acks {
		if !recipients.Contains(ack.Party) {
			return nil, fmt.Errorf("ack party %d is not in recipient set", ack.Party)
		}
		if seen[ack.Party] {
			return nil, fmt.Errorf("duplicate ack for party %d", ack.Party)
		}
		seen[ack.Party] = true
		if ack.PayloadHash != payloadHash {
			return nil, fmt.Errorf("ack from party %d has mismatched payload hash", ack.Party)
		}
		if ack.EnvelopeDigest != envelopeDigest {
			return nil, fmt.Errorf("ack from party %d has mismatched envelope digest", ack.Party)
		}
	}
	return cert, nil
}

// SignBroadcastAck produces a signed BroadcastAck for a party over an envelope.
// The caller must provide a signer bound to the party's identity key.
func SignBroadcastAck(env Envelope, party PartyID, signer BroadcastAckSigner) (BroadcastAck, error) {
	payloadHash := PayloadHashFromEnvelope(env)
	envelopeDigest := env.Digest()
	digest := AckDigest(env.Protocol, env.SessionID, env.Round, env.From, env.PayloadType, payloadHash, envelopeDigest)
	sig, err := signer.SignAck(digest)
	if err != nil {
		return BroadcastAck{}, fmt.Errorf("sign broadcast ack for party %d: %w", party, err)
	}
	return BroadcastAck{
		Party:          party,
		PayloadHash:    payloadHash,
		EnvelopeDigest: envelopeDigest,
		Signature:      sig,
	}, nil
}

// VerifyBroadcastAck checks that an ack is valid for the given envelope and party.
func VerifyBroadcastAck(env Envelope, ack BroadcastAck, verifier BroadcastAckVerifier) error {
	if verifier == nil {
		return errors.New("nil BroadcastAckVerifier")
	}
	payloadHash := PayloadHashFromEnvelope(env)
	if ack.PayloadHash != payloadHash {
		return errors.New("ack payload hash mismatch")
	}
	envelopeDigest := env.Digest()
	if ack.EnvelopeDigest != envelopeDigest {
		return errors.New("ack envelope digest mismatch")
	}
	digest := AckDigest(env.Protocol, env.SessionID, env.Round, env.From, env.PayloadType, payloadHash, envelopeDigest)
	return verifier.VerifyAck(ack.Party, digest, ack.Signature)
}

// VerifyFull performs complete certificate validation: structure checks plus
// individual ack signature verification against the provided verifier.
// Production code must use this method; [VerifyStructure] is for tests and
// low-level parsing only.
func (c *BroadcastCertificate) VerifyFull(env Envelope, parties PartySet, verifier BroadcastAckVerifier) error {
	if err := c.VerifyStructure(env, parties); err != nil {
		return err
	}
	if verifier == nil {
		return fmt.Errorf("%w: %w", ErrInvalidBroadcastCertificate, ErrMissingAckVerifier)
	}
	for _, ack := range c.Acks {
		if err := VerifyBroadcastAck(env, ack, verifier); err != nil {
			return fmt.Errorf("%w: party %d: %w", ErrInvalidBroadcastCertificate, ack.Party, err)
		}
	}
	return nil
}

// VerifyBroadcastCertificateWithSignatures performs full certificate validation
// including individual ack signature verification.
// Prefer [BroadcastCertificate.VerifyFull] for new code.
func VerifyBroadcastCertificateWithSignatures(env Envelope, parties PartySet, cert *BroadcastCertificate, verifier BroadcastAckVerifier) error {
	if cert == nil {
		return ErrMissingBroadcastCertificate
	}
	return cert.VerifyFull(env, parties, verifier)
}

// BroadcastConsistency tracks the collection of broadcast acks for one
// (session, round, from, payloadType) and detects equivocation.
//
// It is safe for concurrent use.
type BroadcastConsistency struct {
	mu          sync.Mutex
	protocol    ProtocolID
	sessionID   SessionID
	round       uint8
	from        PartyID
	payloadType PayloadType

	// canonical digest for the broadcast that has been committed to
	payloadHash    [32]byte
	envelopeDigest EnvelopeDigest
	committed      bool

	recipients PartySet
	acks       map[PartyID]BroadcastAck
	verifier   BroadcastAckVerifier
}

// NewBroadcastConsistency starts tracking a new broadcast consistency session.
// The verifier is used to check each ack signature as it arrives. It must not
// be nil — a nil verifier causes a panic in AddAck.
func NewBroadcastConsistency(protocol ProtocolID, sessionID SessionID, round uint8, from PartyID, payloadType PayloadType, recipients PartySet, verifier BroadcastAckVerifier) (*BroadcastConsistency, error) {
	if verifier == nil {
		return nil, errors.New("nil BroadcastAckVerifier")
	}
	return &BroadcastConsistency{
		protocol:    protocol,
		sessionID:   sessionID,
		round:       round,
		from:        from,
		payloadType: payloadType,
		recipients:  recipients.Clone(),
		acks:        make(map[PartyID]BroadcastAck, len(recipients)),
		verifier:    verifier,
	}, nil
}

// Commit records the canonical broadcast digest for this consistency session.
// Any subsequent ack with a different digest is treated as equivocation.
//
// The first call to Commit returns (true, nil). Subsequent calls with the same
// digest return (false, nil). A call with a different digest returns
// (false, ErrBroadcastEquivocation).
func (bc *BroadcastConsistency) Commit(env Envelope) (bool, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	ph := PayloadHashFromEnvelope(env)
	digest := env.Digest()

	if !bc.committed {
		bc.payloadHash = ph
		bc.envelopeDigest = digest
		bc.committed = true
		return true, nil
	}

	if bc.payloadHash != ph || bc.envelopeDigest != digest {
		return false, fmt.Errorf("%w: protocol=%s session=%s round=%d from=%d payloadType=%s",
			ErrBroadcastEquivocation, bc.protocol, bc.sessionID, bc.round, bc.from, bc.payloadType)
	}
	return false, nil
}

// AddAck records a party's broadcast acknowledgment. It verifies the ack
// signature, checks for digest consistency, and returns an error on:
//   - signature verification failure
//   - digest mismatch (equivocation)
//   - duplicate ack
//   - unknown party
func (bc *BroadcastConsistency) AddAck(env Envelope, ack BroadcastAck) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if !bc.recipients.Contains(ack.Party) {
		return fmt.Errorf("ack party %d is not a recipient", ack.Party)
	}
	if _, exists := bc.acks[ack.Party]; exists {
		return fmt.Errorf("duplicate ack for party %d", ack.Party)
	}

	// Verify the ack signature against our canonical digest.
	ph := PayloadHashFromEnvelope(env)
	digest := env.Digest()

	if bc.committed {
		if ph != bc.payloadHash || digest != bc.envelopeDigest {
			return fmt.Errorf("%w: party %d submitted ack for different digest",
				ErrBroadcastEquivocation, ack.Party)
		}
	}

	if err := VerifyBroadcastAck(env, ack, bc.verifier); err != nil {
		return fmt.Errorf("invalid ack from party %d: %w", ack.Party, err)
	}

	bc.acks[ack.Party] = ack.Clone()
	return nil
}

// Complete returns true when every recipient has submitted a valid ack.
func (bc *BroadcastConsistency) Complete() bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return len(bc.acks) == len(bc.recipients)
}

// Certificate builds the BroadcastCertificate from collected acks.
// It returns an error if not all acks have been collected.
func (bc *BroadcastConsistency) Certificate() (*BroadcastCertificate, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if len(bc.acks) != len(bc.recipients) {
		return nil, fmt.Errorf("incomplete acks: have %d, want %d", len(bc.acks), len(bc.recipients))
	}

	acks := make([]BroadcastAck, 0, len(bc.recipients))
	for _, id := range bc.recipients {
		ack, ok := bc.acks[id]
		if !ok {
			return nil, fmt.Errorf("missing ack for party %d", id)
		}
		acks = append(acks, ack.Clone())
	}

	return &BroadcastCertificate{
		Protocol:       bc.protocol,
		SessionID:      bc.sessionID,
		Round:          bc.round,
		From:           bc.from,
		PayloadType:    bc.payloadType,
		PayloadHash:    bc.payloadHash,
		EnvelopeDigest: bc.envelopeDigest,
		Recipients:     bc.recipients.Clone(),
		Acks:           acks,
	}, nil
}

// AckCount returns the number of verified acks collected so far.
func (bc *BroadcastConsistency) AckCount() int {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return len(bc.acks)
}

// InMemoryAckSigner is a simple BroadcastAckSigner that uses an in-memory
// mapping from PartyID to an Ed25519-like signing function. It is intended
// for tests and single-process deployments.
type InMemoryAckSigner struct {
	party PartyID
	sign  func(digest [32]byte) ([]byte, error)
}

// NewInMemoryAckSigner creates a signer bound to a party.
func NewInMemoryAckSigner(party PartyID, signFn func(digest [32]byte) ([]byte, error)) *InMemoryAckSigner {
	return &InMemoryAckSigner{party: party, sign: signFn}
}

// SignAck implements BroadcastAckSigner.
func (s *InMemoryAckSigner) SignAck(digest [32]byte) ([]byte, error) {
	return s.sign(digest)
}

// InMemoryAckVerifier is a simple BroadcastAckVerifier that uses an in-memory
// mapping from PartyID to a verification function. It is intended for tests
// and single-process deployments.
type InMemoryAckVerifier struct {
	verify func(party PartyID, digest [32]byte, signature []byte) error
}

// NewInMemoryAckVerifier creates a verifier.
func NewInMemoryAckVerifier(verifyFn func(party PartyID, digest [32]byte, signature []byte) error) *InMemoryAckVerifier {
	return &InMemoryAckVerifier{verify: verifyFn}
}

// VerifyAck implements BroadcastAckVerifier.
func (v *InMemoryAckVerifier) VerifyAck(party PartyID, digest [32]byte, signature []byte) error {
	return v.verify(party, digest, signature)
}

// BroadcastAck is one party's signed acknowledgment of a broadcast message.
type BroadcastAck struct {
	Party PartyID `wire:"1,u32"`

	PayloadHash    [32]byte       `wire:"2,bytes,len=32"`
	EnvelopeDigest EnvelopeDigest `wire:"3,bytes,len=32"`

	Signature []byte `wire:"4,bytes,max_bytes=broadcast_signature"`
}

// Clone returns a deep copy of the broadcast ack.
func (a BroadcastAck) Clone() BroadcastAck {
	return BroadcastAck{
		Party:          a.Party,
		PayloadHash:    a.PayloadHash,
		EnvelopeDigest: a.EnvelopeDigest,
		Signature:      slices.Clone(a.Signature),
	}
}

// Equal reports whether a and other are the same BroadcastAck.
func (a BroadcastAck) Equal(b BroadcastAck) bool {
	return a.Party == b.Party &&
		a.PayloadHash == b.PayloadHash &&
		a.EnvelopeDigest == b.EnvelopeDigest &&
		bytes.Equal(a.Signature, b.Signature)
}

// BroadcastCertificate proves that all parties received the same broadcast payload.
type BroadcastCertificate struct {
	Protocol    ProtocolID  `wire:"1,string,max_bytes=protocol_name"`
	SessionID   SessionID   `wire:"2,bytes,len=32"`
	Round       uint8       `wire:"3,u8"`
	From        PartyID     `wire:"4,u32"`
	PayloadType PayloadType `wire:"5,string,max_bytes=payload_type"`

	PayloadHash    [32]byte       `wire:"6,bytes,len=32"`
	EnvelopeDigest EnvelopeDigest `wire:"7,bytes,len=32"`

	Recipients PartySet       `wire:"8,u32list,max_items=broadcast_recipients"`
	Acks       []BroadcastAck `wire:"9,recordlist,max_items=broadcast_recipients"`
}

// Clone returns a deep copy of the broadcast certificate.
func (c *BroadcastCertificate) Clone() *BroadcastCertificate {
	if c == nil {
		return nil
	}
	clone := *c
	clone.Recipients = c.Recipients.Clone()
	clone.Acks = CloneSlice(c.Acks)
	return &clone
}

// VerifyStructure checks that the certificate binds to env and that
// every party acknowledged the same digest. It does NOT verify individual ack
// signatures — use [VerifyFull] for production paths that require signature verification.
func (c *BroadcastCertificate) VerifyStructure(env Envelope, parties PartySet) error {
	if c == nil {
		return ErrMissingBroadcastCertificate
	}
	if c.Protocol != env.Protocol {
		return ErrInvalidBroadcastCertificate
	}
	if c.SessionID != env.SessionID {
		return ErrInvalidBroadcastCertificate
	}
	if c.Round != env.Round {
		return ErrInvalidBroadcastCertificate
	}
	if c.From != env.From {
		return ErrInvalidBroadcastCertificate
	}
	if c.PayloadType != env.PayloadType {
		return ErrInvalidBroadcastCertificate
	}
	if c.PayloadHash != PayloadHashFromEnvelope(env) {
		return ErrInvalidBroadcastCertificate
	}
	if c.EnvelopeDigest != env.Digest() {
		return ErrInvalidBroadcastCertificate
	}
	if len(c.Recipients) != len(parties) {
		return ErrInvalidBroadcastCertificate
	}
	for _, id := range parties {
		if !c.Recipients.Contains(id) {
			return ErrInvalidBroadcastCertificate
		}
	}
	if len(c.Acks) != len(parties) {
		return ErrInvalidBroadcastCertificate
	}
	seen := make(map[PartyID]struct{}, len(c.Acks))
	for _, ack := range c.Acks {
		if !parties.Contains(ack.Party) {
			return ErrInvalidBroadcastCertificate
		}
		if _, ok := seen[ack.Party]; ok {
			return ErrInvalidBroadcastCertificate
		}
		seen[ack.Party] = struct{}{}
		if ack.PayloadHash != c.PayloadHash {
			return ErrInvalidBroadcastCertificate
		}
		if ack.EnvelopeDigest != c.EnvelopeDigest {
			return ErrInvalidBroadcastCertificate
		}
	}
	return nil
}

// Equal reports whether r and other are the same BroadcastCertificate.
// Both nil receivers compare equal. A nil receiver and a non-nil other
// are not equal.
func (a *BroadcastCertificate) Equal(b *BroadcastCertificate) bool {
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
		if !a.Acks[i].Equal(b.Acks[i]) {
			return false
		}
	}
	return true
}
