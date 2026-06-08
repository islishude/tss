package tss

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
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
func AckDigest(protocol ProtocolID, sessionID SessionID, round uint8, from PartyID, payloadType PayloadType, payloadHash, transcriptHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(broadcastAckDigestLabel))
	h.Write([]byte{0})
	h.Write([]byte(protocol))
	var roundBuf [1]byte
	roundBuf[0] = round
	h.Write(roundBuf[:])
	h.Write(sessionID[:])
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], uint32(from))
	h.Write(idBuf[:])
	h.Write([]byte(payloadType))
	h.Write([]byte{0})
	h.Write(payloadHash[:])
	h.Write(transcriptHash[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
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
	payloadHash := sha256.Sum256(env.Payload)
	cert := &BroadcastCertificate{
		Protocol:       env.Protocol,
		SessionID:      env.SessionID,
		Round:          env.Round,
		From:           env.From,
		PayloadType:    env.PayloadType,
		PayloadHash:    payloadHash,
		TranscriptHash: env.TranscriptHash,
		Recipients:     recipients.Clone(),
		Acks:           cloneBroadcastAcks(acks),
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
		if ack.TranscriptHash != env.TranscriptHash {
			return nil, fmt.Errorf("ack from party %d has mismatched transcript hash", ack.Party)
		}
	}
	return cert, nil
}

// SignBroadcastAck produces a signed BroadcastAck for a party over an envelope.
// The caller must provide a signer bound to the party's identity key.
func SignBroadcastAck(env Envelope, party PartyID, signer BroadcastAckSigner) (BroadcastAck, error) {
	payloadHash := sha256.Sum256(env.Payload)
	digest := AckDigest(env.Protocol, env.SessionID, env.Round, env.From, env.PayloadType, payloadHash, env.TranscriptHash)
	sig, err := signer.SignAck(digest)
	if err != nil {
		return BroadcastAck{}, fmt.Errorf("sign broadcast ack for party %d: %w", party, err)
	}
	return BroadcastAck{
		Party:          party,
		PayloadHash:    payloadHash,
		TranscriptHash: env.TranscriptHash,
		Signature:      sig,
	}, nil
}

// VerifyBroadcastAck checks that an ack is valid for the given envelope and party.
func VerifyBroadcastAck(env Envelope, ack BroadcastAck, verifier BroadcastAckVerifier) error {
	payloadHash := sha256.Sum256(env.Payload)
	if ack.PayloadHash != payloadHash {
		return errors.New("ack payload hash mismatch")
	}
	if ack.TranscriptHash != env.TranscriptHash {
		return errors.New("ack transcript hash mismatch")
	}
	digest := AckDigest(env.Protocol, env.SessionID, env.Round, env.From, env.PayloadType, payloadHash, env.TranscriptHash)
	return verifier.VerifyAck(ack.Party, digest, ack.Signature)
}

// VerifyBroadcastCertificateWithSignatures performs full certificate validation
// including individual ack signature verification.
func VerifyBroadcastCertificateWithSignatures(env Envelope, parties PartySet, cert *BroadcastCertificate, verifier BroadcastAckVerifier) error {
	if err := cert.Verify(env, parties); err != nil {
		return err
	}
	for _, ack := range cert.Acks {
		if err := VerifyBroadcastAck(env, ack, verifier); err != nil {
			return fmt.Errorf("%w: party %d: %w", ErrInvalidBroadcastCertificate, ack.Party, err)
		}
	}
	return nil
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
	transcriptHash [32]byte
	committed      bool

	recipients PartySet
	acks       map[PartyID]BroadcastAck
	verifier   BroadcastAckVerifier
}

// NewBroadcastConsistency starts tracking a new broadcast consistency session.
// The verifier is used to check each ack signature as it arrives.
func NewBroadcastConsistency(protocol ProtocolID, sessionID SessionID, round uint8, from PartyID, payloadType PayloadType, recipients PartySet, verifier BroadcastAckVerifier) *BroadcastConsistency {
	return &BroadcastConsistency{
		protocol:    protocol,
		sessionID:   sessionID,
		round:       round,
		from:        from,
		payloadType: payloadType,
		recipients:  recipients.Clone(),
		acks:        make(map[PartyID]BroadcastAck, len(recipients)),
		verifier:    verifier,
	}
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

	ph := sha256.Sum256(env.Payload)
	th := env.TranscriptHash

	if !bc.committed {
		bc.payloadHash = ph
		bc.transcriptHash = th
		bc.committed = true
		return true, nil
	}

	if bc.payloadHash != ph || bc.transcriptHash != th {
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
	ph := sha256.Sum256(env.Payload)
	th := env.TranscriptHash

	if bc.committed {
		if ph != bc.payloadHash || th != bc.transcriptHash {
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
		TranscriptHash: bc.transcriptHash,
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
	Party PartyID

	PayloadHash    [32]byte
	TranscriptHash [32]byte

	Signature []byte
}

// Clone returns a deep copy of the broadcast ack.
func (a BroadcastAck) Clone() BroadcastAck {
	return BroadcastAck{
		Party:          a.Party,
		PayloadHash:    a.PayloadHash,
		TranscriptHash: a.TranscriptHash,
		Signature:      slices.Clone(a.Signature),
	}
}

// BroadcastCertificate proves that all parties received the same broadcast payload.
type BroadcastCertificate struct {
	Protocol    ProtocolID
	SessionID   SessionID
	Round       uint8
	From        PartyID
	PayloadType PayloadType

	PayloadHash    [32]byte
	TranscriptHash [32]byte

	Recipients PartySet
	Acks       []BroadcastAck
}

// Clone returns a deep copy of the broadcast certificate.
func (c *BroadcastCertificate) Clone() *BroadcastCertificate {
	if c == nil {
		return nil
	}
	clone := *c
	clone.Recipients = c.Recipients.Clone()
	clone.Acks = cloneBroadcastAcks(c.Acks)
	return &clone
}

// Verify checks that the certificate binds to env and that
// every party acknowledged the same digest. It does not verify individual ack
// signatures; the caller must supply a verifier for that.
func (c *BroadcastCertificate) Verify(env Envelope, parties PartySet) error {
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
	if c.PayloadHash != sha256.Sum256(env.Payload) {
		return ErrInvalidBroadcastCertificate
	}
	if c.TranscriptHash != env.TranscriptHash {
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
	seen := make(map[PartyID]bool, len(c.Acks))
	for _, ack := range c.Acks {
		if !parties.Contains(ack.Party) {
			return ErrInvalidBroadcastCertificate
		}
		if seen[ack.Party] {
			return ErrInvalidBroadcastCertificate
		}
		seen[ack.Party] = true
		if ack.PayloadHash != c.PayloadHash {
			return ErrInvalidBroadcastCertificate
		}
		if ack.TranscriptHash != c.TranscriptHash {
			return ErrInvalidBroadcastCertificate
		}
	}
	return nil
}
