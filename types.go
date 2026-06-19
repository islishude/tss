package tss

// ProtocolVersion is the semantic protocol version bound into transcripts and
// durable protocol records.
const ProtocolVersion uint16 = 1

const envelopeHashLabel = "github.com/islishude/tss/envelope/v1"

const envelopeWireType = "tss.envelope"

const envelopeWireVersion uint16 = 1

// PartyID identifies a protocol participant.
// The zero value is reserved to mean unset and broadcast mode for Envelope.
type PartyID = uint32

// BroadcastPartyId is the receiver of broadcast mode
const BroadcastPartyId PartyID = 0

// ProtocolID names a threshold signature protocol implemented by this module.
type ProtocolID string

const (
	// ProtocolCGGMP21Secp256k1 identifies the CGGMP21-style threshold ECDSA protocol.
	ProtocolCGGMP21Secp256k1 ProtocolID = "cggmp21-secp256k1"
	// ProtocolFROSTEd25519 identifies the FROST-style threshold Ed25519 protocol.
	ProtocolFROSTEd25519 ProtocolID = "frost-ed25519"
)

// PayloadType names a protocol message payload kind.
type PayloadType string

// Algorithm names a threshold signature algorithm implemented by this module.
type Algorithm string

const (
	// AlgorithmCGGMP21Secp256k1 identifies the CGGMP21-style threshold ECDSA package.
	AlgorithmCGGMP21Secp256k1 Algorithm = "cggmp21-secp256k1"
	// AlgorithmFROSTEd25519 identifies the FROST-style threshold Ed25519 package.
	AlgorithmFROSTEd25519 Algorithm = "frost-ed25519"
)

// DeliveryMode classifies an envelope delivery path.
type DeliveryMode uint8

const (
	// DeliveryDirect is a point-to-point message addressed to a single recipient.
	DeliveryDirect DeliveryMode = iota
	// DeliveryBroadcast is a message sent to all parties.
	DeliveryBroadcast
)

// ConfidentialityPolicy specifies whether a message must be encrypted in transit.
type ConfidentialityPolicy uint8

const (
	// ConfidentialityForbidden means the message must NOT be sent over a confidential channel.
	// Prefer ConfidentialityOptional for most non-secret payloads; use Forbidden only when
	// confidential transport would actively break the protocol (e.g. audit logging that
	// requires visibility into plaintext).
	ConfidentialityForbidden ConfidentialityPolicy = iota
	// ConfidentialityOptional means either plaintext or confidential transport is acceptable.
	// This is the safe default for payloads that contain no secret material (commitments,
	// public keys, ciphertexts). TLS/mTLS deployments can safely mark transport as
	// Confidential=true without triggering policy rejection.
	ConfidentialityOptional
	// ConfidentialityRequired means the message MUST be sent over a confidential channel.
	// Use for payloads that contain secret shares, nonces, or other material that must
	// never appear in plaintext.
	ConfidentialityRequired
)

// BroadcastConsistencyPolicy specifies whether broadcast messages require a consistency certificate.
type BroadcastConsistencyPolicy uint8

const (
	// BroadcastConsistencyNone means no broadcast certificate is required.
	BroadcastConsistencyNone BroadcastConsistencyPolicy = iota
	// BroadcastConsistencyRequired means a valid BroadcastCertificate must be present.
	BroadcastConsistencyRequired
)

// MessageSlotKey identifies a unique protocol message slot for equivocation detection.
// It does not include the payload hash: two different payloads occupying the same
// slot constitute equivocation.
type MessageSlotKey struct {
	Protocol    ProtocolID
	SessionID   SessionID
	Round       uint8
	From        PartyID
	To          PartyID
	PayloadType PayloadType
}

// ReplayCache detects replayed and equivocating protocol messages.
// CheckAndStore atomically checks whether a message slot has been seen and:
//   - Stores the payload hash and returns nil when the slot is new.
//   - Returns [ErrDuplicateMessage] when the slot exists with the same payload hash.
//   - Returns [ErrEquivocation] when the slot exists with a different payload hash.
type ReplayCache interface {
	CheckAndStore(slot MessageSlotKey, payloadHash [32]byte) error
}

// EnvelopeInput carries the caller-provided fields for constructing an Envelope.
type EnvelopeInput struct {
	Protocol    ProtocolID
	SessionID   SessionID
	Round       uint8
	From        PartyID
	To          PartyID
	PayloadType PayloadType
	Payload     []byte
}

// KeyShare is the common interface implemented by algorithm-specific shares.
type KeyShare interface {
	Algorithm() Algorithm
	PartyID() PartyID
	Derive(path DerivationPath, opts ...DeriveOption) (*DerivationResult, error)
	MarshalBinary() ([]byte, error)
	Destroy()
}

// Blame identifies parties and public evidence associated with a protocol failure.
type Blame struct {
	Reason   string   `json:"reason"`
	Parties  PartySet `json:"parties"`
	Evidence []byte   `json:"evidence,omitempty"`
}
