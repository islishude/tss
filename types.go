package tss

// Version is the library wire/protocol version used by current messages.
const Version = 1

const envelopeHashLabel = "github.com/islishude/tss/envelope/v1"

const envelopeWireType = "tss.envelope"

const (
	envelopeFieldProtocol uint16 = iota + 1
	envelopeFieldVersion
	envelopeFieldSessionID
	envelopeFieldRound
	envelopeFieldFrom
	envelopeFieldTo
	envelopeFieldPayloadType
	envelopeFieldPayload
	envelopeFieldTranscriptHash
)

// PartyID identifies one protocol participant; zero is reserved as "unset".
type PartyID uint32

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

// SecurityContext records transport-layer facts verified by the receiving adapter.
// It must NOT be set by protocol callers; only the transport receive path sets it.
type SecurityContext struct {
	Authenticated      bool
	Confidential       bool
	AuthenticatedParty PartyID
	ChannelID          string
	PeerKeyID          string
	ReceivedAtUnix     int64
}

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
	ConfidentialityForbidden ConfidentialityPolicy = iota
	// ConfidentialityOptional means either plaintext or confidential transport is acceptable.
	ConfidentialityOptional
	// ConfidentialityRequired means the message MUST be sent over a confidential channel.
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

// ReplayKey uniquely identifies one protocol message for replay detection.
type ReplayKey struct {
	Protocol       ProtocolID
	SessionID      SessionID
	Round          uint8
	From           PartyID
	To             PartyID
	PayloadType    PayloadType
	TranscriptHash [32]byte
}

// ReplayCache detects replayed protocol messages.
// MarkIfNew returns true on first use of a key and false on subsequent uses.
type ReplayCache interface {
	MarkIfNew(key ReplayKey) bool
}

// EnvelopeInput carries the caller-provided fields for constructing an Envelope.
type EnvelopeInput struct {
	Protocol    ProtocolID
	Version     uint16
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
	PublicKeyBytes() []byte
	MarshalBinary() ([]byte, error)
	Destroy()
}

// Signature is the common transport shape for algorithm-specific signatures.
type Signature struct {
	Algorithm Algorithm `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	Data      []byte    `json:"data"`
	R         []byte    `json:"r,omitempty"`
	S         []byte    `json:"s,omitempty"`
}

// Blame identifies parties and public evidence associated with a protocol failure.
type Blame struct {
	Reason   string    `json:"reason"`
	Parties  []PartyID `json:"parties"`
	Evidence []byte    `json:"evidence,omitempty"`
}
