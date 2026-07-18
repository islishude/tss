package tss

import (
	"errors"
	"fmt"
)

const (
	// ErrCodeInvalidConfig marks invalid local protocol configuration.
	ErrCodeInvalidConfig = "invalid_config"
	// ErrCodeInvalidMessage marks malformed or cross-session protocol messages.
	ErrCodeInvalidMessage = "invalid_message"
	// ErrCodeDuplicate marks replayed or repeated messages for a round.
	ErrCodeDuplicate = "duplicate_message"
	// ErrCodeRound marks a message delivered to the wrong protocol round.
	ErrCodeRound = "wrong_round"
	// ErrCodeVerification marks a failed cryptographic or transcript check.
	ErrCodeVerification = "verification_failed"
	// ErrCodeAggregateSignInvalid marks an aggregate signature that failed verification.
	// The blamed parties form a suspect set — individual partials cannot be verified
	// independently in the current protocol, so all signers are listed as candidate
	// sources. This is not a proof that any specific signer acted maliciously.
	ErrCodeAggregateSignInvalid = "aggregate_sign_invalid"
	// ErrCodeNotReady marks a protocol state that has not collected enough messages.
	ErrCodeNotReady = "not_ready"
	// ErrCodeConsumed marks one-use material that has already been consumed.
	ErrCodeConsumed = "consumed"
	// ErrCodeCompleted marks a protocol session that has already completed.
	ErrCodeCompleted = "completed"
	// ErrCodeAborted marks a protocol session that previously hit an attributable abort.
	ErrCodeAborted = "aborted"
	// ErrCodeNotImplemented marks intentionally unsupported protocol features.
	ErrCodeNotImplemented = "not_implemented"
	// ErrCodeLimitExceeded marks a value that exceeds a configured hard cap.
	ErrCodeLimitExceeded = "limit_exceeded"
	// ErrCodeTooManyParties marks a party set that exceeds the configured maximum.
	ErrCodeTooManyParties = "too_many_parties"
	// ErrCodeTooManySigners marks a signer set that exceeds the configured maximum.
	ErrCodeTooManySigners = "too_many_signers"
	// ErrCodePayloadTooLarge marks a payload that exceeds its byte cap.
	ErrCodePayloadTooLarge = "payload_too_large"
	// ErrCodeProofTooLarge marks a proof input that exceeds its byte cap.
	ErrCodeProofTooLarge = "proof_too_large"
	// ErrCodeInvariant marks an implementation-invariant failure. This is not a
	// protocol-level blame event — it indicates a bug in the library or corrupted
	// local state. No participants are blamed.
	ErrCodeInvariant = "invariant"
)

// ErrUnauthenticatedTransport is returned when an envelope arrives over an unauthenticated transport.
var ErrUnauthenticatedTransport = errors.New("unauthenticated transport")

// ErrSenderIdentityMismatch is returned when the transport-authenticated party differs from Envelope.From.
var ErrSenderIdentityMismatch = errors.New("sender identity mismatch")

// ErrMissingChannelProtection is returned when the receive path does not report
// whether an envelope arrived over plaintext or confidential transport.
var ErrMissingChannelProtection = errors.New("missing channel protection")

// ErrInvalidChannelProtection is returned when the receive path reports an
// undefined non-zero channel-protection value.
var ErrInvalidChannelProtection = errors.New("invalid channel protection")

// ErrMissingConfidentiality is returned when a confidential-required payload arrives over plaintext.
var ErrMissingConfidentiality = errors.New("missing transport confidentiality")

// ErrUnexpectedConfidentiality is returned when a confidential-forbidden payload arrives over a confidential channel.
var ErrUnexpectedConfidentiality = errors.New("unexpected transport confidentiality")

// ErrMissingBroadcastCertificate is returned when a broadcast-consistency-required payload has no certificate.
var ErrMissingBroadcastCertificate = errors.New("missing broadcast certificate")

// ErrInvalidBroadcastCertificate is returned when a broadcast certificate fails validation.
var ErrInvalidBroadcastCertificate = errors.New("invalid broadcast certificate")

// ErrBroadcastEquivocation is returned when a sender sends different payloads to different parties.
var ErrBroadcastEquivocation = errors.New("broadcast equivocation detected")

// ErrDuplicateMessage is returned when an identical message (same slot, same payload hash)
// is delivered more than once.
var ErrDuplicateMessage = errors.New("duplicate message")

// ErrEquivocation is returned when a party sends different payloads to different recipients
// for the same protocol message slot: the slot exists but with a different payload hash.
var ErrEquivocation = errors.New("equivocation detected")

// ErrMissingEnvelopeGuard is returned when an envelope arrives without a configured guard.
var ErrMissingEnvelopeGuard = errors.New("missing envelope guard")

// ErrMissingAckVerifier is returned when broadcast ACK verification is required but no
// verifier is configured.
var ErrMissingAckVerifier = errors.New("missing broadcast ack verifier")

// ErrMissingEnvelopeSignature is returned when policy requires portable sender authentication.
var ErrMissingEnvelopeSignature = errors.New("missing envelope sender signature")

// ErrMissingEnvelopeSignatureVerifier is returned when signature policy has no verifier.
var ErrMissingEnvelopeSignatureVerifier = errors.New("missing envelope signature verifier")

// ErrMissingEnvelopeSigner indicates that a protocol requiring portable direct
// message signatures was started without a local transport-identity signer.
var ErrMissingEnvelopeSigner = errors.New("missing envelope signer")

// ErrInvalidEnvelopeSignature is returned when portable sender authentication fails.
var ErrInvalidEnvelopeSignature = errors.New("invalid envelope sender signature")

// ErrWrongRecipient is returned when a direct message is addressed to the wrong party.
var ErrWrongRecipient = errors.New("wrong envelope recipient")

// ErrSelfSender is returned when a local guard receives an envelope claiming
// to have been sent by the same local party.
var ErrSelfSender = errors.New("envelope sender is local party")

// ErrExpectedDirectMessage is returned when a broadcast envelope arrives for a direct-only payload type.
var ErrExpectedDirectMessage = errors.New("expected direct message")

// ErrExpectedBroadcastMessage is returned when a direct envelope arrives for a broadcast-only payload type.
var ErrExpectedBroadcastMessage = errors.New("expected broadcast message")

// ErrUnknownPayloadPolicy is returned when no delivery policy matches the envelope's protocol/round/payloadType.
var ErrUnknownPayloadPolicy = errors.New("unknown payload delivery policy")

// ErrMissingReplayCache is returned when a session constructor receives a nil ReplayCache.
var ErrMissingReplayCache = errors.New("missing replay cache")

// ErrReplayCacheFull is returned when a bounded replay cache cannot record a
// new message slot without forgetting previously accepted protocol traffic.
var ErrReplayCacheFull = errors.New("replay cache full")

// ErrInvalidSessionID is returned when a session is created with a zero or invalid session ID.
var ErrInvalidSessionID = errors.New("invalid session id")

// ErrPlanHashMismatch is returned when protocol input is bound to a different lifecycle plan.
var ErrPlanHashMismatch = errors.New("lifecycle plan hash mismatch")

// ErrRefreshSchedulerRunning is returned when Run or RunOnce is called while
// another scheduler run is active.
var ErrRefreshSchedulerRunning = errors.New("refresh scheduler is already running")

// ErrRefreshCommitOutcomeUnknown marks a CommitKeyShare error whose durable
// outcome cannot be determined. When this error is wrapped, the callback keeps
// ownership of the refreshed key share for recovery and reconciliation.
var ErrRefreshCommitOutcomeUnknown = errors.New("refresh key-share commit outcome unknown")

// ProtocolError is the stable error shape returned by protocol state machines.
type ProtocolError struct {
	Code  string
	Round uint8
	Party PartyID
	Blame *Blame
	Err   error
}

// Error formats the protocol code with optional round, party, and wrapped error.
func (e *ProtocolError) Error() string {
	if e == nil {
		return ""
	}
	msg := e.Code
	if e.Round != 0 {
		msg = fmt.Sprintf("%s round=%d", msg, e.Round)
	}
	if e.Party != 0 {
		msg = fmt.Sprintf("%s party=%d", msg, e.Party)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

// Unwrap returns the underlying error for errors.Is/errors.As callers.
func (e *ProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewProtocolError constructs a ProtocolError without blame evidence.
func NewProtocolError(code string, round uint8, party PartyID, err error) *ProtocolError {
	return &ProtocolError{Code: code, Round: round, Party: party, Err: err}
}

// IsSessionCompleted reports whether err is a [ProtocolError] with code
// [ErrCodeCompleted], indicating the protocol session has already finished.
func IsSessionCompleted(err error) bool {
	var p *ProtocolError
	return errors.As(err, &p) && p.Code == ErrCodeCompleted
}

// IsSessionAborted reports whether err is a [ProtocolError] with code
// [ErrCodeAborted], indicating the protocol session was aborted due to an
// attributable verification failure.
func IsSessionAborted(err error) bool {
	var p *ProtocolError
	return errors.As(err, &p) && p.Code == ErrCodeAborted
}

// IsAttributableError reports whether err carries blame evidence and
// should cause the session to abort. Verification failures with blame
// are attributable; duplicate messages are not.
//
// This matches the [shouldAbortSession] logic used by protocol handlers.
func IsAttributableError(err error) bool {
	var p *ProtocolError
	if !errors.As(err, &p) {
		return false
	}
	if p.Code == ErrCodeDuplicate {
		return false
	}
	return p.Code == ErrCodeVerification || p.Blame != nil
}
