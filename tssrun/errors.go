package tssrun

import "errors"

// ErrRunNotFound reports that no run exists for the requested identifier.
var ErrRunNotFound = errors.New("tssrun: run not found")

// ErrRunConflict reports that a run mutation conflicts with existing metadata.
var ErrRunConflict = errors.New("tssrun: run conflict")

// ErrPlanDigestConflict reports that a party supplied a different canonical
// run-intent acceptance digest.
var ErrPlanDigestConflict = errors.New("tssrun: plan digest conflict")

// ErrSessionAlreadyUsed reports that a protocol/session identifier is reused.
var ErrSessionAlreadyUsed = errors.New("tssrun: session already used")

// ErrRunNotAccepted reports that the local party has not accepted the plan.
var ErrRunNotAccepted = errors.New("tssrun: run not accepted")

// ErrRunPartyNotParticipant reports that a lifecycle mutation names a party
// outside the run's participant set.
var ErrRunPartyNotParticipant = errors.New("tssrun: party is not a run participant")

// ErrRunCompleted reports that the requested run has completed locally.
var ErrRunCompleted = errors.New("tssrun: run completed")

// ErrRunAborted reports that the requested run was aborted locally.
var ErrRunAborted = errors.New("tssrun: run aborted")

// ErrUnknownSession reports that no active session is registered for an inbound envelope.
var ErrUnknownSession = errors.New("tssrun: unknown session")

// ErrUnknownSessionBufferFull reports that the unknown-session buffer quota is full.
var ErrUnknownSessionBufferFull = errors.New("tssrun: unknown session buffer full")

// ErrSessionConflict reports that a session registry key is already occupied.
var ErrSessionConflict = errors.New("tssrun: session conflict")

// ErrInvalidRunIntent reports malformed or incomplete run metadata.
var ErrInvalidRunIntent = errors.New("tssrun: invalid run intent")

// ErrInvalidRunResult reports malformed local completion metadata.
var ErrInvalidRunResult = errors.New("tssrun: invalid local run result")

// ErrInvalidSessionKey reports a malformed session registry key.
var ErrInvalidSessionKey = errors.New("tssrun: invalid session key")

// ErrMissingTransport reports that a dispatcher has outbound envelopes but no transport.
var ErrMissingTransport = errors.New("tssrun: missing transport")

// ErrInvalidLifecycleRecord reports malformed generation, lease, presign,
// attempt, or cutover metadata.
var ErrInvalidLifecycleRecord = errors.New("tssrun: invalid lifecycle record")

// ErrGenerationNotCurrent reports that an operation named a stale or unknown
// generation binding.
var ErrGenerationNotCurrent = errors.New("tssrun: generation is not current")

// ErrGenerationConflict reports an install or cutover compare-and-swap
// conflict.
var ErrGenerationConflict = errors.New("tssrun: generation conflict")

// ErrRunLeaseConflict reports that a generation fence or incompatible active
// run prevents acquiring or finishing a lease.
var ErrRunLeaseConflict = errors.New("tssrun: run lease conflict")

// ErrRunLeaseNotFound reports that no exact generation-bound lease exists.
var ErrRunLeaseNotFound = errors.New("tssrun: run lease not found")

// ErrRefreshDisabled reports that protocol refresh is durably disabled for a
// key lineage after a prior protocol-level refresh failure.
var ErrRefreshDisabled = errors.New("tssrun: protocol refresh disabled")

// ErrPresignUnavailable reports that a presign is not available for signing.
var ErrPresignUnavailable = errors.New("tssrun: presign unavailable")

// ErrPresignBurned reports that a durable tombstone prevents use of a presign.
var ErrPresignBurned = errors.New("tssrun: presign burned")

// ErrAttemptNotFound reports that no exact durable signing attempt exists.
var ErrAttemptNotFound = errors.New("tssrun: signing attempt not found")

// ErrAttemptConflict reports that an attempt or presign is bound to another
// immutable signing intent.
var ErrAttemptConflict = errors.New("tssrun: signing attempt conflict")

// ErrAttemptNonDeterminism reports that one immutable intent produced a
// different attempt identifier or exact outbox.
var ErrAttemptNonDeterminism = errors.New("tssrun: signing attempt non-determinism")

// ErrAttemptOutcomeUnknown reports that a signing-attempt mutation may have
// committed and must be resolved by querying the same attempt.
var ErrAttemptOutcomeUnknown = errors.New("tssrun: signing attempt outcome unknown")

// ErrCutoverConflict reports an active, stale, or mismatched generation
// cutover fence.
var ErrCutoverConflict = errors.New("tssrun: cutover conflict")

// ErrLifecycleCorrupt reports internally inconsistent durable lifecycle state.
var ErrLifecycleCorrupt = errors.New("tssrun: lifecycle state corrupt")

// ErrFileLifecycleStoreClosed reports use after a file lifecycle store has
// released its passphrase.
var ErrFileLifecycleStoreClosed = errors.New("tssrun: file lifecycle store closed")
