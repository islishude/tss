package tssrun

import "errors"

// ErrRunNotFound reports that no run exists for the requested identifier.
var ErrRunNotFound = errors.New("tssrun: run not found")

// ErrRunConflict reports that a run mutation conflicts with existing metadata.
var ErrRunConflict = errors.New("tssrun: run conflict")

// ErrPlanDigestConflict reports that a party accepted a different plan digest.
var ErrPlanDigestConflict = errors.New("tssrun: plan digest conflict")

// ErrSessionAlreadyUsed reports that a protocol/session identifier is reused.
var ErrSessionAlreadyUsed = errors.New("tssrun: session already used")

// ErrRunNotAccepted reports that the local party has not accepted the plan.
var ErrRunNotAccepted = errors.New("tssrun: run not accepted")

// ErrRunCompleted reports that the requested run has completed locally.
var ErrRunCompleted = errors.New("tssrun: run completed")

// ErrRunAborted reports that the requested run was aborted locally.
var ErrRunAborted = errors.New("tssrun: run aborted")

// ErrUnknownSession reports that no active session is registered for an inbound envelope.
var ErrUnknownSession = errors.New("tssrun: unknown session")

// ErrSessionConflict reports that a session registry key is already occupied.
var ErrSessionConflict = errors.New("tssrun: session conflict")

// ErrInvalidRunIntent reports malformed or incomplete run metadata.
var ErrInvalidRunIntent = errors.New("tssrun: invalid run intent")

// ErrInvalidSessionKey reports a malformed session registry key.
var ErrInvalidSessionKey = errors.New("tssrun: invalid session key")

// ErrMissingTransport reports that a dispatcher has outbound envelopes but no transport.
var ErrMissingTransport = errors.New("tssrun: missing transport")

// ErrStoreConflict reports a durable store compare-and-swap or lifecycle conflict.
var ErrStoreConflict = errors.New("tssrun: store conflict")

// ErrPresignUnavailable reports that a presign is not available for signing.
var ErrPresignUnavailable = errors.New("tssrun: presign unavailable")
