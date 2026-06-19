package secp256k1

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// This file tests state machine invariants across presign and sign sessions.
// These are Tier 0 tests: no Paillier keygen or full CGGMP crypto is used.
// We test session lifecycle, error classification, and policy validation
// that does not require cryptographic material.

func TestPresignSessionRejectsNil(t *testing.T) {
	t.Parallel()
	var s *PresignSession
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := tss.Envelope{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       1,
		From:        2,
		To:          0,
		PayloadType: payloadPresignRound1,
		Payload:     []byte{},
	}
	_, err = s.HandlePresignMessage(testutil.DeliverEnvelope(env))
	if err == nil {
		t.Fatal("expected nil session rejection")
	}
}

func TestSignSessionRejectsNil(t *testing.T) {
	t.Parallel()
	var s *SignSession
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := tss.Envelope{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       1,
		From:        2,
		To:          0,
		PayloadType: payloadSignPartial,
		Payload:     []byte{},
	}
	_, err = s.HandleSignMessage(testutil.DeliverEnvelope(env))
	if err == nil {
		t.Fatal("expected nil session rejection")
	}
}

func TestKeygenSessionRejectsNil(t *testing.T) {
	t.Parallel()
	var s *KeygenSession
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := tss.Envelope{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       1,
		From:        2,
		To:          0,
		PayloadType: payloadKeygenCommitments,
		Payload:     []byte{},
	}
	_, err = s.HandleKeygenMessage(testutil.DeliverEnvelope(env))
	if err == nil {
		t.Fatal("expected nil keygen session rejection")
	}
}

// TestShouldAbortSession verifies the session abort policy:
// verification failures and blame-bearing errors cause abort,
// but duplicate messages do not (they are protocol-level retries).
func TestShouldAbortSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		err       error
		wantAbort bool
	}{
		{
			name:      "nil error",
			err:       nil,
			wantAbort: false,
		},
		{
			name:      "non-protocol error",
			err:       errors.New("plain error"),
			wantAbort: false,
		},
		{
			name: "verification error aborts",
			err: &tss.ProtocolError{
				Code: tss.ErrCodeVerification,
			},
			wantAbort: true,
		},
		{
			name: "blame-bearing error aborts",
			err: &tss.ProtocolError{
				Code:  tss.ErrCodeInvalidMessage,
				Blame: &tss.Blame{Reason: "test"},
			},
			wantAbort: true,
		},
		{
			name: "duplicate does not abort",
			err: &tss.ProtocolError{
				Code: tss.ErrCodeDuplicate,
			},
			wantAbort: false,
		},
		{
			name: "verification with duplicate code does abort",
			err: &tss.ProtocolError{
				Code: tss.ErrCodeVerification,
			},
			wantAbort: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldAbortSession(tt.err)
			if got != tt.wantAbort {
				t.Errorf("shouldAbortSession(%v) = %v, want %v", tt.err, got, tt.wantAbort)
			}
		})
	}
}

func TestCompletedSessionError(t *testing.T) {
	t.Parallel()
	err := completedSessionError(1, 2)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var pe *tss.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatal("expected ProtocolError")
	}
	if pe.Code != tss.ErrCodeCompleted {
		t.Errorf("expected ErrCodeCompleted, got %s", pe.Code)
	}
	if pe.Round != 1 {
		t.Errorf("expected round 1, got %d", pe.Round)
	}
}

func TestAbortedSessionError(t *testing.T) {
	t.Parallel()
	err := abortedSessionError(2, 3)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var pe *tss.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatal("expected ProtocolError")
	}
	if pe.Code != tss.ErrCodeAborted {
		t.Errorf("expected ErrCodeAborted, got %s", pe.Code)
	}
}

func TestPresignMarshalJSONRejected(t *testing.T) {
	t.Parallel()
	p := minimalCGGMP21Presign(t)
	_, err := p.MarshalJSON()
	if err == nil {
		t.Fatal("expected JSON marshal rejection for secret-bearing presign")
	}
}

func TestPresignDestroyClearsSecrets(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	p.Destroy()
	if !IsPresignConsumed(p) {
		t.Fatal("expected presign consumed after Destroy")
	}
}

func TestPresignDestroyMarksTestCopyConsumed(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	cp := clonePresignForTest(p)
	p.Destroy()
	if !IsPresignConsumed(cp) {
		t.Fatal("destroying a presign did not mark an existing test copy consumed")
	}
}

func TestMarkPresignConsumedMarksInPlace(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	cp := clonePresignForTest(p)

	if err := MarkPresignConsumed(p); err != nil {
		t.Fatal(err)
	}
	if !IsPresignConsumed(p) {
		t.Fatal("MarkPresignConsumed did not mark the original presign consumed")
	}
	if !IsPresignConsumed(cp) {
		t.Fatal("MarkPresignConsumed did not update the shared claim")
	}
}

func TestMarkPresignConsumedDoesNotReleaseBoundAttempt(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	intent := bytes.Repeat([]byte{1}, 32)
	if !bindPresignToAttempt(p, intent, false) {
		t.Fatal("failed to bind test attempt")
	}
	if err := MarkPresignConsumed(p); err != nil {
		t.Fatal(err)
	}
	if !bindPresignToAttempt(p, intent, true) {
		t.Fatal("manual consume canceled the existing attempt")
	}
	if bindPresignToAttempt(p, bytes.Repeat([]byte{2}, 32), true) {
		t.Fatal("manual consume released the presign to another attempt")
	}
}

func TestPresignMissingClaimFailsClosed(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	p.state.consumed = nil

	if !IsPresignConsumed(p) {
		t.Fatal("presign without claim state was treated as unconsumed")
	}
	if p.state.consumed != nil {
		t.Fatal("IsPresignConsumed lazily initialized missing claim state")
	}
	if err := p.Validate(); err == nil {
		t.Fatal("presign without claim state passed validation")
	}
	if bindPresignToAttempt(p, bytes.Repeat([]byte{1}, 32), false) {
		t.Fatal("presign without claim state was bound")
	}
	if p.state.consumed != nil {
		t.Fatal("attempt binding lazily initialized missing claim state")
	}
	if err := MarkPresignConsumed(p); err == nil {
		t.Fatal("MarkPresignConsumed accepted missing claim state")
	}
	cp := clonePresignForTest(p)
	if cp.state.consumed != nil || !IsPresignConsumed(cp) {
		t.Fatal("test copy revived presign with missing claim state")
	}
}

func TestPresignMissingAttemptBindingFailsClosed(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	p.state.attempt = nil

	if !IsPresignConsumed(p) {
		t.Fatal("presign without attempt state was treated as unconsumed")
	}
	if err := p.Validate(); err == nil {
		t.Fatal("presign without attempt state passed validation")
	}
	if bindPresignToAttempt(p, bytes.Repeat([]byte{1}, 32), false) {
		t.Fatal("presign without attempt state was bound")
	}
	if err := MarkPresignConsumed(p); err == nil {
		t.Fatal("MarkPresignConsumed accepted missing attempt state")
	}
}

func TestPresignSessionPresignTransfersOwnership(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	session := &PresignSession{
		completed: true,
		presign:   p,
	}
	got, ok := session.Presign()
	if !ok {
		t.Fatal("first Presign call failed")
	}
	if got != p {
		t.Fatal("Presign did not transfer the session-owned presign")
	}
	if session.presign != nil {
		t.Fatal("session retained presign after transfer")
	}
	got, ok = session.Presign()
	if ok || got != nil {
		t.Fatal("second Presign call returned a presign")
	}
}

func TestBindPresignToAttemptRejectsNil(t *testing.T) {
	t.Parallel()
	if bindPresignToAttempt(nil, bytes.Repeat([]byte{1}, 32), false) {
		t.Fatal("nil presign was bound")
	}
}

func TestValidateSignerSetRejectsEmptyKey(t *testing.T) {
	t.Parallel()
	key := &KeyShare{state: &keyShareState{party: 1, threshold: 1, parties: tss.NewPartySet(1)}}
	err := validateSignerSet(key, tss.NewPartySet(), DefaultLimits())
	if err == nil {
		t.Fatal("expected empty signer set rejection")
	}
}

func TestPresignContextValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ctx     PresignContext
		wantErr string
	}{
		{
			name:    "empty key id",
			ctx:     PresignContext{ChainID: "c", Derivation: tss.DerivationRequest{Scheme: tss.DerivationSchemeBIP32Secp256k1}, PolicyDomain: "p", MessageDomain: "m"},
			wantErr: "key id",
		},
		{
			name:    "empty chain id",
			ctx:     PresignContext{KeyID: "k", Derivation: tss.DerivationRequest{Scheme: tss.DerivationSchemeBIP32Secp256k1}, PolicyDomain: "p", MessageDomain: "m"},
			wantErr: "chain id",
		},
		{
			name:    "empty policy domain",
			ctx:     PresignContext{KeyID: "k", ChainID: "c", Derivation: tss.DerivationRequest{Scheme: tss.DerivationSchemeBIP32Secp256k1}, MessageDomain: "m"},
			wantErr: "policy domain",
		},
		{
			name:    "empty message domain",
			ctx:     PresignContext{KeyID: "k", ChainID: "c", Derivation: tss.DerivationRequest{Scheme: tss.DerivationSchemeBIP32Secp256k1}, PolicyDomain: "p"},
			wantErr: "message domain",
		},
		{
			name: "hardened derivation",
			ctx: PresignContext{
				KeyID: "k", ChainID: "c", PolicyDomain: "p", MessageDomain: "m",
				Derivation: tss.DerivationRequest{
					Scheme: tss.DerivationSchemeBIP32Secp256k1,
					Path:   tss.DerivationPath{0x80000000},
				},
			},
			wantErr: "hardened",
		},
		{
			name: "valid",
			ctx: PresignContext{
				KeyID: "k", ChainID: "c", PolicyDomain: "p", MessageDomain: "m",
				Derivation: tss.DerivationRequest{Scheme: tss.DerivationSchemeBIP32Secp256k1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePresignContext(tt.ctx)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
