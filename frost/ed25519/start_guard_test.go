package ed25519

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTStartRequiresEnvelopeGuard(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 2)
	parties := tss.NewPartySet(1, 2)
	newParties := tss.NewPartySet(1, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygenPlan, err := NewKeygenPlan(KeygenPlanOption{SessionID: sessionID, Parties: parties, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	limits := testLimits()
	signPlan, err := NewSignPlan(SignPlanOption{
		Key: shares[1], SessionID: sessionID, Signers: tss.NewPartySet(1, 2),
		Context: testFROSTSigningContext(), Message: []byte("guard"), Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	refreshPlan, err := NewRefreshPlan(RefreshPlanOption{OldKey: shares[1], SessionID: sessionID, Limits: &limits})
	if err != nil {
		t.Fatal(err)
	}
	resharePlan, err := NewResharePlan(ResharePlanOption{
		OldKey: shares[1], SessionID: sessionID, NewParties: newParties, NewThreshold: 2, Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipientPlan, err := NewPublicResharePlan(PublicResharePlanOption{
		OldPublicKey: shares[1].state.publicKey, OldChainCode: shares[1].state.chainCode, OldParties: parties, SessionID: sessionID,
		NewParties: newParties, NewThreshold: 2, Limits: &limits,
	})
	if err != nil {
		t.Fatal(err)
	}

	type startCase struct {
		name    string
		self    tss.PartyID
		parties tss.PartySet
		start   func(*tss.EnvelopeGuard) ([]tss.Envelope, error)
	}

	cases := []startCase{
		{
			name:    "keygen",
			self:    1,
			parties: parties,
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartKeygen(keygenPlan, tss.LocalConfig{Self: 1}, guard)
				return out, err
			},
		},
		{
			name:    "sign",
			self:    1,
			parties: parties,
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartSign(shares[1], signPlan, tss.LocalConfig{Self: 1}, guard)
				return out, err
			},
		},
		{
			name:    "refresh",
			self:    1,
			parties: parties,
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartRefresh(shares[1], refreshPlan, tss.LocalConfig{Self: 1}, guard)
				return out, err
			},
		},
		{
			name:    "reshare dealer",
			self:    1,
			parties: tss.NewPartySet(1, 2, 3),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartReshare(shares[1], resharePlan, tss.LocalConfig{Self: 1}, guard)
				return out, err
			},
		},
		{
			name:    "reshare recipient",
			self:    3,
			parties: tss.NewPartySet(1, 2, 3),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, err := StartReshareRecipient(recipientPlan, tss.LocalConfig{Self: 3}, guard)
				return nil, err
			},
		},
	}

	for _, tc := range cases {
		for _, gc := range []struct {
			name      string
			guard     func() *tss.EnvelopeGuard
			wantGuard error
		}{
			{
				name:      "nil",
				guard:     func() *tss.EnvelopeGuard { return nil },
				wantGuard: tss.ErrMissingEnvelopeGuard,
			},
			{
				name: "wrong protocol",
				guard: func() *tss.EnvelopeGuard {
					return tss.NewTestEnvelopeGuard(tc.self, tc.parties, "wrong-protocol", sessionID, testFROSTPolicies())
				},
			},
			{
				name: "wrong session",
				guard: func() *tss.EnvelopeGuard {
					wrongSession, _ := tss.NewSessionID(nil)
					return tss.NewTestEnvelopeGuard(tc.self, tc.parties, protocol, wrongSession, testFROSTPolicies())
				},
			},
			{
				name: "wrong self",
				guard: func() *tss.EnvelopeGuard {
					return tss.NewTestEnvelopeGuard(testutil.OtherParty(tc.parties, tc.self), tc.parties, protocol, sessionID, testFROSTPolicies())
				},
			},
		} {
			t.Run(tc.name+"/"+gc.name, func(t *testing.T) {
				t.Parallel()

				out, err := tc.start(gc.guard())
				if err == nil {
					t.Fatal("expected guard error")
				}
				if gc.wantGuard != nil && !errors.Is(err, gc.wantGuard) {
					t.Fatalf("expected %v, got %v", gc.wantGuard, err)
				}
				if len(out) != 0 {
					t.Fatalf("expected no outbound messages, got %d", len(out))
				}
			})
		}
	}
}
