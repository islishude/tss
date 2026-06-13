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
	parties := tss.PartySet{1, 2}
	newParties := []tss.PartyID{1, 2, 3}
	sessionID, err := tss.NewSessionID(nil)
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
				_, out, err := StartKeygen(tss.ThresholdConfig{
					Threshold: 2,
					Parties:   parties,
					Self:      1,
					SessionID: sessionID,
				}, guard)
				return out, err
			},
		},
		{
			name:    "sign",
			self:    1,
			parties: parties,
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("guard"), guard)
				return out, err
			},
		},
		{
			name:    "refresh",
			self:    1,
			parties: parties,
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartRefresh(shares[1], tss.ThresholdConfig{
					Threshold: 2,
					Parties:   parties,
					Self:      1,
					SessionID: sessionID,
				}, guard)
				return out, err
			},
		},
		{
			name:    "reshare dealer",
			self:    1,
			parties: tss.PartySet{1, 2, 3},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, out, err := StartReshare(shares[1], newParties, 2, tss.ThresholdConfig{
					Threshold: 2,
					Parties:   parties,
					Self:      1,
					SessionID: sessionID,
				}, guard)
				return out, err
			},
		},
		{
			name:    "reshare recipient",
			self:    3,
			parties: tss.PartySet{1, 2, 3},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, error) {
				_, err := StartReshareRecipient(shares[1].state.publicKey, nil, parties, newParties, 2, tss.ThresholdConfig{
					Threshold: 2,
					Parties:   newParties,
					Self:      3,
					SessionID: sessionID,
				}, guard)
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
