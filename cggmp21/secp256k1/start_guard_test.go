package secp256k1

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21StartRequiresEnvelopeGuard(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	key := minimalKeyShare()
	key.Party = 1
	key.Threshold = 2
	key.Parties = []tss.PartyID{1, 2}
	minimalPresign := func() *Presign {
		return &Presign{
			consumed: new(atomic.Bool),
		}
	}
	plan := ResharePlan{
		SessionID: sessionID,
	}

	type startCase struct {
		name    string
		self    tss.PartyID
		parties tss.PartySet
		start   func(*tss.EnvelopeGuard) ([]tss.Envelope, bool, error)
	}

	cases := []startCase{
		{
			name:    "keygen",
			self:    1,
			parties: tss.PartySet{1, 2},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartKeygen(tss.ThresholdConfig{
					Threshold: 2,
					Parties:   []tss.PartyID{1, 2},
					Self:      1,
					SessionID: sessionID,
				}, guard)
				return out, false, err
			},
		},
		{
			name:    "presign",
			self:    1,
			parties: tss.PartySet{1, 2},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartPresignWithContext(key, sessionID, []tss.PartyID{1, 2}, testPresignContext(), guard)
				return out, false, err
			},
		},
		{
			name:    "sign",
			self:    1,
			parties: tss.PartySet{1, 2},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				p := minimalPresign()
				_, out, err := StartSign(key, p, sessionID, SignRequest{
					Context: testPresignContext(),
					Message: []byte("guard"),
					LowS:    true,
				}, guard)
				return out, IsPresignConsumed(p), err
			},
		},
		{
			name:    "refresh",
			self:    1,
			parties: tss.PartySet{1, 2},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartRefresh(key, tss.ThresholdConfig{
					Threshold: 2,
					Parties:   []tss.PartyID{1, 2},
					Self:      1,
					SessionID: sessionID,
				}, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare",
			self:    1,
			parties: tss.PartySet{1, 2},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := startCGGMP21Reshare(key, tss.ThresholdConfig{
					Threshold: 2,
					Parties:   []tss.PartyID{1, 2},
					Self:      1,
					SessionID: sessionID,
				}, []tss.PartyID{1, 2}, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare dealer",
			self:    1,
			parties: tss.PartySet{1, 2, 3, 4},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareDealer(key, plan, nil, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare receiver",
			self:    3,
			parties: tss.PartySet{1, 2, 3},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareReceiver(plan, 3, nil, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare overlap",
			self:    1,
			parties: tss.PartySet{1, 2, 3},
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareOverlap(key, plan, nil, guard)
				return out, false, err
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
					return tss.NewTestEnvelopeGuard(tc.self, tc.parties, "wrong-protocol", sessionID, testCGGMP21Policies())
				},
			},
			{
				name: "wrong session",
				guard: func() *tss.EnvelopeGuard {
					wrongSession, _ := tss.NewSessionID(nil)
					return tss.NewTestEnvelopeGuard(tc.self, tc.parties, protocol, wrongSession, testCGGMP21Policies())
				},
			},
			{
				name: "wrong self",
				guard: func() *tss.EnvelopeGuard {
					return tss.NewTestEnvelopeGuard(testutil.OtherParty(tc.parties, tc.self), tc.parties, protocol, sessionID, testCGGMP21Policies())
				},
			},
		} {
			t.Run(tc.name+"/"+gc.name, func(t *testing.T) {
				out, consumed, err := tc.start(gc.guard())
				if err == nil {
					t.Fatal("expected guard error")
				}
				if gc.wantGuard != nil && !errors.Is(err, gc.wantGuard) {
					t.Fatalf("expected %v, got %v", gc.wantGuard, err)
				}
				if len(out) != 0 {
					t.Fatalf("expected no outbound messages, got %d", len(out))
				}
				if tc.name == "sign" && consumed {
					t.Fatal("invalid guard consumed presign")
				}
			})
		}
	}
}
