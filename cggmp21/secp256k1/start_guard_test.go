package secp256k1

import (
	"errors"
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
	key.state.Party = 1
	key.state.Threshold = 2
	key.state.Parties = tss.NewPartySet(1, 2)
	key.state.SecurityParams = DefaultSecurityParams()
	oldCommitmentsHash, err := keygenCommitmentsHash(key.state.GroupCommitments)
	if err != nil {
		t.Fatal(err)
	}
	minimalPresign := func() *Presign {
		return &Presign{state: &presignState{Consumed: NewAtomicBoolWire(false), attempt: newPresignAttemptBinding(false)}}
	}
	keygenPlan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	presignPlan := &PresignPlan{state: &presignPlanState{sessionID: sessionID}, limits: DefaultLimits(), securityParams: DefaultSecurityParams()}
	signPlan := &SignPlan{state: &signPlanState{sessionID: sessionID}, limits: DefaultLimits()}
	refreshPlan := &RefreshPlan{state: &refreshPlanState{
		sessionID:               sessionID,
		threshold:               2,
		parties:                 tss.NewPartySet(1, 2),
		publicKey:               key.state.PublicKey,
		chainCode:               key.state.ChainCode,
		paillierBits:            int(DefaultSecurityParams().MinPaillierBits),
		oldPaillierProofSession: key.state.PaillierProofSessionID,
		oldKeygenTranscriptHash: key.state.KeygenTranscriptHash,
		oldPlanHash:             key.state.PlanHash,
		oldCommitmentsHash:      oldCommitmentsHash,
	}, limits: DefaultLimits(), securityParams: DefaultSecurityParams()}
	plan := &ResharePlan{state: &resharePlanState{
		SessionID:             sessionID,
		CurveID:               reshareCurveID,
		OldParties:            tss.NewPartySet(1, 2),
		OldThreshold:          2,
		DealerParties:         tss.NewPartySet(1, 2),
		NewParties:            tss.NewPartySet(1, 2, 3),
		NewThreshold:          2,
		PaillierBits:          int(DefaultSecurityParams().MinPaillierBits),
		ChainCode:             nil,
		OldGroupPublicKey:     nil,
		OldGroupCommitments:   nil,
		OldVerificationShares: map[tss.PartyID][]byte{},
		SecurityParams:        DefaultSecurityParams(),
	}, limits: DefaultLimits()}

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
			parties: tss.NewPartySet(1, 2),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartKeygen(keygenPlan, tss.LocalConfig{Self: 1}, guard)
				return out, false, err
			},
		},
		{
			name:    "presign",
			self:    1,
			parties: tss.NewPartySet(1, 2),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartPresign(key, presignPlan, tss.LocalConfig{Self: 1}, guard)
				return out, false, err
			},
		},
		{
			name:    "sign",
			self:    1,
			parties: tss.NewPartySet(1, 2),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				p := minimalPresign()
				_, out, err := StartSign(key, signPlan, SignRuntime{
					Local:        tss.LocalConfig{Self: 1},
					Guard:        guard,
					Presign:      p,
					AttemptStore: newTestSignAttemptStore(),
				})
				return out, IsPresignConsumed(p), err
			},
		},
		{
			name:    "refresh",
			self:    1,
			parties: tss.NewPartySet(1, 2),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartRefresh(key, refreshPlan, tss.LocalConfig{Self: 1}, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare dealer",
			self:    1,
			parties: tss.NewPartySet(1, 2, 3, 4),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareDealer(key, plan, tss.LocalConfig{Self: 1}, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare receiver",
			self:    3,
			parties: tss.NewPartySet(1, 2, 3),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareReceiver(plan, tss.LocalConfig{Self: 3}, guard)
				return out, false, err
			},
		},
		{
			name:    "reshare overlap",
			self:    1,
			parties: tss.NewPartySet(1, 2, 3),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareOverlap(key, plan, tss.LocalConfig{Self: 1}, guard)
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
					return tss.NewTestEnvelopeGuard(tc.self, tc.parties, tss.ProtocolCGGMP21Secp256k1, wrongSession, testCGGMP21Policies())
				},
			},
			{
				name: "wrong self",
				guard: func() *tss.EnvelopeGuard {
					return tss.NewTestEnvelopeGuard(testutil.OtherParty(tc.parties, tc.self), tc.parties, tss.ProtocolCGGMP21Secp256k1, sessionID, testCGGMP21Policies())
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
