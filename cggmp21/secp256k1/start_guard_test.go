package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/tssrun"
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
		return &Presign{state: &presignState{Consumed: newAtomicBool(), attempt: newPresignAttemptBinding(false)}}
	}
	keygenPlan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID,
		Parties:   tss.NewPartySet(1, 2),
		Threshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	presignPlan := &PresignPlan{state: &presignPlanState{
		sessionID: sessionID,
		presignID: bytes.Repeat([]byte{0x31}, 32),
		epochID:   bytes.Repeat([]byte{0x32}, 32),
		context:   tss.SigningContext{KeyID: "guard-test-key"},
	}, limits: DefaultLimits(), securityParams: DefaultSecurityParams()}
	presignEpochID, err := tssrun.NewEpochID(presignPlan.state.epochID)
	if err != nil {
		t.Fatal(err)
	}
	presignBinding := tssrun.GenerationBinding{KeyID: "guard-test-key", KeyGeneration: "guard-test-generation", EpochID: presignEpochID}
	protocolPresignID := bytes.Repeat([]byte{0x34}, 32)
	signPlan := &SignPlan{state: &signPlanState{sessionID: sessionID, protocolPresignID: protocolPresignID}, limits: DefaultLimits()}
	presignSlot, err := PresignSlotID(protocolPresignID)
	if err != nil {
		t.Fatal(err)
	}
	epochID, err := tssrun.NewEpochID(bytes.Repeat([]byte{0x35}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signBinding := tssrun.GenerationBinding{KeyID: "guard-test-key", KeyGeneration: "guard-test-generation", EpochID: epochID}
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
		sourceEpochID:           bytes.Repeat([]byte{0x33}, 32),
	}, limits: DefaultLimits(), securityParams: DefaultSecurityParams()}
	refreshEpochID, err := tssrun.NewEpochID(refreshPlan.state.sourceEpochID)
	if err != nil {
		t.Fatal(err)
	}
	refreshBinding := tssrun.GenerationBinding{KeyID: "guard-refresh-key", KeyGeneration: "guard-refresh-source", EpochID: refreshEpochID}
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
	reshareEpochID, err := tssrun.NewEpochID(bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reshareBinding := tssrun.GenerationBinding{KeyID: "guard-reshare-key", KeyGeneration: "guard-reshare-source", EpochID: reshareEpochID}

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
				_, out, err := StartPresign(presignPlan, PresignRuntime{
					Local: tss.LocalConfig{Self: 1}, Guard: guard,
					LifecycleStore: newTestLifecycleStore(), Binding: presignBinding,
				})
				return out, false, err
			},
		},
		{
			name:    "sign",
			self:    1,
			parties: tss.NewPartySet(1, 2),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				p := minimalPresign()
				_, out, err := StartSign(signPlan, SignRuntime{
					Local:          tss.LocalConfig{Self: 1},
					Guard:          guard,
					LifecycleStore: newTestLifecycleStore(),
					Binding:        signBinding,
					PresignID:      presignSlot,
					AttemptID:      "guard-test-attempt",
				})
				return out, IsPresignConsumed(p), err
			},
		},
		{
			name:    "refresh",
			self:    1,
			parties: tss.NewPartySet(1, 2),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartRefresh(refreshPlan, RefreshRuntime{
					Local: tss.LocalConfig{Self: 1}, Guard: guard,
					LifecycleStore: newTestLifecycleStore(), Binding: refreshBinding, TargetKeyGeneration: "guard-refresh-target",
				})
				return out, false, err
			},
		},
		{
			name:    "reshare dealer",
			self:    1,
			parties: tss.NewPartySet(1, 2, 3, 4),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareDealer(plan, ReshareRuntime{
					Local: tss.LocalConfig{Self: 1}, Guard: guard,
					LifecycleStore: newTestLifecycleStore(), Binding: reshareBinding, TargetKeyGeneration: "guard-reshare-target",
				})
				return out, false, err
			},
		},
		{
			name:    "reshare receiver",
			self:    3,
			parties: tss.NewPartySet(1, 2, 3),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareReceiver(plan, ReshareRuntime{
					Local: tss.LocalConfig{Self: 3}, Guard: guard,
					LifecycleStore: newTestLifecycleStore(), Binding: reshareBinding, TargetKeyGeneration: "guard-reshare-target",
				})
				return out, false, err
			},
		},
		{
			name:    "reshare overlap",
			self:    1,
			parties: tss.NewPartySet(1, 2, 3),
			start: func(guard *tss.EnvelopeGuard) ([]tss.Envelope, bool, error) {
				_, out, err := StartReshareOverlap(plan, ReshareRuntime{
					Local: tss.LocalConfig{Self: 1}, Guard: guard,
					LifecycleStore: newTestLifecycleStore(), Binding: reshareBinding, TargetKeyGeneration: "guard-reshare-target",
				})
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
