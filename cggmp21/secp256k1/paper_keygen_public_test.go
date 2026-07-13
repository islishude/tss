package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func paperKeygenTestPolicies() tss.PolicySet {
	entries := CGGMP21Policies().Entries()
	for i := range entries {
		entries[i].BroadcastConsistency = tss.BroadcastConsistencyNone
		entries[i].RequireSenderSignature = false
	}
	policies, err := tss.NewPolicySet(entries...)
	if err != nil {
		panic(err)
	}
	return policies
}

func paperKeygenTestGuard(self tss.PartyID, parties tss.PartySet, sid tss.SessionID) *tss.EnvelopeGuard {
	return tss.NewTestEnvelopeGuard(self, parties, tss.ProtocolCGGMP21Secp256k1, sid, paperKeygenTestPolicies())
}

func routePaperKeygen(t *testing.T, sessions map[tss.PartyID]*KeygenSession, parties tss.PartySet, queue []tss.Envelope) {
	t.Helper()
	confirmationStarted := false
	for len(queue) != 0 {
		env := queue[0]
		queue = queue[1:]
		if env.Round == keygenPaperConfirmationRound && !confirmationStarted {
			confirmationStarted = true
			for party, session := range sessions {
				if _, ok := session.KeyShare(); ok {
					t.Fatalf("party %d became sign-ready before the confirmation round", party)
				}
			}
		}
		for _, receiver := range parties {
			if receiver == env.From || env.To != tss.BroadcastPartyId && env.To != receiver {
				continue
			}
			out, err := sessions[receiver].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s round %d from %d to %d: %v", env.PayloadType, env.Round, env.From, receiver, err)
			}
			queue = append(queue, out...)
		}
	}
	if !confirmationStarted {
		t.Fatal("paper keygen never emitted confirmations")
	}
}

func TestPublicKeygenRunsFigure6ThenFigure7(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	sid := tss.SessionID(bytes.Repeat([]byte{0x91}, 32))
	limits := testLimits()
	params := testSecurityParams()
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sid, Parties: parties, Threshold: 2,
		Limits: &limits, SecurityParams: &params,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0, len(parties))
	for _, party := range parties {
		session, out, err := StartKeygen(plan, tss.LocalConfig{Self: party, Rand: testutil.DeterministicReader(int64(9100 + party))}, paperKeygenTestGuard(party, parties, sid))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].PayloadType != payloadFigure6Commitment || out[0].Round != keygenFigure6CommitmentRound {
			t.Fatalf("party %d start output = %#v, want one Figure 6 commitment", party, out)
		}
		if _, ok := session.KeyShare(); ok {
			t.Fatalf("party %d is sign-ready at StartKeygen", party)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	routePaperKeygen(t, sessions, parties, queue)

	var referencePublic, referenceEpoch []byte
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("party %d keygen incomplete", party)
		}
		defer share.Destroy()
		if err := share.ValidateWithLimits(limits); err != nil {
			t.Fatalf("party %d output invalid: %v", party, err)
		}
		epoch, ok := share.EpochContext()
		if !ok || epoch.SourceEpochID != nil {
			t.Fatalf("party %d missing initial epoch context", party)
		}
		identifier, ok := epoch.Identifier(party)
		if !ok {
			t.Fatalf("party %d missing dynamic identifier", party)
		}
		fixedIdentifier := secp.ScalarFromUint64(uint64(party)).Bytes()
		if bytes.Equal(identifier, fixedIdentifier) {
			t.Fatalf("party %d reused transport PartyID as its Shamir coordinate", party)
		}
		if referencePublic == nil {
			referencePublic = bytes.Clone(share.state.PublicKey)
			referenceEpoch = bytes.Clone(epoch.EpochID)
		} else if !bytes.Equal(referencePublic, share.state.PublicKey) || !bytes.Equal(referenceEpoch, epoch.EpochID) {
			t.Fatalf("party %d disagrees on public key or epoch", party)
		}
	}
}

func TestPublicKeygenSingletonCompletesWithoutSelfDelivery(t *testing.T) {
	parties := tss.NewPartySet(1)
	sid := tss.SessionID(bytes.Repeat([]byte{0x90}, 32))
	limits := testLimits()
	params := testSecurityParams()
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sid, Parties: parties, Threshold: 1,
		Limits: &limits, SecurityParams: &params,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, out, err := StartKeygen(
		plan,
		tss.LocalConfig{Self: 1, Rand: testutil.DeterministicReader(9001)},
		paperKeygenTestGuard(1, parties, sid),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PayloadType != payloadFigure6Commitment {
		t.Fatalf("singleton start output = %#v, want one Figure 6 commitment", out)
	}
	share, ok := session.KeyShare()
	if !ok {
		t.Fatal("singleton keygen did not complete without self-delivery")
	}
	defer share.Destroy()
	if err := share.ValidateWithLimits(limits); err != nil {
		t.Fatalf("singleton key share is invalid: %v", err)
	}
}

func TestTrustedDealerImportUsesPaperKeygenAndProducesEpoch(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	sid := tss.SessionID(bytes.Repeat([]byte{0x92}, 32))
	limits := testLimits()
	params := testSecurityParams()
	secretKey, err := ParseSecretKey(secp.ScalarFromUint64(37).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer secretKey.Destroy()
	plan, contributions, err := NewTrustedDealerImport(secretKey, TrustedDealerImportOption{
		SessionID: sid, Parties: parties, Threshold: 2,
		Limits: &limits, SecurityParams: &params, PaillierBits: int(params.MinPaillierBits),
	}, testutil.DeterministicReader(9200))
	if err != nil {
		t.Fatal(err)
	}
	defer destroyCGGMPContributions(contributions)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	queue := make([]tss.Envelope, 0, len(parties))
	for _, party := range parties {
		session, out, err := StartTrustedDealerImport(plan, contributions[party], tss.LocalConfig{
			Self: party, Rand: testutil.DeterministicReader(int64(9250 + party)),
		}, paperKeygenTestGuard(party, parties, sid))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].PayloadType != payloadFigure6Commitment {
			t.Fatalf("party %d trusted import did not start at Figure 6", party)
		}
		sessions[party] = session
		queue = append(queue, out...)
	}
	routePaperKeygen(t, sessions, parties, queue)
	wantPublic, err := secretKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, party := range parties {
		share, ok := sessions[party].KeyShare()
		if !ok {
			t.Fatalf("trusted import incomplete for party %d", party)
		}
		defer share.Destroy()
		if !bytes.Equal(share.state.PublicKey, wantPublic) {
			t.Fatalf("party %d trusted import public key mismatch", party)
		}
		if share.state.Epoch == nil {
			t.Fatalf("party %d trusted import output lacks new EpochContext", party)
		}
	}
}

func TestFigure6RevealEquivocationDoesNotCommit(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	sid := tss.SessionID(bytes.Repeat([]byte{0x93}, 32))
	limits := testLimits()
	params := testSecurityParams()
	plan, err := NewKeygenPlan(KeygenPlanOption{SessionID: sid, Parties: parties, Threshold: 2, Limits: &limits, SecurityParams: &params})
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := StartKeygen(plan, tss.LocalConfig{Self: 1, Rand: testutil.DeterministicReader(9301)}, paperKeygenTestGuard(1, parties, sid))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(plan, tss.LocalConfig{Self: 2, Rand: testutil.DeterministicReader(9302)}, paperKeygenTestGuard(2, parties, sid))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Handle(testutil.DeliverEnvelope(out2[0])); err != nil {
		t.Fatal(err)
	}
	s2, _, err := StartKeygen(plan, tss.LocalConfig{Self: 2, Rand: testutil.DeterministicReader(9302)}, paperKeygenTestGuard(2, parties, sid))
	if err != nil {
		t.Fatal(err)
	}
	reveal2, err := s2.Handle(testutil.DeliverEnvelope(out1[0]))
	if err != nil || len(reveal2) != 1 || reveal2[0].PayloadType != payloadFigure6Reveal {
		t.Fatalf("produce party 2 reveal: out=%v err=%v", reveal2, err)
	}
	payload, err := tss.DecodeBinaryWithLimits[figure6RevealPayload](reveal2[0].Payload, limits)
	if err != nil {
		t.Fatal(err)
	}
	payload.Decommitment[0] ^= 1
	mutated, err := payload.MarshalBinaryWithLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	reveal2[0].Payload = mutated
	out, err := s1.Handle(testutil.DeliverEnvelope(reveal2[0]))
	if err == nil || len(out) != 0 {
		t.Fatalf("equivocated Figure 6 reveal accepted: out=%v err=%v", out, err)
	}
	if s1.pending != nil || s1.keyShare != nil {
		t.Fatal("equivocated Figure 6 reveal committed key material")
	}
}
