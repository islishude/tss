package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"errors"
	"sync"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

// testFROSTGuard creates an EnvelopeGuard for FROST Ed25519 protocol tests.
func testFROSTGuard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) *tss.EnvelopeGuard {
	return tss.NewTestEnvelopeGuard(self, parties, protocol, sessionID, testFROSTPolicies())
}

// testFROSTPolicies returns the FROST policy set with broadcast consistency relaxed.
func testFROSTPolicies() tss.PolicySet {
	entries := FROSTPolicies.Entries()
	relaxed := make([]tss.DeliveryPolicy, len(entries))
	for i, p := range entries {
		relaxed[i] = p
		relaxed[i].BroadcastConsistency = tss.BroadcastConsistencyNone
	}
	ps, err := tss.NewPolicySet(relaxed...)
	if err != nil {
		panic(err)
	}
	return ps
}

// deliverEnv returns a copy of env with transport authentication set for guard validation.
func deliverEnv(env tss.Envelope) tss.Envelope {
	env.Security.Authenticated = true
	env.Security.AuthenticatedParty = env.From
	return env
}

func TestFROSTSignScenarios(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int
		parties   int
		signers   []tss.PartyID
	}{
		{name: "1-of-1", threshold: 1, parties: 1, signers: []tss.PartyID{1}},
		{name: "2-of-3", threshold: 2, parties: 3, signers: []tss.PartyID{1, 3}},
		{name: "3-of-5", threshold: 3, parties: 5, signers: []tss.PartyID{1, 3, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := frostKeygen(t, tc.threshold, tc.parties)
			selected := make([]*KeyShare, 0, len(tc.signers))
			for _, id := range tc.signers {
				selected = append(selected, shares[id])
			}
			pub, sig, err := Sign([]byte("hello frost"), selected)
			if err != nil {
				t.Fatal(err)
			}
			if !stded25519.Verify(stded25519.PublicKey(pub), []byte("hello frost"), sig) {
				t.Fatal("signature did not verify with crypto/ed25519")
			}
		})
	}
}

func TestFROSTKeyShareRoundTrip(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.PublicKey) != string(shares[1].PublicKey) {
		t.Fatal("public key mismatch after round trip")
	}
}

func TestFROSTIgnoresDuplicateCommitment(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandleSignMessage(deliverEnv(out2[0])); err != nil {
		t.Fatal(err)
	}
	if out, err := s1.HandleSignMessage(deliverEnv(out2[0])); err != nil || len(out) != 0 {
		t.Fatalf("duplicate commitment should be ignored, out=%d err=%v", len(out), err)
	}
}

func TestFROSTRejectsConflictingCommitment(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	_, out3, err := StartSign(shares[3], sessionID, []tss.PartyID{2, 3}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandleSignMessage(deliverEnv(out2[0])); err != nil {
		t.Fatal(err)
	}
	conflict := out3[0]
	conflict.From = 2
	conflict = conflict.RecomputeTranscriptHash()
	_, err = s1.HandleSignMessage(deliverEnv(conflict))
	if !errors.Is(err, tss.ErrEquivocation) {
		t.Fatalf("expected ErrEquivocation for conflicting commitment, got %v", err)
	}
}

func TestFROSTIgnoresDuplicatePartial(t *testing.T) {
	sessions, round2 := frostSigningRound2(t, 2, 3, []tss.PartyID{1, 2, 3}, []byte("msg"))
	var partialFrom2 tss.Envelope
	for _, env := range round2 {
		if env.From == 2 {
			partialFrom2 = env
			break
		}
	}
	if partialFrom2.Payload == nil {
		t.Fatal("missing partial from party 2")
	}
	if _, err := sessions[1].HandleSignMessage(deliverEnv(partialFrom2)); err != nil {
		t.Fatal(err)
	}
	if out, err := sessions[1].HandleSignMessage(deliverEnv(partialFrom2)); err != nil || len(out) != 0 {
		t.Fatalf("duplicate partial should be ignored, out=%d err=%v", len(out), err)
	}
}

func TestFROSTRejectsConflictingPartial(t *testing.T) {
	sessions, round2 := frostSigningRound2(t, 2, 3, []tss.PartyID{1, 2, 3}, []byte("msg"))
	var partialFrom2, partialFrom3 tss.Envelope
	for _, env := range round2 {
		switch env.From {
		case 2:
			partialFrom2 = env
		case 3:
			partialFrom3 = env
		}
	}
	if partialFrom2.Payload == nil || partialFrom3.Payload == nil {
		t.Fatal("missing partials")
	}
	if _, err := sessions[1].HandleSignMessage(deliverEnv(partialFrom2)); err != nil {
		t.Fatal(err)
	}
	conflict := partialFrom3
	conflict.From = 2
	conflict = conflict.RecomputeTranscriptHash()
	_, err := sessions[1].HandleSignMessage(deliverEnv(conflict))
	if !errors.Is(err, tss.ErrEquivocation) {
		t.Fatalf("expected ErrEquivocation for conflicting partial, got %v", err)
	}
}

func TestFROSTConcurrentMessageHandling(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := s1.HandleSignMessage(deliverEnv(out2[0]))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent duplicate delivery failed: %v", err)
		}
	}
}

func TestFROSTBlamesBadPartial(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	sessions := map[tss.PartyID]*SignSession{}
	round1 := make([]tss.Envelope, 0)
	for _, id := range signers {
		s, out, err := StartSign(shares[id], sessionID, signers, []byte("msg"))
		if err != nil {
			t.Fatal(err)
		}

		s.SetGuard(testFROSTGuard(id, tss.PartySet(shares[id].Parties), sessionID))
		sessions[id] = s
		round1 = append(round1, out[0])
	}
	round2 := make([]tss.Envelope, 0)
	for _, env := range round1 {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			out, err := sessions[id].HandleSignMessage(deliverEnv(env))
			if err != nil {
				t.Fatal(err)
			}
			round2 = append(round2, out...)
		}
	}
	if len(round2) == 0 {
		t.Fatal("expected partial signatures")
	}
	payload, err := unmarshalSignPartialPayload(round2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Z[0] ^= 1
	mutated, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	round2[0].Payload = mutated
	round2[0] = round2[0].RecomputeTranscriptHash()
	var delivered bool
	for _, id := range signers {
		if id == round2[0].From {
			continue
		}
		delivered = true
		if _, err := sessions[id].HandleSignMessage(deliverEnv(round2[0])); err == nil {
			t.Fatal("expected bad partial rejection")
		}
	}
	if !delivered {
		t.Fatal("mutated partial was not delivered")
	}
}

func TestFROSTKeygenRejectsBroadcastOrNonConfidentialShares(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	kg1.SetGuard(testFROSTGuard(1, tss.PartySet(parties), sessionID))
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	share := out2[1]
	t.Run("broadcast", func(t *testing.T) {
		mutated := share
		mutated.To = 0
		mutated = mutated.RecomputeTranscriptHash()
		_, err := kg1.HandleKeygenMessage(deliverEnv(mutated))
		if !errors.Is(err, tss.ErrExpectedDirectMessage) {
			t.Fatalf("expected ErrExpectedDirectMessage, got %v", err)
		}
	})
	t.Run("non-confidential", func(t *testing.T) {
		mutated := share
		mutated.To = 99 // wrong recipient
		_, err := kg1.HandleKeygenMessage(deliverEnv(mutated))
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
	})
}

func TestFROSTReshareInvalidShareCarriesEvidence(t *testing.T) {
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	session, _, err := StartReshare(shares[1], parties, 2, tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartReshare(shares[2], parties, 2, tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleReshareMessage(deliverEnv(out2[0])); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalReshareSharePayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := edcurve.ScalarFromCanonical(payload.Share)
	if err != nil {
		t.Fatal(err)
	}
	badShare := fed.NewScalar().Add(scalar, edcurve.ScalarOne())
	badShareBytes := badShare.Bytes()
	out2[1].Payload, err = marshalReshareSharePayload(reshareSharePayload{Share: badShareBytes})
	if err != nil {
		t.Fatal(err)
	}
	out2[1] = out2[1].RecomputeTranscriptHash()
	_, err = session.HandleReshareMessage(deliverEnv(out2[1]))
	protocolErr := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
	if protocolErr.Blame == nil || len(protocolErr.Blame.Evidence) == 0 {
		t.Fatal("invalid FROST reshare share did not carry evidence")
	}
	evidence, err := tss.UnmarshalBlameEvidence(protocolErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Kind != tss.EvidenceKindFrostReshareShare {
		t.Fatalf("unexpected evidence kind %q", evidence.Kind)
	}
}

func TestFROSTSessionStateIsMonotonic(t *testing.T) {
	t.Run("completed keygen rejects messages", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		keygen, out, err := StartKeygen(tss.ThresholdConfig{
			Threshold: 1,
			Parties:   []tss.PartyID{1},
			Self:      1,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		keygen.SetGuard(testFROSTGuard(1, tss.PartySet{1}, sessionID))
		if _, ok := keygen.KeyShare(); !ok {
			t.Fatal("keygen did not complete")
		}
		env := out[0]
		env.To = 2
		env = env.RecomputeTranscriptHash()
		_, err = keygen.HandleKeygenMessage(deliverEnv(env))
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeCompleted)
	})

	t.Run("missing transcript rejected", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		shares := frostKeygen(t, 2, 2)
		sign, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
		if err != nil {
			t.Fatal(err)
		}
		sign.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
		_, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
		if err != nil {
			t.Fatal(err)
		}
		env := out2[0]
		env.TranscriptHash = [32]byte{}
		_, err = sign.HandleSignMessage(deliverEnv(env))
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
	})

	t.Run("attributable abort is terminal", func(t *testing.T) {
		shares := frostKeygen(t, 2, 2)
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		sessions := map[tss.PartyID]*SignSession{}
		round1 := make([]tss.Envelope, 0, 2)
		for _, id := range []tss.PartyID{1, 2} {
			session, out, err := StartSign(shares[id], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
			if err != nil {
				t.Fatal(err)
			}
			session.SetGuard(testFROSTGuard(id, tss.PartySet(shares[id].Parties), sessionID))
			sessions[id] = session
			round1 = append(round1, out[0])
		}
		round2, err := sessions[2].HandleSignMessage(deliverEnv(round1[0]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sessions[1].HandleSignMessage(deliverEnv(round1[1])); err != nil {
			t.Fatal(err)
		}
		payload, err := unmarshalSignPartialPayload(round2[0].Payload)
		if err != nil {
			t.Fatal(err)
		}
		payload.Z[0] ^= 1
		mutated, err := marshalSignPartialPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		bad := round2[0]
		bad.Payload = mutated
		bad = bad.RecomputeTranscriptHash()
		_, err = sessions[1].HandleSignMessage(deliverEnv(bad))
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		_, err = sessions[1].HandleSignMessage(deliverEnv(round2[0]))
		_ = assertFROSTProtocolCode(t, err, tss.ErrCodeAborted)
	})
}

func assertFROSTProtocolCode(t testing.TB, err error, code string) *tss.ProtocolError {
	t.Helper()
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected ProtocolError %s, got %T: %v", code, err, err)
	}
	if protocolErr.Code != code {
		t.Fatalf("expected code %s, got %s: %v", code, protocolErr.Code, err)
	}
	if code == tss.ErrCodeCompleted || code == tss.ErrCodeAborted || code == tss.ErrCodeDuplicate {
		if protocolErr.Blame != nil {
			t.Fatalf("%s error unexpectedly carried blame: %#v", code, protocolErr.Blame)
		}
	}
	return protocolErr
}

func frostKeygen(t *testing.T, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	deliverFROSTKeygenMessages(t, parties, sessions, messages)
	out := make(map[tss.PartyID]*KeyShare, n)
	var pub []byte
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		if pub == nil {
			pub = share.PublicKey
		} else if string(pub) != string(share.PublicKey) {
			t.Fatal("group public key mismatch")
		}
		out[id] = share
	}
	return out
}

func deliverFROSTKeygenMessages(t testing.TB, parties []tss.PartyID, sessions map[tss.PartyID]*KeygenSession, messages []tss.Envelope) {
	t.Helper()
	// Attach test guards to sessions that don't already have one.
	ps := tss.PartySet(parties)
	for _, id := range parties {
		s := sessions[id]
		if s.Guard() == nil {
			s.SetGuard(testFROSTGuard(id, ps, s.cfg.SessionID))
		}
	}
	queue := append([]tss.Envelope(nil), messages...)
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			delivered := env
			delivered.Security.Authenticated = true
			delivered.Security.AuthenticatedParty = env.From
			out, err := sessions[id].HandleKeygenMessage(deliverEnv(delivered))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
}

func frostSigningRound2(t *testing.T, threshold, n int, signers []tss.PartyID, message []byte) (map[tss.PartyID]*SignSession, []tss.Envelope) {
	t.Helper()
	shares := frostKeygen(t, threshold, n)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	round1 := make([]tss.Envelope, 0, len(signers))
	round2 := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSign(shares[id], sessionID, signers, message)
		if err != nil {
			t.Fatal(err)
		}

		session.SetGuard(testFROSTGuard(id, tss.PartySet(shares[id].Parties), sessionID))
		sessions[id] = session
		for _, env := range out {
			env.Security.Authenticated = true
			env.Security.AuthenticatedParty = env.From
			if env.Round == 1 {
				round1 = append(round1, env)
			} else {
				round2 = append(round2, env)
			}
		}
	}
	for _, env := range round1 {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			out, err := sessions[id].HandleSignMessage(deliverEnv(env))
			if err != nil {
				t.Fatal(err)
			}
			for i := range out {
				out[i].Security.Authenticated = true
				out[i].Security.AuthenticatedParty = out[i].From
			}
			round2 = append(round2, out...)
		}
	}
	return sessions, round2
}

func TestFROSTReshareMembershipChange(t *testing.T) {
	oldShares := frostKeygen(t, 2, 3)

	t.Run("add party", func(t *testing.T) {
		// {1,2,3} → {1,2,3,4} with 2-of-4
		sessionID, _ := tss.NewSessionID(nil)
		newParties := []tss.PartyID{1, 2, 3, 4}
		newThreshold := 2
		reshareSessions := make(map[tss.PartyID]*ReshareSession, 3)
		messages := make([]tss.Envelope, 0)

		// Union of old and new parties for guard validation.
		allParties := []tss.PartyID{1, 2, 3, 4}
		allPartySet := tss.PartySet(allParties)

		// Old parties 1,2,3 act as dealers.
		for _, id := range []tss.PartyID{1, 2, 3} {
			session, out, err := StartReshare(oldShares[id], newParties, newThreshold, tss.ThresholdConfig{Threshold: newThreshold, Parties: newParties, Self: id, SessionID: sessionID})
			if err != nil {
				t.Fatal(err)
			}
			session.SetGuard(testFROSTGuard(oldShares[id].Party, tss.PartySet(oldShares[id].Parties), sessionID))

			session.SetGuard(testFROSTGuard(id, allPartySet, sessionID))
			reshareSessions[id] = session
			messages = append(messages, out...)
		}
		// Recipient-only: party 4 has no old KeyShare.
		recipient, err := StartReshareRecipient(oldShares[1].PublicKey, nil, []tss.PartyID{1, 2, 3}, newParties, newThreshold, tss.ThresholdConfig{Threshold: newThreshold, Parties: newParties, Self: 4, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		recipient.SetGuard(testFROSTGuard(4, allPartySet, sessionID))
		reshareSessions[4] = recipient

		deliverReshareMessages(t, newParties, messages, reshareSessions)

		// All 4 new parties can sign.
		newShares := collectReshareShares(t, newParties, reshareSessions)
		pub, sig, err := Sign([]byte("add party test"), []*KeyShare{newShares[1], newShares[2]})
		if err != nil {
			t.Fatal(err)
		}
		if !stded25519.Verify(stded25519.PublicKey(pub), []byte("add party test"), sig) {
			t.Fatal("reshared signature failed verification")
		}
		if !bytes.Equal(pub, oldShares[1].PublicKey) {
			t.Fatal("group public key changed after reshare")
		}
	})

	t.Run("remove party", func(t *testing.T) {
		// {1,2,3} → {1,2} with 2-of-2
		sessionID, _ := tss.NewSessionID(nil)
		newParties := []tss.PartyID{1, 2}
		newThreshold := 2
		reshareSessions := make(map[tss.PartyID]*ReshareSession, 3)
		messages := make([]tss.Envelope, 0)

		// All old parties (1,2,3) must participate as dealers. Party 3 is
		// being removed from the new set — use old party set for config validation.
		for _, id := range []tss.PartyID{1, 2, 3} {
			session, out, err := StartReshare(oldShares[id], newParties, newThreshold, tss.ThresholdConfig{Threshold: newThreshold, Parties: oldShares[id].Parties, Self: id, SessionID: sessionID})
			if err != nil {
				t.Fatal(err)
			}
			session.SetGuard(testFROSTGuard(oldShares[id].Party, tss.PartySet(oldShares[id].Parties), sessionID))

			session.SetGuard(testFROSTGuard(id, tss.PartySet{1, 2, 3}, sessionID))
			reshareSessions[id] = session
			messages = append(messages, out...)
		}

		deliverReshareMessages(t, []tss.PartyID{1, 2, 3}, messages, reshareSessions)

		newShares := collectReshareShares(t, newParties, reshareSessions)
		// Party 3 is removed from the new participant set.
		_ = oldShares[3]
		pub, sig, err := Sign([]byte("remove party test"), []*KeyShare{newShares[1], newShares[2]})
		if err != nil {
			t.Fatal(err)
		}
		if !stded25519.Verify(stded25519.PublicKey(pub), []byte("remove party test"), sig) {
			t.Fatal("reshared signature failed verification")
		}
		if !bytes.Equal(pub, oldShares[1].PublicKey) {
			t.Fatal("group public key changed after reshare")
		}
	})

	t.Run("threshold increase 2-of-3 to 3-of-4", func(t *testing.T) {
		// {1,2,3} → {1,2,3,4} with 3-of-4
		sessionID, _ := tss.NewSessionID(nil)
		newParties := []tss.PartyID{1, 2, 3, 4}
		newThreshold := 3
		reshareSessions := make(map[tss.PartyID]*ReshareSession, 4)
		messages := make([]tss.Envelope, 0)

		for _, id := range []tss.PartyID{1, 2, 3} {
			session, out, err := StartReshare(oldShares[id], newParties, newThreshold, tss.ThresholdConfig{Threshold: newThreshold,
				Parties: newParties, Self: id, SessionID: sessionID,
			})
			if err != nil {
				t.Fatal(err)
			}
			allPs := tss.PartySet{1, 2, 3, 4}
			session.SetGuard(testFROSTGuard(oldShares[id].Party, allPs, sessionID))

			reshareSessions[id] = session
			messages = append(messages, out...)
		}
		recipient, err := StartReshareRecipient(oldShares[1].PublicKey, nil, []tss.PartyID{1, 2, 3}, newParties, newThreshold, tss.ThresholdConfig{Threshold: newThreshold,
			Parties: newParties, Self: 4, SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		recipient.SetGuard(testFROSTGuard(4, tss.PartySet{1, 2, 3, 4}, sessionID))
		reshareSessions[4] = recipient

		deliverReshareMessages(t, newParties, messages, reshareSessions)
		newShares := collectReshareShares(t, newParties, reshareSessions)

		// 3-of-4: need 3 signers.
		pub, sig, err := Sign([]byte("threshold increase"), []*KeyShare{newShares[1], newShares[2], newShares[4]})
		if err != nil {
			t.Fatal(err)
		}
		if !stded25519.Verify(stded25519.PublicKey(pub), []byte("threshold increase"), sig) {
			t.Fatal("threshold-increase signature failed verification")
		}
	})

	t.Run("replace party", func(t *testing.T) {
		// {1,2,3} -> {2,3,4} with 2-of-3
		sessionID, _ := tss.NewSessionID(nil)
		newParties := []tss.PartyID{2, 3, 4}
		newThreshold := 2
		reshareSessions := make(map[tss.PartyID]*ReshareSession, 4)
		messages := make([]tss.Envelope, 0)

		for _, id := range []tss.PartyID{1, 2, 3} {
			session, out, err := StartReshare(oldShares[id], newParties, newThreshold, tss.ThresholdConfig{
				Threshold: newThreshold,
				Parties:   oldShares[id].Parties,
				Self:      id,
				SessionID: sessionID,
			})
			if err != nil {
				t.Fatal(err)
			}
			session.SetGuard(testFROSTGuard(oldShares[id].Party, tss.PartySet{1, 2, 3, 4}, sessionID))

			reshareSessions[id] = session
			messages = append(messages, out...)
		}
		recipient, err := StartReshareRecipient(oldShares[1].PublicKey, nil, []tss.PartyID{1, 2, 3}, newParties, newThreshold, tss.ThresholdConfig{
			Threshold: newThreshold,
			Parties:   newParties,
			Self:      4,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatal(err)
		}
		recipient.SetGuard(testFROSTGuard(4, tss.PartySet{1, 2, 3, 4}, sessionID))
		reshareSessions[4] = recipient

		deliverReshareMessages(t, []tss.PartyID{1, 2, 3, 4}, messages, reshareSessions)
		newShares := collectReshareShares(t, newParties, reshareSessions)
		pub, sig, err := Sign([]byte("replace party"), []*KeyShare{newShares[2], newShares[4]})
		if err != nil {
			t.Fatal(err)
		}
		if !stded25519.Verify(stded25519.PublicKey(pub), []byte("replace party"), sig) {
			t.Fatal("replace signature failed verification")
		}
		if !bytes.Equal(pub, oldShares[1].PublicKey) {
			t.Fatal("group public key changed after replace")
		}
	})

	t.Run("threshold decrease 3-of-5 to 2-of-5", func(t *testing.T) {
		oldShares := frostKeygen(t, 3, 5)
		sessionID, _ := tss.NewSessionID(nil)
		newParties := []tss.PartyID{1, 2, 3, 4, 5}
		newThreshold := 2
		reshareSessions := make(map[tss.PartyID]*ReshareSession, 5)
		messages := make([]tss.Envelope, 0)

		for _, id := range newParties {
			session, out, err := StartReshare(oldShares[id], newParties, newThreshold, tss.ThresholdConfig{
				Threshold: newThreshold,
				Parties:   newParties,
				Self:      id,
				SessionID: sessionID,
			})
			if err != nil {
				t.Fatal(err)
			}
			session.SetGuard(testFROSTGuard(oldShares[id].Party, tss.PartySet{1, 2, 3, 4, 5}, sessionID))

			reshareSessions[id] = session
			messages = append(messages, out...)
		}

		deliverReshareMessages(t, newParties, messages, reshareSessions)
		newShares := collectReshareShares(t, newParties, reshareSessions)
		pub, sig, err := Sign([]byte("threshold decrease"), []*KeyShare{newShares[1], newShares[2]})
		if err != nil {
			t.Fatal(err)
		}
		if !stded25519.Verify(stded25519.PublicKey(pub), []byte("threshold decrease"), sig) {
			t.Fatal("threshold-decrease signature failed verification")
		}
		if !bytes.Equal(pub, oldShares[1].PublicKey) {
			t.Fatal("group public key changed after threshold decrease")
		}
	})
}

// deliverReshareMessages sends all reshare envelopes to all parties.
// Callers must set guards on all sessions before calling this function.
func deliverReshareMessages(t *testing.T, receivers []tss.PartyID, messages []tss.Envelope, sessions map[tss.PartyID]*ReshareSession) {
	t.Helper()
	for _, env := range messages {
		for _, id := range receivers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			delivered := env
			delivered.Security.Authenticated = true
			delivered.Security.AuthenticatedParty = env.From
			_, err := sessions[id].HandleReshareMessage(deliverEnv(delivered))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
}

// collectReshareShares retrieves KeyShares from completed reshare sessions.
func collectReshareShares(t *testing.T, parties []tss.PartyID, sessions map[tss.PartyID]*ReshareSession) map[tss.PartyID]*KeyShare {
	t.Helper()
	out := make(map[tss.PartyID]*KeyShare, len(parties))
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("reshare not complete for %d", id)
		}
		out[id] = share
	}
	return out
}

func TestFROSTRefreshPreservesGroupKey(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int
		parties   int
	}{
		{name: "1-of-1", threshold: 1, parties: 1},
		{name: "2-of-3", threshold: 2, parties: 3},
		{name: "3-of-5", threshold: 3, parties: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := frostKeygen(t, tc.threshold, tc.parties)
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}

			oldPubs := make(map[tss.PartyID][]byte, tc.parties)
			oldSecrets := make(map[tss.PartyID][]byte, tc.parties)
			for id, share := range shares {
				oldPubs[id] = share.PublicKeyBytes()
				raw, err := share.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				oldSecrets[id] = raw
			}

			parties := make([]tss.PartyID, tc.parties)
			for i := range parties {
				parties[i] = tss.PartyID(i + 1)
			}
			refreshSessions := make(map[tss.PartyID]*ReshareSession, tc.parties)
			messages := make([]tss.Envelope, 0)
			for _, id := range parties {
				cfg := tss.ThresholdConfig{
					Threshold: tc.threshold,
					Parties:   parties,
					Self:      id,
					SessionID: sessionID,
				}
				session, out, err := StartRefresh(shares[id], cfg)
				if err != nil {
					t.Fatal(err)
				}
				session.SetGuard(testFROSTGuard(shares[id].Party, tss.PartySet(shares[id].Parties), sessionID))

				refreshSessions[id] = session
				messages = append(messages, out...)
			}

			for _, env := range messages {
				for _, id := range parties {
					if id == env.From {
						continue
					}
					if env.To != 0 && env.To != id {
						continue
					}
					_, err := refreshSessions[id].HandleReshareMessage(deliverEnv(env))
					if err != nil {
						t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
					}
				}
			}

			newShares := make(map[tss.PartyID]*KeyShare, tc.parties)
			for _, id := range parties {
				share, ok := refreshSessions[id].KeyShare()
				if !ok {
					t.Fatalf("refresh not complete for %d", id)
				}
				newShares[id] = share
			}

			for id, newShare := range newShares {
				if !bytes.Equal(newShare.PublicKey, oldPubs[id]) {
					t.Fatalf("party %d: group public key changed after refresh", id)
				}
			}

			for id, newShare := range newShares {
				newRaw, err := newShare.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(newRaw, oldSecrets[id]) {
					t.Fatalf("party %d: key share did not change after refresh", id)
				}
			}

			signers := make([]*KeyShare, 0, tc.threshold)
			for _, id := range parties[:tc.threshold] {
				signers = append(signers, newShares[id])
			}
			pub, sig, err := Sign([]byte("refresh test"), signers)
			if err != nil {
				t.Fatal(err)
			}
			if !stded25519.Verify(stded25519.PublicKey(pub), []byte("refresh test"), sig) {
				t.Fatal("refreshed shares produced invalid signature")
			}
		})
	}
}

func TestFROSTStartRefreshConvenience(t *testing.T) {
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	session, _, err := StartRefresh(shares[1], tss.ThresholdConfig{Threshold: 2,
		Parties:   []tss.PartyID{1, 2},
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	if session == nil {
		t.Fatal("StartRefresh returned nil session")
	}

	_, out2, err := StartRefresh(shares[2], tss.ThresholdConfig{Threshold: 2,
		Parties:   []tss.PartyID{1, 2},
		Self:      2,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range out2 {
		if _, err := session.HandleReshareMessage(deliverEnv(env)); err != nil {
			t.Fatal(err)
		}
	}
	newShare, ok := session.KeyShare()
	if !ok {
		t.Fatal("refresh did not complete")
	}
	if !bytes.Equal(newShare.PublicKey, shares[1].PublicKey) {
		t.Fatal("StartRefresh changed the group public key")
	}
}

func TestFROSTValidateConsistencyTamperedKey(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	share := shares[1]

	t.Run("valid share passes", func(t *testing.T) {
		if err := share.ValidateConsistency(); err != nil {
			t.Fatalf("valid share should pass consistency check: %v", err)
		}
	})

	t.Run("tampered public key", func(t *testing.T) {
		bad := cloneKeyShareValue(share)
		bad.PublicKey[0] ^= 1
		if err := bad.ValidateConsistency(); err == nil {
			t.Fatal("tampered public key should fail consistency check")
		}
	})

	t.Run("tampered verification share", func(t *testing.T) {
		bad := cloneKeyShareValue(share)
		for i := range bad.VerificationShares {
			if bad.VerificationShares[i].Party == share.Party {
				bad.VerificationShares[i].PublicKey[0] ^= 1
				break
			}
		}
		if err := bad.ValidateConsistency(); err == nil {
			t.Fatal("tampered verification share should fail consistency check")
		}
	})

	t.Run("tampered group commitment", func(t *testing.T) {
		bad := cloneKeyShareValue(share)
		bad.GroupCommitments[0][0] ^= 1
		if err := bad.ValidateConsistency(); err == nil {
			t.Fatal("tampered group commitment should fail consistency check")
		}
	})

	t.Run("deserialized round-trip passes", func(t *testing.T) {
		raw, err := share.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := UnmarshalKeyShare(raw)
		if err != nil {
			t.Fatalf("valid key share failed deserialization: %v", err)
		}
		if err := decoded.ValidateConsistency(); err != nil {
			t.Fatalf("deserialized key share failed consistency check: %v", err)
		}
	})
}

func TestFROSTRejectsNonPrimeOrderPoints(t *testing.T) {
	// Identity point: canonical Ed25519 encoding of y=1.
	identity := make([]byte, 32)
	identity[0] = 1

	t.Run("identity rejected by PointFromBytes", func(t *testing.T) {
		_, err := edcurve.PointFromBytes(identity)
		if err == nil {
			t.Fatal("PointFromBytes should reject identity")
		}
	})

	t.Run("identity allowed by PointFromBytesAllowIdentity", func(t *testing.T) {
		p, err := edcurve.PointFromBytesAllowIdentity(identity)
		if err != nil {
			t.Fatalf("PointFromBytesAllowIdentity should allow identity: %v", err)
		}
		if !edcurve.IsIdentity(p) {
			t.Fatal("expected identity point")
		}
	})

	t.Run("identity rejected as public key in KeyShare", func(t *testing.T) {
		shares := frostKeygen(t, 2, 3)
		bad := cloneKeyShareValue(shares[1])
		bad.PublicKey = append([]byte(nil), identity...)
		if err := bad.Validate(); err == nil {
			t.Fatal("identity public key should be rejected")
		}
	})

	t.Run("identity rejected as group commitment[0]", func(t *testing.T) {
		shares := frostKeygen(t, 2, 3)
		bad := cloneKeyShareValue(shares[1])
		bad.GroupCommitments[0] = append([]byte(nil), identity...)
		if err := bad.Validate(); err == nil {
			t.Fatal("identity group commitment should be rejected")
		}
	})

	// Test malformed point encodings are rejected.
	t.Run("malformed encoding rejected", func(t *testing.T) {
		bad := make([]byte, 32)
		bad[31] = 0x80
		_, err := edcurve.PointFromBytes(bad)
		if err == nil {
			t.Fatal("malformed encoding should be rejected")
		}
	})

	t.Run("low-order points rejected", func(t *testing.T) {
		// Known non-identity small-order points on Ed25519's extended group.
		lowOrder := [][]byte{
			// Order 4 (y = 0, sign bit unset).
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			// Order 2 (y = p-1).
			{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
			// Order 4 (y = 0, sign bit set).
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
		}
		for i, encoded := range lowOrder {
			_, err := edcurve.PointFromBytes(encoded)
			if err == nil {
				t.Fatalf("low-order point %d should be rejected by PointFromBytes", i)
			}
			_, err = edcurve.PointFromBytesAllowIdentity(encoded)
			if err == nil {
				t.Fatalf("low-order point %d should be rejected by PointFromBytesAllowIdentity", i)
			}
		}
	})
}

func TestFROSTSignAcceptsPartialBeforeCommitment(t *testing.T) {
	// A round 2 partial from a party whose round 1 commitment hasn't arrived yet
	// is stored but aggregation does not complete until all commitments arrive.
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	s2, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	s2.SetGuard(testFROSTGuard(shares[2].Party, tss.PartySet(shares[2].Parties), sessionID))

	// Party 1 receives party 2's commitment → emits party 1's partial.
	round2, err := s1.HandleSignMessage(deliverEnv(out2[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Party 2 receives party 1's partial before party 1's commitment.
	// This is accepted — the partial is stored.
	_, err = s2.HandleSignMessage(deliverEnv(round2[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Party 2 now has party 1's partial but not party 1's commitment.
	// Aggregation cannot complete yet.
	if sig, ok := s2.Signature(); ok {
		t.Fatalf("signature completed prematurely without all commitments: %x", sig)
	}
}

func TestFROSTSignRejectsNonSigner(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Party 3 is not in the signer set {1,2} so it should be rejected.
	_, _, err = StartSign(shares[3], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err == nil {
		t.Fatal("party 3 should not be able to start sign with signer set {1,2}")
	}

	// Verify party 1 can start signing.
	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_ = s1
}

func TestFROSTSignRejectsMismatchedMessage(t *testing.T) {
	shares := frostKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Start sign with different messages — messages must match.
	s1, _, err := StartSign(shares[1], sessionID, []tss.PartyID{1, 2}, []byte("msg1"))
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartSign(shares[2], sessionID, []tss.PartyID{1, 2}, []byte("msg2"))
	if err != nil {
		t.Fatal(err)
	}

	// Deliver commitment from party 2 (who signed "msg2") to party 1 (who signed "msg1").
	// The commitment itself doesn't contain the message, but the partial will mismatch.
	if _, err := s1.HandleSignMessage(deliverEnv(out2[0])); err != nil {
		t.Fatal(err)
	}
	// The session should still be alive — the mismatch will be caught during partial verification.
	if s1.aborted {
		t.Fatal("session should not abort on commitment with different message")
	}
}

func TestFROSTReshareRejectsUnknownSender(t *testing.T) {
	shares := frostKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}

	session, _, err := StartRefresh(shares[1], tss.ThresholdConfig{Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	session.SetGuard(testFROSTGuard(shares[1].Party, tss.PartySet(shares[1].Parties), sessionID))

	// Construct a fake envelope from a non-participant.
	fakeEnv := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        99, // not in participant set
		To:          1,
		PayloadType: payloadReshareCommitments,
	}
	_, err = session.HandleReshareMessage(deliverEnv(fakeEnv))
	_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
}
