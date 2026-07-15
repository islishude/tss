package ed25519

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTReshareStartRejectsNilPlan(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 2)

	tests := []struct {
		name  string
		start func() error
	}{
		{
			name: "dealer",
			start: func() error {
				_, out, err := StartReshare(shares[1], nil, tss.LocalConfig{Self: 1}, nil)
				if out != nil {
					t.Fatal("nil reshare plan produced outbound messages")
				}
				return err
			},
		},
		{
			name: "recipient",
			start: func() error {
				_, err := StartReshareRecipient(nil, tss.LocalConfig{Self: 3}, nil)
				return err
			},
		},
		{
			name: "refresh",
			start: func() error {
				_, out, err := StartRefresh(shares[1], nil, tss.LocalConfig{Self: 1}, nil)
				if out != nil {
					t.Fatal("nil refresh plan produced outbound messages")
				}
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.start()
			var protocolErr *tss.ProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.Code != tss.ErrCodeInvalidConfig {
				t.Fatalf("got %v, want ErrCodeInvalidConfig", err)
			}
		})
	}
}

func TestFROSTRefreshPlanRejectsMixedSourceGenerations(t *testing.T) {
	t.Parallel()

	parties := tss.NewPartySet(1, 2)
	original := frostKeygen(t, 2, 2)
	firstRefreshID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	firstSessions := make(map[tss.PartyID]*ReshareSession, len(parties))
	firstMessages := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := startFROSTRefresh(original[id], tss.ThresholdConfig{
			Threshold: 2, Parties: parties, Self: id, SessionID: firstRefreshID,
		})
		if err != nil {
			t.Fatal(err)
		}
		firstSessions[id] = session
		firstMessages = append(firstMessages, out...)
	}
	deliverReshareMessages(t, parties, firstMessages, firstSessions)
	refreshed := collectReshareShares(t, parties, firstSessions)

	mixedRefreshID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	newGenerationSession, _, err := startFROSTRefresh(refreshed[1], tss.ThresholdConfig{
		Threshold: 2, Parties: parties, Self: 1, SessionID: mixedRefreshID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer newGenerationSession.Destroy()
	oldGenerationSession, oldOut, err := startFROSTRefresh(original[2], tss.ThresholdConfig{
		Threshold: 2, Parties: parties, Self: 2, SessionID: mixedRefreshID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer oldGenerationSession.Destroy()

	oldCommitment := mustFROSTEnvelope(t, oldOut, payloadReshareCommitments, tss.BroadcastPartyId)
	if _, err := newGenerationSession.Handle(testutil.DeliverEnvelope(oldCommitment)); err == nil || !errors.Is(err, errPlanHashMismatch) {
		t.Fatalf("expected mixed source generation plan mismatch, got %v", err)
	}
	if _, ok := newGenerationSession.commits[2]; ok {
		t.Fatal("mixed-generation commitment mutated refresh state")
	}
}

func TestFROSTPayloadDecodersRespectFrameLimits(t *testing.T) {
	t.Parallel()
	limits := testLimits()

	keygenSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	keygen1, keygenOut, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   tss.NewPartySet(1, 2),
		Self:      1,
		SessionID: keygenSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer keygen1.Destroy()
	keygen2, keygenOut2, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   tss.NewPartySet(1, 2),
		Self:      2,
		SessionID: keygenSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer keygen2.Destroy()
	keygenRound2, err := keygen1.Handle(testutil.DeliverEnvelope(
		mustFROSTEnvelope(t, keygenOut2, payloadKeygenCommitments, tss.BroadcastPartyId),
	))
	if err != nil {
		t.Fatal(err)
	}
	keygenOut = append(keygenOut, keygenRound2...)

	shares := frostKeygen(t, 2, 2)
	confirmation, err := shares[1].NewConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	confirmationRaw, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign1, signOut1, err := startFROSTSign(
		shares[1],
		signSessionID,
		tss.NewPartySet(1, 2),
		[]byte("frame limits"),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, signOut2, err := startFROSTSign(
		shares[2],
		signSessionID,
		tss.NewPartySet(1, 2),
		[]byte("frame limits"),
	)
	if err != nil {
		t.Fatal(err)
	}
	partialOut, err := sign1.Handle(testutil.DeliverEnvelope(signOut2[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(partialOut) != 1 {
		t.Fatalf("got %d partial envelopes, want 1", len(partialOut))
	}

	reshareSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, reshareOut, err := startFROSTReshare(
		shares[1],
		tss.NewPartySet(1, 2, 3),
		2,
		tss.ThresholdConfig{
			Threshold: 2,
			Parties:   tss.NewPartySet(1, 2),
			Self:      1,
			SessionID: reshareSessionID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var keygenCommitRaw, keygenShareRaw, reshareCommitRaw, reshareShareRaw []byte
	for _, env := range keygenOut {
		switch env.PayloadType {
		case payloadKeygenCommitments:
			keygenCommitRaw = env.Payload
		case payloadKeygenShare:
			keygenShareRaw = env.Payload
		}
	}
	for _, env := range reshareOut {
		switch env.PayloadType {
		case payloadReshareCommitments:
			reshareCommitRaw = env.Payload
		case payloadReshareShare:
			reshareShareRaw = env.Payload
		}
	}

	tests := []struct {
		name   string
		raw    []byte
		decode func([]byte, Limits) error
	}{
		{"keygen commitments", keygenCommitRaw, func(raw []byte, limits Limits) error {
			var payload keygenCommitmentsPayload
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
		{"keygen share", keygenShareRaw, func(raw []byte, limits Limits) error {
			var payload keygenSharePayload
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
		{"keygen confirmation", confirmationRaw, func(raw []byte, limits Limits) error {
			var payload KeygenConfirmation
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
		{"nonce commitment", signOut1[0].Payload, func(raw []byte, limits Limits) error {
			var payload nonceCommitment
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
		{"sign partial", partialOut[0].Payload, func(raw []byte, limits Limits) error {
			var payload signPartialPayload
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
		{"reshare commitments", reshareCommitRaw, func(raw []byte, limits Limits) error {
			var payload reshareCommitmentsPayload
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
		{"reshare share", reshareShareRaw, func(raw []byte, limits Limits) error {
			var payload reshareSharePayload
			return payload.UnmarshalBinaryWithLimits(raw, limits)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.raw) == 0 {
				t.Fatal("missing encoded payload")
			}
			small := limits
			small.Payload.MaxSerializedPayloadBytes = len(tc.raw) - 1
			if err := tc.decode(tc.raw, small); err == nil {
				t.Fatal("decoder ignored payload frame limit")
			}
		})
	}
}
