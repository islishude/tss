package ed25519

import (
	"errors"
	"sync"
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

func TestFROSTKeygenChainCodeCommitAccessorConcurrentWithDelivery(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	session1, _, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      1,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   parties,
		Self:      2,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 1000 {
			_ = session1.GetChainCodeCommitByPartyID(2)
		}
	}()
	go func() {
		defer wg.Done()
		for _, env := range out2 {
			if _, err := session1.HandleKeygenMessage(testutil.DeliverEnvelope(env)); err != nil {
				t.Errorf("deliver %s: %v", env.PayloadType, err)
				return
			}
		}
	}()
	wg.Wait()

	var nilSession *KeygenSession
	if got := nilSession.GetChainCodeCommitByPartyID(1); got != nil {
		t.Fatal("nil session returned a chain-code commitment")
	}
}

func TestFROSTPayloadDecodersRespectFrameLimits(t *testing.T) {
	t.Parallel()
	limits := testLimits()

	keygenSessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, keygenOut, err := startFROSTKeygen(tss.ThresholdConfig{
		Threshold: 2,
		Parties:   tss.NewPartySet(1, 2),
		Self:      1,
		SessionID: keygenSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}

	shares := frostKeygen(t, 2, 2)
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
	partialOut, err := sign1.HandleSignMessage(testutil.DeliverEnvelope(signOut2[0]))
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
