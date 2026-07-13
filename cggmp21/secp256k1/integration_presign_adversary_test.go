//go:build integration

package secp256k1

import (
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestThresholdECDSATamperedRound1BlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := startTestPresign(shares[1], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startTestPresign(shares[2], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload[0] ^= 1
	if _, err := s1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected tampered Figure 8 round1 rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], tss.NewPartySet(1, 2), nil))
	}
}

func TestThresholdECDSATamperedRound2ProofBlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*presignRound2Payload)
	}{
		{name: "delta", mutate: func(p *presignRound2Payload) { p.Delta.Proof.TranscriptHash[0] ^= 1 }},
		{name: "sigma", mutate: func(p *presignRound2Payload) { p.Sigma.Proof.TranscriptHash[0] ^= 1 }},
		{name: "round1 echo", mutate: func(p *presignRound2Payload) { p.Round1Echo[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			s1, out1, err := startTestPresign(shares[1], sessionID, tss.NewPartySet(1, 2))
			if err != nil {
				t.Fatal(err)
			}
			s2, out2, err := startTestPresign(shares[2], sessionID, tss.NewPartySet(1, 2))
			if err != nil {
				t.Fatal(err)
			}
			_ = deliverPresignMessagesTo(t, s1, 1, out2)
			round2 := deliverPresignMessagesTo(t, s2, 2, out1)
			if len(round2) != 1 || round2[0].To != 1 {
				t.Fatalf("unexpected round2 messages: %#v", round2)
			}
			mutated, err := mutatePresignRound2Payload(round2[0].Payload, tc.mutate)
			if err != nil {
				t.Fatal(err)
			}
			round2[0].Payload = mutated
			_, err = s1.Handle(testutil.DeliverEnvelope(round2[0]))
			assertProtocolBlamesParty(t, err, 2)
			_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], tss.NewPartySet(1, 2), nil))
		})
	}
}

func TestThresholdECDSARound3RejectsWrongEpoch(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)
	s1, out1, err := startTestPresign(shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startTestPresign(shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	round2From1 := deliverPresignMessagesTo(t, s1, 1, out2)
	round2From2 := deliverPresignMessagesTo(t, s2, 2, out1)
	round3From2, err := s2.Handle(testutil.DeliverEnvelope(round2From1[0]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Handle(testutil.DeliverEnvelope(round2From2[0])); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalPresignRound3Payload(round3From2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Delta.Destroy()
	payload.EpochID[0] ^= 1
	round3From2[0].Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s1.Handle(testutil.DeliverEnvelope(round3From2[0]))
	assertProtocolBlamesParty(t, err, 2)
}

func TestThresholdECDSAPaillierPublicKeyMismatchRejected(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)
	s1, _, err := startTestPresign(shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startTestPresign(shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalPresignRound1Payload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierPublicKey, err = shares[1].paillierPublicFor(1, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload, err = payload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Handle(testutil.DeliverEnvelope(out2[0])); err == nil {
		t.Fatal("expected presign Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], signers, nil))
	}
}

func assertProtocolBlamesParty(t *testing.T, err error, party tss.PartyID) {
	t.Helper()
	if err == nil {
		t.Fatal("expected protocol rejection")
	}
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Party != party {
		t.Fatalf("unexpected error: %v", err)
	}
}
