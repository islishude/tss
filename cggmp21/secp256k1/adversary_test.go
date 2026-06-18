//go:build integration || vectorgen

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestCGGMP21KeygenEnvelopeFailClosed(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	kg1, _, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	commit := out2[0]
	share := out2[1]
	t.Run("wrong session", func(t *testing.T) {
		mutated := commit
		mutated.SessionID, err = tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong protocol", func(t *testing.T) {
		mutated := commit
		mutated.Protocol = "wrong-protocol"
		_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong round", func(t *testing.T) {
		mutated := commit
		mutated.Round = 2
		_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong recipient", func(t *testing.T) {
		mutated := share
		mutated.To = 3
		_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
		if !errors.Is(err, tss.ErrWrongRecipient) {
			t.Fatalf("expected ErrWrongRecipient, got %v", err)
		}
	})
	t.Run("broadcast secret share", func(t *testing.T) {
		mutated := share
		mutated.To = 0
		_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
		if !errors.Is(err, tss.ErrExpectedDirectMessage) {
			t.Fatalf("expected ErrExpectedDirectMessage, got %v", err)
		}
	})
	t.Run("non-confidential secret share", func(t *testing.T) {
		mutated := share
		_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelopeWithProtection(mutated, tss.ChannelPlaintext))
		if !errors.Is(err, tss.ErrMissingConfidentiality) {
			t.Fatalf("expected ErrMissingConfidentiality, got %v", err)
		}
	})
	t.Run("malformed payload", func(t *testing.T) {
		mutated := commit
		mutated.Payload = []byte("malformed")
		_, err := kg1.HandleKeygenMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("duplicate commitment", func(t *testing.T) {
		kg, _, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kg.HandleKeygenMessage(testutil.DeliverEnvelope(commit)); err != nil {
			t.Fatal(err)
		}
		_, err = kg.HandleKeygenMessage(testutil.DeliverEnvelope(commit))
		if !errors.Is(err, tss.ErrDuplicateMessage) {
			t.Fatalf("expected ErrDuplicateMessage, got %v", err)
		}
	})
}

func TestCGGMP21KeygenMalformedCommitmentHasEvidence(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2)
	kg1, _, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startCGGMP21Keygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireFieldByName(out2[0].Payload, keygenCommitmentsPayloadWireType, keygenCommitmentsPayload{}, "Commitments", wire.EncodeBytesList([][]byte{{0x02}}))
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	_, err = kg1.HandleKeygenMessage(testutil.DeliverEnvelope(out2[0]))
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestCGGMP21PresignEnvelopeFailClosed(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := tss.NewPartySet(1, 2)
	s1, _, err := startTestPresign(h.shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := startTestPresign(h.shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	round1 := out2[0]

	t.Run("sender not signer", func(t *testing.T) {
		mutated := round1
		mutated.From = 3
		_, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong session", func(t *testing.T) {
		mutated := round1
		mutated.SessionID, err = tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong round", func(t *testing.T) {
		mutated := round1
		mutated.Round = 2
		_, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong recipient", func(t *testing.T) {
		mutated := round1
		mutated.To = 3
		_, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(mutated))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("duplicate round1", func(t *testing.T) {
		session, _, err := startTestPresign(h.shares[1], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.HandlePresignMessage(testutil.DeliverEnvelope(round1)); err != nil {
			t.Fatal(err)
		}
		_, err = session.HandlePresignMessage(testutil.DeliverEnvelope(round1))
		if !errors.Is(err, tss.ErrDuplicateMessage) {
			t.Fatalf("expected ErrDuplicateMessage, got %v", err)
		}
	})
}

func TestCGGMP21PresignRound1MalformedEvidence(t *testing.T) {
	h := newHarness(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*presignRound1Payload)
	}{
		{name: "gamma", mutate: func(p *presignRound1Payload) { p.Gamma = []byte{0x02} }},
		{name: "enc_k", mutate: func(p *presignRound1Payload) { p.EncK = []byte{0x01} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
			if err != nil {
				t.Fatal(err)
			}
			_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
			if err != nil {
				t.Fatal(err)
			}
			mutated, err := mutatePresignRound1Payload(out2[0].Payload, tc.mutate)
			if err != nil {
				t.Fatal(err)
			}
			out2[0].Payload = mutated
			_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0]))
			if err == nil {
				_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[1]))
			}
			_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, tss.NewPartySet(1, 2), nil))
		})
	}
}

func TestCGGMP21PresignRound1ProofOrderingAndReplay(t *testing.T) {
	h := newHarness(t, 2, 3)

	t.Run("proof before public", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		proof := presignRound1ProofEnvelopeFor(t, out2, 1)
		out, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(proof))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Fatal("proof without public round1 emitted round2")
		}
		out, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0]))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].PayloadType != payloadPresignRound2 {
			t.Fatalf("got %d messages after public round1, want one round2", len(out))
		}
	})

	t.Run("public before proof", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		out, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0]))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Fatal("public round1 without proof emitted round2")
		}
		out, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(presignRound1ProofEnvelopeFor(t, out2, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].PayloadType != payloadPresignRound2 {
			t.Fatalf("got %d messages after proof, want one round2", len(out))
		}
	})

	t.Run("duplicate proof", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		proof := presignRound1ProofEnvelopeFor(t, out2, 1)
		if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(proof)); err != nil {
			t.Fatal(err)
		}
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(proof))
		if !errors.Is(err, tss.ErrDuplicateMessage) {
			t.Fatalf("expected ErrDuplicateMessage, got %v", err)
		}
	})

	t.Run("wrong recipient", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		proof := presignRound1ProofEnvelopeFor(t, out2, 1)
		proof.To = 3
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(proof))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})

	t.Run("mutated public hash", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
			t.Fatal(err)
		}
		proof := presignRound1ProofEnvelopeFor(t, out2, 1)
		mutated, err := mutatePresignRound1ProofPayload(proof.Payload, func(p *presignRound1ProofPayload) {
			p.PublicRound1Hash[0] ^= 1
		})
		if err != nil {
			t.Fatal(err)
		}
		proof.Payload = mutated
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(proof))
		_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, tss.NewPartySet(1, 2), nil))
	})

	t.Run("mutated enc proof", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
			t.Fatal(err)
		}
		proof := presignRound1ProofEnvelopeFor(t, out2, 1)
		mutated, err := mutatePresignRound1ProofPayload(proof.Payload, func(p *presignRound1ProofPayload) {
			p.EncKProof.TranscriptHash[0] ^= 1
		})
		if err != nil {
			t.Fatal(err)
		}
		proof.Payload = mutated
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(proof))
		_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, tss.NewPartySet(1, 2), nil))
	})

	t.Run("cross recipient proof replay", func(t *testing.T) {
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2, 3))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2, 3))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
			t.Fatal(err)
		}
		proofFor3 := presignRound1ProofEnvelopeFor(t, out2, 3)
		proofFor3.To = 1
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(proofFor3))
		_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, tss.NewPartySet(1, 2, 3), nil))
	})
}

func TestCGGMP21SessionStateIsMonotonic(t *testing.T) {
	t.Run("completed signing rejects duplicate and wrong-recipient messages", func(t *testing.T) {
		h := newHarness(t, 1, 1)
		presigns := secpPresign(t, h.shares, tss.NewPartySet(1))
		digest := sha256.Sum256([]byte("completed session"))
		signID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		session, out, err := StartSignDigest(h.shares[1], presigns[1], signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := session.Signature(); !ok {
			t.Fatal("signing did not complete")
		}
		duplicate := out[0]
		if _, err = session.HandleSignMessage(testutil.DeliverEnvelope(duplicate)); err == nil {
			t.Fatal("completed session accepted duplicate message")
		}
		assertNoBlame(t, testutil.AssertProtocolError(t, err, tss.ErrCodeCompleted))

		wrongRecipient := out[0]
		wrongRecipient.To = 2
		if _, err = session.HandleSignMessage(testutil.DeliverEnvelope(wrongRecipient)); err == nil {
			t.Fatal("completed session accepted wrong-recipient message")
		}
		assertNoBlame(t, testutil.AssertProtocolError(t, err, tss.ErrCodeCompleted))
	})

	t.Run("attributable presign abort is terminal", func(t *testing.T) {
		h := newHarness(t, 2, 3)
		sessionID, err := tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		s1, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		_, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := mutatePresignRound1Payload(out2[0].Payload, func(p *presignRound1Payload) {
			p.Gamma = []byte{0x02}
		})
		if err != nil {
			t.Fatal(err)
		}
		bad := out2[0]
		bad.Payload = mutated
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(bad))
		_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, tss.NewPartySet(1, 2), nil))
		_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(out2[0]))
		assertNoBlame(t, testutil.AssertProtocolError(t, err, tss.ErrCodeAborted))
	})
}

func TestCGGMP21PresignRound2WrongRecipientRejected(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	_ = deliverPresignMessagesTo(t, s1, 1, out2)
	round2 := deliverPresignMessagesTo(t, s2, 2, out1)
	round2[0].To = 3
	_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(round2[0]))
	_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
}

func TestCGGMP21PresignRound3MalformedDeltaEvidence(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := startTestPresign(h.shares[2], sessionID, tss.NewPartySet(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	round2From1 := deliverPresignMessagesTo(t, s1, 1, out2)
	round2From2 := deliverPresignMessagesTo(t, s2, 2, out1)
	round3From2, err := s2.HandlePresignMessage(testutil.DeliverEnvelope(round2From1[0]))
	if err != nil {
		t.Fatal(err)
	}
	round3From1, err := s1.HandlePresignMessage(testutil.DeliverEnvelope(round2From2[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(round3From1) != 1 {
		t.Fatalf("expected one local round3 message, got %d", len(round3From1))
	}
	if len(round3From2) != 1 {
		t.Fatalf("expected one round3 message, got %d", len(round3From2))
	}
	mutated, err := testutil.RewriteWireFieldByName(round3From2[0].Payload, presignRound3PayloadWireType, presignRound3Payload{}, "Delta", []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	round3From2[0].Payload = mutated
	_, err = s1.HandlePresignMessage(testutil.DeliverEnvelope(round3From2[0]))
	_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, tss.NewPartySet(1, 2), nil))
}

func TestCGGMP21SignerSetOrderCanonicalized(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := startTestPresign(h.shares[1], sessionID, tss.NewPartySet(2, 1))
	if err != nil {
		t.Fatal(err)
	}
	if session.signers[0] != 1 || session.signers[1] != 2 {
		t.Fatalf("signer set was not canonicalized: %v", session.signers)
	}
}

func TestCGGMP21SignFailClosedAndEvidence(t *testing.T) {
	h := newHarness(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	digest := sha256.Sum256([]byte("sign fail closed"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	newSignCase := func(t *testing.T) (*SignSession, []tss.Envelope, map[tss.PartyID]*Presign) {
		t.Helper()
		presigns := secpPresign(t, h.shares, signers)
		_, out2, err := StartSignDigest(h.shares[2], presigns[2], signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		session, _, err := StartSignDigest(h.shares[1], presigns[1], signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return session, out2, presigns
	}

	t.Run("transcript mismatch", func(t *testing.T) {
		session, out2, presigns := newSignCase(t)
		payload, err := unmarshalSignPartialPayload(out2[0].Payload)
		if err != nil {
			t.Fatal(err)
		}
		payload.PresignTranscript = make([]byte, sha256.Size)
		mutated, err := marshalSignPartialPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		env := out2[0]
		env.Payload = mutated
		_, err = session.HandleSignMessage(testutil.DeliverEnvelope(env))
		_ = assertBlameEvidence(t, err, h.evidenceContext(signID, 1, signers, presigns[1]))
	})
	t.Run("malformed scalar", func(t *testing.T) {
		session, out2, presigns := newSignCase(t)
		mutated, err := testutil.RewriteWireFieldByName(out2[0].Payload, signPartialPayloadWireType, signPartialPayload{}, "S", []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		env := out2[0]
		env.Payload = mutated
		_, err = session.HandleSignMessage(testutil.DeliverEnvelope(env))
		_ = assertBlameEvidence(t, err, h.evidenceContext(signID, 1, signers, presigns[1]))
	})
	t.Run("wrong round", func(t *testing.T) {
		session, out2, _ := newSignCase(t)
		env := out2[0]
		env.Round = 2
		_, err = session.HandleSignMessage(testutil.DeliverEnvelope(env))
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("duplicate partial", func(t *testing.T) {
		session, out2, _ := newSignCase(t)
		if _, err := session.HandleSignMessage(testutil.DeliverEnvelope(out2[0])); err != nil {
			t.Fatal(err)
		}
		_, err = session.HandleSignMessage(testutil.DeliverEnvelope(out2[0]))
		assertNoBlame(t, testutil.AssertProtocolError(t, err, tss.ErrCodeCompleted))
	})
}

func TestCGGMP21SignRejectsBadDigestAndConflictingReuseBeforeOutbound(t *testing.T) {
	h := newHarness(t, 2, 3)
	presigns := secpPresign(t, h.shares, tss.NewPartySet(1, 2))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if session, out, err := StartSignDigest(h.shares[1], presigns[1], signID, []byte{1}); err == nil || session != nil || out != nil {
		t.Fatalf("bad digest should fail before creating session/outbound message: session=%v out=%d err=%v", session, len(out), err)
	}
	digest := sha256.Sum256([]byte("reuse outbound"))
	store := newTestSignAttemptStore()
	_, firstOut, err := StartSignDigestWithStore(h.shares[1], presigns[1], signID, digest[:], store)
	if err != nil {
		t.Fatal(err)
	}
	_, resumedOut, err := StartSignDigestWithStore(h.shares[1], presigns[1], signID, digest[:], store)
	if err != nil {
		t.Fatalf("same attempt did not resume: %v", err)
	}
	firstRaw, _ := firstOut[0].MarshalBinary()
	resumedRaw, _ := resumedOut[0].MarshalBinary()
	if !bytes.Equal(firstRaw, resumedRaw) {
		t.Fatal("same attempt resumed with a different envelope")
	}
	otherDigest := sha256.Sum256([]byte("conflicting reuse outbound"))
	if session, out, err := StartSignDigestWithStore(h.shares[1], presigns[1], signID, otherDigest[:], store); err == nil || session != nil || out != nil {
		t.Fatalf("conflicting reuse should fail before returning an outbound message: session=%v out=%d err=%v", session, len(out), err)
	}
}
