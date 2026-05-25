package secp256k1

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/islishude/tss"
)

type protocolHarness struct {
	threshold int
	parties   []tss.PartyID
	shares    map[tss.PartyID]*KeyShare
}

func newHarness(t testing.TB, threshold, n int) *protocolHarness {
	t.Helper()
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	return &protocolHarness{
		threshold: threshold,
		parties:   parties,
		shares:    secpKeygen(t, threshold, n),
	}
}

func (h *protocolHarness) evidenceContext(sessionID tss.SessionID, receiver tss.PartyID, signers []tss.PartyID, presign *Presign) EvidenceContext {
	ctx := secpEvidenceContext(h.shares[receiver], signers, presign)
	ctx.SessionID = sessionID
	return ctx
}

func TestCGGMP21KeygenEnvelopeFailClosed(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
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
		mutated = mutated.WithTranscriptHash()
		_, err = kg1.HandleKeygenMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong protocol", func(t *testing.T) {
		mutated := commit
		mutated.Protocol = "wrong-protocol"
		mutated = mutated.WithTranscriptHash()
		_, err := kg1.HandleKeygenMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong round", func(t *testing.T) {
		mutated := commit
		mutated.Round = 2
		mutated = mutated.WithTranscriptHash()
		_, err := kg1.HandleKeygenMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeRound)
	})
	t.Run("wrong recipient", func(t *testing.T) {
		mutated := share
		mutated.To = 3
		mutated = mutated.WithTranscriptHash()
		_, err := kg1.HandleKeygenMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("duplicate commitment", func(t *testing.T) {
		kg, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kg.HandleKeygenMessage(commit); err != nil {
			t.Fatal(err)
		}
		_, err = kg.HandleKeygenMessage(commit)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeDuplicate)
	})
}

func TestCGGMP21KeygenMalformedCommitmentHasEvidence(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	kg1, _, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := rewriteWireField(out2[0].Payload, keygenCommitmentsPayloadWireType, keygenCommitmentsPayloadFieldCommitments, encodeBytesList([][]byte{{0x02}}))
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].WithTranscriptHash()
	_, err = kg1.HandleKeygenMessage(out2[0])
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestCGGMP21PresignEnvelopeFailClosed(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	s1, _, err := StartPresign(h.shares[1], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartPresign(h.shares[2], sessionID, signers)
	if err != nil {
		t.Fatal(err)
	}
	round1 := out2[0]

	t.Run("sender not signer", func(t *testing.T) {
		mutated := round1
		mutated.From = 3
		mutated = mutated.WithTranscriptHash()
		_, err := s1.HandlePresignMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong session", func(t *testing.T) {
		mutated := round1
		mutated.SessionID, err = tss.NewSessionID(nil)
		if err != nil {
			t.Fatal(err)
		}
		mutated = mutated.WithTranscriptHash()
		_, err = s1.HandlePresignMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("wrong round", func(t *testing.T) {
		mutated := round1
		mutated.Round = 2
		mutated = mutated.WithTranscriptHash()
		_, err := s1.HandlePresignMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeRound)
	})
	t.Run("wrong recipient", func(t *testing.T) {
		mutated := round1
		mutated.To = 3
		mutated = mutated.WithTranscriptHash()
		_, err := s1.HandlePresignMessage(mutated)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
	})
	t.Run("duplicate round1", func(t *testing.T) {
		session, _, err := StartPresign(h.shares[1], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.HandlePresignMessage(round1); err != nil {
			t.Fatal(err)
		}
		_, err = session.HandlePresignMessage(round1)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeDuplicate)
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
			s1, _, err := StartPresign(h.shares[1], sessionID, []tss.PartyID{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			_, out2, err := StartPresign(h.shares[2], sessionID, []tss.PartyID{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			mutated, err := mutatePresignRound1Payload(out2[0].Payload, tc.mutate)
			if err != nil {
				t.Fatal(err)
			}
			out2[0].Payload = mutated
			out2[0] = out2[0].WithTranscriptHash()
			_, err = s1.HandlePresignMessage(out2[0])
			_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, []tss.PartyID{1, 2}, nil))
		})
	}
}

func TestCGGMP21PresignRound2WrongRecipientRejected(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := StartPresign(h.shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := StartPresign(h.shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandlePresignMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	round2, err := s2.HandlePresignMessage(out1[0])
	if err != nil {
		t.Fatal(err)
	}
	round2[0].To = 3
	round2[0] = round2[0].WithTranscriptHash()
	_, err = s1.HandlePresignMessage(round2[0])
	_ = assertProtocolErrorCode(t, err, tss.ErrCodeInvalidMessage)
}

func TestCGGMP21PresignRound3MalformedDeltaEvidence(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, out1, err := StartPresign(h.shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	s2, out2, err := StartPresign(h.shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	round2From1, err := s1.HandlePresignMessage(out2[0])
	if err != nil {
		t.Fatal(err)
	}
	round2From2, err := s2.HandlePresignMessage(out1[0])
	if err != nil {
		t.Fatal(err)
	}
	round3From2, err := s2.HandlePresignMessage(round2From1[0])
	if err != nil {
		t.Fatal(err)
	}
	round3From1, err := s1.HandlePresignMessage(round2From2[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(round3From1) != 1 {
		t.Fatalf("expected one local round3 message, got %d", len(round3From1))
	}
	if len(round3From2) != 1 {
		t.Fatalf("expected one round3 message, got %d", len(round3From2))
	}
	mutated, err := rewriteWireField(round3From2[0].Payload, presignRound3PayloadWireType, presignRound3PayloadFieldDelta, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	round3From2[0].Payload = mutated
	round3From2[0] = round3From2[0].WithTranscriptHash()
	_, err = s1.HandlePresignMessage(round3From2[0])
	_ = assertBlameEvidence(t, err, h.evidenceContext(sessionID, 1, []tss.PartyID{1, 2}, nil))
}

func TestCGGMP21SignerSetOrderCanonicalized(t *testing.T) {
	h := newHarness(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := StartPresign(h.shares[1], sessionID, []tss.PartyID{2, 1})
	if err != nil {
		t.Fatal(err)
	}
	if session.signers[0] != 1 || session.signers[1] != 2 {
		t.Fatalf("signer set was not canonicalized: %v", session.signers)
	}
}

func TestCGGMP21SignFailClosedAndEvidence(t *testing.T) {
	h := newHarness(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, h.shares, signers)
	digest := sha256.Sum256([]byte("sign fail closed"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartSignDigest(h.shares[1], presigns[1], signID, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartSignDigest(h.shares[2], presigns[2], signID, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	t.Run("transcript mismatch", func(t *testing.T) {
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
		env = env.WithTranscriptHash()
		_, err = s1.HandleSignMessage(env)
		_ = assertBlameEvidence(t, err, h.evidenceContext(signID, 1, signers, presigns[1]))
	})
	t.Run("malformed scalar", func(t *testing.T) {
		session, _, err := StartSignDigest(h.shares[1], clonePresign(presigns[1]), signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := rewriteWireField(out2[0].Payload, signPartialPayloadWireType, signPartialPayloadFieldS, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		env := out2[0]
		env.Payload = mutated
		env = env.WithTranscriptHash()
		_, err = session.HandleSignMessage(env)
		_ = assertBlameEvidence(t, err, h.evidenceContext(signID, 1, signers, presigns[1]))
	})
	t.Run("wrong round", func(t *testing.T) {
		env := out2[0]
		env.Round = 2
		env = env.WithTranscriptHash()
		_, err := s1.HandleSignMessage(env)
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeRound)
	})
	t.Run("duplicate partial", func(t *testing.T) {
		session, _, err := StartSignDigest(h.shares[1], clonePresign(presigns[1]), signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.HandleSignMessage(out2[0]); err != nil {
			t.Fatal(err)
		}
		_, err = session.HandleSignMessage(out2[0])
		_ = assertProtocolErrorCode(t, err, tss.ErrCodeDuplicate)
	})
}

func TestCGGMP21SignRejectsBadDigestAndPresignReuseBeforeOutbound(t *testing.T) {
	h := newHarness(t, 2, 3)
	presigns := secpPresign(t, h.shares, []tss.PartyID{1, 2})
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if session, out, err := StartSignDigest(h.shares[1], presigns[1], signID, []byte{1}); err == nil || session != nil || out != nil {
		t.Fatalf("bad digest should fail before creating session/outbound message: session=%v out=%d err=%v", session, len(out), err)
	}
	digest := sha256.Sum256([]byte("reuse outbound"))
	if _, _, err := StartSignDigest(h.shares[1], presigns[1], signID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if session, out, err := StartSignDigest(h.shares[1], presigns[1], signID, digest[:]); err == nil || session != nil || out != nil {
		t.Fatalf("presign reuse should fail before creating session/outbound message: session=%v out=%d err=%v", session, len(out), err)
	}
}

func assertProtocolErrorCode(t testing.TB, err error, code string) *tss.ProtocolError {
	t.Helper()
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected ProtocolError %s, got %T: %v", code, err, err)
	}
	if protocolErr.Code != code {
		t.Fatalf("expected code %s, got %s: %v", code, protocolErr.Code, err)
	}
	return protocolErr
}

func clonePresign(in *Presign) *Presign {
	if in == nil {
		return nil
	}
	out := *in
	out.Signers = append([]tss.PartyID(nil), in.Signers...)
	out.R = append([]byte(nil), in.R...)
	out.LittleR = append([]byte(nil), in.LittleR...)
	out.KShare = append([]byte(nil), in.KShare...)
	out.ChiShare = append([]byte(nil), in.ChiShare...)
	out.Delta = append([]byte(nil), in.Delta...)
	out.TranscriptHash = append([]byte(nil), in.TranscriptHash...)
	out.Consumed = false
	return &out
}
