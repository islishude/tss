//go:build integration || vectorgen

package secp256k1

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/islishude/tss"
)

func TestThresholdECDSAPresignReuseRejected(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	presign := presigns[1]
	digest := sha256.Sum256([]byte("reuse"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartSignDigest(shares[1], presign, signID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartSignDigest(shares[1], presign, signID, digest[:]); err == nil {
		t.Fatal("expected presign reuse rejection")
	}
}

func TestThresholdECDSATamperedEncKBlamesSender(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload[0] ^= 1
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := s1.HandlePresignMessage(deliverCGGMPEnv(out2[0])); err == nil {
		t.Fatal("expected tampered EncK rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
	}
}

func TestThresholdECDSATamperedRound2ProofBlamesSender(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*presignRound2Payload)
	}{
		{name: "delta", mutate: func(p *presignRound2Payload) { p.Delta.Proof[0] ^= 1 }},
		{name: "sigma", mutate: func(p *presignRound2Payload) { p.Sigma.Proof[0] ^= 1 }},
		{name: "echo", mutate: func(p *presignRound2Payload) { p.Round1Echo[0] ^= 1 }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			s1, out1, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			s1.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
			s2, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			s2.SetGuard(testCGGMP21Guard(2, tss.PartySet(shares[2].Parties), sessionID))
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
			round2[0] = round2[0].RecomputeTranscriptHash()
			_, err = s1.HandlePresignMessage(deliverCGGMPEnv(round2[0]))
			if err == nil {
				t.Fatal("expected tampered round2 proof rejection")
			}
			var protocolErr *tss.ProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.Party != 2 {
				t.Fatalf("unexpected error: %v", err)
			}
			_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
		})
	}
}

func TestThresholdECDSAPaillierPublicKeyMismatchRejected(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	s1.SetGuard(testCGGMP21Guard(1, tss.PartySet(shares[1].Parties), sessionID))
	_, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalPresignRound1Payload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierPublicKey = shares[1].PaillierPublicKey
	mutated, err := marshalPresignRound1Payload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].RecomputeTranscriptHash()
	if _, err := s1.HandlePresignMessage(deliverCGGMPEnv(out2[0])); err == nil {
		t.Fatal("expected presign Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
	}
}

func TestThresholdECDSA_PresignRoundTrip(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 1, 1)
	presigns := secpPresign(t, shares, []tss.PartyID{1})
	presign := presigns[1]
	raw, err := presign.MarshalBinary()
	if err != nil {
		t.Fatalf("Presign MarshalBinary: %v", err)
	}
	restored, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatalf("UnmarshalPresign: %v", err)
	}
	if restored.Consumed {
		t.Fatal("fresh presign after round-trip is consumed")
	}
	digest := sha256.Sum256([]byte("round-trip test"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	signSession, _, err := StartSignDigest(shares[1], restored, sessionID, digest[:])
	if err != nil {
		t.Fatalf("StartSignDigest with round-tripped presign: %v", err)
	}
	sig, ok := signSession.Signature()
	if !ok {
		t.Fatal("expected sign session to produce a signature")
	}
	if !VerifyDigest(shares[1].PublicKey, digest[:], sig) {
		t.Fatal("ECDSA signature from round-tripped presign did not verify")
	}
}

func TestThresholdECDSA_PresignConsumedRoundTrip(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	presign := presigns[1]
	digest := sha256.Sum256([]byte("consumed round-trip"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Consume the presign.
	_, _, err = StartSignDigest(shares[1], presign, sessionID, digest[:])
	if err != nil {
		t.Fatalf("StartSignDigest: %v", err)
	}
	// Serialize and deserialize the consumed presign.
	raw, err := presign.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary on consumed presign: %v", err)
	}
	restored, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatalf("UnmarshalPresign consumed: %v", err)
	}
	if !IsPresignConsumed(restored) {
		t.Fatal("consumed state was not preserved through round-trip")
	}
	// Attempting to sign with the consumed restored presign must fail.
	sessionID2, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = StartSignDigest(shares[1], restored, sessionID2, digest[:])
	_ = assertProtocolErrorCode(t, err, tss.ErrCodeConsumed)
}

func TestThresholdECDSA_PresignRejectReuse(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	presigns := secpPresign(t, shares, []tss.PartyID{1, 2})
	presign := presigns[1]
	digest := sha256.Sum256([]byte("reuse test"))
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	// First sign succeeds.
	_, _, err = StartSignDigest(shares[1], presign, sessionID, digest[:])
	if err != nil {
		t.Fatalf("first StartSignDigest: %v", err)
	}
	// Reusing the same presign must fail with ErrCodeConsumed.
	sessionID2, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = StartSignDigest(shares[1], presign, sessionID2, digest[:])
	_ = assertProtocolErrorCode(t, err, tss.ErrCodeConsumed)
}

func TestThresholdECDSA_PresignRejectsKeyBindingMismatchBeforeConsume(t *testing.T) {
	runLimitedIntegration(t)

	shares := secpKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	presign := (presigns[1]).Clone()
	presign.KeygenTranscriptHash = append([]byte(nil), presign.KeygenTranscriptHash...)
	presign.KeygenTranscriptHash[0] ^= 1
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("key binding mismatch"))
	_, _, err = StartSignDigest(shares[1], presign, signID, digest[:])
	if err == nil || !strings.Contains(err.Error(), "keygen transcript binding") {
		t.Fatalf("expected key binding rejection, got %v", err)
	}
	if presign.Consumed {
		t.Fatal("presign was consumed before key binding validation completed")
	}
}
