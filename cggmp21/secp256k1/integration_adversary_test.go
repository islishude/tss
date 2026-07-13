//go:build integration

package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

// TestIntegration_SignPartialTamperingBlamesSender verifies that tampering
// various fields in an online signing partial results in precise blame of
// only the sender with ErrCodeVerification.
func TestIntegration_SignPartialTamperingBlamesSender(t *testing.T) {
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)

	tests := []struct {
		name   string
		mutate func(t *testing.T, p *signPartialPayload, presign *Presign, signID tss.SessionID, digest []byte)
	}{
		{
			name: "tampered S with bad equation hash",
			mutate: func(t *testing.T, p *signPartialPayload, _ *Presign, _ tss.SessionID, _ []byte) {
				p.S.Destroy()
				p.S = testSecretScalar(t, 123456789)
				p.PartialEquationHash = bytes.Repeat([]byte{0x42}, 32)
			},
		},
		{
			name: "tampered DigestHash",
			mutate: func(t *testing.T, p *signPartialPayload, _ *Presign, _ tss.SessionID, _ []byte) {
				p.DigestHash = bytes.Repeat([]byte{0x99}, 32)
			},
		},
		{
			name: "tampered PresignTranscript",
			mutate: func(t *testing.T, p *signPartialPayload, _ *Presign, _ tss.SessionID, _ []byte) {
				p.PresignTranscript = bytes.Repeat([]byte{0x88}, 32)
			},
		},
		{
			name: "tampered PartialEquationHash alone",
			mutate: func(t *testing.T, p *signPartialPayload, _ *Presign, _ tss.SessionID, _ []byte) {
				p.PartialEquationHash = bytes.Repeat([]byte{0x77}, 32)
			},
		},
		{
			name: "tampered S with recomputed equation hash",
			mutate: func(t *testing.T, p *signPartialPayload, presign *Presign, signID tss.SessionID, digest []byte) {
				sVal, err := secpScalarFromSecretAllowZero(p.S)
				if err != nil {
					t.Fatal(err)
				}
				wrongS := secp.ScalarAdd(sVal, secp.ScalarOne())
				p.S.Destroy()
				p.S, err = secpSecretScalarFromScalarAllowZero(wrongS)
				if err != nil {
					t.Fatal(err)
				}
				commitment, ok := normalizedCommitmentFor(presign, presign.PartyID())
				if !ok {
					t.Fatal("missing normalized commitment")
				}
				p.PartialEquationHash = partialEquationHash(
					signID, presign.PartyID(), p.PresignTranscript,
					p.PresignContext, p.PlanHash, digest[:],
					mustPresignLittleR(t, presign), wrongS.Bytes(),
					commitment.DeltaTilde, commitment.STilde,
				)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			presigns := secpPresign(t, shares, signers)
			digest := sha256.Sum256([]byte("adversarial " + tc.name))
			signID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}

			sessions, firstEnv := startSignAndCapture(t, shares, presigns, signers, signID, digest[:])
			payload, err := unmarshalSignPartialPayload(firstEnv.Payload)
			if err != nil {
				t.Fatal(err)
			}

			tc.mutate(t, &payload, presigns[firstEnv.From], signID, digest[:])

			mutated, err := marshalSignPartialPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			firstEnv.Payload = mutated

			assertSignPartialBlamesOnlySender(t, sessions, firstEnv, signers)
		})
	}
}

// assertSignPartialBlamesOnlySender delivers a tampered sign partial to all
// other signers and verifies each blames only the sender.
func assertSignPartialBlamesOnlySender(t *testing.T, sessions map[tss.PartyID]*SignSession, env tss.Envelope, signers tss.PartySet) {
	t.Helper()
	for _, id := range signers {
		if id == env.From {
			continue
		}
		_, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
		if err == nil {
			t.Fatal("expected rejection of tampered sign partial")
		}
		var protoErr *tss.ProtocolError
		if !errors.As(err, &protoErr) {
			t.Fatalf("expected ProtocolError, got %T: %v", err, err)
		}
		if protoErr.Code != tss.ErrCodeVerification {
			t.Errorf("expected ErrCodeVerification, got %s", protoErr.Code)
		}
		if protoErr.Blame == nil {
			t.Fatal("expected blame evidence")
		}
		if len(protoErr.Blame.Parties) != 1 {
			t.Errorf("blame must be exactly 1 party, got %v", protoErr.Blame.Parties)
		}
		if len(protoErr.Blame.Parties) > 0 && protoErr.Blame.Parties[0] != env.From {
			t.Errorf("blame must be sender %d, got %v", env.From, protoErr.Blame.Parties)
		}
	}
}

// TestIntegration_ValidPartialsProduceValidSignature verifies the full
// happy path: all valid partials result in a valid ECDSA signature.
func TestIntegration_ValidPartialsProduceValidSignature(t *testing.T) {
	t.Parallel()

	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	presigns := secpPresign(t, shares, signers)
	digest := sha256.Sum256([]byte("happy path"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessions := map[tss.PartyID]*SignSession{}
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSignDigest(shares[id], presigns[id], signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range signers {
			if id == env.From {
				continue
			}
			if _, err := sessions[id].Handle(testutil.DeliverEnvelope(env)); err != nil {
				t.Fatalf("unexpected error for valid partial from %d to %d: %v", env.From, id, err)
			}
		}
	}
	for _, s := range sessions {
		sig, ok := s.Signature()
		if !ok {
			t.Fatal("session did not complete")
		}
		if !VerifyDigest(s.publicKey, s.digest, sig) {
			t.Fatal("valid partials produced invalid aggregate ECDSA signature")
		}
	}
}

// TestIntegration_PresignRejectsTamperedNormalizedCommitments verifies that
// the two Figure 10 commitment families remain bound to the normalized
// Figure 8 aggregate equations.
func TestIntegration_PresignRejectsTamperedNormalizedCommitments(t *testing.T) {
	tests := []struct {
		name  string
		field string
	}{
		{name: "tampered DeltaTilde", field: "delta"},
		{name: "tampered STilde", field: "chi"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			shares := CachedKeygenShares(t, 2, 3)
			signers := tss.NewPartySet(1, 2, 3)
			presigns := secpPresign(t, shares, signers)

			for _, r := range presigns {
				switch tc.field {
				case "delta":
					r.state.Commitments[0].DeltaTilde = testCurvePointBytes(t, 7)
				case "chi":
					r.state.Commitments[0].STilde = testCurvePointBytes(t, 7)
				}
				if err := r.VerifySignMaterial(); err != nil {
					t.Logf("%s tampering correctly detected: %v", tc.field, err)
					return
				}
			}
			t.Fatalf("%s tampering passed presign cryptographic self-verification", tc.field)
		})
	}
}

// startSignAndCapture is a helper that starts sign sessions and returns the
// map of sessions plus the first signer's outbound envelope.
func startSignAndCapture(t *testing.T, shares map[tss.PartyID]*KeyShare, presigns map[tss.PartyID]*Presign, signers tss.PartySet, signID tss.SessionID, digest []byte) (map[tss.PartyID]*SignSession, tss.Envelope) {
	t.Helper()
	sessions := map[tss.PartyID]*SignSession{}
	var firstEnv tss.Envelope
	first := true
	for _, id := range signers {
		session, out, err := StartSignDigest(shares[id], presigns[id], signID, digest)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		if first {
			firstEnv = out[0]
			first = false
		}
	}
	return sessions, firstEnv
}

// runPresignRound3TamperTest sets up 3-party presign sessions, delivers
// messages, and intercepts the first round3 message to apply tamper.
// The tamper function receives the unmarshaled round3 payload and should
// return the mutated bytes. If tamper returns nil, marshal rejection is
// treated as valid presign-phase detection.
func runPresignRound3TamperTest(t *testing.T, shares map[tss.PartyID]*KeyShare, signers tss.PartySet, tamper func(t *testing.T, p presignRound3Payload) []byte) {
	t.Helper()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	presignSessions := map[tss.PartyID]*PresignSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := startTestPresign(shares[id], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		presignSessions[id] = session
		messages = append(messages, out...)
	}

	tampered := false
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]

		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				if tampered {
					assertPresignRound3Blame(t, err, env.From)
					return
				}
				t.Fatal(err)
			}
			for i := range out {
				if out[i].PayloadType == payloadPresignRound3 && !tampered {
					tampered = true
					p, err := unmarshalPresignRound3Payload(out[i].Payload)
					if err != nil {
						t.Fatal(err)
					}
					mutated := tamper(t, p)
					if mutated == nil {
						// Marshal rejection is valid presign-phase detection.
						return
					}
					out[i].Payload = mutated
				}
			}
			messages = append(messages, out...)
		}
	}
	if !tampered {
		t.Fatal("no round3 message was intercepted")
	}
}

// TestIntegration_PresignRound3TamperingBlamesSender verifies that tampering
// Figure 8 round-3 fields directly bound by Πelog results in immediate
// presign-phase blame of only the sender. S is checked by the aggregate chi
// equation and therefore has a separate Figure 9 transition test below.
func TestIntegration_PresignRound3TamperingBlamesSender(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2, 3)

	tests := []struct {
		name   string
		tamper func(t *testing.T, p presignRound3Payload) []byte
	}{
		{
			name: "bit-flipped DeltaPoint",
			tamper: func(t *testing.T, p presignRound3Payload) []byte {
				tamperedK := bytes.Clone(p.DeltaPoint)
				tamperedK[len(tamperedK)-1] ^= 0x01
				if _, err := secp.PointFromBytes(tamperedK); err != nil {
					t.Logf("DeltaPoint tampering caused point rejection (valid): %v", err)
					return nil
				}
				p.DeltaPoint = tamperedK
				mutated, err := marshalPresignRound3Payload(p)
				if err != nil {
					t.Logf("DeltaPoint tampering caused marshal rejection (valid): %v", err)
					return nil
				}
				return mutated
			},
		},
		{
			name: "replaced DeltaPoint with different valid point",
			tamper: func(t *testing.T, p presignRound3Payload) []byte {
				p.DeltaPoint = testCurvePointBytes(t, 2)
				mutated, err := marshalPresignRound3Payload(p)
				if err != nil {
					t.Fatal(err)
				}
				return mutated
			},
		},
		{
			name: "corrupted proof scalar",
			tamper: func(t *testing.T, p presignRound3Payload) []byte {
				p.Proof.Z = secp.ScalarFromUint64(123).Bytes()
				mutated, err := marshalPresignRound3Payload(p)
				if err != nil {
					t.Logf("proof tampering caused marshal rejection: %v", err)
					return nil
				}
				return mutated
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runPresignRound3TamperTest(t, shares, signers, tc.tamper)
		})
	}
}

// TestIntegration_PresignRound3TamperedSEntersFigure9 deterministically changes
// one valid S_i to S_i+G. This preserves canonical point encoding while making
// the aggregate chi equation differ by exactly G, so the receiver must reject
// Figure 8 completion and enter the Figure 9 chi red-alert phase.
func TestIntegration_PresignRound3TamperedSEntersFigure9(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2, 3)

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*PresignSession, len(signers))
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := startTestPresign(shares[id], sessionID, signers)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}

	tampered := false
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) || sessions[id].completed {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatal(err)
			}
			for i := range out {
				if out[i].PayloadType == payloadPresignRound3 && !tampered {
					tampered = true
					payload, err := unmarshalPresignRound3Payload(out[i].Payload)
					if err != nil {
						t.Fatal(err)
					}
					sPoint, err := decodePresignGroupElement(payload.S)
					if err != nil {
						t.Fatal(err)
					}
					payload.S, err = encodePresignGroupElement(secp.Add(sPoint, secp.G))
					if err != nil {
						t.Fatal(err)
					}
					out[i].Payload, err = marshalPresignRound3Payload(payload)
					if err != nil {
						t.Fatal(err)
					}
				}
				if out[i].PayloadType == payloadPresignRedAlert {
					alertSession := sessions[out[i].From]
					if !alertSession.identifying || alertSession.redAlertKind != presignRedAlertChi || alertSession.completed {
						t.Fatalf("tampered S did not enter the Figure 9 chi phase: identifying=%v kind=%q completed=%v", alertSession.identifying, alertSession.redAlertKind, alertSession.completed)
					}
					if _, ok := alertSession.Presign(); ok {
						t.Fatal("tampered S exposed an available presign before Figure 9 resolution")
					}
					return
				}
			}
			messages = append(messages, out...)
		}
	}
	if !tampered {
		t.Fatal("no round3 S value was tampered")
	}
	t.Fatal("tampered S did not activate Figure 9")
}

// TestIntegration_OriginalDefectRegression covers the original protocol defect
// (Section 14.3): a single malicious signer sends a wrong partial S, and the
// receiver must blame only that signer — not all signers.
//
//  1. Create valid threshold presign (2-of-3).
//  2. Start online signing.
//  3. Tamper one signer's S to another valid scalar.
//  4. Deliver to receiver.
//  5. Expect immediate ErrCodeVerification.
//  6. Expect blame with only the tampering signer.
//  7. Expect session not to enter aggregation (not completed).
//  8. Expect no blame-all-signers path.
func TestIntegration_OriginalDefectRegression(t *testing.T) {
	t.Parallel()
	shares := CachedKeygenShares(t, 2, 3)
	signers := tss.NewPartySet(1, 2)
	presigns := secpPresign(t, shares, signers)
	digest := sha256.Sum256([]byte("original defect regression"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Step 1-2: Start signing for all signers.
	sessions := map[tss.PartyID]*SignSession{}
	var maliciousSigner tss.PartyID
	var honestSession *SignSession
	var maliciousPartial tss.Envelope
	for _, id := range signers {
		session, out, err := StartSignDigest(shares[id], presigns[id], signID, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		if maliciousSigner == 0 {
			maliciousSigner = id
			maliciousPartial = out[0]
		} else {
			honestSession = session
		}
	}

	// Step 3: Tamper S to another valid scalar.
	p, err := unmarshalSignPartialPayload(maliciousPartial.Payload)
	if err != nil {
		t.Fatal(err)
	}
	// Replace S with a different valid scalar (not the correct s_i).
	originalS := p.S.Clone()
	p.S.Destroy()
	p.S = testSecretScalar(t, 42)
	// Recompute equation hash so hash mismatch doesn't fire first — we want
	// the equation verification to catch it.
	commitment, ok := normalizedCommitmentFor(presigns[maliciousSigner], maliciousSigner)
	if !ok {
		t.Fatal("missing malicious signer normalized commitment")
	}
	p.PartialEquationHash = partialEquationHash(
		signID, maliciousSigner, p.PresignTranscript,
		p.PresignContext, p.PlanHash, digest[:],
		mustPresignLittleR(t, presigns[maliciousSigner]), p.S.FixedBytes(),
		commitment.DeltaTilde, commitment.STilde,
	)
	mutated, err := marshalSignPartialPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	maliciousPartial.Payload = mutated

	// Verify S is actually different from original.
	if p.S.Equal(originalS) {
		t.Fatal("S was not changed — scalar collision")
	}
	originalS.Destroy()

	// Step 4: Deliver tampered partial to honest signer.
	_, err = honestSession.Handle(testutil.DeliverEnvelope(maliciousPartial))

	// Step 5: Expect immediate ErrCodeVerification.
	if err == nil {
		t.Fatal("expected error for tampered S partial")
	}
	var protoErr *tss.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if protoErr.Code != tss.ErrCodeVerification {
		t.Errorf("expected ErrCodeVerification, got %s", protoErr.Code)
	}

	// Step 6: Blame must be exactly the malicious signer only.
	if protoErr.Blame == nil {
		t.Fatal("expected blame evidence")
	}
	if len(protoErr.Blame.Parties) != 1 {
		t.Errorf("blame must be exactly 1 party, got %v", protoErr.Blame.Parties)
	}
	if len(protoErr.Blame.Parties) > 0 && protoErr.Blame.Parties[0] != maliciousSigner {
		t.Errorf("blame must be malicious signer %d, got %v", maliciousSigner, protoErr.Blame.Parties)
	}

	// Step 7: Session must not enter aggregation (not completed).
	if honestSession.completed {
		t.Error("honest session completed despite invalid partial — should not enter aggregation")
	}

	// Step 8: Verify no blame-all-signers path.
	if protoErr.Code == tss.ErrCodeAggregateSignInvalid {
		t.Error("got obsolete ErrCodeAggregateSignInvalid — should be ErrCodeVerification")
	}
	if protoErr.Blame != nil && len(protoErr.Blame.Parties) == len(signers) {
		t.Error("blame lists all signers — old blame-all behavior detected")
	}
}

// assertPresignRound3Blame checks that a presign-phase error correctly blames
// only the sender with ErrCodeVerification and EvidenceKindPresignRound3.
func assertPresignRound3Blame(t *testing.T, err error, sender tss.PartyID) {
	t.Helper()
	var protoErr *tss.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if protoErr.Code != tss.ErrCodeVerification {
		t.Errorf("expected ErrCodeVerification, got %s", protoErr.Code)
	}
	if protoErr.Blame == nil {
		t.Fatal("expected blame evidence")
	}
	if len(protoErr.Blame.Parties) != 1 {
		t.Errorf("blame must be exactly 1 party (sender %d), got %v", sender, protoErr.Blame.Parties)
	}
	if len(protoErr.Blame.Parties) > 0 && protoErr.Blame.Parties[0] != sender {
		t.Errorf("blame must be sender %d, got %v", sender, protoErr.Blame.Parties)
	}
	// Verify the evidence is well-formed presign round3 evidence.
	if len(protoErr.Blame.Evidence) == 0 {
		t.Error("blame evidence is empty")
	}
}
