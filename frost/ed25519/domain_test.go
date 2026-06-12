package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

// TestFROSTSignDomainSeparation verifies that FROST signing artifacts
// (commitments, partial signatures) are rejected when presented under
// the wrong domain context: wrong session, wrong message, wrong signer
// set, wrong public key, or wrong protocol.
func TestFROSTSignDomainSeparation(t *testing.T) {
	t.Parallel()

	shares := frostKeygen(t, 2, 3)
	parties := tss.SortParties(shares[1].Parties)
	messageA := []byte("message-A")
	messageB := []byte("message-B")

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{name: "cross-session", fn: func(t *testing.T) {
			t.Parallel()

			sidA, _ := tss.NewSessionID(nil)
			_, outA, err := StartSign(shares[1], sidA, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}
			commitA := outA[0]

			sidB, _ := tss.NewSessionID(nil)
			sess1B, _, err := StartSign(shares[1], sidB, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess1B.SetGuard(testFROSTGuard(1, tss.PartySet(parties), sidB))

			commitA.Security.Authenticated = true
			commitA.Security.AuthenticatedParty = commitA.From
			_, err = sess1B.HandleSignMessage(testutil.DeliverEnvelope(commitA))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
		}},
		{name: "cross-protocol", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			sess1, _, err := StartSign(shares[1], sid, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess1.SetGuard(testFROSTGuard(1, tss.PartySet(parties), sid))
			_, out2, err := StartSign(shares[2], sid, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}

			commit2 := out2[0]
			commit2.Protocol = "wrong-protocol"
			commit2 = commit2.RecomputeTranscriptHash()
			commit2.Security.Authenticated = true
			commit2.Security.AuthenticatedParty = commit2.From

			_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(commit2))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
		}},
		{name: "partial-acceptance", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			signers := []tss.PartyID{1, 2}

			sess1, out1, err := StartSign(shares[1], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess1.SetGuard(testFROSTGuard(1, tss.PartySet(parties), sid))

			sess2, out2, err := StartSign(shares[2], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess2.SetGuard(testFROSTGuard(2, tss.PartySet(parties), sid))

			// Deliver party 2's commitment to party 1 → party 1 emits its partial.
			cb := out2[0]
			cb.Security.Authenticated = true
			cb.Security.AuthenticatedParty = cb.From
			partials1, err := sess1.HandleSignMessage(testutil.DeliverEnvelope(cb))
			if err != nil {
				t.Fatal(err)
			}
			if len(partials1) == 0 || partials1[0].PayloadType != payloadSignPartial {
				t.Fatal("expected party 1 to emit partial")
			}
			party1Partial := partials1[0]
			party1Partial.Security.Authenticated = true
			party1Partial.Security.AuthenticatedParty = party1Partial.From

			// Deliver party 1's commitment to party 2 → party 2 emits its partial.
			ca := out1[0]
			ca.Security.Authenticated = true
			ca.Security.AuthenticatedParty = ca.From
			_, err = sess2.HandleSignMessage(testutil.DeliverEnvelope(ca))
			if err != nil {
				t.Fatal(err)
			}

			// Deliver party 1's partial to party 2's session.
			_, err = sess2.HandleSignMessage(testutil.DeliverEnvelope(party1Partial))
			if err != nil {
				t.Fatal(err)
			}

			sig, ok := sess2.Signature()
			if !ok {
				t.Fatal("expected signature after partial acceptance")
			}
			pubKey := shares[1].PublicKeyBytes()
			if !stded25519.Verify(stded25519.PublicKey(pubKey), messageA, sig) {
				t.Fatal("signature did not verify")
			}
		}},
		{name: "wrong-message", fn: func(t *testing.T) {
			t.Parallel()

			// All sessions share the same session ID so guard passes cross-context.
			sid, _ := tss.NewSessionID(nil)
			signers := []tss.PartyID{1, 2}

			sess1A, out1A, err := StartSign(shares[1], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess1A.SetGuard(testFROSTGuard(1, tss.PartySet(parties), sid))

			// Party 2 with message A — commitment only, for party 1's session.
			_, out2A, err := StartSign(shares[2], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with message B — to get partial computed with wrong message's binding factors.
			sess2B, _, err := StartSign(shares[2], sid, signers, messageB)
			if err != nil {
				t.Fatal(err)
			}
			sess2B.SetGuard(testFROSTGuard(2, tss.PartySet(parties), sid))

			// Give party 1 party 2's message-A commitment → party 1 emits its partial.
			cbA := out2A[0]
			cbA.Security.Authenticated = true
			cbA.Security.AuthenticatedParty = cbA.From
			_, err = sess1A.HandleSignMessage(testutil.DeliverEnvelope(cbA))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (message B) party 1's commitment → party 2 emits partial (for message B).
			ca := out1A[0]
			ca.Security.Authenticated = true
			ca.Security.AuthenticatedParty = ca.From
			partialsB, err := sess2B.HandleSignMessage(testutil.DeliverEnvelope(ca))
			if err != nil {
				t.Fatal(err)
			}
			if len(partialsB) == 0 || partialsB[0].PayloadType != payloadSignPartial {
				t.Fatal("expected party 2 to emit partial for message B")
			}
			part2B := partialsB[0]
			part2B.Security.Authenticated = true
			part2B.Security.AuthenticatedParty = part2B.From

			// Deliver message-B partial to message-A session — binding factors mismatch.
			_, err = sess1A.HandleSignMessage(testutil.DeliverEnvelope(part2B))
			pe := assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
			if pe.Blame == nil {
				t.Fatal("expected blame evidence on verification failure")
			}
		}},
		{name: "wrong-signer-set", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			signers2 := []tss.PartyID{1, 2}
			signers3 := []tss.PartyID{1, 2, 3}

			// Party 1 for 2-signer set.
			sess1_2, out1, err := StartSign(shares[1], sid, signers2, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess1_2.SetGuard(testFROSTGuard(1, tss.PartySet(parties), sid))

			// Party 2 for 2-signer set — commitment for party 1.
			_, out2_2, err := StartSign(shares[2], sid, signers2, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 for 3-signer set — to get partial with 3-signer Lagrange.
			sess2_3, out2_3, err := StartSign(shares[2], sid, signers3, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess2_3.SetGuard(testFROSTGuard(2, tss.PartySet(parties), sid))

			// Party 3 for 3-signer set.
			sess3, out3, err := StartSign(shares[3], sid, signers3, messageA)
			if err != nil {
				t.Fatal(err)
			}
			sess3.SetGuard(testFROSTGuard(3, tss.PartySet(parties), sid))

			// Give party 1 (2-signer) party 2's 2-signer commitment → party 1 emits partial.
			cb2 := out2_2[0]
			cb2.Security.Authenticated = true
			cb2.Security.AuthenticatedParty = cb2.From
			_, err = sess1_2.HandleSignMessage(testutil.DeliverEnvelope(cb2))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (3-signer) party 1's and party 3's commitments → parry 2 emits 3-signer partial.
			ca := out1[0]
			ca.Security.Authenticated = true
			ca.Security.AuthenticatedParty = ca.From
			_, err = sess2_3.HandleSignMessage(testutil.DeliverEnvelope(ca))
			if err != nil {
				t.Fatal(err)
			}
			cc3 := out3[0]
			cc3.Security.Authenticated = true
			cc3.Security.AuthenticatedParty = cc3.From
			partials3, err := sess2_3.HandleSignMessage(testutil.DeliverEnvelope(cc3))
			if err != nil {
				t.Fatal(err)
			}
			if len(partials3) == 0 || partials3[0].PayloadType != payloadSignPartial {
				t.Fatal("expected party 2 to emit 3-signer partial")
			}
			part2_3 := partials3[0]
			part2_3.Security.Authenticated = true
			part2_3.Security.AuthenticatedParty = part2_3.From

			// Deliver 3-signer partial to 2-signer session — Lagrange/binding factor mismatch.
			_, err = sess1_2.HandleSignMessage(testutil.DeliverEnvelope(part2_3))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)

			_ = out2_3 // avoid unused warning
		}},
		{name: "wrong-public-key-HD", fn: func(t *testing.T) {
			t.Parallel()

			hdShares := cachedFrostKeygen(t, 2, 2, true)

			child1, err := DeriveNonHardenedBIP32(hdShares[1].PublicKey, hdShares[1].ChainCode, []uint32{1})
			if err != nil {
				t.Fatal(err)
			}
			child2, err := DeriveNonHardenedBIP32(hdShares[1].PublicKey, hdShares[1].ChainCode, []uint32{2})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(child1.AdditiveShift, child2.AdditiveShift) {
				t.Fatal("shifts must differ")
			}

			sid, _ := tss.NewSessionID(nil)
			signers := []tss.PartyID{1, 2}

			// Party 1 with shift1.
			sess1, out1, err := StartSignWithOptions(hdShares[1], sid, signers, messageA,
				SignOptions{AdditiveShift: child1.AdditiveShift})
			if err != nil {
				t.Fatal(err)
			}
			sess1.SetGuard(testFROSTGuard(1, tss.PartySet(hdShares[1].Parties), sid))

			// Party 2 with shift1 — commitment only (for party 1).
			_, out2_s1, err := StartSignWithOptions(hdShares[2], sid, signers, messageA,
				SignOptions{AdditiveShift: child1.AdditiveShift})
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with shift2 — to get partial computed with wrong shift.
			sess2_s2, out2_s2, err := StartSignWithOptions(hdShares[2], sid, signers, messageA,
				SignOptions{AdditiveShift: child2.AdditiveShift})
			if err != nil {
				t.Fatal(err)
			}
			sess2_s2.SetGuard(testFROSTGuard(2, tss.PartySet(hdShares[2].Parties), sid))

			// Give party 1 party 2's shift1 commitment → party 1 emits partial.
			cb1 := out2_s1[0]
			cb1.Security.Authenticated = true
			cb1.Security.AuthenticatedParty = cb1.From
			_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(cb1))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (shift2) party 1's commitment → party 2 emits shift2 partial.
			ca := out1[0]
			ca.Security.Authenticated = true
			ca.Security.AuthenticatedParty = ca.From
			partials2, err := sess2_s2.HandleSignMessage(testutil.DeliverEnvelope(ca))
			if err != nil {
				t.Fatal(err)
			}
			if len(partials2) == 0 || partials2[0].PayloadType != payloadSignPartial {
				t.Fatal("expected party 2 to emit shift2 partial")
			}
			part2_s2 := partials2[0]
			part2_s2.Security.Authenticated = true
			part2_s2.Security.AuthenticatedParty = part2_s2.From

			// Deliver shift2 partial to shift1 session — verifyKey mismatch in binding factors.
			_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(part2_s2))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)

			_ = out2_s2 // avoid unused warning
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.fn)
	}
}
