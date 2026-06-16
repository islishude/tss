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
	messageA := []byte("message-A")
	messageB := []byte("message-B")

	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{name: "cross-session", fn: func(t *testing.T) {
			t.Parallel()

			sidA, _ := tss.NewSessionID(nil)
			_, outA, err := startFROSTSign(shares[1], sidA, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}
			commitA := outA[0]

			sidB, _ := tss.NewSessionID(nil)
			sess1B, _, err := startFROSTSign(shares[1], sidB, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}
			_, err = sess1B.HandleSignMessage(testutil.DeliverEnvelope(commitA))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
		}},
		{name: "cross-protocol", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			sess1, _, err := startFROSTSign(shares[1], sid, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}
			_, out2, err := startFROSTSign(shares[2], sid, []tss.PartyID{1, 2}, messageA)
			if err != nil {
				t.Fatal(err)
			}

			commit2 := out2[0]
			commit2.Protocol = "wrong-protocol"

			_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(commit2))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
		}},
		{name: "partial-acceptance", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			signers := []tss.PartyID{1, 2}

			sess1, out1, err := startFROSTSign(shares[1], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}

			sess2, out2, err := startFROSTSign(shares[2], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Deliver party 2's commitment to party 1 → party 1 emits its partial.
			cb := out2[0]
			partials1, err := sess1.HandleSignMessage(testutil.DeliverEnvelope(cb))
			if err != nil {
				t.Fatal(err)
			}
			if len(partials1) == 0 || partials1[0].PayloadType != payloadSignPartial {
				t.Fatal("expected party 1 to emit partial")
			}
			party1Partial := partials1[0]

			// Deliver party 1's commitment to party 2 → party 2 emits its partial.
			ca := out1[0]
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

			sess1A, out1A, err := startFROSTSign(shares[1], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with message A — commitment only, for party 1's session.
			_, out2A, err := startFROSTSign(shares[2], sid, signers, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with message B — to get partial computed with wrong message's binding factors.
			sess2B, _, err := startFROSTSign(shares[2], sid, signers, messageB)
			if err != nil {
				t.Fatal(err)
			}

			// Give party 1 party 2's message-A commitment → party 1 emits its partial.
			cbA := out2A[0]
			_, err = sess1A.HandleSignMessage(testutil.DeliverEnvelope(cbA))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (message B) party 1's message-A commitment.
			// The lifecycle plan hash rejects the cross-message intent before a
			// partial is emitted.
			ca := out1A[0]
			_, err = sess2B.HandleSignMessage(testutil.DeliverEnvelope(ca))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		}},
		{name: "wrong-signer-set", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			signers2 := []tss.PartyID{1, 2}
			signers3 := []tss.PartyID{1, 2, 3}

			// Party 1 for 2-signer set.
			sess1_2, out1, err := startFROSTSign(shares[1], sid, signers2, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 for 2-signer set — commitment for party 1.
			_, out2_2, err := startFROSTSign(shares[2], sid, signers2, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 for 3-signer set.
			sess2_3, _, err := startFROSTSign(shares[2], sid, signers3, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Party 3 for 3-signer set.
			_, _, err = startFROSTSign(shares[3], sid, signers3, messageA)
			if err != nil {
				t.Fatal(err)
			}

			// Give party 1 (2-signer) party 2's 2-signer commitment → party 1 emits partial.
			cb2 := out2_2[0]
			_, err = sess1_2.HandleSignMessage(testutil.DeliverEnvelope(cb2))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (3-signer) party 1's 2-signer commitment. The plan
			// hash rejects the cross-signer-set intent before a partial is emitted.
			ca := out1[0]
			_, err = sess2_3.HandleSignMessage(testutil.DeliverEnvelope(ca))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		}},
		{name: "wrong-public-key-HD", fn: func(t *testing.T) {
			t.Parallel()

			hdShares := cachedFrostKeygen(t, 2, 2)

			child1, err := DeriveNonHardenedBIP32(hdShares[1].state.publicKey, hdShares[1].state.chainCode, []uint32{1})
			if err != nil {
				t.Fatal(err)
			}
			child2, err := DeriveNonHardenedBIP32(hdShares[1].state.publicKey, hdShares[1].state.chainCode, []uint32{2})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(child1.AdditiveShift, child2.AdditiveShift) {
				t.Fatal("shifts must differ")
			}

			sid, _ := tss.NewSessionID(nil)
			signers := []tss.PartyID{1, 2}

			// Party 1 with shift1.
			sess1, out1, err := startFROSTSignWithOptions(hdShares[1], sid, signers, messageA,
				SignOptions{Context: testFROSTSigningContext([]uint32{1})})
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with shift1 — commitment only (for party 1).
			_, out2_s1, err := startFROSTSignWithOptions(hdShares[2], sid, signers, messageA,
				SignOptions{Context: testFROSTSigningContext([]uint32{1})})
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with shift2.
			sess2_s2, _, err := startFROSTSignWithOptions(hdShares[2], sid, signers, messageA,
				SignOptions{Context: testFROSTSigningContext([]uint32{2})})
			if err != nil {
				t.Fatal(err)
			}

			// Give party 1 party 2's shift1 commitment → party 1 emits partial.
			cb1 := out2_s1[0]
			_, err = sess1.HandleSignMessage(testutil.DeliverEnvelope(cb1))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (shift2) party 1's shift1 commitment. The plan hash
			// rejects the cross-HD-path intent before a partial is emitted.
			ca := out1[0]
			_, err = sess2_s2.HandleSignMessage(testutil.DeliverEnvelope(ca))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.fn)
	}
}
