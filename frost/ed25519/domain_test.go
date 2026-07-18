package ed25519

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
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
			_, outA, err := startFROSTSign(shares[1], sidA, tss.NewPartySet(1, 2), messageA)
			if err != nil {
				t.Fatal(err)
			}
			commitA := outA[0]

			sidB, _ := tss.NewSessionID(nil)
			sess1B, _, err := startFROSTSign(shares[1], sidB, tss.NewPartySet(1, 2), messageA)
			if err != nil {
				t.Fatal(err)
			}
			_, err = sess1B.Handle(testutil.DeliverEnvelope(commitA))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
		}},
		{name: "cross-protocol", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			sess1, _, err := startFROSTSign(shares[1], sid, tss.NewPartySet(1, 2), messageA)
			if err != nil {
				t.Fatal(err)
			}
			_, out2, err := startFROSTSign(shares[2], sid, tss.NewPartySet(1, 2), messageA)
			if err != nil {
				t.Fatal(err)
			}

			commit2 := out2[0]
			commit2.Protocol = "wrong-protocol"

			_, err = sess1.Handle(testutil.DeliverEnvelope(commit2))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeInvalidMessage)
		}},
		{name: "partial-acceptance", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			signers := tss.NewPartySet(1, 2)

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
			partials1, err := sess1.Handle(testutil.DeliverEnvelope(cb))
			if err != nil {
				t.Fatal(err)
			}
			if len(partials1) == 0 || partials1[0].PayloadType != payloadSignPartial {
				t.Fatal("expected party 1 to emit partial")
			}
			party1Partial := partials1[0]

			// Deliver party 1's commitment to party 2 → party 2 emits its partial.
			ca := out1[0]
			_, err = sess2.Handle(testutil.DeliverEnvelope(ca))
			if err != nil {
				t.Fatal(err)
			}

			// Deliver party 1's partial to party 2's session.
			_, err = sess2.Handle(testutil.DeliverEnvelope(party1Partial))
			if err != nil {
				t.Fatal(err)
			}

			sig, ok := sess2.Signature()
			if !ok {
				t.Fatal("expected signature after partial acceptance")
			}
			pubKey := mustKeyShareMetadata(t, shares[1]).PublicKey
			if !stded25519.Verify(stded25519.PublicKey(pubKey.Bytes()), messageA, sig) {
				t.Fatal("signature did not verify")
			}
		}},
		{name: "wrong-message", fn: func(t *testing.T) {
			t.Parallel()

			// All sessions share the same session ID so guard passes cross-context.
			sid, _ := tss.NewSessionID(nil)
			signers := tss.NewPartySet(1, 2)

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
			_, err = sess1A.Handle(testutil.DeliverEnvelope(cbA))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (message B) party 1's message-A commitment.
			// The lifecycle plan hash rejects the cross-message intent before a
			// partial is emitted.
			ca := out1A[0]
			_, err = sess2B.Handle(testutil.DeliverEnvelope(ca))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		}},
		{name: "wrong-signer-set", fn: func(t *testing.T) {
			t.Parallel()

			sid, _ := tss.NewSessionID(nil)
			signers2 := tss.NewPartySet(1, 2)
			signers3 := tss.NewPartySet(1, 2, 3)

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
			_, err = sess1_2.Handle(testutil.DeliverEnvelope(cb2))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (3-signer) party 1's 2-signer commitment. The plan
			// hash rejects the cross-signer-set intent before a partial is emitted.
			ca := out1[0]
			_, err = sess2_3.Handle(testutil.DeliverEnvelope(ca))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		}},
		{name: "wrong-public-key-HD", fn: func(t *testing.T) {
			t.Parallel()

			hdShares := cachedFrostKeygen(t, 2, 2)

			child1, err := DeriveNonHardenedBIP32(hdShares[1].state.PublicKey.Bytes(), hdShares[1].state.ChainCode, []uint32{1})
			if err != nil {
				t.Fatal(err)
			}
			child2, err := DeriveNonHardenedBIP32(hdShares[1].state.PublicKey.Bytes(), hdShares[1].state.ChainCode, []uint32{2})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(child1.AdditiveShift, child2.AdditiveShift) {
				t.Fatal("shifts must differ")
			}

			sid, _ := tss.NewSessionID(nil)
			signers := tss.NewPartySet(1, 2)

			// Party 1 with shift1.
			sess1, out1, err := startFROSTSignWithOptions(hdShares[1], sid, signers, messageA,
				testSignOptions{Context: testFROSTSigningContext([]uint32{1})})
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with shift1 — commitment only (for party 1).
			_, out2_s1, err := startFROSTSignWithOptions(hdShares[2], sid, signers, messageA,
				testSignOptions{Context: testFROSTSigningContext([]uint32{1})})
			if err != nil {
				t.Fatal(err)
			}

			// Party 2 with shift2.
			sess2_s2, _, err := startFROSTSignWithOptions(hdShares[2], sid, signers, messageA,
				testSignOptions{Context: testFROSTSigningContext([]uint32{2})})
			if err != nil {
				t.Fatal(err)
			}

			// Give party 1 party 2's shift1 commitment → party 1 emits partial.
			cb1 := out2_s1[0]
			_, err = sess1.Handle(testutil.DeliverEnvelope(cb1))
			if err != nil {
				t.Fatal(err)
			}

			// Give party 2 (shift2) party 1's shift1 commitment. The plan hash
			// rejects the cross-HD-path intent before a partial is emitted.
			ca := out1[0]
			_, err = sess2_s2.Handle(testutil.DeliverEnvelope(ca))
			_ = assertFROSTProtocolCode(t, err, tss.ErrCodeVerification)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.fn)
	}
}

type frostReshareTranscriptFixture struct {
	sessionID          tss.SessionID
	oldParties         tss.PartySet
	newParties         tss.PartySet
	newThreshold       int
	oldPublicKey       []byte
	chainCode          []byte
	planHash           []byte
	refreshMode        bool
	dealerCommitments  map[tss.PartyID][][]byte
	newCommitments     [][]byte
	verificationShares []VerificationShare
}

func TestFROSTReshareTranscriptFixedDigest(t *testing.T) {
	t.Parallel()
	fixture := newFROSTReshareTranscriptFixture(t)
	const want = "84e49bfca0f9e9d9d843849b11da4812498ac5987eadee2c036fae3abd5fc7cd"
	if got := hex.EncodeToString(fixture.digest()); got != want {
		t.Fatalf("reshare transcript digest = %s, want %s", got, want)
	}
}

func TestFROSTReshareTranscriptBindsEveryField(t *testing.T) {
	t.Parallel()
	base := newFROSTReshareTranscriptFixture(t)
	baseline := base.digest()
	replacementPoint := mustFROSTTranscriptVerificationSharePoint(t, 9)
	tests := []struct {
		name   string
		mutate func(*frostReshareTranscriptFixture)
	}{
		{name: "session ID", mutate: func(f *frostReshareTranscriptFixture) { f.sessionID[0] ^= 1 }},
		{name: "old parties", mutate: func(f *frostReshareTranscriptFixture) { f.oldParties = tss.NewPartySet(1, 2, 5) }},
		{name: "new parties", mutate: func(f *frostReshareTranscriptFixture) { f.newParties = tss.NewPartySet(2, 3, 5) }},
		{name: "new threshold", mutate: func(f *frostReshareTranscriptFixture) { f.newThreshold++ }},
		{name: "old public key", mutate: func(f *frostReshareTranscriptFixture) { f.oldPublicKey[0] ^= 1 }},
		{name: "chain code", mutate: func(f *frostReshareTranscriptFixture) { f.chainCode[0] ^= 1 }},
		{name: "plan hash", mutate: func(f *frostReshareTranscriptFixture) { f.planHash[0] ^= 1 }},
		{name: "refresh mode", mutate: func(f *frostReshareTranscriptFixture) { f.refreshMode = !f.refreshMode }},
		{name: "dealer commitment", mutate: func(f *frostReshareTranscriptFixture) { f.dealerCommitments[2][1][0] ^= 1 }},
		{name: "dealer commitment list", mutate: func(f *frostReshareTranscriptFixture) {
			f.dealerCommitments[2] = append(f.dealerCommitments[2], bytes.Repeat([]byte{0x5a}, 32))
		}},
		{name: "new commitment", mutate: func(f *frostReshareTranscriptFixture) { f.newCommitments[1][0] ^= 1 }},
		{name: "verification share party", mutate: func(f *frostReshareTranscriptFixture) { f.verificationShares[0].Party = 5 }},
		{name: "verification share point", mutate: func(f *frostReshareTranscriptFixture) {
			f.verificationShares[0].PublicKey = replacementPoint.Clone()
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := base.clone()
			tc.mutate(&fixture)
			if got := fixture.digest(); bytes.Equal(got, baseline) {
				t.Fatal("reshare transcript digest did not bind mutated field")
			}
		})
	}
}

func TestFROSTReshareTranscriptCanonicalOrdering(t *testing.T) {
	t.Parallel()
	base := newFROSTReshareTranscriptFixture(t)
	want := base.digest()
	reordered := base.clone()
	reordered.oldParties = tss.NewPartySet(3, 2, 1)
	reordered.newParties = tss.NewPartySet(4, 3, 2)
	for left, right := 0, len(reordered.verificationShares)-1; left < right; left, right = left+1, right-1 {
		reordered.verificationShares[left], reordered.verificationShares[right] = reordered.verificationShares[right], reordered.verificationShares[left]
	}
	reverseDealerMap := make(map[tss.PartyID][][]byte, len(reordered.dealerCommitments))
	for _, party := range tss.NewPartySet(3, 2, 1) {
		reverseDealerMap[party] = reordered.dealerCommitments[party]
	}
	reordered.dealerCommitments = reverseDealerMap
	if got := reordered.digest(); !bytes.Equal(got, want) {
		t.Fatalf("canonical reordering changed reshare transcript: got %x want %x", got, want)
	}
}

func newFROSTReshareTranscriptFixture(t *testing.T) frostReshareTranscriptFixture {
	t.Helper()
	verificationShares := make([]VerificationShare, 0, 3)
	for _, party := range tss.NewPartySet(2, 3, 4) {
		verificationShares = append(verificationShares, VerificationShare{
			Party:     party,
			PublicKey: mustFROSTTranscriptVerificationSharePoint(t, int64(party)),
		})
	}
	return frostReshareTranscriptFixture{
		sessionID:    testutil.MustSessionID(901),
		oldParties:   tss.NewPartySet(1, 2, 3),
		newParties:   tss.NewPartySet(2, 3, 4),
		newThreshold: 2,
		oldPublicKey: bytes.Repeat([]byte{0x11}, 32),
		chainCode:    bytes.Repeat([]byte{0x22}, 32),
		planHash:     bytes.Repeat([]byte{0x33}, 32),
		dealerCommitments: map[tss.PartyID][][]byte{
			1: {bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32)},
			2: {bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32)},
			3: {bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32)},
		},
		newCommitments: [][]byte{
			bytes.Repeat([]byte{0x71}, 32),
			bytes.Repeat([]byte{0x72}, 32),
		},
		verificationShares: verificationShares,
	}
}

func mustFROSTTranscriptVerificationSharePoint(t *testing.T, scalar int64) VerificationSharePoint {
	t.Helper()
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(scalar))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := newVerificationSharePointFromPoint(point)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func (f frostReshareTranscriptFixture) digest() []byte {
	return frostReshareTranscriptHash(
		f.sessionID,
		f.oldParties,
		f.newParties,
		f.newThreshold,
		f.oldPublicKey,
		f.chainCode,
		f.planHash,
		f.refreshMode,
		f.dealerCommitments,
		f.newCommitments,
		f.verificationShares,
	)
}

func (f frostReshareTranscriptFixture) clone() frostReshareTranscriptFixture {
	out := f
	out.oldParties = f.oldParties.Clone()
	out.newParties = f.newParties.Clone()
	out.oldPublicKey = bytes.Clone(f.oldPublicKey)
	out.chainCode = bytes.Clone(f.chainCode)
	out.planHash = bytes.Clone(f.planHash)
	out.dealerCommitments = make(map[tss.PartyID][][]byte, len(f.dealerCommitments))
	for party, commitments := range f.dealerCommitments {
		out.dealerCommitments[party] = cloneFROSTTranscriptBytesList(commitments)
	}
	out.newCommitments = cloneFROSTTranscriptBytesList(f.newCommitments)
	out.verificationShares = make([]VerificationShare, len(f.verificationShares))
	for i, share := range f.verificationShares {
		out.verificationShares[i] = VerificationShare{Party: share.Party, PublicKey: share.PublicKey.Clone()}
	}
	return out
}

func cloneFROSTTranscriptBytesList(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = bytes.Clone(in[i])
	}
	return out
}
