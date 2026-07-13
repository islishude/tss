//go:build tier1

package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
)

func TestTier1_CGGMP21_Presign_Figure9ProofsAreComplete(t *testing.T) {
	for _, kind := range []presignRedAlertKind{presignRedAlertNonce, presignRedAlertChi} {
		t.Run(string(kind), func(t *testing.T) {
			s1, s2 := figure9ReadyPresignSessions(t)
			p1 := mustPrepareFigure9(t, s1, kind)
			defer p1.destroy()
			p2 := mustPrepareFigure9(t, s2, kind)
			defer p2.destroy()

			if !bytes.Equal(p1.alert, p2.alert) {
				t.Fatal("honest parties derived different Figure 9 alert digests")
			}
			for _, test := range []struct {
				name     string
				verifier *PresignSession
				accused  tss.PartyID
				payload  presignRedAlertPayload
				wantPeer tss.PartyID
			}{
				{name: "party1_verifies_party2", verifier: s1, accused: 2, payload: p2.payload, wantPeer: 1},
				{name: "party2_verifies_party1", verifier: s2, accused: 1, payload: p1.payload, wantPeer: 2},
			} {
				t.Run(test.name, func(t *testing.T) {
					if len(test.payload.Pairs) != 1 || test.payload.Pairs[0].Peer != test.wantPeer {
						t.Fatalf("Figure 9 peer set = %+v, want exactly %d", test.payload.Pairs, test.wantPeer)
					}
					if err := test.payload.Pairs[0].Proof.Validate(); err != nil {
						t.Fatalf("invalid Figure 9 affine proof record: %v", err)
					}
					if err := test.payload.DecProof.Validate(); err != nil {
						t.Fatalf("invalid Figure 9 decryption proof record: %v", err)
					}
					if err := test.verifier.verifyFigure9Payload(test.accused, test.payload); err != nil {
						t.Fatalf("verify complete Figure 9 payload: %v", err)
					}
				})
			}
		})
	}
}

func TestTier1_CGGMP21_Presign_Figure9MutationsAreRejected(t *testing.T) {
	for _, kind := range []presignRedAlertKind{presignRedAlertNonce, presignRedAlertChi} {
		t.Run(string(kind), func(t *testing.T) {
			s1, s2 := figure9ReadyPresignSessions(t)
			prepared := mustPrepareFigure9(t, s2, kind)
			defer prepared.destroy()

			tests := []struct {
				name   string
				mutate func(*presignRedAlertPayload)
			}{
				{name: "alert_digest", mutate: func(p *presignRedAlertPayload) { p.AlertDigest[0] ^= 1 }},
				{name: "peer", mutate: func(p *presignRedAlertPayload) { p.Pairs[0].Peer = 3 }},
				{name: "inbound_ciphertext", mutate: func(p *presignRedAlertPayload) {
					p.Pairs[0].Inbound.Ciphertext[len(p.Pairs[0].Inbound.Ciphertext)-1] ^= 1
				}},
				{name: "outbound_ciphertext", mutate: func(p *presignRedAlertPayload) {
					p.Pairs[0].Outbound.Ciphertext[len(p.Pairs[0].Outbound.Ciphertext)-1] ^= 1
				}},
				{name: "affine_proof", mutate: func(p *presignRedAlertPayload) { p.Pairs[0].Proof.TranscriptHash[0] ^= 1 }},
				{name: "decryption_proof", mutate: func(p *presignRedAlertPayload) { p.DecProof.TranscriptHash[0] ^= 1 }},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					payload := prepared.payload.Clone()
					defer payload.Destroy()
					test.mutate(&payload)
					if err := s1.verifyFigure9Payload(s2.key.state.Party, payload); err == nil {
						t.Fatal("mutated Figure 9 payload verified")
					}
				})
			}
		})
	}
}

func TestTier1_CGGMP21_Presign_InvalidFigure9ProofBlamesOnlyDirectSender(t *testing.T) {
	for _, kind := range []presignRedAlertKind{presignRedAlertNonce, presignRedAlertChi} {
		t.Run(string(kind), func(t *testing.T) {
			s1, s2 := figure9ReadyPresignSessions(t)
			receiver := mustPrepareFigure9(t, s1, kind)
			defer receiver.destroy()
			s1.commitPresignRedAlert(receiver)

			sender := mustPrepareFigure9(t, s2, kind)
			defer sender.destroy()
			mutated := sender.payload.Clone()
			defer mutated.Destroy()
			mutated.DecProof.TranscriptHash[0] ^= 1
			env := mustFigure9Envelope(t, s2, mutated)

			out, err := s1.Handle(testutil.DeliverEnvelope(env))
			if len(out) != 0 {
				t.Fatalf("invalid Figure 9 proof emitted %d envelopes", len(out))
			}
			protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
			if protocolErr.Blame == nil || len(protocolErr.Blame.Parties) != 1 || protocolErr.Blame.Parties[0] != s2.key.state.Party {
				t.Fatalf("Figure 9 blame = %#v, want only direct sender %d", protocolErr.Blame, s2.key.state.Party)
			}
			if !s1.aborted || s1.identifying || s1.kShare != nil || s1.gamma != nil || s1.xBar != nil || s1.paillier != nil || s1.redAlertPayloads != nil {
				t.Fatal("attributed Figure 9 abort did not destroy retained secret state")
			}
		})
	}
}

func TestTier1_CGGMP21_Presign_AllValidFigure9ProofsAbortWithoutBlame(t *testing.T) {
	s1, s2 := figure9ReadyPresignSessions(t)
	receiver := mustPrepareFigure9(t, s1, presignRedAlertChi)
	defer receiver.destroy()
	sender := mustPrepareFigure9(t, s2, presignRedAlertChi)
	defer sender.destroy()

	// An otherwise valid Figure 9 envelope received before the red-alert phase is
	// active must not reserve its replay slot or abort the presign.
	out, err := s1.Handle(testutil.DeliverEnvelope(sender.envelope))
	if len(out) != 0 {
		t.Fatalf("early Figure 9 envelope emitted %d envelopes", len(out))
	}
	early := testutil.AssertProtocolError(t, err, tss.ErrCodeRound)
	if early.Blame != nil || s1.aborted || s1.identifying {
		t.Fatalf("early Figure 9 delivery mutated terminal state: blame=%#v aborted=%v identifying=%v", early.Blame, s1.aborted, s1.identifying)
	}

	s1.commitPresignRedAlert(receiver)
	out, err = s1.Handle(testutil.DeliverEnvelope(sender.envelope))
	if len(out) != 0 {
		t.Fatalf("all-valid Figure 9 fallback emitted %d envelopes", len(out))
	}
	terminal := testutil.AssertProtocolError(t, err, tss.ErrCodeInvariant)
	if terminal.Blame != nil {
		t.Fatalf("all-valid Figure 9 fallback blamed an honest sender: %#v", terminal.Blame)
	}
	if !s1.aborted || s1.identifying || s1.kShare != nil || s1.gamma != nil || s1.xBar != nil || s1.paillier != nil || s1.redAlertPayloads != nil {
		t.Fatal("all-valid Figure 9 fallback did not destroy retained secret state")
	}
}

func TestTier1_CGGMP21_Presign_LocalZeroDeltaAndChiRemainValid(t *testing.T) {
	s1, _ := figure9ReadyPresignSessions(t)
	self, ok := s1.partyState(s1.key.state.Party)
	if !ok {
		t.Fatal("missing local Figure 8 state")
	}
	var peer *presignPartyState
	for _, party := range s1.signers {
		if party == s1.key.state.Party {
			continue
		}
		peer, ok = s1.partyState(party)
		if !ok {
			t.Fatalf("missing peer Figure 8 state for party %d", party)
		}
		break
	}
	if peer == nil {
		t.Fatal("missing peer Figure 8 state")
	}
	selfDelta, err := secpScalarFromSecretAllowZero(self.round3.delta)
	if err != nil {
		t.Fatal(err)
	}
	peerDelta, err := secpScalarFromSecretAllowZero(peer.round3.delta)
	if err != nil {
		t.Fatal(err)
	}
	aggregateDelta := secp.ScalarAdd(selfDelta, peerDelta)
	if aggregateDelta.IsZero() {
		t.Fatal("honest Figure 8 fixture has zero aggregate delta")
	}
	selfS, err := decodePresignGroupElement(self.round3.sPoint)
	if err != nil {
		t.Fatal(err)
	}
	peerS, err := decodePresignGroupElement(peer.round3.sPoint)
	if err != nil {
		t.Fatal(err)
	}
	aggregateS := secp.Add(selfS, peerS)
	peerSBytes, err := encodePresignGroupElement(aggregateS)
	if err != nil {
		t.Fatal(err)
	}

	self.round3.delta.Destroy()
	self.round3.delta, err = secpSecretScalarFromScalarAllowZero(secp.ScalarZero())
	if err != nil {
		t.Fatal(err)
	}
	peer.round3.delta.Destroy()
	peer.round3.delta, err = secpSecretScalarFromScalarAllowZero(aggregateDelta)
	if err != nil {
		t.Fatal(err)
	}
	self.round3.chi.Destroy()
	self.round3.chi, err = secpSecretScalarFromScalarAllowZero(secp.ScalarZero())
	if err != nil {
		t.Fatal(err)
	}
	clear(self.round3.sPoint)
	self.round3.sPoint = nil
	clear(peer.round3.sPoint)
	peer.round3.sPoint = peerSBytes

	prepared, ready, err := s1.maybePreparePresignCompletion()
	if err != nil || !ready || prepared == nil || prepared.presign == nil {
		t.Fatalf("local zero Figure 8 shares did not produce a normalized presign: ready=%v err=%v", ready, err)
	}
	defer prepared.destroy()
	chi, err := secpScalarFromSecretAllowZero(prepared.presign.state.ChiShare)
	if err != nil {
		t.Fatal(err)
	}
	if !chi.IsZero() {
		t.Fatal("local zero chi was not preserved through normalization")
	}
	if err := prepared.presign.VerifyCryptographicMaterialWithLimits(testLimits()); err != nil {
		t.Fatalf("normalized presign with local zero shares failed cryptographic validation: %v", err)
	}
}

func TestTier1_CGGMP21_Presign_AggregateZeroDeltaIsUnattributed(t *testing.T) {
	s1, _ := figure9ReadyPresignSessions(t)
	self, ok := s1.partyState(s1.key.state.Party)
	if !ok {
		t.Fatal("missing local Figure 8 state")
	}
	selfDelta, err := secpScalarFromSecretAllowZero(self.round3.delta)
	if err != nil {
		t.Fatal(err)
	}
	var peer *presignPartyState
	for _, party := range s1.signers {
		if party == s1.key.state.Party {
			continue
		}
		peer, ok = s1.partyState(party)
		if !ok {
			t.Fatalf("missing peer Figure 8 state for party %d", party)
		}
		break
	}
	if peer == nil {
		t.Fatal("missing peer Figure 8 state")
	}
	peer.round3.delta.Destroy()
	peer.round3.delta, err = secpSecretScalarFromScalarAllowZero(secp.ScalarNeg(selfDelta))
	if err != nil {
		t.Fatal(err)
	}

	prepared, ready, err := s1.preparePresignCompletionEffects()
	if prepared != nil {
		defer prepared.destroy()
	}
	if err == nil || ready {
		t.Fatalf("zero aggregate delta completion ready=%v err=%v", ready, err)
	}
	var redAlert *presignRedAlertError
	if errors.As(err, &redAlert) {
		t.Fatalf("zero aggregate delta incorrectly entered attributed Figure 9 kind %s", redAlert.kind)
	}
	if s1.identifying || s1.redAlertKind != "" || len(s1.redAlertPayloads) != 0 {
		t.Fatal("zero aggregate delta mutated Figure 9 attribution state")
	}
}

func figure9ReadyPresignSessions(t *testing.T) (*PresignSession, *PresignSession) {
	t.Helper()
	s1, s2, round3From1, round3From2 := presignSessionsWithRound3Outputs(t)
	t.Cleanup(func() {
		s1.Destroy()
		s2.Destroy()
	})

	tx2, err := s1.buildAcceptPresignRound3Tx(round3From2)
	if err != nil {
		t.Fatalf("verify party 2 Figure 8 round3: %v", err)
	}
	installPresignRound3Tx(t, s1, tx2)
	tx1, err := s2.buildAcceptPresignRound3Tx(round3From1)
	if err != nil {
		t.Fatalf("verify party 1 Figure 8 round3: %v", err)
	}
	installPresignRound3Tx(t, s2, tx1)
	if !s1.allRound3Accepted() || !s2.allRound3Accepted() {
		t.Fatal("Figure 9 test setup is missing Figure 8 round3 broadcasts")
	}
	return s1, s2
}

func mustPrepareFigure9(t *testing.T, session *PresignSession, kind presignRedAlertKind) *preparedPresignRedAlert {
	t.Helper()
	prepared, err := session.preparePresignRedAlert(kind)
	if err != nil {
		t.Fatalf("prepare Figure 9 %s proof: %v", kind, err)
	}
	return prepared
}

func mustFigure9Envelope(t *testing.T, sender *PresignSession, payload presignRedAlertPayload) tss.Envelope {
	t.Helper()
	raw, err := payload.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal Figure 9 payload: %v", err)
	}
	defer clear(raw)
	env, err := newFigure9Envelope(sender.config, sender.key.state.Party, raw)
	if err != nil {
		t.Fatalf("build Figure 9 envelope: %v", err)
	}
	return env
}
