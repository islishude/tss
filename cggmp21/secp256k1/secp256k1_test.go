package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestMain(m *testing.M) {
	restoreBits := SetDefaultPaillierBitsForTesting(768)
	restoreMin := pai.SetMinimumModulusBitsForTesting(512)
	restoreKeygenMin := SetMinKeygenPaillierBitsForTesting(768)
	restoreSign := SetAcceptExperimentalUsageForTesting(true)
	restoreSP := zkpai.SetSecurityParamsForTesting(zkpai.SecurityParams{
		Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 512,
	})
	code := m.Run()
	restoreBits()
	restoreMin()
	restoreKeygenMin()
	restoreSign()
	restoreSP()
	os.Exit(code)
}

func TestThresholdECDSASignScenarios(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int
		parties   int
		signers   []tss.PartyID
	}{
		{name: "1-of-1", threshold: 1, parties: 1, signers: []tss.PartyID{1}},
		{name: "2-of-3", threshold: 2, parties: 3, signers: []tss.PartyID{1, 3}},
		{name: "3-of-5", threshold: 3, parties: 5, signers: []tss.PartyID{1, 3, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := secpKeygen(t, tc.threshold, tc.parties)
			selected := make([]*KeyShare, 0, len(tc.signers))
			for _, id := range tc.signers {
				selected = append(selected, shares[id])
			}
			digest := sha256.Sum256([]byte("hello secp256k1"))
			pub, sig, err := SignDigest(digest[:], selected)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyDigest(pub, digest[:], sig) {
				t.Fatal("signature did not verify")
			}
		})
	}
}

func TestThresholdECDSASignerSubsets(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	for _, signers := range [][]tss.PartyID{{1, 2}, {1, 3}, {2, 3}} {
		selected := make([]*KeyShare, 0, len(signers))
		for _, id := range signers {
			selected = append(selected, shares[id])
		}
		digest := sha256.Sum256([]byte("subset"))
		pub, sig, err := SignDigest(digest[:], selected)
		if err != nil {
			t.Fatalf("signers %v: %v", signers, err)
		}
		if !VerifyDigest(pub, digest[:], sig) {
			t.Fatalf("signers %v: signature did not verify", signers)
		}
	}
}

func TestThresholdECDSAHDAdditiveShift(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 3, KeygenOptions{EnableHD: true})
	signers := []tss.PartyID{1, 2}
	path := []uint32{0, 17}
	derived, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testPresignContext()
	ctx.DerivationPath = path
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("hd additive shift"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSign(shares[id], presigns[id], signID, request)
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
			if _, err := sessions[id].HandleSignMessage(env); err != nil {
				t.Fatal(err)
			}
		}
	}
	sig, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	if !VerifySignature(derived, request, sig) {
		t.Fatal("shifted signature did not verify against derived key")
	}
	if VerifySignature(shares[1].PublicKey, request, sig) {
		t.Fatal("shifted signature verified against unshifted key")
	}
}

func TestThresholdECDSAKeygenHDChainCode(t *testing.T) {
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygenWithOptions(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: sessionID}, KeygenOptions{EnableHD: true})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		if len(share.ChainCode) != 32 {
			t.Fatalf("party %d missing chain code", id)
		}
	}
}

func TestThresholdECDSAPresignReuseRejected(t *testing.T) {
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

func TestThresholdECDSATamperedOnlinePartialFails(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	digest := sha256.Sum256([]byte("online tamper"))
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
	payload, err := unmarshalSignPartialPayload(messages[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.S = scalarBytes(bigOne())
	mutated, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	messages[0].Payload = mutated
	messages[0] = messages[0].WithTranscriptHash()
	delivered := false
	for _, id := range signers {
		if id == messages[0].From {
			continue
		}
		delivered = true
		if _, err := sessions[id].HandleSignMessage(messages[0]); err == nil {
			t.Fatal("expected tampered partial rejection")
		} else {
			_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[id], signers, presigns[id]))
		}
	}
	if !delivered {
		t.Fatal("tampered partial was not delivered")
	}
}

func TestThresholdECDSATamperedEncKBlamesSender(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload[0] ^= 1
	out2[0] = out2[0].WithTranscriptHash()
	if _, err := s1.HandlePresignMessage(out2[0]); err == nil {
		t.Fatal("expected tampered EncK rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
	}
}

func TestThresholdECDSATamperedRound2ProofBlamesSender(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*presignRound2Payload)
	}{
		{name: "delta", mutate: func(p *presignRound2Payload) { p.Delta.Proof[0] ^= 1 }},
		{name: "sigma", mutate: func(p *presignRound2Payload) { p.Sigma.Proof[0] ^= 1 }},
		{name: "echo", mutate: func(p *presignRound2Payload) { p.Round1Echo[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessionID, err := tss.NewSessionID(nil)
			if err != nil {
				t.Fatal(err)
			}
			s1, out1, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			s2, out2, err := StartPresign(shares[2], sessionID, []tss.PartyID{1, 2})
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
			if len(round2) != 1 || round2[0].To != 1 {
				t.Fatalf("unexpected round2 messages: %#v", round2)
			}
			mutated, err := mutatePresignRound2Payload(round2[0].Payload, tc.mutate)
			if err != nil {
				t.Fatal(err)
			}
			round2[0].Payload = mutated
			round2[0] = round2[0].WithTranscriptHash()
			_, err = s1.HandlePresignMessage(round2[0])
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
	shares := secpKeygen(t, 2, 3)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, _, err := StartPresign(shares[1], sessionID, []tss.PartyID{1, 2})
	if err != nil {
		t.Fatal(err)
	}
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
	out2[0] = out2[0].WithTranscriptHash()
	if _, err := s1.HandlePresignMessage(out2[0]); err == nil {
		t.Fatal("expected presign Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, secpEvidenceContext(shares[1], []tss.PartyID{1, 2}, nil))
	}
}

func TestThresholdECDSAKeygenPaillierPublicKeyMismatchRejected(t *testing.T) {
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
	payload, err := unmarshalKeygenCommitmentsPayload(out2[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.PaillierPublicKey, err = kg1.paillier.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	out2[0].Payload = mutated
	out2[0] = out2[0].WithTranscriptHash()
	if _, err := kg1.HandleKeygenMessage(out2[0]); err == nil {
		t.Fatal("expected keygen Paillier key mismatch rejection")
	} else {
		_ = assertBlameEvidence(t, err, EvidenceContext{Parties: parties})
	}
}

func TestThresholdECDSAStaticNoSecretShareRegression(t *testing.T) {
	body, err := os.ReadFile("sign.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{"SecretShare", "NonceShare", "InterpolateConstant"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sign.go still contains forbidden regression marker %q", forbidden)
		}
	}
}

func TestThresholdECDSAKeyShareRoundTrip(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	raw, err := shares[1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.PublicKey) != string(shares[1].PublicKey) {
		t.Fatal("public key mismatch after round trip")
	}
}

// secpKeygenWithoutConfirmation runs keygen without the confirmation exchange.
// Only use in tests that verify the confirmation step itself.
func secpKeygenWithoutConfirmation(t testing.TB, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		out[id] = share
	}
	return out
}

func secpKeygen(t testing.TB, threshold, n int) map[tss.PartyID]*KeyShare {
	t.Helper()
	session, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]tss.PartyID, n)
	for i := range parties {
		parties[i] = tss.PartyID(i + 1)
	}
	sessions := make(map[tss.PartyID]*KeygenSession, n)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		kg, out, err := StartKeygen(tss.ThresholdConfig{Threshold: threshold, Parties: parties, Self: id, SessionID: session})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
		}
	}
	out := make(map[tss.PartyID]*KeyShare, n)
	var pub []byte
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("keygen not complete for %d", id)
		}
		if pub == nil {
			pub = share.PublicKey
		} else if string(pub) != string(share.PublicKey) {
			t.Fatal("group public key mismatch")
		}
		out[id] = share
	}
	// Exchange and verify keygen confirmations.
	confirmations := make([]*KeygenConfirmation, n)
	for i, id := range parties {
		c, err := out[id].KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		confirmations[i] = c
	}
	for _, id := range parties {
		if err := VerifyKeygenConfirmations(out[id], confirmations); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func secpPresign(t testing.TB, shares map[tss.PartyID]*KeyShare, signers []tss.PartyID) map[tss.PartyID]*Presign {
	return secpPresignWithContext(t, shares, signers, testPresignContext())
}

func secpPresignWithContext(t testing.TB, shares map[tss.PartyID]*KeyShare, signers []tss.PartyID, ctx PresignContext) map[tss.PartyID]*Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	presignSessions := map[tss.PartyID]*PresignSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := StartPresignWithContext(shares[id], sessionID, signers, ctx)
		if err != nil {
			t.Fatal(err)
		}
		presignSessions[id] = session
		messages = append(messages, out...)
	}
	for len(messages) > 0 {
		env := messages[0]
		messages = messages[1:]
		for _, id := range signers {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].HandlePresignMessage(env)
			if err != nil {
				t.Fatal(err)
			}
			messages = append(messages, out...)
		}
	}
	out := make(map[tss.PartyID]*Presign, len(signers))
	for _, id := range signers {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			t.Fatalf("presign not complete for %d", id)
		}
		out[id] = presign
	}
	return out
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

func secpEvidenceContext(share *KeyShare, signers []tss.PartyID, presign *Presign) EvidenceContext {
	ctx := EvidenceContext{
		Parties:              append([]tss.PartyID(nil), share.Parties...),
		PublicKey:            append([]byte(nil), share.PublicKey...),
		PaillierPublicKeys:   append([]PaillierPublicShare(nil), share.PaillierPublicKeys...),
		Signers:              append([]tss.PartyID(nil), signers...),
		KeygenTranscriptHash: append([]byte(nil), share.KeygenTranscriptHash...),
	}
	if presign != nil {
		ctx.PresignTranscriptHash = append([]byte(nil), presign.TranscriptHash...)
	}
	return ctx
}

func assertBlameEvidence(t testing.TB, err error, ctx EvidenceContext) *tss.ProtocolError {
	t.Helper()
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if protocolErr.Blame == nil || len(protocolErr.Blame.Evidence) == 0 {
		t.Fatalf("missing blame evidence: %v", err)
	}
	if verifyErr := VerifyBlameEvidence(protocolErr.Blame.Evidence, ctx); verifyErr != nil {
		t.Fatalf("blame evidence did not verify: %v", verifyErr)
	}
	lower := strings.ToLower(string(protocolErr.Blame.Evidence))
	for _, forbidden := range []string{"secret", "nonce", "k_share", "chi_share", "paillier_private"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("evidence contains sensitive field marker %q: %s", forbidden, protocolErr.Blame.Evidence)
		}
	}
	decoded, err := tss.UnmarshalBlameEvidence(protocolErr.Blame.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Protocol = "wrong-protocol"
	mutated, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyBlameEvidence(mutated, ctx) == nil {
		t.Fatal("tampered blame evidence verified")
	}
	return protocolErr
}

// Proactive refresh tests

func TestThresholdECDSAProactiveRefresh1of1(t *testing.T) {
	shares := secpKeygen(t, 1, 1)
	oldPub := shares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := tss.ThresholdConfig{Threshold: 1, Self: 1, SessionID: sessionID}
	session, out, err := StartRefresh(shares[1], config)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range out {
		if _, err := session.HandleRefreshMessage(env); err != nil {
			if !strings.Contains(err.Error(), "already completed") {
				t.Fatal(err)
			}
		}
	}
	newShare, ok := session.KeyShare()
	if !ok {
		t.Fatal("refresh did not complete")
	}
	// Confirm the new share (self-confirm for 1-of-1).
	conf, err := newShare.KeygenConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeygenConfirmations(newShare, []*KeygenConfirmation{conf}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldPub, newShare.PublicKey) {
		t.Fatal("public key changed after refresh")
	}
	if !bytes.Equal(shares[1].ChainCode, newShare.ChainCode) {
		t.Fatal("chain code changed after refresh")
	}
	digest := sha256.Sum256([]byte("refresh 1-of-1"))
	pub, sig, err := SignDigest(digest[:], []*KeyShare{newShare})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after refresh did not verify")
	}
	if !bytes.Equal(oldPub, pub) {
		t.Fatal("public key from signing differs from original")
	}
}

func TestThresholdECDSARefreshInvalidShareCarriesEvidence(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	session, _, err := StartRefresh(shares[1], tss.ThresholdConfig{Threshold: 2, Self: 1, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartRefresh(shares[2], tss.ThresholdConfig{Threshold: 2, Self: 2, SessionID: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleRefreshMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalRefreshSharePayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	badShare := new(big.Int).SetBytes(payload.Share)
	badShare.Add(badShare, big.NewInt(1))
	badShare.Mod(badShare, secp.Order())
	if badShare.Sign() == 0 {
		badShare.SetInt64(1)
	}
	out2[1].Payload, err = marshalRefreshSharePayload(refreshSharePayload{Share: scalarBytes(badShare)})
	if err != nil {
		t.Fatal(err)
	}
	out2[1] = out2[1].WithTranscriptHash()
	_, err = session.HandleRefreshMessage(out2[1])
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSAReshareInvalidShareCarriesEvidence(t *testing.T) {
	shares := secpKeygen(t, 2, 2)
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	session, _, err := StartReshare(shares[1], tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sessionID}, parties)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := StartReshare(shares[2], tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sessionID}, parties)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleReshareMessage(out2[0]); err != nil {
		t.Fatal(err)
	}
	payload, err := unmarshalReshareSharePayload(out2[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	badShare := new(big.Int).SetBytes(payload.Share)
	badShare.Add(badShare, big.NewInt(1))
	badShare.Mod(badShare, secp.Order())
	if badShare.Sign() == 0 {
		badShare.SetInt64(1)
	}
	out2[1].Payload, err = marshalReshareSharePayload(reshareSharePayload{Share: scalarBytes(badShare)})
	if err != nil {
		t.Fatal(err)
	}
	out2[1] = out2[1].WithTranscriptHash()
	_, err = session.HandleReshareMessage(out2[1])
	_ = assertBlameEvidence(t, err, EvidenceContext{SessionID: sessionID, Parties: parties})
}

func TestThresholdECDSAProactiveRefresh2of3(t *testing.T) {
	shares := secpKeygen(t, 2, 3)
	oldPub := shares[1].PublicKeyBytes()

	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2, 3}
	sessions := make(map[tss.PartyID]*RefreshSession)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := StartRefresh(shares[id], tss.ThresholdConfig{Threshold: 2, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleRefreshMessage(env)
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	newShares := make(map[tss.PartyID]*KeyShare)
	for _, id := range parties {
		share, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("refresh not complete for %d", id)
		}
		newShares[id] = share
		if !bytes.Equal(oldPub, share.PublicKey) {
			t.Fatalf("party %d public key changed after refresh", id)
		}
	}
	// Exchange and verify keygen confirmations for refreshed shares.
	refreshConfirmations := make([]*KeygenConfirmation, len(parties))
	for i, id := range parties {
		c, err := newShares[id].KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		refreshConfirmations[i] = c
	}
	for _, id := range parties {
		if err := VerifyKeygenConfirmations(newShares[id], refreshConfirmations); err != nil {
			t.Fatal(err)
		}
	}
	signers := []*KeyShare{newShares[1], newShares[3]}
	digest := sha256.Sum256([]byte("refresh 2-of-3"))
	pub, sig, err := SignDigest(digest[:], signers)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after refresh did not verify")
	}
}

func TestThresholdECDSAProactiveRefreshPreservesChainCode(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 2, KeygenOptions{EnableHD: true})
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2}
	sessions := make(map[tss.PartyID]*RefreshSession)
	queue := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := StartRefresh(shares[id], tss.ThresholdConfig{Threshold: 2, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		queue = append(queue, out...)
	}
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleRefreshMessage(env)
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	for _, id := range parties {
		newShare, ok := sessions[id].KeyShare()
		if !ok {
			t.Fatalf("refresh not complete for %d", id)
		}
		if len(newShare.ChainCode) != 32 {
			t.Fatalf("party %d missing chain code after refresh", id)
		}
		if !bytes.Equal(shares[id].ChainCode, newShare.ChainCode) {
			t.Fatalf("party %d chain code changed after refresh", id)
		}
	}
	// Confirm refreshed shares.
	hdRefreshConfirmations := make([]*KeygenConfirmation, len(parties))
	for i, id := range parties {
		c, err := sessions[id].newShare.KeygenConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		hdRefreshConfirmations[i] = c
	}
	for _, id := range parties {
		if err := VerifyKeygenConfirmations(sessions[id].newShare, hdRefreshConfirmations); err != nil {
			t.Fatal(err)
		}
	}
	signers := []*KeyShare{sessions[1].newShare, sessions[2].newShare}
	digest := sha256.Sum256([]byte("hd refresh"))
	pub, sig, err := SignDigest(digest[:], signers)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(pub, digest[:], sig) {
		t.Fatal("signature after HD refresh did not verify")
	}
}

// BIP32 derivation tests

func TestBIP32SingleLevel(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	pubKey := shares[1].PublicKey
	chainCode := shares[1].ChainCode

	childPub, shift, childChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(childPub) != 33 {
		t.Fatal("child public key must be 33 bytes")
	}
	if len(shift) != 32 {
		t.Fatal("additive shift must be 32 bytes")
	}
	if len(childChain) != 32 {
		t.Fatal("child chain code must be 32 bytes")
	}
	derived, err := DerivePublicKey(pubKey, shift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, childPub) {
		t.Fatal("DeriveBIP32 and DerivePublicKey mismatch")
	}
}

func TestBIP32MultiLevel(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	pubKey := shares[1].PublicKey
	chainCode := shares[1].ChainCode

	childPub, shift, childChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(childPub) != 33 {
		t.Fatal("child public key must be 33 bytes")
	}
	if len(shift) != 32 {
		t.Fatal("additive shift must be 32 bytes")
	}
	if len(childChain) != 32 {
		t.Fatal("child chain code must be 32 bytes")
	}
	// Two-step cumulative should produce consistent chain code with direct.
	_, _, midChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	_, _, finalChain, err := DeriveBIP32(pubKey, chainCode, []uint32{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(childChain, finalChain) {
		t.Fatal("multi-level chain code mismatch")
	}
	_ = midChain
	derived, err := DerivePublicKey(pubKey, shift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, childPub) {
		t.Fatal("DeriveBIP32 and DerivePublicKey mismatch for multi-level")
	}
}

func TestBIP32DeriveAndSign(t *testing.T) {
	shares := secpKeygenWithOptions(t, 2, 3, KeygenOptions{EnableHD: true})
	path := []uint32{0, 5}
	childPub, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, path)
	if err != nil {
		t.Fatal(err)
	}
	signers := []tss.PartyID{1, 2}
	ctx := testPresignContext()
	ctx.DerivationPath = path
	presigns := secpPresignWithContext(t, shares, signers, ctx)
	request := SignRequest{Context: ctx, Message: []byte("bip32 derived signing"), LowS: true}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession)
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSign(shares[id], presigns[id], signID, request)
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
			if _, err := sessions[id].HandleSignMessage(env); err != nil {
				t.Fatal(err)
			}
		}
	}
	sig, ok := sessions[1].Signature()
	if !ok {
		t.Fatal("signature not completed")
	}
	if !VerifySignature(childPub, request, sig) {
		t.Fatal("signature did not verify against derived BIP32 key")
	}
	if VerifySignature(shares[1].PublicKey, request, sig) {
		t.Fatal("signature verified against master key (should use derived key)")
	}
}

func TestBIP32RejectsHardened(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	_, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{HardenedKeyStart})
	if err == nil {
		t.Fatal("expected error for hardened index")
	}
	_, _, _, err = DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{0, HardenedKeyStart + 1})
	if err == nil {
		t.Fatal("expected error for hardened index in path")
	}
}

func TestBIP32RejectsEmptyChainCode(t *testing.T) {
	shares := secpKeygen(t, 1, 1)
	if len(shares[1].ChainCode) > 0 {
		t.Skip("unexpected chain code with HD disabled")
	}
	_, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{0})
	if err == nil {
		t.Fatal("expected error for empty chain code")
	}
}

func TestBIP32RejectsEmptyPath(t *testing.T) {
	shares := secpKeygenWithOptions(t, 1, 1, KeygenOptions{EnableHD: true})
	_, _, _, err := DeriveBIP32(shares[1].PublicKey, shares[1].ChainCode, []uint32{})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestThresholdECDSA_PresignRoundTrip(t *testing.T) {
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
