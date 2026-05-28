package secp256k1

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
)

func TestMain(m *testing.M) {
	restoreBits := SetDefaultPaillierBitsForTesting(768)
	restoreMin := pai.SetMinimumModulusBitsForTesting(512)
	code := m.Run()
	restoreBits()
	restoreMin()
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
	shares := secpKeygen(t, 2, 3)
	signers := []tss.PartyID{1, 2}
	presigns := secpPresign(t, shares, signers)
	shift := scalarBytes(big.NewInt(17))
	derived, err := DerivePublicKey(shares[1].PublicKey, shift)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hd additive shift"))
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[tss.PartyID]*SignSession, len(signers))
	messages := make([]tss.Envelope, 0, len(signers))
	for _, id := range signers {
		session, out, err := StartSignDigestWithOptions(shares[id], presigns[id], signID, digest[:], SignOptions{LowS: true, AdditiveShift: shift})
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
	if !VerifyDigest(derived, digest[:], sig) {
		t.Fatal("shifted signature did not verify against derived key")
	}
	if VerifyDigest(shares[1].PublicKey, digest[:], sig) {
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
	return out
}

func secpPresign(t testing.TB, shares map[tss.PartyID]*KeyShare, signers []tss.PartyID) map[tss.PartyID]*Presign {
	t.Helper()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	presignSessions := map[tss.PartyID]*PresignSession{}
	messages := make([]tss.Envelope, 0)
	for _, id := range signers {
		session, out, err := StartPresign(shares[id], sessionID, signers)
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
