package secp256k1

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21KeygenPlanDigestBindsGlobalIntentAndCopies(t *testing.T) {
	t.Parallel()

	sessionID := cggmpPlanTestSession(0x41)
	parties := []tss.PartyID{3, 1, 2}
	bits := defaultPaillierBits()
	plan, err := NewKeygenPlanWithPaillierBits(sessionID, parties, 2, false, bits)
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewKeygenPlanWithPaillierBits(sessionID, []tss.PartyID{1, 2, 3}, 2, false, bits)
	if err != nil {
		t.Fatal(err)
	}
	assertSameCGGMPPlanDigest(t, plan, same)

	parties[0] = 99
	gotParties := plan.Parties()
	gotParties[0] = 99
	if !bytes.Equal(cggmpPartyIDsBytes(plan.Parties()), cggmpPartyIDsBytes([]tss.PartyID{1, 2, 3})) {
		t.Fatal("keygen plan party getter or constructor aliases caller memory")
	}
	if plan.PaillierBits() != bits {
		t.Fatalf("PaillierBits() = %d, want %d", plan.PaillierBits(), bits)
	}

	for name, other := range map[string]*KeygenPlan{
		"threshold": mustCGGMPKeygenPlan(t, sessionID, []tss.PartyID{1, 2, 3}, 3, false, bits),
		"hd":        mustCGGMPKeygenPlan(t, sessionID, []tss.PartyID{1, 2, 3}, 2, true, bits),
		"paillier":  mustCGGMPKeygenPlan(t, sessionID, []tss.PartyID{1, 2, 3}, 2, false, bits+64),
		"session":   mustCGGMPKeygenPlan(t, cggmpPlanTestSession(0x42), []tss.PartyID{1, 2, 3}, 2, false, bits),
	} {
		assertDifferentCGGMPPlanDigest(t, name, plan, other)
	}
	if _, err := NewKeygenPlanWithPaillierBits(sessionID, []tss.PartyID{1, 2}, 3, false, bits); err == nil {
		t.Fatal("keygen plan accepted threshold greater than party count")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
	if _, err := NewKeygenPlanWithPaillierBits(sessionID, []tss.PartyID{1, 2}, 2, false, bits-1); err == nil {
		t.Fatal("keygen plan accepted undersized Paillier modulus")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
}

func TestCGGMP21SignPlanDigestBindsEffectiveDurableTimeout(t *testing.T) {
	t.Parallel()

	newPlan := func(timeout time.Duration) *SignPlan {
		return &SignPlan{state: &signPlanState{
			sessionID:         cggmpPlanTestSession(0x54),
			presignTranscript: bytes.Repeat([]byte{0x11}, 32),
			contextHash:       bytes.Repeat([]byte{0x22}, 32),
			digest:            bytes.Repeat([]byte{0x33}, 32),
			request: SignRequest{
				AttemptStore:        newTestSignAttemptStore(),
				DurableStoreTimeout: timeout,
			},
		}}
	}

	assertSameCGGMPPlanDigest(t, newPlan(0), newPlan(DefaultSignAttemptStoreTimeout))
	assertDifferentCGGMPPlanDigest(t, "sub-millisecond durable timeout", newPlan(1200*time.Microsecond), newPlan(1900*time.Microsecond))
}

func TestCGGMP21SignPlanMismatchDoesNotAbortSession(t *testing.T) {
	t.Parallel()

	s := &SignSession{
		presign: &Presign{state: &presignState{
			signers:        []tss.PartyID{1, 2},
			transcriptHash: bytes.Repeat([]byte{0x41}, 32),
			contextHash:    bytes.Repeat([]byte{0x42}, 32),
		}},
		planHash: bytes.Repeat([]byte{0x43}, 32),
	}
	_, err := s.verifySignPartial(2, signPartialPayload{
		PresignTranscript: bytes.Repeat([]byte{0x41}, 32),
		PresignContext:    bytes.Repeat([]byte{0x42}, 32),
		PlanHash:          bytes.Repeat([]byte{0x44}, 32),
	})
	if !errors.Is(err, errPlanHashMismatch) {
		t.Fatalf("verifySignPartial() error = %v, want plan mismatch sentinel", err)
	}
	if shouldAbortSession(tss.NewProtocolError(tss.ErrCodeVerification, 1, 2, err)) {
		t.Fatal("plan mismatch would abort sign session")
	}
}

func TestCGGMP21EarlyConfirmationPlanMismatchDoesNotMutate(t *testing.T) {
	t.Parallel()

	sessionID := cggmpPlanTestSession(0x55)
	wantPlanHash := bytes.Repeat([]byte{0x71}, 32)
	confirmation := &KeygenConfirmation{
		SessionID:       sessionID,
		Sender:          2,
		Threshold:       2,
		Parties:         []tss.PartyID{1, 2},
		PublicKey:       []byte{0x02},
		TranscriptHash:  bytes.Repeat([]byte{0x72}, 32),
		CommitmentsHash: bytes.Repeat([]byte{0x73}, 32),
		PlanHash:        bytes.Repeat([]byte{0x74}, 32),
	}
	payload, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	s := &KeygenSession{
		cfg:            tss.ThresholdConfig{SessionID: sessionID},
		planHash:       wantPlanHash,
		confirmations:  make(map[tss.PartyID][]byte),
		chainCodes:     make(map[tss.PartyID][]byte),
		chainCodeComms: make(map[tss.PartyID][]byte),
	}
	_, err = s.handleKeygenConfirmation(tss.Envelope{
		Round:   keygenConfirmationRound,
		From:    confirmation.Sender,
		Payload: payload,
	})
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if !errors.Is(protocolErr.Err, errPlanHashMismatch) {
		t.Fatalf("confirmation error = %v, want plan mismatch sentinel", protocolErr.Err)
	}
	if len(s.confirmations) != 0 || len(s.chainCodes) != 0 {
		t.Fatal("early confirmation plan mismatch mutated keygen state")
	}
	if shouldAbortSession(err) {
		t.Fatal("early confirmation plan mismatch would abort keygen session")
	}
}

func TestCGGMP21LifecyclePlanGettersReturnCopies(t *testing.T) {
	t.Parallel()

	refresh := &RefreshPlan{state: &refreshPlanState{
		sessionID:    cggmpPlanTestSession(0x51),
		threshold:    2,
		parties:      []tss.PartyID{1, 2, 3},
		publicKey:    []byte{0x02, 0x01},
		chainCode:    []byte{0x03, 0x04},
		paillierBits: defaultPaillierBits(),
	}}
	refreshParties := refresh.Parties()
	refreshParties[0] = 99
	refreshPublic := refresh.PublicKeyBytes()
	refreshPublic[0] ^= 0xff
	refreshChain := refresh.ChainCodeBytes()
	refreshChain[0] ^= 0xff
	if refresh.state.parties[0] != 1 || refresh.state.publicKey[0] != 0x02 || refresh.state.chainCode[0] != 0x03 {
		t.Fatal("refresh plan getter aliases internal state")
	}

	presign := &PresignPlan{state: &presignPlanState{
		sessionID:     cggmpPlanTestSession(0x52),
		threshold:     2,
		parties:       []tss.PartyID{1, 2, 3},
		publicKey:     []byte{0x02, 0x02},
		keygenHash:    []byte{0x10, 0x11},
		signers:       []tss.PartyID{1, 2},
		context:       PresignContext{KeyID: "key", ChainID: "chain", PolicyDomain: "policy", MessageDomain: "message", DerivationPath: []uint32{1, 2}},
		contextHash:   []byte{0x20, 0x21},
		additiveShift: []byte{0x30, 0x31},
	}}
	presignParties := presign.Parties()
	presignParties[0] = 99
	presignPublic := presign.PublicKeyBytes()
	presignPublic[0] ^= 0xff
	presignKeygen := presign.KeygenTranscriptHashBytes()
	presignKeygen[0] ^= 0xff
	presignSigners := presign.Signers()
	presignSigners[0] = 99
	presignContext := presign.Context()
	presignContext.DerivationPath[0] = 99
	presignContextHash := presign.ContextHashBytes()
	presignContextHash[0] ^= 0xff
	presignShift := presign.AdditiveShiftBytes()
	presignShift[0] ^= 0xff
	if presign.state.parties[0] != 1 ||
		presign.state.publicKey[0] != 0x02 ||
		presign.state.keygenHash[0] != 0x10 ||
		presign.state.signers[0] != 1 ||
		presign.state.context.DerivationPath[0] != 1 ||
		presign.state.contextHash[0] != 0x20 ||
		presign.state.additiveShift[0] != 0x30 {
		t.Fatal("presign plan getter aliases internal state")
	}

	sign := &SignPlan{state: &signPlanState{
		sessionID:         cggmpPlanTestSession(0x53),
		presignID:         []byte{0x40, 0x41},
		presignTranscript: []byte{0x45, 0x46},
		contextHash:       []byte{0x50, 0x51},
		digest:            []byte{0x60, 0x61},
		request:           SignRequest{Context: PresignContext{DerivationPath: []uint32{3, 4}}, Message: []byte("message")},
	}}
	presignID := sign.PresignIDBytes()
	presignID[0] ^= 0xff
	presignTranscript := sign.PresignTranscriptHashBytes()
	presignTranscript[0] ^= 0xff
	contextHash := sign.ContextHashBytes()
	contextHash[0] ^= 0xff
	digest := sign.MessageDigestBytes()
	digest[0] ^= 0xff
	request := sign.Request()
	request.Message[0] ^= 0xff
	request.Context.DerivationPath[0] = 99
	if sign.state.presignID[0] != 0x40 ||
		sign.state.presignTranscript[0] != 0x45 ||
		sign.state.contextHash[0] != 0x50 ||
		sign.state.digest[0] != 0x60 ||
		sign.state.request.Message[0] != 'm' ||
		sign.state.request.Context.DerivationPath[0] != 3 {
		t.Fatal("sign plan getter aliases internal state")
	}
}

type cggmpDigestPlan interface {
	Digest() ([]byte, error)
}

func assertSameCGGMPPlanDigest(t *testing.T, a, b cggmpDigestPlan) {
	t.Helper()
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(da, db) {
		t.Fatal("plan digests differ")
	}
}

func assertDifferentCGGMPPlanDigest(t *testing.T, name string, a, b cggmpDigestPlan) {
	t.Helper()
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(da, db) {
		t.Fatalf("plan digest did not bind %s", name)
	}
}

func mustCGGMPKeygenPlan(t *testing.T, sessionID tss.SessionID, parties []tss.PartyID, threshold int, enableHD bool, paillierBits int) *KeygenPlan {
	t.Helper()
	plan, err := NewKeygenPlanWithPaillierBits(sessionID, parties, threshold, enableHD, paillierBits)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func cggmpPlanTestSession(fill byte) tss.SessionID {
	var sessionID tss.SessionID
	for i := range sessionID {
		sessionID[i] = fill
	}
	return sessionID
}

func cggmpPartyIDsBytes(parties []tss.PartyID) []byte {
	out := make([]byte, 0, len(parties)*4)
	for _, id := range parties {
		out = append(out, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	return out
}
