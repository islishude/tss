package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

func TestCGGMP21KeygenPlanDigestBindsGlobalIntentAndCopies(t *testing.T) {
	t.Parallel()

	sessionID := cggmpPlanTestSession(0x41)
	parties := tss.NewPartySet(3, 1, 2)
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: parties, Threshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSameCGGMPPlanDigest(t, plan, same)

	parties[0] = 99
	snapshot, ok := plan.Snapshot()
	if !ok {
		t.Fatal("missing keygen plan snapshot")
	}
	gotParties := snapshot.Parties
	gotParties[0] = 99
	again, ok := plan.Snapshot()
	if !ok {
		t.Fatal("missing keygen plan snapshot")
	}
	if !bytes.Equal(cggmpPartyIDsBytes(again.Parties), cggmpPartyIDsBytes(tss.NewPartySet(1, 2, 3))) {
		t.Fatal("keygen plan snapshot or constructor aliases caller memory")
	}
	localLimits := DefaultLimits()
	localLimits.Payload.MaxMessageBytes--
	withLocalLimits, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
		Limits: &localLimits,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSameCGGMPPlanDigest(t, plan, withLocalLimits)

	for name, other := range map[string]*KeygenPlan{
		"threshold": mustCGGMPKeygenPlan(t, sessionID, tss.NewPartySet(1, 2, 3), 3),
		"session":   mustCGGMPKeygenPlan(t, cggmpPlanTestSession(0x42), tss.NewPartySet(1, 2, 3), 2),
	} {
		assertDifferentCGGMPPlanDigest(t, name, plan, other)
	}
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2), Threshold: 3,
	}); err == nil {
		t.Fatal("keygen plan accepted threshold greater than party count")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
	strictLimits := DefaultLimits()
	strictLimits.Threshold.MaxParties = 2
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2, 3), Threshold: 2,
		Limits: &strictLimits,
	}); err == nil {
		t.Fatal("keygen plan ignored local party limit")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
	strictLimits = DefaultLimits()
	strictLimits.Paillier.MaxModulusBits = int(DefaultSecurityParams().MinPaillierBits) - 1
	if _, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID, Parties: tss.NewPartySet(1, 2), Threshold: 2,
		Limits: &strictLimits,
	}); err == nil {
		t.Fatal("keygen plan ignored local Paillier modulus limit")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
}

func TestCGGMP21KeygenPlanZeroValueIsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := new(KeygenPlan).Digest(); err == nil {
		t.Fatal("zero-value keygen plan produced a digest")
	}
	if _, _, err := StartKeygen(nil, tss.LocalConfig{Self: 1}, nil); err == nil {
		t.Fatal("nil keygen plan started a session")
	} else {
		_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
	}
}

func TestCGGMP21SignPlanDigestExcludesRuntimeDependencies(t *testing.T) {
	t.Parallel()

	newPlan := func(signers tss.PartySet) *SignPlan {
		return &SignPlan{state: &signPlanState{
			sessionID:         cggmpPlanTestSession(0x54),
			presignTranscript: bytes.Repeat([]byte{0x11}, 32),
			contextHash:       bytes.Repeat([]byte{0x22}, 32),
			signers:           signers.Clone(),
			digest:            bytes.Repeat([]byte{0x33}, 32),
		}}
	}

	assertSameCGGMPPlanDigest(t, newPlan(tss.NewPartySet(1, 2)), newPlan(tss.NewPartySet(1, 2)))
	assertDifferentCGGMPPlanDigest(t, "signer set", newPlan(tss.NewPartySet(1, 2)), newPlan(tss.NewPartySet(1, 3)))
}

func TestCGGMP21SignPlanMismatchDoesNotAbortSession(t *testing.T) {
	t.Parallel()

	s := &SignSession{
		presign: &Presign{state: &presignState{

			Signers:        tss.NewPartySet(1, 2),
			TranscriptHash: bytes.Repeat([]byte{0x41}, 32),
			ContextHash:    bytes.Repeat([]byte{0x42}, 32),
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
		Parties:         tss.NewPartySet(1, 2),
		PublicKey:       []byte{0x02},
		TranscriptHash:  bytes.Repeat([]byte{0x72}, 32),
		CommitmentsHash: bytes.Repeat([]byte{0x73}, 32),
		ChainCode:       bytes.Repeat([]byte{0x75}, 32),
		PlanHash:        bytes.Repeat([]byte{0x74}, 32),
	}
	payload, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	s := &KeygenSession{
		cfg:           tss.ThresholdConfig{SessionID: sessionID},
		planHash:      wantPlanHash,
		round1:        newKeygenRound1Inbox(tss.NewPartySet(confirmation.Sender)),
		confirmations: newKeygenConfirmationInbox(tss.NewPartySet(confirmation.Sender)),
	}
	_, err = s.buildAcceptCGGMPKeygenConfirmationTx(tss.Envelope{
		Round:   keygenConfirmationRound,
		From:    confirmation.Sender,
		Payload: payload,
	})
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if !errors.Is(protocolErr.Err, errPlanHashMismatch) {
		t.Fatalf("confirmation error = %v, want plan mismatch sentinel", protocolErr.Err)
	}
	if len(s.confirmations.slots) != 0 || len(s.confirmations.reveals) != 0 {
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
		parties:      tss.NewPartySet(1, 2, 3),
		publicKey:    []byte{0x02, 0x01},
		chainCode:    []byte{0x03, 0x04},
		paillierBits: int(DefaultSecurityParams().MinPaillierBits),
	}}
	refreshSnapshot, ok := refresh.Snapshot()
	if !ok {
		t.Fatal("missing refresh plan snapshot")
	}
	refreshSnapshot.Parties[0] = 99
	refreshSnapshot.PublicKey[0] ^= 0xff
	refreshSnapshot.ChainCode[0] ^= 0xff
	if refresh.state.parties[0] != 1 || refresh.state.publicKey[0] != 0x02 || refresh.state.chainCode[0] != 0x03 {
		t.Fatal("refresh plan snapshot aliases internal state")
	}

	presign := &PresignPlan{state: &presignPlanState{
		sessionID:  cggmpPlanTestSession(0x52),
		threshold:  2,
		parties:    tss.NewPartySet(1, 2, 3),
		publicKey:  []byte{0x02, 0x02},
		keygenHash: []byte{0x10, 0x11},
		signers:    tss.NewPartySet(1, 2),
		context: tss.SigningContext{KeyID: "key", ChainID: "chain", Derivation: tss.DerivationRequest{
			Scheme:       tss.DerivationSchemeBIP32Secp256k1,
			Path:         tss.DerivationPath{1, 2},
			ResolvedPath: tss.DerivationPath{1, 2},
		}, PolicyDomain: "policy", MessageDomain: "message"},
		contextHash: []byte{0x20, 0x21},
		derivation: &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			RequestedPath:  tss.DerivationPath{1, 2},
			ResolvedPath:   tss.DerivationPath{1, 2},
			AdditiveShift:  []byte{0x30, 0x31},
			ChildPublicKey: []byte{0x02, 0x03},
			ChildChainCode: []byte{0x04},
		},
	}}
	presignSnapshot, ok := presign.Snapshot()
	if !ok {
		t.Fatal("missing presign plan snapshot")
	}
	presignSnapshot.Parties[0] = 99
	presignSnapshot.PublicKey[0] ^= 0xff
	presignSnapshot.KeygenTranscriptHash[0] ^= 0xff
	presignSnapshot.Signers[0] = 99
	presignSnapshot.Context.Derivation.Path[0] = 99
	presignSnapshot.ContextHash[0] ^= 0xff
	presignSnapshot.Derivation.AdditiveShift[0] ^= 0xff
	presignSnapshot.VerificationKey[0] ^= 0xff
	if presign.state.parties[0] != 1 ||
		presign.state.publicKey[0] != 0x02 ||
		presign.state.keygenHash[0] != 0x10 ||
		presign.state.signers[0] != 1 ||
		presign.state.context.Derivation.Path[0] != 1 ||
		presign.state.contextHash[0] != 0x20 ||
		presign.state.derivation.AdditiveShift[0] != 0x30 ||
		presign.state.derivation.ChildPublicKey[0] != 0x02 {
		t.Fatal("presign plan snapshot aliases internal state")
	}

	sign := &SignPlan{state: &signPlanState{
		sessionID:         cggmpPlanTestSession(0x53),
		presignContentID:  []byte{0x40, 0x41},
		presignTranscript: []byte{0x45, 0x46},
		contextHash:       []byte{0x50, 0x51},
		digest:            []byte{0x60, 0x61},
		signers:           tss.NewPartySet(1, 2),
		intent: SignIntent{
			SessionID: cggmpPlanTestSession(0x53),
			Context: tss.SigningContext{Derivation: tss.DerivationRequest{
				Scheme:       tss.DerivationSchemeBIP32Secp256k1,
				Path:         tss.DerivationPath{3, 4},
				ResolvedPath: tss.DerivationPath{3, 4},
			}},
			Message: []byte("message"),
			Signers: tss.NewPartySet(1, 2),
		},
	}}
	signSnapshot, ok := sign.Snapshot()
	if !ok {
		t.Fatal("missing sign plan snapshot")
	}
	signSnapshot.PresignTranscriptHash[0] ^= 0xff
	signSnapshot.ContextHash[0] ^= 0xff
	signSnapshot.MessageDigest[0] ^= 0xff
	signSnapshot.Intent.Message[0] ^= 0xff
	signSnapshot.Intent.Context.Derivation.Path[0] = 99
	signSnapshot.Intent.Signers[0] = 99
	if sign.state.presignContentID[0] != 0x40 ||
		sign.state.presignTranscript[0] != 0x45 ||
		sign.state.contextHash[0] != 0x50 ||
		sign.state.digest[0] != 0x60 ||
		sign.state.intent.Message[0] != 'm' ||
		sign.state.intent.Context.Derivation.Path[0] != 3 ||
		sign.state.intent.Signers[0] != 1 {
		t.Fatal("sign plan snapshot aliases internal state")
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

func mustCGGMPKeygenPlan(t *testing.T, sessionID tss.SessionID, parties tss.PartySet, threshold int) *KeygenPlan {
	t.Helper()
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: sessionID,
		Parties:   parties,
		Threshold: threshold,
	})
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

func cggmpPartyIDsBytes(parties tss.PartySet) []byte {
	out := make([]byte, 0, len(parties)*4)
	for _, id := range parties {
		out = append(out, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	return out
}
