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

func TestCGGMP21RefreshPlanDigestBindsSourceGeneration(t *testing.T) {
	t.Parallel()

	newPlan := func(oldSession, oldTranscript, oldPlan, oldCommitments, sourceEpoch byte) *RefreshPlan {
		return &RefreshPlan{
			state: &refreshPlanState{
				sessionID:               cggmpPlanTestSession(0x50),
				threshold:               2,
				parties:                 tss.NewPartySet(1, 2),
				publicKey:               []byte{0x02, 0x01},
				chainCode:               bytes.Repeat([]byte{0x02}, 32),
				paillierBits:            int(DefaultSecurityParams().MinPaillierBits),
				oldPaillierProofSession: cggmpPlanTestSession(oldSession),
				oldKeygenTranscriptHash: bytes.Repeat([]byte{oldTranscript}, 32),
				oldPlanHash:             bytes.Repeat([]byte{oldPlan}, 32),
				oldCommitmentsHash:      bytes.Repeat([]byte{oldCommitments}, 32),
				sourceEpochID:           bytes.Repeat([]byte{sourceEpoch}, 32),
			},
			securityParams: DefaultSecurityParams(),
		}
	}

	base := newPlan(0x11, 0x12, 0x13, 0x14, 0x15)
	assertSameCGGMPPlanDigest(t, base, newPlan(0x11, 0x12, 0x13, 0x14, 0x15))
	for name, other := range map[string]*RefreshPlan{
		"old Paillier proof session": newPlan(0x21, 0x12, 0x13, 0x14, 0x15),
		"old keygen transcript":      newPlan(0x11, 0x22, 0x13, 0x14, 0x15),
		"old lifecycle plan":         newPlan(0x11, 0x12, 0x23, 0x14, 0x15),
		"old commitments":            newPlan(0x11, 0x12, 0x13, 0x24, 0x15),
		"source epoch":               newPlan(0x11, 0x12, 0x13, 0x14, 0x25),
	} {
		assertDifferentCGGMPPlanDigest(t, name, base, other)
	}
	for name, sourceEpochID := range map[string][]byte{
		"missing source epoch": nil,
		"zero source epoch":    make([]byte, 32),
	} {
		invalid := newPlan(0x11, 0x12, 0x13, 0x14, 0x15)
		invalid.state.sourceEpochID = sourceEpochID
		if _, err := invalid.Digest(); err == nil {
			t.Fatalf("refresh plan accepted %s", name)
		}
	}
}

func TestCGGMP21PresignPlanDigestBindsPresignAndEpochIDs(t *testing.T) {
	t.Parallel()

	newPlan := func(presignID, epochID byte) *PresignPlan {
		return &PresignPlan{
			state: &presignPlanState{
				sessionID:   cggmpPlanTestSession(0x5a),
				presignID:   bytes.Repeat([]byte{presignID}, 32),
				threshold:   2,
				parties:     tss.NewPartySet(1, 2, 3),
				publicKey:   []byte{0x02, 0x01},
				keygenHash:  bytes.Repeat([]byte{0x31}, 32),
				signers:     tss.NewPartySet(1, 2),
				contextHash: bytes.Repeat([]byte{0x32}, 32),
				epochID:     bytes.Repeat([]byte{epochID}, 32),
			},
			securityParams: DefaultSecurityParams(),
		}
	}

	base := newPlan(0x41, 0x42)
	assertSameCGGMPPlanDigest(t, base, newPlan(0x41, 0x42))
	assertDifferentCGGMPPlanDigest(t, "presign id", base, newPlan(0x51, 0x42))
	assertDifferentCGGMPPlanDigest(t, "epoch id", base, newPlan(0x41, 0x52))

	for name, plan := range map[string]*PresignPlan{
		"missing presign id": newPlan(0x41, 0x42),
		"zero presign id":    newPlan(0x41, 0x42),
		"missing epoch id":   newPlan(0x41, 0x42),
		"zero epoch id":      newPlan(0x41, 0x42),
	} {
		switch name {
		case "missing presign id":
			plan.state.presignID = nil
		case "zero presign id":
			plan.state.presignID = make([]byte, 32)
		case "missing epoch id":
			plan.state.epochID = nil
		case "zero epoch id":
			plan.state.epochID = make([]byte, 32)
		}
		if _, err := plan.Digest(); err == nil {
			t.Fatalf("presign plan accepted %s", name)
		}
	}
}

func TestCGGMP21NewPresignPlanRejectsInventoryIDAndRequestTimeHD(t *testing.T) {
	t.Parallel()

	key := minimalKeyShare()
	key.state.Party = 1
	sessionID := cggmpPlanTestSession(0x5b)
	validPresignID := bytes.Repeat([]byte{0x61}, 32)
	baseContext := testPresignContext()
	for _, tc := range []struct {
		name      string
		presignID []byte
		context   tss.SigningContext
	}{
		{name: "missing presign id", context: baseContext},
		{name: "short presign id", presignID: validPresignID[:31], context: baseContext},
		{name: "zero presign id", presignID: make([]byte, 32), context: baseContext},
		{name: "requested derivation path", presignID: validPresignID, context: func() tss.SigningContext {
			ctx := baseContext.Clone()
			ctx.Derivation.Path = tss.DerivationPath{1}
			return ctx
		}()},
		{name: "resolved derivation path", presignID: validPresignID, context: func() tss.SigningContext {
			ctx := baseContext.Clone()
			ctx.Derivation.ResolvedPath = tss.DerivationPath{1}
			return ctx
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewPresignPlan(PresignPlanOption{
				Key:       key,
				SessionID: sessionID,
				PresignID: tc.presignID,
				Signers:   tss.NewPartySet(1),
				Context:   tc.context,
			})
			if err == nil {
				t.Fatal("invalid presign plan input accepted")
			}
			_ = testutil.AssertProtocolError(t, err, tss.ErrCodeInvalidConfig)
		})
	}
}

func TestCGGMP21SignPlanDigestExcludesRuntimeDependencies(t *testing.T) {
	t.Parallel()

	newPlan := func(signers tss.PartySet) *SignPlan {
		return &SignPlan{state: &signPlanState{
			sessionID:         cggmpPlanTestSession(0x54),
			protocolPresignID: bytes.Repeat([]byte{0x10}, 32),
			epochID:           bytes.Repeat([]byte{0x12}, 32),
			gamma:             bytes.Repeat([]byte{0x13}, 33),
			presignTranscript: bytes.Repeat([]byte{0x11}, 32),
			contextHash:       bytes.Repeat([]byte{0x22}, 32),
			verificationKey:   bytes.Repeat([]byte{0x23}, 33),
			presignPlanHash:   bytes.Repeat([]byte{0x24}, 32),
			signers:           signers.Clone(),
			digest:            bytes.Repeat([]byte{0x33}, 32),
		}}
	}

	assertSameCGGMPPlanDigest(t, newPlan(tss.NewPartySet(1, 2)), newPlan(tss.NewPartySet(1, 2)))
	assertDifferentCGGMPPlanDigest(t, "signer set", newPlan(tss.NewPartySet(1, 2)), newPlan(tss.NewPartySet(1, 3)))
}

func TestCGGMP21SignPlanMismatchDoesNotAbortSession(t *testing.T) {
	t.Parallel()

	err := requirePlanHash("sign", bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x43}, 32))
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
		EpochID:         bytes.Repeat([]byte{0x76}, 32),
	}
	payload, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	s := &KeygenSession{
		cfg: tss.ThresholdConfig{
			SessionID: sessionID,
			Self:      1,
			Parties:   confirmation.Parties.Clone(),
			Threshold: confirmation.Threshold,
		},
		limits:             testLimits(),
		planHash:           wantPlanHash,
		figure6:            &figure6State{result: &figure6Result{publicKey: bytes.Clone(confirmation.PublicKey)}},
		auxInfo:            new(auxInfoState),
		paperConfirmations: make(map[tss.PartyID]*KeygenConfirmation),
		paperAccepted:      make(map[paperKeygenMessageKey]struct{}),
	}
	env := tss.Envelope{
		Protocol:    tss.ProtocolCGGMP21Secp256k1,
		SessionID:   sessionID,
		Round:       keygenPaperConfirmationRound,
		From:        confirmation.Sender,
		To:          tss.BroadcastPartyId,
		PayloadType: payloadKeygenConfirmation,
		Payload:     payload,
	}
	_, err = s.handlePaperKeygenConfirmationLocked(testutil.DeliverEnvelope(env), newPaperKeygenMessageKey(env))
	protocolErr := testutil.AssertProtocolError(t, err, tss.ErrCodeVerification)
	if !errors.Is(protocolErr.Err, errPlanHashMismatch) {
		t.Fatalf("confirmation error = %v, want plan mismatch sentinel", protocolErr.Err)
	}
	if len(s.paperConfirmations) != 0 || len(s.paperAccepted) != 0 {
		t.Fatal("early confirmation plan mismatch mutated keygen state")
	}
	if shouldAbortSession(err) {
		t.Fatal("early confirmation plan mismatch would abort keygen session")
	}
}

func TestCGGMP21LifecyclePlanGettersReturnCopies(t *testing.T) {
	t.Parallel()

	refresh := &RefreshPlan{state: &refreshPlanState{
		sessionID:               cggmpPlanTestSession(0x51),
		threshold:               2,
		parties:                 tss.NewPartySet(1, 2, 3),
		publicKey:               []byte{0x02, 0x01},
		chainCode:               []byte{0x03, 0x04},
		paillierBits:            int(DefaultSecurityParams().MinPaillierBits),
		oldPaillierProofSession: cggmpPlanTestSession(0x54),
		oldKeygenTranscriptHash: []byte{0x05, 0x06},
		oldPlanHash:             []byte{0x07, 0x08},
		oldCommitmentsHash:      []byte{0x09, 0x0a},
		sourceEpochID:           []byte{0x0b, 0x0c},
	}}
	refreshSnapshot, ok := refresh.Snapshot()
	if !ok {
		t.Fatal("missing refresh plan snapshot")
	}
	refreshClone := refreshSnapshot.Clone()
	refreshClone.Parties[0] = 98
	refreshClone.PublicKey[0] ^= 0xff
	refreshClone.ChainCode[0] ^= 0xff
	refreshClone.OldKeygenTranscriptHash[0] ^= 0xff
	refreshClone.OldPlanHash[0] ^= 0xff
	refreshClone.OldCommitmentsHash[0] ^= 0xff
	refreshClone.SourceEpochID[0] ^= 0xff
	if refreshSnapshot.Parties[0] != 1 || refreshSnapshot.PublicKey[0] != 0x02 || refreshSnapshot.ChainCode[0] != 0x03 ||
		refreshSnapshot.OldKeygenTranscriptHash[0] != 0x05 || refreshSnapshot.OldPlanHash[0] != 0x07 || refreshSnapshot.OldCommitmentsHash[0] != 0x09 ||
		refreshSnapshot.SourceEpochID[0] != 0x0b {
		t.Fatal("refresh plan snapshot clone aliases source")
	}
	refreshSnapshot.Parties[0] = 99
	refreshSnapshot.PublicKey[0] ^= 0xff
	refreshSnapshot.ChainCode[0] ^= 0xff
	refreshSnapshot.OldKeygenTranscriptHash[0] ^= 0xff
	refreshSnapshot.OldPlanHash[0] ^= 0xff
	refreshSnapshot.OldCommitmentsHash[0] ^= 0xff
	refreshSnapshot.SourceEpochID[0] ^= 0xff
	if refresh.state.parties[0] != 1 || refresh.state.publicKey[0] != 0x02 || refresh.state.chainCode[0] != 0x03 ||
		refresh.state.oldKeygenTranscriptHash[0] != 0x05 || refresh.state.oldPlanHash[0] != 0x07 || refresh.state.oldCommitmentsHash[0] != 0x09 ||
		refresh.state.sourceEpochID[0] != 0x0b {
		t.Fatal("refresh plan snapshot aliases internal state")
	}
	refreshEpochID := refresh.SourceEpochID()
	refreshEpochID[0] ^= 0xff
	if refresh.state.sourceEpochID[0] != 0x0b {
		t.Fatal("refresh source epoch accessor aliases internal state")
	}

	presign := &PresignPlan{state: &presignPlanState{
		sessionID:  cggmpPlanTestSession(0x52),
		presignID:  []byte{0x0e, 0x0f},
		threshold:  2,
		parties:    tss.NewPartySet(1, 2, 3),
		publicKey:  []byte{0x02, 0x02},
		keygenHash: []byte{0x10, 0x11},
		epochID:    []byte{0x12, 0x13},
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
	presignSnapshot.PresignID[0] ^= 0xff
	presignSnapshot.PublicKey[0] ^= 0xff
	presignSnapshot.KeygenTranscriptHash[0] ^= 0xff
	presignSnapshot.Signers[0] = 99
	presignSnapshot.Context.Derivation.Path[0] = 99
	presignSnapshot.ContextHash[0] ^= 0xff
	presignSnapshot.Derivation.AdditiveShift[0] ^= 0xff
	presignSnapshot.VerificationKey[0] ^= 0xff
	presignSnapshot.EpochID[0] ^= 0xff
	if presign.state.parties[0] != 1 ||
		presign.state.presignID[0] != 0x0e ||
		presign.state.publicKey[0] != 0x02 ||
		presign.state.keygenHash[0] != 0x10 ||
		presign.state.epochID[0] != 0x12 ||
		presign.state.signers[0] != 1 ||
		presign.state.context.Derivation.Path[0] != 1 ||
		presign.state.contextHash[0] != 0x20 ||
		presign.state.derivation.AdditiveShift[0] != 0x30 ||
		presign.state.derivation.ChildPublicKey[0] != 0x02 {
		t.Fatal("presign plan snapshot aliases internal state")
	}
	sign := &SignPlan{state: &signPlanState{
		sessionID:         cggmpPlanTestSession(0x53),
		protocolPresignID: []byte{0x40, 0x41},
		epochID:           []byte{0x42, 0x43},
		gamma:             []byte{0x44, 0x45},
		presignTranscript: []byte{0x45, 0x46},
		contextHash:       []byte{0x50, 0x51},
		verificationKey:   []byte{0x52, 0x53},
		presignPlanHash:   []byte{0x54, 0x55},
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
	signSnapshot.ProtocolPresignID[0] ^= 0xff
	signSnapshot.EpochID[0] ^= 0xff
	signSnapshot.Gamma[0] ^= 0xff
	signSnapshot.PresignTranscriptHash[0] ^= 0xff
	signSnapshot.ContextHash[0] ^= 0xff
	signSnapshot.VerificationKey[0] ^= 0xff
	signSnapshot.PresignPlanHash[0] ^= 0xff
	signSnapshot.MessageDigest[0] ^= 0xff
	signSnapshot.Intent.Message[0] ^= 0xff
	signSnapshot.Intent.Context.Derivation.Path[0] = 99
	signSnapshot.Intent.Signers[0] = 99
	if sign.state.protocolPresignID[0] != 0x40 ||
		sign.state.epochID[0] != 0x42 ||
		sign.state.gamma[0] != 0x44 ||
		sign.state.presignTranscript[0] != 0x45 ||
		sign.state.contextHash[0] != 0x50 ||
		sign.state.verificationKey[0] != 0x52 ||
		sign.state.presignPlanHash[0] != 0x54 ||
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
