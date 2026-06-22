package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"sync"
	"testing"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire/wireutil"
	"github.com/islishude/tss/internal/zk/schnorr"
	"github.com/islishude/tss/internal/zk/signprep"
)

// testCGGMP21Guard is a helper that creates an EnvelopeGuard for CGGMP21 protocol tests.
// It uses the production policy set but relaxes broadcast consistency requirements
// since test harnesses don't coordinate BroadcastCertificates.
func testCGGMP21Guard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) *tss.EnvelopeGuard {
	return tss.NewTestEnvelopeGuard(self, parties, tss.ProtocolCGGMP21Secp256k1, sessionID, testCGGMP21Policies())
}

func testCGGMP21GuardParties(parties tss.PartySet, self tss.PartyID) tss.PartySet {
	ps := parties.Clone()
	if !ps.Contains(self) {
		ps = append(ps, self)
	}
	return ps.Sorted()
}

func mustKeyShareMetadata(t testing.TB, share *KeyShare) KeySharePublicMetadata {
	t.Helper()
	meta, ok := share.PublicMetadata()
	if !ok {
		t.Fatal("missing key share metadata")
	}
	return meta
}

func mustKeyShareParties(t testing.TB, share *KeyShare) tss.PartySet {
	t.Helper()
	return mustKeyShareMetadata(t, share).Parties
}

func mustKeySharePublicKey(t testing.TB, share *KeyShare) []byte {
	t.Helper()
	return mustKeyShareMetadata(t, share).PublicKey
}

func mustKeyShareChainCode(t testing.TB, share *KeyShare) []byte {
	t.Helper()
	return mustKeyShareMetadata(t, share).ChainCode
}

func testCurvePoint(scalar int64) *secp.Point {
	return secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(scalar)))
}

func testCurvePointBytes(t testing.TB, scalar int64) []byte {
	t.Helper()
	raw, err := secp.PointBytes(testCurvePoint(scalar))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testSchnorrProof(t testing.TB) *schnorr.Proof {
	t.Helper()
	return &schnorr.Proof{
		Commitment: testCurvePointBytes(t, 1),
		Response:   secp.ScalarFromBigInt(big.NewInt(2)).Bytes(),
	}
}

func mustPresignMetadata(t testing.TB, presign *Presign) PresignPublicMetadata {
	t.Helper()
	meta, ok := presign.PublicMetadata()
	if !ok {
		t.Fatal("missing presign metadata")
	}
	return meta
}

func mustPresignContextHash(t testing.TB, presign *Presign) []byte {
	t.Helper()
	return mustPresignMetadata(t, presign).ContextHash
}

func mustPresignLittleR(t testing.TB, presign *Presign) []byte {
	t.Helper()
	return mustPresignMetadata(t, presign).LittleR
}

func mustPresignVerifyShare(t testing.TB, presign *Presign, party tss.PartyID) signVerifyShare {
	t.Helper()
	share, ok := presignVerifyShare(presign, party)
	if !ok {
		t.Fatalf("missing presign verify share for party %d", party)
	}
	return share.Clone()
}

func mustSignVerifyShareKPointBytes(t testing.TB, share signVerifyShare) []byte {
	t.Helper()
	out, err := share.kPointBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustSignVerifyShareChiPointBytes(t testing.TB, share signVerifyShare) []byte {
	t.Helper()
	out, err := share.chiPointBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// testCGGMP21Policies returns the production CGGMP21 policy set with broadcast
// consistency relaxed to None for all payload types. Tests that specifically
// exercise broadcast consistency should use CGGMP21Policies directly.
func testCGGMP21Policies() tss.PolicySet {
	entries := CGGMP21Policies().Entries()
	relaxed := make([]tss.DeliveryPolicy, len(entries))
	for i, p := range entries {
		relaxed[i] = p
		relaxed[i].BroadcastConsistency = tss.BroadcastConsistencyNone
	}
	ps, err := tss.NewPolicySet(relaxed...)
	if err != nil {
		panic(err)
	}
	return ps
}

func chooseTestGuard(guards []*tss.EnvelopeGuard, fallback func() *tss.EnvelopeGuard) *tss.EnvelopeGuard {
	if len(guards) > 0 {
		return guards[0]
	}
	return fallback()
}

// clonePresignForTest returns a new Presign handle that deep-copies
// immutable public metadata (signers, keys, transcripts, context, etc.)
// while sharing the one-use lifecycle pointers (consumed, attempt).
//
// consumed (*atomic.Bool) and attempt (*presignAttemptBinding) are
// deliberately shared rather than deep-copied: every copy of a Presign is
// a handle to the same one-use lifecycle.  Marking any handle consumed
// must be immediately visible to every other handle so that a second
// StartSignDigest through a different handle is reliably rejected.
// Independent consumed flags would allow nonce reuse, which leaks the
// private key.
func clonePresignForTest(p *Presign) *Presign {
	if p == nil || p.state == nil {
		return nil
	}
	return &Presign{state: &presignState{
		Consumed:             p.state.Consumed,
		attempt:              p.state.attempt,
		SecurityParams:       p.state.SecurityParams,
		Party:                p.state.Party,
		Threshold:            p.state.Threshold,
		Signers:              slices.Clone(p.state.Signers),
		R:                    secp.Clone(p.state.R),
		LittleR:              p.state.LittleR,
		TranscriptHash:       slices.Clone(p.state.TranscriptHash),
		Context:              p.state.Context.Clone(),
		ContextHash:          slices.Clone(p.state.ContextHash),
		Derivation:           p.state.Derivation.Clone(),
		PlanHash:             slices.Clone(p.state.PlanHash),
		PublicKey:            secp.Clone(p.state.PublicKey),
		KeygenTranscriptHash: slices.Clone(p.state.KeygenTranscriptHash),
		PartiesHash:          slices.Clone(p.state.PartiesHash),
		VerifyShares:         tss.CloneSlice(p.state.VerifyShares),
		Verification:         p.state.Verification.clone(),
		KShare:               p.state.KShare.Clone(),
		ChiShare:             p.state.ChiShare.Clone(),
		DeltaAggregate:       p.state.DeltaAggregate.Clone(),
	}}
}

func startCGGMP21Keygen(config tss.ThresholdConfig, guards ...*tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(config.Self, testCGGMP21GuardParties(config.Parties, config.Self), config.SessionID)
	})
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID:      config.SessionID,
		Parties:        config.Parties,
		Threshold:      config.Threshold,
		Limits:         testLimitsPtr(),
		SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	return StartKeygen(plan, localConfigFromThresholdConfig(config), guard)
}

func startCGGMP21KeygenWithPlanOption(config tss.ThresholdConfig, option KeygenPlanOption, guards ...*tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(config.Self, testCGGMP21GuardParties(config.Parties, config.Self), config.SessionID)
	})
	option.SessionID = config.SessionID
	option.Parties = config.Parties
	option.Threshold = config.Threshold
	if option.Limits == nil {
		option.Limits = testLimitsPtr()
	}
	if option.SecurityParams == nil {
		option.SecurityParams = testSecurityParamsPtr()
	}
	plan, err := NewKeygenPlan(option)
	if err != nil {
		return nil, nil, err
	}
	return StartKeygen(plan, localConfigFromThresholdConfig(config), guard)
}

func startCGGMP21PresignWithContext(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, ctx PresignContext, guards ...*tss.EnvelopeGuard) (*PresignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(key.state.Party, testCGGMP21GuardParties(key.state.Parties, key.state.Party), sessionID)
	})
	plan, err := NewPresignPlan(PresignPlanOption{
		Key:            key,
		SessionID:      sessionID,
		Signers:        signers,
		Context:        ctx,
		Limits:         testLimitsPtr(),
		SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	return StartPresign(key, plan, tss.LocalConfig{Self: key.state.Party}, guard)
}

func startCGGMP21Sign(key *KeyShare, presign *Presign, sessionID tss.SessionID, request SignRequest, guards ...*tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(key.state.Party, testCGGMP21GuardParties(key.state.Parties, key.state.Party), sessionID)
	})
	if request.AttemptStore == nil {
		request.AttemptStore = newTestSignAttemptStore()
	}
	plan, err := NewSignPlan(SignPlanOption{
		Key:       key,
		Presign:   presign,
		SessionID: sessionID,
		Request:   request,
		Limits:    testLimitsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	return StartSign(key, presign, plan, tss.LocalConfig{Self: key.state.Party, Context: context.Background()}, guard)
}

func startCGGMP21Refresh(oldKey *KeyShare, config tss.ThresholdConfig, guards ...*tss.EnvelopeGuard) (*RefreshSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(config.Self, testCGGMP21GuardParties(oldKey.state.Parties, config.Self), config.SessionID)
	})
	plan, err := NewRefreshPlan(RefreshPlanOption{
		OldKey:         oldKey,
		SessionID:      config.SessionID,
		Limits:         testLimitsPtr(),
		SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	return StartRefresh(oldKey, plan, localConfigFromThresholdConfig(config), guard)
}

func startCGGMP21ReshareDealer(oldKey *KeyShare, plan *ResharePlan, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareDealerSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(oldKey.state.Party, testCGGMP21GuardParties(tss.MergePartySet(plan.state.DealerParties, plan.state.NewParties), oldKey.state.Party), plan.state.SessionID)
	})
	return StartReshareDealer(oldKey, plan, tss.LocalConfig{Self: oldKey.state.Party, Rand: rng}, guard)
}

func startCGGMP21ReshareReceiver(plan *ResharePlan, localParty tss.PartyID, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareReceiverSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(localParty, testCGGMP21GuardParties(tss.MergePartySet(plan.state.DealerParties, plan.state.NewParties), localParty), plan.state.SessionID)
	})
	return StartReshareReceiver(plan, tss.LocalConfig{Self: localParty, Rand: rng}, guard)
}

func startCGGMP21ReshareOverlap(oldKey *KeyShare, plan *ResharePlan, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareOverlapSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(oldKey.state.Party, testCGGMP21GuardParties(tss.MergePartySet(plan.state.DealerParties, plan.state.NewParties), oldKey.state.Party), plan.state.SessionID)
	})
	return StartReshareOverlap(oldKey, plan, tss.LocalConfig{Self: oldKey.state.Party, Rand: rng}, guard)
}

func localConfigFromThresholdConfig(config tss.ThresholdConfig) tss.LocalConfig {
	return tss.LocalConfig{
		Self:         config.Self,
		Rand:         config.Rand,
		Context:      config.Context,
		RoundTimeout: config.RoundTimeout,
		Log:          config.Log,
	}
}

// --- PresignContext factory ---

func testPresignContext() PresignContext {
	return PresignContext{
		KeyID:   "test-key",
		ChainID: "test-chain",
		Derivation: tss.DerivationRequest{
			Scheme: tss.DerivationSchemeBIP32Secp256k1,
		},
		PolicyDomain:  "test-policy",
		MessageDomain: "test-message",
	}
}

// --- Convenience wrappers ---

// startTestPresign is a convenience wrapper around StartPresign that
// uses testPresignContext(). Only for use in tests.
func startTestPresign(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, guards ...*tss.EnvelopeGuard) (*PresignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		if !sessionID.Valid() {
			return nil
		}
		return testCGGMP21Guard(key.state.Party, key.state.Parties, sessionID)
	})
	return startCGGMP21PresignWithContext(key, sessionID, signers, testPresignContext(), guard)
}

// StartSignDigest is a convenience wrapper around startSignDigestBound for tests.
func StartSignDigest(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte, guards ...*tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	if presign == nil || presign.state == nil {
		return nil, nil, errNilPresign
	}
	if key == nil || key.state == nil {
		return nil, nil, errors.New("nil key share")
	}
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		if !sessionID.Valid() {
			return nil
		}
		return testCGGMP21Guard(key.state.Party, key.state.Parties, sessionID)
	})
	return startSignDigestBound(context.Background(), key, presign, sessionID, digest32, presign.state.ContextHash, newTestSignAttemptStore(), guard, testLimits())
}

func StartSignDigestWithStore(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte, store SignAttemptStore, guards ...*tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	if presign == nil || presign.state == nil {
		return nil, nil, errNilPresign
	}
	if key == nil || key.state == nil {
		return nil, nil, errors.New("nil key share")
	}
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		if !sessionID.Valid() {
			return nil
		}
		return testCGGMP21Guard(key.state.Party, key.state.Parties, sessionID)
	})
	return startSignDigestBound(context.Background(), key, presign, sessionID, digest32, presign.state.ContextHash, store, guard, testLimits())
}

type testSignAttemptStore struct {
	mu       sync.Mutex
	attempts map[string]SignAttemptRecord
	burns    map[string]struct{}
}

func newTestSignAttemptStore() *testSignAttemptStore {
	return &testSignAttemptStore{
		attempts: make(map[string]SignAttemptRecord),
		burns:    make(map[string]struct{}),
	}
}

func (s *testSignAttemptStore) LoadSignAttempt(ctx context.Context, presignID []byte) (SignAttemptRecord, error) {
	if s == nil {
		return SignAttemptRecord{}, errors.New("nil test sign attempt store")
	}
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[string(presignID)]; ok {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, ok := s.attempts[string(presignID)]
	if !ok {
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	return record.Clone(), nil
}

func (s *testSignAttemptStore) CommitSignAttempt(ctx context.Context, candidate SignAttemptRecord) (SignAttemptCommit, error) {
	if ctx == nil {
		return SignAttemptCommit{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptCommit{}, err
	}
	if err := validateSignAttemptCandidate(candidate); err != nil {
		return SignAttemptCommit{}, err
	}
	key := string(candidate.PresignContentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[key]; ok {
		return SignAttemptCommit{}, ErrSignAttemptBurned
	}
	if existing, ok := s.attempts[key]; ok {
		if candidate.SameBaseAttempt(existing) {
			return SignAttemptCommit{Status: SignAttemptExistingSame, Record: existing.Clone()}, nil
		}
		if bytes.Equal(existing.IntentHash, candidate.IntentHash) {
			return SignAttemptCommit{}, ErrSignAttemptNonDeterminism
		}
		return SignAttemptCommit{}, ErrSignAttemptConflict
	}
	s.attempts[key] = candidate.Clone()
	return SignAttemptCommit{Status: SignAttemptCreated, Record: candidate.Clone()}, nil
}

func (s *testSignAttemptStore) UpdateSignAttemptDelivery(ctx context.Context, update SignAttemptDeliveryUpdate) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	key := string(update.PresignContentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[key]; ok {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, ok := s.attempts[key]
	if !ok {
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	updated, err := applySignAttemptDeliveryUpdate(record, update)
	if err != nil {
		return SignAttemptRecord{}, err
	}
	s.attempts[key] = updated.Clone()
	return updated.Clone(), nil
}

func (s *testSignAttemptStore) CompleteSignAttempt(ctx context.Context, result SignAttemptResult) (SignAttemptRecord, error) {
	if ctx == nil {
		return SignAttemptRecord{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return SignAttemptRecord{}, err
	}
	key := string(result.PresignContentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.burns[key]; ok {
		return SignAttemptRecord{}, ErrSignAttemptBurned
	}
	record, ok := s.attempts[key]
	if !ok {
		return SignAttemptRecord{}, ErrSignAttemptNotFound
	}
	if !bytes.Equal(record.AttemptHash, result.AttemptHash) {
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	if record.Completed {
		if bytes.Equal(record.SignatureR, result.Signature.R) && bytes.Equal(record.SignatureS, result.Signature.S) && record.SignatureRecoveryID == result.Signature.RecoveryID {
			return record.Clone(), nil
		}
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	record.Completed = true
	record.SignatureR = slices.Clone(result.Signature.R)
	record.SignatureS = slices.Clone(result.Signature.S)
	record.SignatureRecoveryID = result.Signature.RecoveryID
	s.attempts[key] = record
	return record.Clone(), nil
}

func (s *testSignAttemptStore) BurnPresign(ctx context.Context, burn SignAttemptBurn) error {
	if s == nil {
		return errors.New("nil test sign attempt store")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := string(burn.PresignContentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.attempts[key]; ok {
		return ErrSignAttemptConflict
	}
	if s.burns == nil {
		s.burns = make(map[string]struct{})
	}
	s.burns[key] = struct{}{}
	return nil
}

// errNilPresign is a sentinel error for nil presign in test helpers.
var errNilPresign = errNilPresignError{}

type errNilPresignError struct{}

func (errNilPresignError) Error() string { return "nil presign" }

// SignDigest is a convenience wrapper around SignDigestInteractive for tests.
func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	return signWithDigest(digest32, signers, testPresignContext(), true, testLimits())
}

func deliverKeygenMessages(t testing.TB, sessions map[tss.PartyID]*KeygenSession, parties tss.PartySet, messages []tss.Envelope) {
	t.Helper()
	if err := deliverKeygenMessagesE(sessions, parties, messages); err != nil {
		t.Fatal(err)
	}
}

func deliverKeygenMessagesE(sessions map[tss.PartyID]*KeygenSession, parties tss.PartySet, messages []tss.Envelope) error {
	for _, id := range parties {
		s := sessions[id]
		if s.guard == nil {
			return fmt.Errorf("missing guard for keygen session %d", id)
		}
	}
	queue := append([]tss.Envelope(nil), messages...)
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleKeygenMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				return fmt.Errorf("deliver %s from %d to %d: %w", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
	return nil
}

// --- Minimal presign fixture ---

// minimalCGGMP21Presign creates a Presign with minimal valid fields for
// wire-format testing. No keygen or Paillier crypto is performed.
func minimalCGGMP21Presign(tb testing.TB) *Presign {
	one := secp.ScalarOne()
	RPoint := secp.ScalarBaseMult(one)
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		tb.Fatal("PointBytes: " + err.Error())
	}
	minimalProof := mustMinimalSignPrepProofForTest(tb)
	littleR := secp.ScalarFromFieldElement(RPoint.X)
	transcript := sha256.Sum256([]byte("minimal presign"))
	planHash := sha256.Sum256([]byte("minimal presign plan"))
	ctx := testPresignContext()
	contextHash := presignContextHash(ctx)
	zeroShift := secp.ScalarZero().Bytes()
	childChainCode := bytes.Repeat([]byte{0x42}, 32)
	kShare, err := secpSecretScalarFromScalar(one)
	if err != nil {
		tb.Fatal("k share: " + err.Error())
	}
	chiShare, err := secpSecretScalarFromScalar(one)
	if err != nil {
		tb.Fatal("chi share: " + err.Error())
	}
	delta, err := secpSecretScalarFromScalar(one)
	if err != nil {
		tb.Fatal("delta: " + err.Error())
	}
	var verificationSessionID tss.SessionID
	copy(verificationSessionID[:], bytes.Repeat([]byte{0x31}, len(verificationSessionID)))
	return &Presign{state: &presignState{
		Consumed:       NewAtomicBoolWire(false),
		attempt:        newPresignAttemptBinding(false),
		SecurityParams: testSecurityParams(),
		Party:          1,
		Threshold:      2,
		Signers:        tss.NewPartySet(1, 2),
		R:              secp.Clone(RPoint),
		LittleR:        littleR,
		TranscriptHash: transcript[:],
		Context:        ctx,
		ContextHash:    contextHash,
		Derivation: &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: slices.Clone(R),
			ChildChainCode: slices.Clone(childChainCode),
			AdditiveShift:  slices.Clone(zeroShift),
		},
		PlanHash:             planHash[:],
		PublicKey:            secp.Clone(RPoint),
		KeygenTranscriptHash: transcript[:],
		PartiesHash:          wireutil.PartySetHash(tss.NewPartySet(1, 2), partySetHashLabel),
		VerifyShares: []signVerifyShare{{
			Party:    1,
			KPoint:   secp.Clone(RPoint),
			ChiPoint: secp.Clone(RPoint),
			Proof:    minimalProof,
		}, {
			Party:    2,
			KPoint:   secp.Clone(RPoint),
			ChiPoint: secp.Clone(RPoint),
			Proof:    minimalProof.Clone(),
		}},
		Verification: presignVerificationContext{
			SessionID:  verificationSessionID,
			Round1Echo: bytes.Repeat([]byte{0x32}, 32),
			Entries: []presignVerificationEntry{{
				Party:             1,
				Gamma:             slices.Clone(R),
				EncK:              []byte{1},
				PaillierPublicKey: testPaillierPublicKey(65),
				XBarPoint:         secp.Clone(RPoint),
				Delta:             one,
			}, {
				Party:             2,
				Gamma:             slices.Clone(R),
				EncK:              []byte{1},
				PaillierPublicKey: testPaillierPublicKey(77),
				XBarPoint:         secp.Clone(RPoint),
				Delta:             one,
			}},
		},
		KShare:         kShare,
		ChiShare:       chiShare,
		DeltaAggregate: delta,
	}}
}

func testLimitsPtr() *Limits {
	limits := testLimits()
	return &limits
}

func testSecurityParamsPtr() *SecurityParams {
	params := testSecurityParams()
	return &params
}

func mustMinimalSignPrepProofForTest(tb testing.TB) *signprep.Proof {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kScalar := secp.ScalarFromBigInt(one)
	twoScalar := secp.ScalarFromBigInt(two)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(kScalar))
	xBarPoint := kPoint
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(twoScalar))
	stmt := signprep.Statement{
		Protocol:             tss.ProtocolCGGMP21Secp256k1,
		SessionID:            tss.SessionID{1},
		Party:                1,
		Signers:              tss.NewPartySet(1),
		ContextHash:          bytes.Repeat([]byte{0xaa}, 32),
		PublicKey:            kPoint,
		KeygenTranscriptHash: bytes.Repeat([]byte{0xbb}, 32),
		PartiesHash:          bytes.Repeat([]byte{0xcc}, 32),
		KPoint:               kPoint,
		ChiPoint:             chiPoint,
		XBarPoint:            xBarPoint,
		EncK:                 make([]byte, 256),
		PaillierPublicKey:    make([]byte, 256),
		Gamma:                kPoint,
		Delta:                kScalar.Bytes(),
	}
	wit := signprep.Witness{
		KShare:   testSecretScalar(tb, 1),
		MTASum:   testSecretScalar(tb, 1),
		ChiShare: testSecretScalar(tb, 2),
	}
	proof, err := signprep.Prove(testutil.DeterministicReader(42), stmt, wit)
	if err != nil {
		tb.Fatal("signprep.Prove: " + err.Error())
	}
	return proof
}
