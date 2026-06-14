package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire/wireutil"
	"github.com/islishude/tss/internal/zk/signprep"
)

// testCGGMP21Guard is a helper that creates an EnvelopeGuard for CGGMP21 protocol tests.
// It uses the production policy set but relaxes broadcast consistency requirements
// since test harnesses don't coordinate BroadcastCertificates.
func testCGGMP21Guard(self tss.PartyID, parties tss.PartySet, sessionID tss.SessionID) *tss.EnvelopeGuard {
	return tss.NewTestEnvelopeGuard(self, parties, protocol, sessionID, testCGGMP21Policies())
}

func testCGGMP21GuardParties(parties []tss.PartyID, self tss.PartyID) tss.PartySet {
	ps := tss.PartySet(parties).Clone()
	if !ps.Contains(self) {
		ps = append(ps, self)
	}
	return ps.Sorted()
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

func clonePresignForTest(p *Presign) *Presign {
	if p == nil || p.state == nil {
		return nil
	}
	return &Presign{state: &presignState{
		consumed:       p.state.consumed,
		attempt:        p.state.attempt,
		version:        p.state.version,
		party:          p.state.party,
		threshold:      p.state.threshold,
		signers:        slices.Clone(p.state.signers),
		r:              slices.Clone(p.state.r),
		littleR:        slices.Clone(p.state.littleR),
		transcriptHash: slices.Clone(p.state.transcriptHash),
		context: PresignContext{
			KeyID:          p.state.context.KeyID,
			ChainID:        p.state.context.ChainID,
			DerivationPath: slices.Clone(p.state.context.DerivationPath),
			PolicyDomain:   p.state.context.PolicyDomain,
			MessageDomain:  p.state.context.MessageDomain,
		},
		contextHash:          slices.Clone(p.state.contextHash),
		additiveShift:        slices.Clone(p.state.additiveShift),
		planHash:             slices.Clone(p.state.planHash),
		publicKey:            slices.Clone(p.state.publicKey),
		keygenTranscriptHash: slices.Clone(p.state.keygenTranscriptHash),
		partiesHash:          slices.Clone(p.state.partiesHash),
		verifyShares:         cloneSignVerifyShares(p.state.verifyShares),
		kShare:               p.state.kShare.Clone(),
		chiShare:             p.state.chiShare.Clone(),
		delta:                p.state.delta.Clone(),
	}}
}

func startCGGMP21Keygen(config tss.ThresholdConfig, guards ...*tss.EnvelopeGuard) (*KeygenSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(config.Self, testCGGMP21GuardParties(config.Parties, config.Self), config.SessionID)
	})
	plan, err := NewKeygenPlan(KeygenPlanOption{
		SessionID: config.SessionID,
		Parties:   config.Parties,
		Threshold: config.Threshold,
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
	plan, err := NewKeygenPlan(option)
	if err != nil {
		return nil, nil, err
	}
	return StartKeygen(plan, localConfigFromThresholdConfig(config), guard)
}

func startCGGMP21PresignWithContext(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, ctx PresignContext, guards ...*tss.EnvelopeGuard) (*PresignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(key.state.party, testCGGMP21GuardParties(key.state.parties, key.state.party), sessionID)
	})
	plan, err := NewPresignPlan(key, sessionID, signers, ctx)
	if err != nil {
		return nil, nil, err
	}
	return StartPresign(key, plan, tss.LocalConfig{Self: key.state.party}, guard)
}

func startCGGMP21Sign(key *KeyShare, presign *Presign, sessionID tss.SessionID, request SignRequest, guards ...*tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(key.state.party, testCGGMP21GuardParties(key.state.parties, key.state.party), sessionID)
	})
	if request.AttemptStore == nil {
		request.AttemptStore = newTestSignAttemptStore()
	}
	plan, err := NewSignPlan(key, presign, sessionID, request)
	if err != nil {
		return nil, nil, err
	}
	return StartSign(key, presign, plan, tss.LocalConfig{Self: key.state.party, Context: context.Background()}, guard)
}

func startCGGMP21Refresh(oldKey *KeyShare, config tss.ThresholdConfig, guards ...*tss.EnvelopeGuard) (*RefreshSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(config.Self, testCGGMP21GuardParties(oldKey.state.parties, config.Self), config.SessionID)
	})
	plan, err := NewRefreshPlan(oldKey, config.SessionID)
	if err != nil {
		return nil, nil, err
	}
	return StartRefresh(oldKey, plan, localConfigFromThresholdConfig(config), guard)
}

func startCGGMP21ReshareDealer(oldKey *KeyShare, plan *ResharePlan, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareDealerSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(oldKey.state.party, testCGGMP21GuardParties([]tss.PartyID(testCGGMP21ReshareParties(plan.state.dealerParties, plan.state.newParties)), oldKey.state.party), plan.state.sessionID)
	})
	return StartReshareDealer(oldKey, plan, tss.LocalConfig{Self: oldKey.state.party, Rand: rng}, guard)
}

func startCGGMP21ReshareReceiver(plan *ResharePlan, localParty tss.PartyID, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareReceiverSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(localParty, testCGGMP21GuardParties([]tss.PartyID(testCGGMP21ReshareParties(plan.state.dealerParties, plan.state.newParties)), localParty), plan.state.sessionID)
	})
	return StartReshareReceiver(plan, tss.LocalConfig{Self: localParty, Rand: rng}, guard)
}

func startCGGMP21ReshareOverlap(oldKey *KeyShare, plan *ResharePlan, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareOverlapSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(oldKey.state.party, testCGGMP21GuardParties([]tss.PartyID(testCGGMP21ReshareParties(plan.state.dealerParties, plan.state.newParties)), oldKey.state.party), plan.state.sessionID)
	})
	return StartReshareOverlap(oldKey, plan, tss.LocalConfig{Self: oldKey.state.party, Rand: rng}, guard)
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

func testCGGMP21ReshareParties(a, b []tss.PartyID) tss.PartySet {
	seen := make(map[tss.PartyID]struct{}, len(a)+len(b))
	parties := make([]tss.PartyID, 0, len(a)+len(b))
	for _, set := range [][]tss.PartyID{a, b} {
		for _, id := range set {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			parties = append(parties, id)
		}
	}
	return tss.PartySet(tss.SortParties(parties))
}

// --- PresignContext factory ---

func testPresignContext() PresignContext {
	return PresignContext{
		KeyID:         "test-key",
		ChainID:       "test-chain",
		PolicyDomain:  "test-policy",
		MessageDomain: "test-message",
	}
}

// --- Convenience wrappers ---

// startTestPresign is a convenience wrapper around StartPresign that
// uses testPresignContext(). Only for use in tests.
func startTestPresign(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, guards ...*tss.EnvelopeGuard) (*PresignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		if !sessionID.Valid() {
			return nil
		}
		return testCGGMP21Guard(key.state.party, tss.PartySet(key.state.parties), sessionID)
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
		return testCGGMP21Guard(key.state.party, tss.PartySet(key.state.parties), sessionID)
	})
	return startSignDigestBound(context.Background(), key, presign, sessionID, digest32, presign.state.contextHash, true, newTestSignAttemptStore(), guard)
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
		return testCGGMP21Guard(key.state.party, tss.PartySet(key.state.parties), sessionID)
	})
	return startSignDigestBound(context.Background(), key, presign, sessionID, digest32, presign.state.contextHash, true, store, guard)
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
	key := string(candidate.PresignID)
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
	key := string(update.PresignID)
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
	key := string(result.PresignID)
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
		if bytes.Equal(record.SignatureR, result.Signature.R) && bytes.Equal(record.SignatureS, result.Signature.S) {
			return record.Clone(), nil
		}
		return SignAttemptRecord{}, ErrSignAttemptConflict
	}
	record.Completed = true
	record.SignatureR = slices.Clone(result.Signature.R)
	record.SignatureS = slices.Clone(result.Signature.S)
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
	key := string(burn.PresignID)
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
	return SignDigestInteractive(digest32, signers, testPresignContext())
}

func deliverKeygenMessages(t testing.TB, sessions map[tss.PartyID]*KeygenSession, parties []tss.PartyID, messages []tss.Envelope) {
	t.Helper()
	for _, id := range parties {
		s := sessions[id]
		if s.Guard() == nil {
			t.Fatalf("missing guard for keygen session %d", id)
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
			// Simulate authenticated, optionally confidential transport delivery.
			delivered := env
			delivered.Security.Authenticated = true
			delivered.Security.AuthenticatedParty = env.From
			if env.To != 0 {
				delivered.Security.Confidential = true
			}
			out, err := sessions[id].HandleKeygenMessage(delivered)
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
}

// --- Minimal presign fixture ---

// minimalCGGMP21Presign creates a Presign with minimal valid fields for
// wire-format testing. No keygen or Paillier crypto is performed.
func minimalCGGMP21Presign(tb testing.TB) *Presign {
	one := big.NewInt(1)
	RPoint := secp.ScalarBaseMult(secp.ScalarFromBigInt(one))
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		tb.Fatal("PointBytes: " + err.Error())
	}
	minimalProof := mustMinimalSignPrepProofForTest(tb)
	littleR := new(big.Int).Mod(RPoint.X.BigInt(), secp.Order())
	transcript := sha256.Sum256([]byte("minimal presign"))
	planHash := sha256.Sum256([]byte("minimal presign plan"))
	ctx := testPresignContext()
	contextHash := presignContextHash(ctx)
	kShare, err := secpSecretScalarFromBig(one)
	if err != nil {
		tb.Fatal("k share: " + err.Error())
	}
	chiShare, err := secpSecretScalarFromBig(one)
	if err != nil {
		tb.Fatal("chi share: " + err.Error())
	}
	delta, err := secpSecretScalarFromBig(one)
	if err != nil {
		tb.Fatal("delta: " + err.Error())
	}
	return &Presign{state: &presignState{
		consumed:             new(atomic.Bool),
		attempt:              newPresignAttemptBinding(false),
		version:              tss.Version,
		party:                1,
		threshold:            1,
		signers:              []tss.PartyID{1},
		r:                    R,
		littleR:              scalarBytes(littleR),
		transcriptHash:       transcript[:],
		context:              ctx,
		contextHash:          contextHash,
		planHash:             planHash[:],
		publicKey:            R,
		keygenTranscriptHash: transcript[:],
		partiesHash:          wireutil.PartySetHash([]tss.PartyID{1}, partySetHashLabel),
		verifyShares: []SignVerifyShare{{
			Party:    1,
			KPoint:   R,
			ChiPoint: R,
			Proof:    minimalProof,
		}},
		kShare:   kShare,
		chiShare: chiShare,
		delta:    delta,
	}}
}

func mustMinimalSignPrepProofForTest(tb testing.TB) []byte {
	one := big.NewInt(1)
	two := big.NewInt(2)
	kScalar := secp.ScalarFromBigInt(one)
	twoScalar := secp.ScalarFromBigInt(two)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(kScalar))
	xBarPoint := kPoint
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(twoScalar))
	stmt := signprep.Statement{
		Protocol:             protocol,
		SessionID:            tss.SessionID{1},
		Party:                1,
		Signers:              []tss.PartyID{1},
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
		Delta:                scalarBytes(one),
	}
	wit := signprep.Witness{
		KShare:   one,
		MTASum:   one,
		ChiShare: two,
	}
	proof, err := signprep.Prove(testutil.DeterministicReader(42), stmt, wit)
	if err != nil {
		tb.Fatal("signprep.Prove: " + err.Error())
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		tb.Fatal("proof.MarshalBinary: " + err.Error())
	}
	return proofBytes
}
