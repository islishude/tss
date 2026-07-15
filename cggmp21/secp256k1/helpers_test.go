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
	"testing"

	"github.com/islishude/tss"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/zk/schnorr"
	"github.com/islishude/tss/tssrun"
)

type testEnvelopeIdentity struct{}

func (testEnvelopeIdentity) SignEnvelopeDigest([32]byte) ([]byte, error) { return []byte{1}, nil }
func (testEnvelopeIdentity) VerifyEnvelopeSignature(tss.PartyID, [32]byte, []byte) error {
	return nil
}

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

func attachTestEpoch(t testing.TB, share *KeyShare) {
	t.Helper()
	if share == nil || share.state == nil {
		t.Fatal("nil key share")
	}
	publicShares := make([]EpochPublicShare, len(share.state.Parties))
	for i, party := range share.state.Parties {
		publicShares[i] = EpochPublicShare{Party: party, PublicKey: testCurvePointBytes(t, int64(i+1))}
	}
	var sid, rid tss.SessionID
	sid[0] = 0x71
	rid[0] = 0x72
	auxiliaryDigest := sha256.Sum256([]byte("key share metadata test epoch"))
	epoch, err := NewEpochContext(EpochContextOption{
		SID:             sid,
		RID:             rid,
		Threshold:       share.state.Threshold,
		Parties:         share.state.Parties,
		PublicShares:    publicShares,
		AuxiliaryDigest: auxiliaryDigest[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	share.state.Epoch = epoch
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

func mustPresignLittleR(t testing.TB, presign *Presign) []byte {
	t.Helper()
	return mustPresignMetadata(t, presign).LittleR
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
		relaxed[i].RequireSenderSignature = false
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
	commitments := make([]normalizedPresignCommitment, len(p.state.Commitments))
	for i := range p.state.Commitments {
		commitments[i] = p.state.Commitments[i].clone()
	}
	return &Presign{state: &presignState{
		Consumed:             p.state.Consumed,
		attempt:              p.state.attempt,
		SecurityParams:       p.state.SecurityParams,
		Party:                p.state.Party,
		Threshold:            p.state.Threshold,
		Signers:              slices.Clone(p.state.Signers),
		PresignID:            slices.Clone(p.state.PresignID),
		EpochID:              slices.Clone(p.state.EpochID),
		Gamma:                secp.Clone(p.state.Gamma),
		LittleR:              p.state.LittleR,
		KShare:               p.state.KShare.Clone(),
		ChiShare:             p.state.ChiShare.Clone(),
		Commitments:          commitments,
		TranscriptHash:       slices.Clone(p.state.TranscriptHash),
		Context:              p.state.Context.Clone(),
		ContextHash:          slices.Clone(p.state.ContextHash),
		PublicKey:            secp.Clone(p.state.PublicKey),
		KeygenTranscriptHash: slices.Clone(p.state.KeygenTranscriptHash),
		PartiesHash:          slices.Clone(p.state.PartiesHash),
		PlanHash:             slices.Clone(p.state.PlanHash),
		Derivation:           p.state.Derivation.Clone(),
		Epoch:                p.state.Epoch.Clone(),
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

func startCGGMP21PresignWithContext(key *KeyShare, sessionID tss.SessionID, signers tss.PartySet, ctx tss.SigningContext, guards ...*tss.EnvelopeGuard) (*PresignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(key.state.Party, testCGGMP21GuardParties(key.state.Parties, key.state.Party), sessionID)
	})
	plan, err := NewPresignPlan(PresignPlanOption{
		Key:            key,
		SessionID:      sessionID,
		PresignID:      sessionID[:],
		Signers:        signers,
		Context:        ctx,
		Limits:         testLimitsPtr(),
		SecurityParams: testSecurityParamsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	runtime, err := prepareTestPresignRuntime(context.Background(), key, plan, tss.LocalConfig{Self: key.state.Party}, guard)
	if err != nil {
		return nil, nil, err
	}
	return StartPresign(plan, runtime)
}

func prepareTestPresignRuntime(ctx context.Context, key *KeyShare, plan *PresignPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (PresignRuntime, error) {
	if key == nil || key.state == nil || key.state.Epoch == nil || plan == nil || plan.state == nil {
		return PresignRuntime{}, errors.New("invalid test presign runtime input")
	}
	epochID, err := tssrun.NewEpochID(key.state.Epoch.EpochID)
	if err != nil {
		return PresignRuntime{}, err
	}
	binding := tssrun.GenerationBinding{
		KeyID:         plan.state.context.KeyID,
		KeyGeneration: tssrun.KeyGeneration(fmt.Sprintf("test-presign-generation-%d", key.state.Party)),
		EpochID:       epochID,
	}
	store := newTestLifecycleStore()
	if err := installTestLifecycleGeneration(ctx, store, key, binding, plan.limits); err != nil {
		return PresignRuntime{}, err
	}
	return PresignRuntime{
		Local:          local,
		Guard:          guard,
		LifecycleStore: store,
		Binding:        binding,
	}, nil
}

func loadPersistedPresignForTest(session *PresignSession) (*Presign, error) {
	if session == nil {
		return nil, errors.New("nil presign session")
	}
	descriptor, ok := session.Presign()
	if !ok {
		return nil, errors.New("presign session is not durably complete")
	}
	storeCtx, cancel := durableStoreContext(context.Background(), session.lifecycleTimeout)
	candidate, err := session.lifecycleStore.PreparePresignCandidate(storeCtx, session.lifecycleLease.Binding, descriptor.SlotID())
	cancel()
	if err != nil {
		return nil, err
	}
	defer clear(candidate.Blob)
	defer clear(candidate.Metadata)
	var presign Presign
	if err := presign.UnmarshalBinaryWithLimits(candidate.Blob, session.limits); err != nil {
		return nil, err
	}
	if err := presign.VerifyCryptographicMaterialWithLimits(session.limits); err != nil {
		presign.Destroy()
		return nil, err
	}
	return &presign, nil
}

func startCGGMP21Sign(key *KeyShare, presign *Presign, sessionID tss.SessionID, request SignRequest, guards ...*tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(key.state.Party, testCGGMP21GuardParties(key.state.Parties, key.state.Party), sessionID)
	})
	return startCGGMP21SignWithLocal(key, presign, sessionID, request, tss.LocalConfig{Self: key.state.Party}, guard)
}

func startCGGMP21SignWithLocal(key *KeyShare, presign *Presign, sessionID tss.SessionID, request SignRequest, local tss.LocalConfig, guard *tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
	metadata, ok := presign.PublicMetadata()
	if !ok {
		return nil, nil, errors.New("invalid public presign metadata")
	}
	plan, err := NewSignPlan(SignPlanOption{
		Key:     key,
		Presign: metadata,
		Intent: SignIntent{
			SessionID: sessionID,
			Context:   request.Context,
			Message:   request.Message,
			Signers:   presign.state.Signers,
		},
		Limits: testLimitsPtr(),
	})
	if err != nil {
		return nil, nil, err
	}
	store := newTestLifecycleStore()
	runtime, err := prepareTestSignRuntime(context.Background(), key, presign, sessionID, store, local, guard)
	if err != nil {
		return nil, nil, err
	}
	return StartSign(plan, runtime)
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
	runtime, err := prepareTestRefreshRuntime(oldKey, plan, localConfigFromThresholdConfig(config), guard)
	if err != nil {
		return nil, nil, err
	}
	return StartRefresh(plan, runtime)
}

func startCGGMP21ReshareDealer(oldKey *KeyShare, plan *ResharePlan, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareDealerSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(oldKey.state.Party, testCGGMP21GuardParties(tss.MergePartySet(plan.state.DealerParties, plan.state.NewParties), oldKey.state.Party), plan.state.SessionID)
	})
	runtime, err := prepareTestReshareRuntime(oldKey, plan, tss.LocalConfig{Self: oldKey.state.Party, Rand: rng}, guard)
	if err != nil {
		return nil, nil, err
	}
	return StartReshareDealer(plan, runtime)
}

func startCGGMP21ReshareReceiver(plan *ResharePlan, localParty tss.PartyID, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareReceiverSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(localParty, testCGGMP21GuardParties(tss.MergePartySet(plan.state.DealerParties, plan.state.NewParties), localParty), plan.state.SessionID)
	})
	runtime, err := prepareTestReshareRuntime(nil, plan, tss.LocalConfig{Self: localParty, Rand: rng}, guard)
	if err != nil {
		return nil, nil, err
	}
	return StartReshareReceiver(plan, runtime)
}

func startCGGMP21ReshareOverlap(oldKey *KeyShare, plan *ResharePlan, rng io.Reader, guards ...*tss.EnvelopeGuard) (*ReshareOverlapSession, []tss.Envelope, error) {
	guard := chooseTestGuard(guards, func() *tss.EnvelopeGuard {
		return testCGGMP21Guard(oldKey.state.Party, testCGGMP21GuardParties(tss.MergePartySet(plan.state.DealerParties, plan.state.NewParties), oldKey.state.Party), plan.state.SessionID)
	})
	runtime, err := prepareTestReshareRuntime(oldKey, plan, tss.LocalConfig{Self: oldKey.state.Party, Rand: rng}, guard)
	if err != nil {
		return nil, nil, err
	}
	return StartReshareOverlap(plan, runtime)
}

func prepareTestRefreshRuntime(key *KeyShare, plan *RefreshPlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (RefreshRuntime, error) {
	if key == nil || key.state == nil || key.state.Epoch == nil || plan == nil || plan.state == nil {
		return RefreshRuntime{}, errors.New("invalid test refresh runtime input")
	}
	epochID, err := tssrun.NewEpochID(key.state.Epoch.EpochID)
	if err != nil {
		return RefreshRuntime{}, err
	}
	binding := tssrun.GenerationBinding{KeyID: "test-refresh-key", KeyGeneration: "refresh-source", EpochID: epochID}
	store := newTestLifecycleStore()
	if err := installTestLifecycleGeneration(context.Background(), store, key, binding, plan.limits); err != nil {
		return RefreshRuntime{}, err
	}
	return RefreshRuntime{
		Local:               local,
		Guard:               guard,
		LifecycleStore:      store,
		Binding:             binding,
		TargetKeyGeneration: "refresh-target",
	}, nil
}

func prepareTestReshareRuntime(key *KeyShare, plan *ResharePlan, local tss.LocalConfig, guard *tss.EnvelopeGuard) (ReshareRuntime, error) {
	if plan == nil || plan.state == nil {
		return ReshareRuntime{}, errors.New("invalid test reshare runtime input")
	}
	epochID, err := tssrun.NewEpochID(plan.state.SourceEpochID)
	if err != nil {
		return ReshareRuntime{}, err
	}
	binding := tssrun.GenerationBinding{KeyID: "test-reshare-key", KeyGeneration: "reshare-source", EpochID: epochID}
	store := newTestLifecycleStore()
	if key != nil {
		blob, marshalErr := key.MarshalBinaryWithLimits(plan.limits)
		if marshalErr != nil {
			return ReshareRuntime{}, marshalErr
		}
		defer clear(blob)
		if _, installErr := store.InstallInitialGeneration(context.Background(), binding, blob, key.state.PlanHash); installErr != nil {
			return ReshareRuntime{}, installErr
		}
	}
	return ReshareRuntime{
		Local:               local,
		Guard:               guard,
		LifecycleStore:      store,
		Binding:             binding,
		TargetKeyGeneration: "reshare-target",
	}, nil
}

func localConfigFromThresholdConfig(config tss.ThresholdConfig) tss.LocalConfig {
	return tss.LocalConfig{
		Self:           config.Self,
		Rand:           config.Rand,
		Context:        config.Context,
		RoundTimeout:   config.RoundTimeout,
		Log:            config.Log,
		EnvelopeSigner: config.EnvelopeSigner,
	}
}

// --- PresignContext factory ---

func testPresignContext() tss.SigningContext {
	return tss.SigningContext{
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
	return StartSignDigestWithStore(key, presign, sessionID, digest32, newTestLifecycleStore(), guard)
}

func StartSignDigestWithStore(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte, store tssrun.LifecycleStore, guards ...*tss.EnvelopeGuard) (*SignSession, []tss.Envelope, error) {
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
	ctx := context.Background()
	runtime, err := prepareTestSignRuntime(ctx, key, presign, sessionID, store, tss.LocalConfig{Self: key.state.Party, Context: ctx}, guard)
	if err != nil {
		return nil, nil, err
	}
	planHashInput := slices.Concat(sessionID[:], digest32, presign.state.ContextHash)
	planHash := sha256.Sum256(planHashInput)
	publicContext := signAttemptPublicContextFromPresign(presign)
	defer publicContext.destroy()
	outbox, rawOutbox, err := buildSignAttemptOutbox(ctx, key, presign, publicContext, runtime.Binding,
		runtime.PresignID, runtime.AttemptID, sessionID, digest32, presign.state.ContextHash, planHash[:], runtime.DeliveryPolicy, runtime.Local.EnvelopeSigner, testLimits())
	if err != nil {
		return nil, nil, err
	}
	defer clearSignAttemptOutbox(&outbox)
	defer clear(rawOutbox)
	lease, err := store.AcquireRunLease(ctx, runtime.Binding, tssrun.RunSign, sessionID)
	if err != nil {
		return nil, nil, err
	}
	query := tssrun.AttemptQuery{Binding: runtime.Binding, PresignID: runtime.PresignID, AttemptID: runtime.AttemptID, IntentDigest: bytes.Clone(outbox.IntentDigest)}
	coordinator, err := newSignAttemptCoordinator(store, lease, query, DefaultLifecycleStoreTimeout, testLimits())
	if err != nil {
		return nil, nil, err
	}
	commit, err := coordinator.claim(ctx, outbox, rawOutbox)
	if err != nil {
		return nil, nil, err
	}
	// The lifecycle-backed session owns and destroys the key it receives.
	// Keep the caller's fixture independently usable across later presign/sign
	// attempts by transferring an explicit clone to the session.
	sessionKey := key.Clone()
	if sessionKey == nil {
		return nil, nil, errors.New("clone sign-session key share")
	}
	session, out, err := signSessionFromLifecycleAttempt(ctx, sessionKey, commit.Record, coordinator, guard, testLimits())
	if err != nil {
		sessionKey.Destroy()
		return nil, nil, err
	}
	return session, out, nil
}

func prepareTestSignRuntime(ctx context.Context, key *KeyShare, presign *Presign, sessionID tss.SessionID, store tssrun.LifecycleStore, local tss.LocalConfig, guard *tss.EnvelopeGuard) (SignRuntime, error) {
	if store == nil || key == nil || key.state == nil || key.state.Epoch == nil || presign == nil || presign.state == nil {
		return SignRuntime{}, errors.New("invalid test sign runtime input")
	}
	if local.Self == tss.BroadcastPartyId {
		local.Self = key.state.Party
	}
	if local.Context == nil {
		local.Context = ctx
	}
	epochID, err := tssrun.NewEpochID(key.state.Epoch.EpochID)
	if err != nil {
		return SignRuntime{}, err
	}
	binding := tssrun.GenerationBinding{KeyID: presign.state.Context.KeyID, KeyGeneration: "test-generation", EpochID: epochID}
	if err := installTestLifecycleGeneration(ctx, store, key, binding, testLimits()); err != nil {
		return SignRuntime{}, err
	}
	blob, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		return SignRuntime{}, err
	}
	defer clear(blob)
	metadata, err := presign.LifecycleMetadataWithLimits(testLimits())
	if err != nil {
		return SignRuntime{}, err
	}
	defer clear(metadata)
	presignID, err := PresignSlotID(presign.state.PresignID)
	if err != nil {
		return SignRuntime{}, err
	}
	if err := commitTestAvailablePresignFromLease(ctx, store, binding, presignID, blob, metadata, fmt.Sprintf("sign-runtime-%x", sessionID)); err != nil {
		return SignRuntime{}, err
	}
	policy, err := CGGMP21Policies().Match(tss.ProtocolCGGMP21Secp256k1, signStartRound, payloadSignPartial)
	if err != nil {
		return SignRuntime{}, err
	}
	return SignRuntime{
		Local:          local,
		Guard:          guard,
		LifecycleStore: store,
		Binding:        binding,
		PresignID:      presignID,
		AttemptID:      fmt.Sprintf("test-attempt-%d-%x", key.state.Party, sessionID),
		DeliveryPolicy: SignAttemptDeliveryPolicy{Mode: policy.Mode, Confidentiality: policy.Confidentiality, BroadcastConsistency: policy.BroadcastConsistency, Recipients: presign.state.Signers.Clone()},
	}, nil
}

func installTestLifecycleGeneration(ctx context.Context, store tssrun.LifecycleStore, key *KeyShare, binding tssrun.GenerationBinding, limits Limits) error {
	if store == nil || key == nil || key.state == nil {
		return errors.New("invalid test lifecycle generation input")
	}
	metadata, ok := key.PublicMetadata()
	if !ok {
		return errors.New("missing key share metadata")
	}
	blob, err := key.MarshalBinaryWithLimits(limits)
	if err != nil {
		return err
	}
	defer clear(blob)
	_, err = store.InstallInitialGeneration(ctx, binding, blob, metadata.PlanHash)
	return err
}

func commitTestAvailablePresignFromLease(
	ctx context.Context,
	store tssrun.LifecycleStore,
	binding tssrun.GenerationBinding,
	presignID string,
	blob, metadata []byte,
	label string,
) error {
	if ctx == nil || store == nil {
		return errors.New("invalid test available-presign input")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("cggmp21-test-presign-lease"))
	_, _ = h.Write([]byte(binding.KeyID))
	_, _ = h.Write([]byte(binding.KeyGeneration))
	_, _ = h.Write(binding.EpochID[:])
	_, _ = h.Write([]byte(presignID))
	_, _ = h.Write([]byte(label))
	sessionID, err := tss.NewSessionID(bytes.NewReader(h.Sum(nil)))
	if err != nil {
		return err
	}
	lease, err := store.AcquireRunLease(ctx, binding, tssrun.RunPresign, sessionID)
	if err != nil {
		return err
	}
	return store.CommitAvailablePresignFromLease(ctx, lease, presignID, blob, metadata)
}

func prepareTestSignRuntimeFromPersisted(ctx context.Context, session *PresignSession, descriptor PersistedPresign, signSessionID tss.SessionID, guard *tss.EnvelopeGuard) (SignRuntime, error) {
	if session == nil || session.lifecycleStore == nil || !session.leaseFinished {
		return SignRuntime{}, errors.New("presign session is not durably complete")
	}
	metadata := descriptor.PublicMetadata()
	policy, err := CGGMP21Policies().Match(tss.ProtocolCGGMP21Secp256k1, signStartRound, payloadSignPartial)
	if err != nil {
		return SignRuntime{}, err
	}
	return SignRuntime{
		Local:          tss.LocalConfig{Self: metadata.Party, Context: ctx},
		Guard:          guard,
		LifecycleStore: session.lifecycleStore,
		Binding:        session.lifecycleLease.Binding,
		PresignID:      descriptor.SlotID(),
		AttemptID:      fmt.Sprintf("test-attempt-%d-%x", metadata.Party, signSessionID),
		DeliveryPolicy: SignAttemptDeliveryPolicy{
			Mode:                 policy.Mode,
			Confidentiality:      policy.Confidentiality,
			BroadcastConsistency: policy.BroadcastConsistency,
			Recipients:           metadata.Signers.Clone(),
		},
	}, nil
}

func newTestLifecycleStore() *tssrun.MemoryLifecycleStore {
	return tssrun.NewMemoryLifecycleStore()
}

// errNilPresign is a sentinel error for nil presign in test helpers.
var errNilPresign = errNilPresignError{}

type errNilPresignError struct{}

func (errNilPresignError) Error() string { return "nil presign" }

// SignDigest runs a full interactive raw-digest signing simulation for tests.
func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	return signCGGMP21Simulation(digest32, signers, testPresignContext(), true, testLimits())
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
	queue := slices.Clone(messages)
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				return fmt.Errorf("deliver %s from %d to %d: %w", env.PayloadType, env.From, id, err)
			}
			queue = append(queue, out...)
		}
	}
	return nil
}

// --- Minimal presign fixture ---

// minimalCGGMP21Presign creates a mathematically valid normalized Figure 8
// artifact for wire and lifecycle tests. Party 1 owns the full local opening;
// party 2's public commitments are the group identity.
func minimalCGGMP21Presign(tb testing.TB) *Presign {
	one := secp.ScalarOne()
	gamma := secp.ScalarBaseMult(one)
	gammaBytes, err := secp.PointBytes(gamma)
	if err != nil {
		tb.Fatal("PointBytes: " + err.Error())
	}
	littleR := secp.ScalarFromFieldElement(gamma.X)
	transcript := sha256.Sum256([]byte("minimal presign"))
	planHash := sha256.Sum256([]byte("minimal presign plan"))
	presignID := sha256.Sum256([]byte("minimal presign id"))
	var epochSID, epochRID tss.SessionID
	epochSID[0] = 0x41
	epochRID[0] = 0x42
	auxiliaryDigest := sha256.Sum256([]byte("minimal epoch auxiliary digest"))
	epoch, err := NewEpochContext(EpochContextOption{
		SID:       epochSID,
		RID:       epochRID,
		Threshold: 2,
		Parties:   tss.NewPartySet(1, 2),
		PublicShares: []EpochPublicShare{
			{Party: 1, PublicKey: bytes.Clone(gammaBytes)},
			{Party: 2, PublicKey: bytes.Clone(gammaBytes)},
		},
		AuxiliaryDigest: auxiliaryDigest[:],
	})
	if err != nil {
		tb.Fatal("epoch context: " + err.Error())
	}
	ctx := testPresignContext()
	ctx.Derivation.Path = nil
	ctx.Derivation.ResolvedPath = nil
	contextHash := presignContextHash(ctx)
	kShare, err := secpSecretScalarFromScalar(one)
	if err != nil {
		tb.Fatal("k share: " + err.Error())
	}
	chiShare, err := secpSecretScalarFromScalar(one)
	if err != nil {
		tb.Fatal("chi share: " + err.Error())
	}
	return &Presign{state: &presignState{
		Consumed:       NewAtomicBoolWire(false),
		attempt:        newPresignAttemptBinding(false),
		SecurityParams: testSecurityParams(),
		Party:          1,
		Threshold:      2,
		Signers:        tss.NewPartySet(1, 2),
		PresignID:      presignID[:],
		EpochID:        bytes.Clone(epoch.EpochID),
		Gamma:          secp.Clone(gamma),
		LittleR:        littleR,
		KShare:         kShare,
		ChiShare:       chiShare,
		Commitments: []normalizedPresignCommitment{
			{Party: 1, DeltaTilde: bytes.Clone(gammaBytes), STilde: bytes.Clone(gammaBytes)},
			{Party: 2},
		},
		TranscriptHash:       transcript[:],
		Context:              ctx,
		ContextHash:          contextHash,
		PublicKey:            secp.Clone(gamma),
		KeygenTranscriptHash: transcript[:],
		PartiesHash:          tss.PartySetHash(tss.NewPartySet(1, 2), partySetHashLabel),
		PlanHash:             planHash[:],
		Derivation: &tss.DerivationResult{
			Scheme:         tss.DerivationSchemeBIP32Secp256k1,
			ChildPublicKey: bytes.Clone(gammaBytes),
			ChildChainCode: bytes.Repeat([]byte{0x43}, 32),
			AdditiveShift:  secp.ScalarZero().Bytes(),
		},
		Epoch: epoch,
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
