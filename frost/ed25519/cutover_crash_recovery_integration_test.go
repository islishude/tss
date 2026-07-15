//go:build integration

package ed25519

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testharness"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROST_Refresh_CutoverCrashRestartUsesDurableGeneration(t *testing.T) {
	seed := testutil.SeedFromEnv(t, 1701)
	parties := tss.NewPartySet(1, 2, 3)
	source := frostKeygen(t, 2, len(parties))
	defer destroyCrashRecoveryShares(source)
	target, targetSessionID := runCrashRecoveryRefresh(t, source, parties, seed)
	defer destroyCrashRecoveryShares(target)

	sourceSessionID := source[1].KeygenSessionID()
	if targetSessionID == sourceSessionID {
		t.Fatal("refresh fixture reused the source generation identifier")
	}
	wantPublicKey := mustKeyShareMetadata(t, source[1]).PublicKey.Bytes()

	for _, tc := range []struct {
		name          string
		point         testharness.CrashPoint
		wantSessionID tss.SessionID
	}{
		{name: "before persist reloads source", point: testharness.CrashBeforePersist, wantSessionID: sourceSessionID},
		{name: "after persist reloads target", point: testharness.CrashAfterPersist, wantSessionID: targetSessionID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stores := make(map[tss.PartyID]*testharness.CrashyStore, len(parties))
			initial := make(map[tss.PartyID][]byte, len(parties))
			defer destroyCrashRecoveryStores(stores)
			defer clearCrashRecoveryBlobs(initial)

			for _, party := range parties {
				initial[party] = marshalCrashRecoveryShare(t, source[party])
				stores[party] = testharness.NewCrashyStore(initial[party], tc.point)
			}
			for _, party := range parties {
				replacement := marshalCrashRecoveryShare(t, target[party])
				if err := stores[party].CompareAndSwap(initial[party], replacement); !errors.Is(err, testharness.ErrCrashInjected) {
					t.Fatalf("party %d cutover error = %v, want ErrCrashInjected", party, err)
				}
			}
			clearCrashRecoveryBlobs(initial)

			// A restarted process has only the authoritative durable blobs. The
			// protocol-session and candidate objects above are deliberately not
			// used for recovery or signing.
			recovered := make(map[tss.PartyID]*KeyShare, len(parties))
			defer destroyCrashRecoveryShares(recovered)
			for _, party := range parties {
				share := loadCrashRecoveryShare(t, stores[party])
				if share == nil {
					t.Fatalf("party %d durable generation is missing", party)
				}
				if got := share.KeygenSessionID(); got != tc.wantSessionID {
					t.Fatalf("party %d recovered the wrong lifecycle generation", party)
				}
				recovered[party] = share
			}
			assertCrashRecoverySignature(
				t,
				wantPublicKey,
				[]byte("frost refresh crash restart"),
				recovered[1],
				recovered[2],
			)
		})
	}
}

func TestFROST_Reshare_CutoverCrashRestartUsesDurableCommittee(t *testing.T) {
	seed := testutil.SeedFromEnv(t, 2701)
	oldParties := tss.NewPartySet(1, 2, 3)
	newParties := tss.NewPartySet(2, 3, 4)
	allParties := tss.NewPartySet(1, 2, 3, 4)
	source := frostKeygen(t, 2, len(oldParties))
	defer destroyCrashRecoveryShares(source)
	target, targetSessionID := runCrashRecoveryReshare(t, source, oldParties, newParties, seed)
	defer destroyCrashRecoveryShares(target)

	sourceSessionID := source[1].KeygenSessionID()
	if targetSessionID == sourceSessionID {
		t.Fatal("reshare fixture reused the source generation identifier")
	}
	wantPublicKey := mustKeyShareMetadata(t, source[1]).PublicKey.Bytes()

	for _, tc := range []struct {
		name          string
		point         testharness.CrashPoint
		wantParties   tss.PartySet
		wantSessionID tss.SessionID
		signers       tss.PartySet
	}{
		{
			name:          "before persist reloads old committee",
			point:         testharness.CrashBeforePersist,
			wantParties:   oldParties,
			wantSessionID: sourceSessionID,
			signers:       tss.NewPartySet(1, 2),
		},
		{
			name:          "after persist reloads new committee",
			point:         testharness.CrashAfterPersist,
			wantParties:   newParties,
			wantSessionID: targetSessionID,
			signers:       tss.NewPartySet(2, 4),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stores := make(map[tss.PartyID]*testharness.CrashyStore, len(allParties))
			initial := make(map[tss.PartyID][]byte, len(oldParties))
			defer destroyCrashRecoveryStores(stores)
			defer clearCrashRecoveryBlobs(initial)

			for _, party := range allParties {
				if source[party] != nil {
					initial[party] = marshalCrashRecoveryShare(t, source[party])
				}
				stores[party] = testharness.NewCrashyStore(initial[party], tc.point)
			}
			for _, party := range allParties {
				var replacement []byte
				if target[party] != nil {
					replacement = marshalCrashRecoveryShare(t, target[party])
				}
				if err := stores[party].CompareAndSwap(initial[party], replacement); !errors.Is(err, testharness.ErrCrashInjected) {
					t.Fatalf("party %d cutover error = %v, want ErrCrashInjected", party, err)
				}
			}
			clearCrashRecoveryBlobs(initial)

			recovered := make(map[tss.PartyID]*KeyShare, len(tc.wantParties))
			defer destroyCrashRecoveryShares(recovered)
			for _, party := range allParties {
				share := loadCrashRecoveryShare(t, stores[party])
				wantPresent := tc.wantParties.Contains(party)
				if (share != nil) != wantPresent {
					t.Fatalf("party %d durable membership does not match recovered committee", party)
				}
				if share == nil {
					continue
				}
				if got := share.KeygenSessionID(); got != tc.wantSessionID {
					t.Fatalf("party %d recovered the wrong lifecycle generation", party)
				}
				recovered[party] = share
			}
			assertCrashRecoverySignature(
				t,
				wantPublicKey,
				[]byte("frost reshare crash restart"),
				recovered[tc.signers[0]],
				recovered[tc.signers[1]],
			)
		})
	}
}

func TestFROST_RefreshScheduler_CommitOwnershipFollowsDurableOutcome(t *testing.T) {
	seed := testutil.SeedFromEnv(t, 3701)
	parties := tss.NewPartySet(1, 2, 3)
	source := frostKeygen(t, 2, len(parties))
	defer destroyCrashRecoveryShares(source)
	target, targetSessionID := runCrashRecoveryRefresh(t, source, parties, seed)
	defer destroyCrashRecoveryShares(target)
	sourceSessionID := source[1].KeygenSessionID()

	for _, tc := range []struct {
		name              string
		point             testharness.CrashPoint
		outcomeUnknown    bool
		wantDurable       tss.SessionID
		wantCandidateLive bool
	}{
		{
			name:        "definite failure destroys candidate",
			point:       testharness.CrashBeforePersist,
			wantDurable: sourceSessionID,
		},
		{
			name:              "unknown outcome preserves callback ownership",
			point:             testharness.CrashAfterPersist,
			outcomeUnknown:    true,
			wantDurable:       targetSessionID,
			wantCandidateLive: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initial := marshalCrashRecoveryShare(t, source[1])
			defer clear(initial)
			store := testharness.NewCrashyStore(initial, tc.point)
			defer store.Destroy()

			runner := &crashRecoveryRefreshRunner{candidate: target[1]}
			var callbackCandidate *KeyShare
			options := tss.RefreshSchedulerOptions[*KeyShare]{
				Interval:    time.Hour,
				Transport:   crashRecoveryRefreshTransport{},
				Runner:      runner,
				ReplayCache: tss.NewInMemoryReplayCache(),
				AckVerifier: tss.NewInMemoryAckVerifier(func(tss.PartyID, [32]byte, []byte) error { return nil }),
				LoadKeyShare: func(context.Context) (*KeyShare, error) {
					return source[1], nil
				},
				SessionIDSource: func(context.Context, *KeyShare) (tss.SessionID, error) {
					return targetSessionID, nil
				},
				ClaimSessionID: func(context.Context, tss.SessionID) error { return nil },
				CommitKeyShare: func(_ context.Context, previous, refreshed *KeyShare) error {
					if previous != source[1] {
						return errors.New("scheduler supplied a non-authoritative source share")
					}
					callbackCandidate = refreshed
					replacement, err := refreshed.MarshalBinary()
					if err != nil {
						return err
					}
					err = store.CompareAndSwap(initial, replacement)
					if err == nil {
						return errors.New("crash store did not inject the configured persistence failure")
					}
					if tc.outcomeUnknown {
						return fmt.Errorf("durable commit may have succeeded: %w: %w", tss.ErrRefreshCommitOutcomeUnknown, err)
					}
					return err
				},
			}
			scheduler, err := tss.NewRefreshScheduler(options)
			if err != nil {
				t.Fatal(err)
			}
			err = scheduler.RunOnce(context.Background())
			clear(initial)
			if !errors.Is(err, testharness.ErrCrashInjected) {
				t.Fatalf("RunOnce error = %v, want ErrCrashInjected", err)
			}
			if got := errors.Is(err, tss.ErrRefreshCommitOutcomeUnknown); got != tc.outcomeUnknown {
				t.Fatalf("unknown-outcome classification = %v, want %v", got, tc.outcomeUnknown)
			}
			if callbackCandidate == nil {
				t.Fatal("commit callback did not receive the refreshed candidate")
			}
			candidateLive := callbackCandidate.ValidateConsistency() == nil
			if candidateLive != tc.wantCandidateLive {
				t.Fatalf("callback candidate live = %v, want %v", candidateLive, tc.wantCandidateLive)
			}
			if candidateLive {
				defer callbackCandidate.Destroy()
			}

			// Reconciliation is based on a fresh authoritative read, even when
			// the callback still owns a valid in-memory candidate.
			authoritative := loadCrashRecoveryShare(t, store)
			if authoritative == nil {
				t.Fatal("authoritative durable generation is missing")
			}
			defer authoritative.Destroy()
			if got := authoritative.KeygenSessionID(); got != tc.wantDurable {
				t.Fatal("authoritative durable read returned the wrong generation")
			}
		})
	}
}

type crashRecoveryRefreshRunner struct {
	candidate *KeyShare
}

func (*crashRecoveryRefreshRunner) Protocol() tss.ProtocolID {
	return tss.ProtocolFROSTEd25519
}

func (r *crashRecoveryRefreshRunner) StartRefresh(context.Context, *KeyShare, tss.RefreshRunConfig) (tss.RefreshSession[*KeyShare], []tss.Envelope, error) {
	if r == nil || r.candidate == nil {
		return nil, nil, errors.New("missing crash-recovery refresh candidate")
	}
	return &crashRecoveryRefreshSession{candidate: r.candidate.Clone()}, nil, nil
}

type crashRecoveryRefreshSession struct {
	candidate *KeyShare
}

func (*crashRecoveryRefreshSession) Handle(tss.InboundEnvelope) ([]tss.Envelope, error) {
	return nil, errors.New("completed crash-recovery refresh session received an envelope")
}

func (s *crashRecoveryRefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil || s.candidate == nil {
		return nil, false
	}
	return s.candidate.Clone(), true
}

func (s *crashRecoveryRefreshSession) Destroy() {
	if s == nil || s.candidate == nil {
		return
	}
	s.candidate.Destroy()
	s.candidate = nil
}

type crashRecoveryRefreshTransport struct{}

func (crashRecoveryRefreshTransport) Send(context.Context, tss.Envelope) error { return nil }

func (crashRecoveryRefreshTransport) Broadcast(context.Context, tss.Envelope) error { return nil }

func (crashRecoveryRefreshTransport) Receive(context.Context) (tss.InboundEnvelope, error) {
	return tss.InboundEnvelope{}, errors.New("completed crash-recovery refresh session requested input")
}

func runCrashRecoveryRefresh(
	t *testing.T,
	source map[tss.PartyID]*KeyShare,
	parties tss.PartySet,
	seed int64,
) (map[tss.PartyID]*KeyShare, tss.SessionID) {
	t.Helper()
	sessionID := testutil.MustSessionID(seed + 1)
	sessions := make(map[tss.PartyID]*ReshareSession, len(parties))
	messages := make([]tss.Envelope, 0)
	for _, party := range parties {
		session, out, err := startFROSTRefresh(source[party], tss.ThresholdConfig{
			Threshold: source[party].Threshold(),
			Parties:   parties,
			Self:      party,
			SessionID: sessionID,
			Rand:      testutil.DeterministicReader(seed + int64(party) + 10),
		})
		if err != nil {
			t.Fatalf("start refresh for party %d: %v", party, err)
		}
		sessions[party] = session
		messages = append(messages, out...)
	}
	defer destroyCrashRecoverySessions(sessions)
	deliverReshareMessages(t, parties, messages, sessions)
	return collectReshareShares(t, parties, sessions), sessionID
}

func runCrashRecoveryReshare(
	t *testing.T,
	source map[tss.PartyID]*KeyShare,
	oldParties, newParties tss.PartySet,
	seed int64,
) (map[tss.PartyID]*KeyShare, tss.SessionID) {
	t.Helper()
	sessionID := testutil.MustSessionID(seed + 1)
	allParties := tss.MergePartySet(oldParties, newParties)
	sessions := make(map[tss.PartyID]*ReshareSession, len(allParties))
	messages := make([]tss.Envelope, 0)
	for _, party := range oldParties {
		session, out, err := startFROSTReshare(source[party], newParties, 2, tss.ThresholdConfig{
			Threshold: 2,
			Parties:   oldParties,
			Self:      party,
			SessionID: sessionID,
			Rand:      testutil.DeterministicReader(seed + int64(party) + 20),
		})
		if err != nil {
			t.Fatalf("start reshare dealer %d: %v", party, err)
		}
		sessions[party] = session
		messages = append(messages, out...)
	}
	for _, party := range newParties {
		if oldParties.Contains(party) {
			continue
		}
		recipient, err := startFROSTReshareRecipient(source[oldParties[0]], oldParties, newParties, 2, tss.ThresholdConfig{
			Threshold: 2,
			Parties:   newParties,
			Self:      party,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatalf("start reshare recipient %d: %v", party, err)
		}
		sessions[party] = recipient
	}
	defer destroyCrashRecoverySessions(sessions)
	deliverReshareMessages(t, allParties, messages, sessions)
	return collectReshareShares(t, newParties, sessions), sessionID
}

func marshalCrashRecoveryShare(t *testing.T, share *KeyShare) []byte {
	t.Helper()
	if share == nil {
		t.Fatal("cannot persist a nil key share")
	}
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal crash-recovery key share: %v", err)
	}
	return raw
}

func loadCrashRecoveryShare(t *testing.T, store *testharness.CrashyStore) *KeyShare {
	t.Helper()
	raw := store.Load()
	defer clear(raw)
	if len(raw) == 0 {
		return nil
	}
	share, err := tss.DecodeBinary[KeyShare](raw)
	if err != nil {
		t.Fatalf("decode authoritative crash-recovery key share: %v", err)
	}
	return share
}

func assertCrashRecoverySignature(t *testing.T, wantPublicKey, message []byte, signers ...*KeyShare) {
	t.Helper()
	publicKey, signature, err := signFROSTSimulation(message, signers, testFROSTSigningContext())
	if err != nil {
		t.Fatalf("sign with recovered generation: %v", err)
	}
	if !bytes.Equal(publicKey, wantPublicKey) {
		t.Fatal("recovered generation changed the group public key")
	}
	if !stded25519.Verify(stded25519.PublicKey(publicKey), message, signature) {
		t.Fatal("recovered generation produced an invalid signature")
	}
}

func destroyCrashRecoverySessions(sessions map[tss.PartyID]*ReshareSession) {
	for party, session := range sessions {
		if session != nil {
			session.Destroy()
		}
		delete(sessions, party)
	}
}

func destroyCrashRecoveryShares(shares map[tss.PartyID]*KeyShare) {
	for party, share := range shares {
		if share != nil {
			share.Destroy()
		}
		delete(shares, party)
	}
}

func destroyCrashRecoveryStores(stores map[tss.PartyID]*testharness.CrashyStore) {
	for party, store := range stores {
		if store != nil {
			store.Destroy()
		}
		delete(stores, party)
	}
}

func clearCrashRecoveryBlobs(blobs map[tss.PartyID][]byte) {
	for party, blob := range blobs {
		clear(blob)
		delete(blobs, party)
	}
}
