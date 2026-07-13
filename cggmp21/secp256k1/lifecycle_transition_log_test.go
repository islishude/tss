package secp256k1

import (
	"context"
	"errors"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
)

type captureLifecycleLogger struct {
	entries []lifecycleLogEntry
}

func (l *captureLifecycleLogger) Debug(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogDebug, msg, fields)
}

func (l *captureLifecycleLogger) Info(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogInfo, msg, fields)
}

func (l *captureLifecycleLogger) Warn(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogWarn, msg, fields)
}

func (l *captureLifecycleLogger) Error(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogError, msg, fields)
}

func (l *captureLifecycleLogger) record(ctx context.Context, level lifecycleLogLevel, msg string, fields []any) {
	l.entries = append(l.entries, lifecycleLogEntry{
		ctx: ctx, level: level, msg: msg, fields: append([]any(nil), fields...),
	})
}

func TestFast_StagedLifecycleLoggerFlushesOnlyCommittedEffects(t *testing.T) {
	t.Parallel()

	target := new(captureLifecycleLogger)
	staged := new(stagedLifecycleLogger)
	staged.Debug(context.Background(), "debug", "party_id", 1)
	staged.Info(context.Background(), "info", "session_id", "session")
	staged.Warn(context.Background(), "warn")
	staged.Error(context.Background(), "error")
	if len(target.entries) != 0 {
		t.Fatal("staged lifecycle log reached target before commit")
	}
	staged.flush(target)
	if len(target.entries) != 4 {
		t.Fatalf("flushed lifecycle log entries = %d, want 4", len(target.entries))
	}
	for i, want := range []string{"debug", "info", "warn", "error"} {
		if target.entries[i].msg != want {
			t.Fatalf("flushed lifecycle log %d = %q, want %q", i, target.entries[i].msg, want)
		}
	}
	if len(target.entries[0].fields) != 2 || target.entries[0].fields[1] != 1 {
		t.Fatal("staged lifecycle log did not preserve fields")
	}
	staged.flush(target)
	if len(target.entries) != 4 {
		t.Fatal("repeated flush replayed committed lifecycle logs")
	}
	staged.Info(context.Background(), "discarded")
	staged.discard()
	staged.flush(target)
	if len(target.entries) != 4 {
		t.Fatal("discarded lifecycle log reached target")
	}
}

func TestCGGMP21KeygenReplayCommitFailureDoesNotLogStagedSuccess(t *testing.T) {
	session1, out1, session2, out2 := cggmpTwoPartyKeygenSessions(t)
	defer session1.Destroy()
	defer session2.Destroy()
	_, sharesFrom2 := exchangeKeygenCommitmentsForShares(t, session1, out1, session2, out2)
	share := mustCGGMPEnvelope(t, sharesFrom2, payloadKeygenShare, session1.cfg.Self)

	logger := new(captureLifecycleLogger)
	session1.cfg.Log = logger
	cache := tss.NewBoundedReplayCache(1)
	if err := cache.CheckAndStore(tss.MessageSlotKey{
		Protocol: "full-cache", SessionID: session1.cfg.SessionID, Round: 1,
		From: 99, To: 100, PayloadType: "full-cache",
	}, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	session1.guard.ReplayCache = cache

	out, err := session1.Handle(testutil.DeliverEnvelope(share))
	if !errors.Is(err, tss.ErrReplayCacheFull) {
		t.Fatalf("keygen replay commit failure = %v, want ErrReplayCacheFull", err)
	}
	if len(out) != 0 {
		t.Fatalf("keygen replay commit failure emitted %d envelopes", len(out))
	}
	if len(logger.entries) != 0 {
		t.Fatalf("keygen replay commit failure emitted %d staged success logs", len(logger.entries))
	}
}
