package secp256k1

import (
	"context"
	"slices"
	"testing"
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
		ctx: ctx, level: level, msg: msg, fields: slices.Clone(fields),
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
