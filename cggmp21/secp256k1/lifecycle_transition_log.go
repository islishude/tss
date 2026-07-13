package secp256k1

import (
	"context"

	"github.com/islishude/tss"
)

type lifecycleLogLevel uint8

const (
	lifecycleLogDebug lifecycleLogLevel = iota
	lifecycleLogInfo
	lifecycleLogWarn
	lifecycleLogError
)

type lifecycleLogEntry struct {
	ctx    context.Context
	level  lifecycleLogLevel
	msg    string
	fields []any
}

// stagedLifecycleLogger records transition effects until replay and live state
// have committed. Rejected staged transitions discard these effects.
type stagedLifecycleLogger struct {
	entries []lifecycleLogEntry
}

// Debug stages a debug-level transition effect.
func (l *stagedLifecycleLogger) Debug(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogDebug, msg, fields)
}

// Info stages an info-level transition effect.
func (l *stagedLifecycleLogger) Info(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogInfo, msg, fields)
}

// Warn stages a warning-level transition effect.
func (l *stagedLifecycleLogger) Warn(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogWarn, msg, fields)
}

// Error stages an error-level transition effect.
func (l *stagedLifecycleLogger) Error(ctx context.Context, msg string, fields ...any) {
	l.record(ctx, lifecycleLogError, msg, fields)
}

func (l *stagedLifecycleLogger) record(ctx context.Context, level lifecycleLogLevel, msg string, fields []any) {
	if l == nil {
		return
	}
	l.entries = append(l.entries, lifecycleLogEntry{
		ctx:    ctx,
		level:  level,
		msg:    msg,
		fields: append([]any(nil), fields...),
	})
}

func (l *stagedLifecycleLogger) flush(target tss.Logger) {
	if l == nil {
		return
	}
	if target == nil {
		target = tss.NopLogger()
	}
	entries := l.entries
	l.entries = nil
	for i := range entries {
		entry := &entries[i]
		switch entry.level {
		case lifecycleLogDebug:
			target.Debug(entry.ctx, entry.msg, entry.fields...)
		case lifecycleLogInfo:
			target.Info(entry.ctx, entry.msg, entry.fields...)
		case lifecycleLogWarn:
			target.Warn(entry.ctx, entry.msg, entry.fields...)
		case lifecycleLogError:
			target.Error(entry.ctx, entry.msg, entry.fields...)
		}
	}
}

func (l *stagedLifecycleLogger) discard() {
	if l == nil {
		return
	}
	for i := range l.entries {
		clear(l.entries[i].fields)
	}
	l.entries = nil
}
