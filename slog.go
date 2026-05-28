package tss

import (
	"context"
	"log/slog"
)

// SLogger adapts [log/slog.Logger] to the [Logger] interface.
type SLogger struct{ *slog.Logger }

// NewSLogger returns an SLogger that wraps sl.
func NewSLogger(sl *slog.Logger) *SLogger {
	if sl == nil {
		sl = slog.Default()
	}
	return &SLogger{Logger: sl}
}

// Debug logs at debug level.
func (l *SLogger) Debug(ctx context.Context, msg string, fields ...any) {
	l.LogAttrs(ctx, slog.LevelDebug, msg, pairsToAttrs(fields)...)
}

// Info logs at info level.
func (l *SLogger) Info(ctx context.Context, msg string, fields ...any) {
	l.LogAttrs(ctx, slog.LevelInfo, msg, pairsToAttrs(fields)...)
}

// Warn logs at warn level.
func (l *SLogger) Warn(ctx context.Context, msg string, fields ...any) {
	l.LogAttrs(ctx, slog.LevelWarn, msg, pairsToAttrs(fields)...)
}

// Error logs at error level.
func (l *SLogger) Error(ctx context.Context, msg string, fields ...any) {
	l.LogAttrs(ctx, slog.LevelError, msg, pairsToAttrs(fields)...)
}

func pairsToAttrs(fields []any) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		attrs = append(attrs, slog.Any(key, fields[i+1]))
	}
	return attrs
}
