package tss

import "context"

// Logger is the logging interface used by protocol sessions.
// The zero-value is a no-op implementation that discards all messages.
type Logger interface {
	Debug(ctx context.Context, msg string, fields ...any)
	Info(ctx context.Context, msg string, fields ...any)
	Warn(ctx context.Context, msg string, fields ...any)
	Error(ctx context.Context, msg string, fields ...any)
}

type noopLogger struct{}

// Debug is a no-op.
func (noopLogger) Debug(_ context.Context, _ string, _ ...any) {}

// Info is a no-op.
func (noopLogger) Info(_ context.Context, _ string, _ ...any) {}

// Warn is a no-op.
func (noopLogger) Warn(_ context.Context, _ string, _ ...any) {}

// Error is a no-op.
func (noopLogger) Error(_ context.Context, _ string, _ ...any) {}

var nopLogger noopLogger

// NopLogger returns a logger that discards all messages.
func NopLogger() Logger { return nopLogger }

// Logger returns the configured Logger or a no-op implementation when unset.
func (c ThresholdConfig) Logger() Logger {
	if c.Log != nil {
		return c.Log
	}
	return nopLogger
}

// Logger returns the configured Logger or a no-op implementation when unset.
func (c LocalConfig) Logger() Logger {
	if c.Log != nil {
		return c.Log
	}
	return nopLogger
}
