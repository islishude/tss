package tss

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewSLogger(t *testing.T) {
	t.Parallel()
	t.Run("nil logger uses default", func(t *testing.T) {
		sl := NewSLogger(nil)
		if sl == nil {
			t.Fatal("expected non-nil SLogger")
		}
		if sl.Logger == nil {
			t.Fatal("expected non-nil underlying logger")
		}
		// Must not panic when logging.
		sl.Info(context.Background(), "test")
	})

	t.Run("explicit logger returned", func(t *testing.T) {
		custom := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
		sl := NewSLogger(custom)
		if sl.Logger != custom {
			t.Error("expected the exact configured slog.Logger")
		}
	})
}

func TestSLoggerMethods(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	sl := NewSLogger(slog.New(handler))

	ctx := context.Background()

	t.Run("Debug", func(t *testing.T) {
		buf.Reset()
		sl.Debug(ctx, "debug msg", "key1", "val1")
		entry := parseJSONLog(t, &buf)
		if entry.Level != "DEBUG" {
			t.Errorf("level = %q, want DEBUG", entry.Level)
		}
		if entry.Message != "debug msg" {
			t.Errorf("msg = %q, want %q", entry.Message, "debug msg")
		}
		if entry.extra["key1"] != "val1" {
			t.Errorf("key1 = %v, want val1", entry.extra["key1"])
		}
	})

	t.Run("Info", func(t *testing.T) {
		buf.Reset()
		sl.Info(ctx, "info msg", "foo", 42)
		entry := parseJSONLog(t, &buf)
		if entry.Level != "INFO" {
			t.Errorf("level = %q, want INFO", entry.Level)
		}
		if entry.Message != "info msg" {
			t.Errorf("msg = %q, want %q", entry.Message, "info msg")
		}
		if v, ok := entry.extra["foo"]; !ok {
			t.Error("missing key foo")
		} else if n, ok := v.(float64); !ok || n != 42 {
			t.Errorf("foo = %v, want 42", v)
		}
	})

	t.Run("Warn", func(t *testing.T) {
		buf.Reset()
		sl.Warn(ctx, "warn msg", "alert", true)
		entry := parseJSONLog(t, &buf)
		if entry.Level != "WARN" {
			t.Errorf("level = %q, want WARN", entry.Level)
		}
		if entry.Message != "warn msg" {
			t.Errorf("msg = %q, want %q", entry.Message, "warn msg")
		}
		if v, ok := entry.extra["alert"]; !ok {
			t.Error("missing key alert")
		} else if b, ok := v.(bool); !ok || !b {
			t.Errorf("alert = %v, want true", v)
		}
	})

	t.Run("Error", func(t *testing.T) {
		buf.Reset()
		sl.Error(ctx, "error msg", "code", 500)
		entry := parseJSONLog(t, &buf)
		if entry.Level != "ERROR" {
			t.Errorf("level = %q, want ERROR", entry.Level)
		}
		if entry.Message != "error msg" {
			t.Errorf("msg = %q, want %q", entry.Message, "error msg")
		}
		if v, ok := entry.extra["code"]; !ok {
			t.Error("missing key code")
		} else if n, ok := v.(float64); !ok || n != 500 {
			t.Errorf("code = %v, want 500", v)
		}
	})

	t.Run("no fields", func(t *testing.T) {
		buf.Reset()
		sl.Info(ctx, "no fields")
		entry := parseJSONLog(t, &buf)
		if entry.Message != "no fields" {
			t.Errorf("msg = %q", entry.Message)
		}
		// Extra fields (other than time, level, msg) should be absent.
		if len(entry.extra) != 0 {
			t.Errorf("expected no extra fields, got %v", entry.extra)
		}
	})
}

func TestPairsToAttrs(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		attrs := pairsToAttrs(nil)
		if len(attrs) != 0 {
			t.Errorf("expected 0 attrs, got %d", len(attrs))
		}
	})

	t.Run("even number of string-keyed pairs", func(t *testing.T) {
		attrs := pairsToAttrs([]any{"a", 1, "b", "two"})
		if len(attrs) != 2 {
			t.Fatalf("expected 2 attrs, got %d", len(attrs))
		}
		if attrs[0].Key != "a" {
			t.Errorf("attrs[0].Key = %q", attrs[0].Key)
		}
		if attrs[1].Key != "b" {
			t.Errorf("attrs[1].Key = %q", attrs[1].Key)
		}
	})

	t.Run("odd number drops last unpaired", func(t *testing.T) {
		attrs := pairsToAttrs([]any{"x", 1, "y"})
		if len(attrs) != 1 {
			t.Fatalf("expected 1 attr, got %d", len(attrs))
		}
		if attrs[0].Key != "x" {
			t.Errorf("attrs[0].Key = %q", attrs[0].Key)
		}
	})

	t.Run("non-string key skipped", func(t *testing.T) {
		attrs := pairsToAttrs([]any{42, "val", "good", "val"})
		if len(attrs) != 1 {
			t.Fatalf("expected 1 attr, got %d", len(attrs))
		}
		if attrs[0].Key != "good" {
			t.Errorf("attrs[0].Key = %q, want good", attrs[0].Key)
		}
	})

	t.Run("multiple non-string keys skipped", func(t *testing.T) {
		attrs := pairsToAttrs([]any{true, "v1", "ok", "v2", 3.14, "v3"})
		// true is not string -> skip; "ok"->"v2" kept; 3.14 not string -> skip last unpaired
		if len(attrs) != 1 {
			t.Fatalf("expected 1 attr, got %d", len(attrs))
		}
		if attrs[0].Key != "ok" {
			t.Errorf("attrs[0].Key = %q, want ok", attrs[0].Key)
		}
	})

	t.Run("mixed valid and invalid", func(t *testing.T) {
		attrs := pairsToAttrs([]any{"valid", "value", 99, "dropped", "also", true})
		if len(attrs) != 2 {
			t.Fatalf("expected 2 attrs, got %d", len(attrs))
		}
		if attrs[0].Key != "valid" {
			t.Errorf("attrs[0].Key = %q", attrs[0].Key)
		}
		if attrs[1].Key != "also" {
			t.Errorf("attrs[1].Key = %q", attrs[1].Key)
		}
	})
}

func TestSLoggerImplementsLogger(t *testing.T) {
	t.Parallel()
	// Compile-time check: *SLogger must implement Logger.
	var _ Logger = (*SLogger)(nil)
}

// logEntry holds the parsed fields from a JSON log line.
type logEntry struct {
	Level   string
	Message string
	extra   map[string]any
}

func parseJSONLog(t *testing.T, buf *bytes.Buffer) logEntry {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("empty log output")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatalf("invalid JSON log: %v", err)
	}
	entry := logEntry{extra: make(map[string]any)}
	if v, ok := raw["level"]; ok {
		entry.Level, _ = v.(string)
	}
	if v, ok := raw["msg"]; ok {
		entry.Message, _ = v.(string)
	}
	for k, v := range raw {
		if k == "level" || k == "msg" || k == "time" {
			continue
		}
		entry.extra[k] = v
	}
	return entry
}
