package tss

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"
)

func TestThresholdConfigCtx(t *testing.T) {
	t.Run("nil context returns background", func(t *testing.T) {
		cfg := ThresholdConfig{}
		ctx := cfg.Ctx()
		if ctx == nil {
			t.Fatal("expected non-nil context")
		}
		if ctx != context.Background() {
			t.Error("expected context.Background() when Context is nil")
		}
	})

	t.Run("set context returned as-is", func(t *testing.T) {
		type ctxKey struct{}
		parent := context.WithValue(context.Background(), ctxKey{}, "value")
		cfg := ThresholdConfig{Context: parent}
		ctx := cfg.Ctx()
		if ctx != parent {
			t.Error("expected the exact configured context")
		}
		if v, ok := ctx.Value(ctxKey{}).(string); !ok || v != "value" {
			t.Error("configured context lost its values")
		}
	})
}

func TestThresholdConfigValidate(t *testing.T) {
	valid := func() ThresholdConfig {
		return ThresholdConfig{
			Threshold: 2,
			Parties:   []PartyID{1, 2, 3},
			Self:      1,
		}
	}

	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			name string
			cfg  ThresholdConfig
		}{
			{"2-of-3", ThresholdConfig{Threshold: 2, Parties: []PartyID{1, 2, 3}, Self: 1}},
			{"3-of-3", ThresholdConfig{Threshold: 3, Parties: []PartyID{1, 2, 3}, Self: 1}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.cfg.Validate(); err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("1-of-1 requires explicit AllowOneOfOne", func(t *testing.T) {
		// Production defaults reject 1-of-1.
		cfg1 := ThresholdConfig{Threshold: 1, Parties: []PartyID{5}, Self: 5}
		if err := cfg1.Validate(); err == nil {
			t.Error("expected error for 1-of-1 without explicit AllowOneOfOne")
		}
		// Explicitly enabling AllowOneOfOne with MinProductionThreshold=1 allows it.
		limits := ThresholdLimits{
			MaxParties:              DefaultMaxParties,
			MaxThreshold:            DefaultMaxThreshold,
			MaxSigners:              DefaultMaxSigners,
			AllowOneOfOne:           true,
			MinProductionThreshold:  1,
			AllowOversizedSignerSet: false,
		}
		if err := cfg1.ValidateWithLimits(limits); err != nil {
			t.Errorf("1-of-1 with explicit AllowOneOfOne should pass: %v", err)
		}
	})
	t.Run("threshold zero or negative", func(t *testing.T) {
		cfg := valid()
		cfg.Threshold = 0
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for threshold=0")
		}
		cfg.Threshold = -1
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for threshold=-1")
		}
	})

	t.Run("empty parties", func(t *testing.T) {
		cfg := valid()
		cfg.Parties = nil
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for nil parties")
		}
		cfg.Parties = []PartyID{}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for empty parties")
		}
	})

	t.Run("threshold exceeds party count", func(t *testing.T) {
		cfg := valid()
		cfg.Threshold = 4 // parties has 3
		if err := cfg.Validate(); err == nil {
			t.Error("expected error when threshold > len(parties)")
		}
	})

	t.Run("reserved party id zero", func(t *testing.T) {
		cfg := valid()
		cfg.Parties = []PartyID{0, 2, 3}
		cfg.Self = 2
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for party id 0")
		}
	})

	t.Run("duplicate party ids", func(t *testing.T) {
		cfg := valid()
		cfg.Parties = []PartyID{1, 2, 2}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for duplicate party ids")
		}
	})

	t.Run("self not in parties", func(t *testing.T) {
		cfg := valid()
		cfg.Self = 99
		if err := cfg.Validate(); err == nil {
			t.Error("expected error when self is not in parties")
		}
	})

	t.Run("self matches but with duplicate", func(t *testing.T) {
		// Duplicate is caught before the self-in-parties check.
		cfg := ThresholdConfig{
			Threshold: 2,
			Parties:   []PartyID{1, 1, 3},
			Self:      3,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for duplicate party ids")
		}
	})
}

func TestThresholdConfigSortedParties(t *testing.T) {
	t.Run("already sorted", func(t *testing.T) {
		cfg := ThresholdConfig{Parties: []PartyID{1, 2, 3, 4, 5}}
		got := cfg.SortedParties()
		want := []PartyID{1, 2, 3, 4, 5}
		if !partySlicesEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		// Verify original backing array is not shared (it's a clone).
		if len(got) > 0 && &cfg.Parties[0] == &got[0] {
			t.Error("sorted parties must be a clone, not the original slice")
		}
	})

	t.Run("reversed order", func(t *testing.T) {
		cfg := ThresholdConfig{Parties: []PartyID{5, 4, 3, 2, 1}}
		got := cfg.SortedParties()
		want := []PartyID{1, 2, 3, 4, 5}
		if !partySlicesEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("random non-contiguous", func(t *testing.T) {
		cfg := ThresholdConfig{Parties: []PartyID{42, 7, 100, 3, 15}}
		got := cfg.SortedParties()
		want := []PartyID{3, 7, 15, 42, 100}
		if !partySlicesEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("preserves original order", func(t *testing.T) {
		original := []PartyID{3, 1, 2}
		cfg := ThresholdConfig{Parties: original}
		cfg.SortedParties()
		if original[0] != 3 || original[1] != 1 || original[2] != 2 {
			t.Error("SortedParties mutated the original parties slice")
		}
	})
}

func TestThresholdConfigReader(t *testing.T) {
	t.Run("nil rand returns crypto/rand", func(t *testing.T) {
		cfg := ThresholdConfig{}
		r := cfg.Reader()
		if r == nil {
			t.Fatal("expected non-nil reader")
		}
		if r != rand.Reader {
			t.Error("expected rand.Reader when Rand is nil")
		}
	})

	t.Run("configured rand returned", func(t *testing.T) {
		custom := &bytes.Buffer{}
		cfg := ThresholdConfig{Rand: custom}
		r := cfg.Reader()
		if r != custom {
			t.Error("expected the exact configured Rand reader")
		}
	})
}

func TestThresholdConfigLogger(t *testing.T) {
	t.Run("nil log returns noop", func(t *testing.T) {
		cfg := ThresholdConfig{}
		l := cfg.Logger()
		if l == nil {
			t.Fatal("expected non-nil logger")
		}
		// Calling methods on the noop logger must not panic.
		l.Debug(context.Background(), "test")
		l.Info(context.Background(), "test")
		l.Warn(context.Background(), "test")
		l.Error(context.Background(), "test")
	})

	t.Run("configured logger returned", func(t *testing.T) {
		custom := &testLogger{}
		cfg := ThresholdConfig{Log: custom}
		l := cfg.Logger()
		if l != custom {
			t.Error("expected the exact configured Logger")
		}
	})
}

func TestThresholdConfigZeroValue(t *testing.T) {
	// All methods must be safe to call on the zero value of ThresholdConfig.
	var zero ThresholdConfig
	_ = zero.Ctx()
	_ = zero.Reader()
	_ = zero.Logger()
	_ = zero.SortedParties()
	// Validate is expected to fail on the zero value, but must not panic.
	if err := zero.Validate(); err == nil {
		t.Error("expected Validate to fail on zero-value ThresholdConfig")
	}
}

func TestThresholdConfigLogAndTimeoutFields(t *testing.T) {
	// Log and RoundTimeout are stored as-is with no getter transformation.
	logger := &testLogger{}
	timeout := 5 * time.Second
	cfg := ThresholdConfig{
		Log:          logger,
		RoundTimeout: timeout,
	}
	if cfg.Log != logger {
		t.Error("Log field mismatch")
	}
	if cfg.RoundTimeout != timeout {
		t.Error("RoundTimeout field mismatch")
	}
}

// partySlicesEqual compares two PartyID slices for equality.
func partySlicesEqual(a, b []PartyID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testLogger implements Logger for testing.
type testLogger struct{}

func (l *testLogger) Debug(_ context.Context, _ string, _ ...any) {}
func (l *testLogger) Info(_ context.Context, _ string, _ ...any)  {}
func (l *testLogger) Warn(_ context.Context, _ string, _ ...any)  {}
func (l *testLogger) Error(_ context.Context, _ string, _ ...any) {}
