package bip32util

import "testing"

func TestResolveDeriveConfig(t *testing.T) {
	t.Parallel()

	if ErrorOnInvalidChild == SkipInvalidChild {
		t.Fatal("ErrorOnInvalidChild and SkipInvalidChild must be distinct")
	}

	tests := []struct {
		name string
		opts []DeriveOption
		want InvalidChildMode
	}{
		{name: "nil options use default", opts: nil, want: ErrorOnInvalidChild},
		{name: "empty options use default", opts: []DeriveOption{}, want: ErrorOnInvalidChild},
		{name: "explicit mode overrides default", opts: []DeriveOption{WithInvalidChildMode(SkipInvalidChild)}, want: SkipInvalidChild},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := ResolveDeriveConfig(tc.opts)
			if cfg.InvalidChildMode != tc.want {
				t.Fatalf("InvalidChildMode = %d, want %d", cfg.InvalidChildMode, tc.want)
			}
		})
	}

	_ = ResolveDeriveConfig([]DeriveOption{WithInvalidChildMode(SkipInvalidChild)})
	if cfg := ResolveDeriveConfig(nil); cfg.InvalidChildMode != ErrorOnInvalidChild {
		t.Fatal("fresh config should keep default after prior override")
	}
}
