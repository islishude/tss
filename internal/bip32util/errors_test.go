package bip32util

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	errs := []error{
		ErrChainCodeRequired,
		ErrInvalidChainCodeLength,
		ErrInvalidPublicKey,
		ErrHardenedDerivationUnsupported,
		ErrInvalidChild,
		ErrDerivationDepthOverflow,
		ErrInvalidExtendedPublicKey,
	}
	for i, a := range errs {
		if a == nil {
			t.Errorf("sentinel error at index %d is nil", i)
		}
		for j := i + 1; j < len(errs); j++ {
			if errors.Is(a, errs[j]) || errors.Is(errs[j], a) {
				t.Errorf("errors at %d and %d should be distinct", i, j)
			}
		}
	}

	tests := []struct {
		name  string
		err   error
		match error
		want  bool
	}{
		{name: "chain code required matches itself", err: ErrChainCodeRequired, match: ErrChainCodeRequired, want: true},
		{name: "hardened derivation matches itself", err: ErrHardenedDerivationUnsupported, match: ErrHardenedDerivationUnsupported, want: true},
		{name: "distinct sentinels do not match", err: ErrChainCodeRequired, match: ErrInvalidChild, want: false},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := errors.Is(tc.err, tc.match); got != tc.want {
				t.Fatalf("errors.Is(%v, %v) = %v, want %v", tc.err, tc.match, got, tc.want)
			}
		})
	}
}
