package tss

import (
	"errors"
	"reflect"
	"testing"
)

func TestDerivationPathParseStringRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want DerivationPath
	}{
		{in: "m", want: nil},
		{in: "m/0/1/2", want: DerivationPath{0, 1, 2}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDerivationPath(tc.in)
			if err != nil {
				t.Fatalf("ParseDerivationPath(%q): %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("path = %#v, want %#v", got, tc.want)
			}
			if got.String() != tc.in {
				t.Fatalf("String() = %q, want %q", got.String(), tc.in)
			}
		})
	}
}

func TestDerivationPathRejectsMalformedAndHardened(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"",
		"0/1",
		"m/",
		"m//1",
		"m/abc",
		"m/0'/1",
		"m/2147483648",
	} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDerivationPath(input); err == nil {
				t.Fatalf("ParseDerivationPath(%q) succeeded", input)
			}
		})
	}
}

func TestDerivationPathCloneReturnsOwnedCopy(t *testing.T) {
	t.Parallel()
	path := DerivationPath{1, 2, 3}
	clone := path.Clone()
	clone[0] = 99
	if path[0] != 1 {
		t.Fatal("Clone aliases original path")
	}
}

func TestDerivationPathValidateNonHardened(t *testing.T) {
	t.Parallel()
	if err := (DerivationPath{0, HardenedKeyStart - 1}).ValidateNonHardened(); err != nil {
		t.Fatalf("valid non-hardened path rejected: %v", err)
	}
	if err := (DerivationPath{HardenedKeyStart}).ValidateNonHardened(); err == nil {
		t.Fatal("hardened path accepted")
	}
}

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

func TestDerivationResultEqual(t *testing.T) {
	t.Parallel()

	a := &DerivationResult{Scheme: DerivationSchemeBIP32Secp256k1, Depth: 3, ChildNumber: 42}
	b := &DerivationResult{Scheme: DerivationSchemeBIP32Secp256k1, Depth: 3, ChildNumber: 42}

	if !a.Equal(b) {
		t.Fatal("identical results should be equal")
	}
	if !(*DerivationResult)(nil).Equal(nil) {
		t.Fatal("two nil results should be equal")
	}
	if a.Equal(nil) {
		t.Fatal("non-nil should not equal nil")
	}
	if ((*DerivationResult)(nil)).Equal(b) {
		t.Fatal("nil should not equal non-nil")
	}

	// Differ by scheme.
	c := &DerivationResult{Scheme: DerivationSchemeEd25519KhovratovichLaw, Depth: 3, ChildNumber: 42}
	if a.Equal(c) {
		t.Fatal("different schemes should not be equal")
	}

	// Differ by child public key.
	d := a.Clone()
	d.ChildPublicKey = []byte{1, 2, 3}
	if a.Equal(d) {
		t.Fatal("different child public keys should not be equal")
	}

	// Differ by parent fingerprint.
	e := a.Clone()
	e.ParentFingerprint = [4]byte{0xde, 0xad, 0xbe, 0xef}
	if a.Equal(e) {
		t.Fatal("different parent fingerprints should not be equal")
	}

	// Clone should produce equal result.
	cloned := a.Clone()
	if !a.Equal(cloned) {
		t.Fatal("Clone should produce an equal result")
	}
}
