package tss

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/islishude/tss/internal/wire"
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

func TestDerivationResultWireRoundTrip(t *testing.T) {
	t.Parallel()

	makeResult := func() *DerivationResult {
		return &DerivationResult{
			Scheme:            DerivationSchemeBIP32Secp256k1,
			ChildPublicKey:    make([]byte, 33),
			ChildChainCode:    make([]byte, 32),
			RequestedPath:     DerivationPath{0, 1, 2},
			ResolvedPath:      DerivationPath{0, 1, 2},
			Depth:             3,
			ParentFingerprint: [4]byte{0xde, 0xad, 0xbe, 0xef},
			ChildNumber:       2,
			AdditiveShift:     make([]byte, 32),
		}
	}

	t.Run("full result with additive shift", func(t *testing.T) {
		t.Parallel()
		r := makeResult()
		raw, err := r.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		decoded, err := UnmarshalDerivationResult(raw)
		if err != nil {
			t.Fatalf("UnmarshalDerivationResult: %v", err)
		}
		if !decoded.Equal(r) {
			t.Fatal("round-trip mismatch")
		}
	})

	t.Run("master path", func(t *testing.T) {
		t.Parallel()
		r := makeResult()
		r.RequestedPath = nil
		r.ResolvedPath = nil
		r.Depth = 0
		raw, err := r.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		decoded, err := UnmarshalDerivationResult(raw)
		if err != nil {
			t.Fatalf("UnmarshalDerivationResult: %v", err)
		}
		if !decoded.Equal(r) {
			t.Fatal("round-trip mismatch for master path")
		}
	})

	t.Run("without additive shift", func(t *testing.T) {
		t.Parallel()
		r := makeResult()
		r.AdditiveShift = nil
		raw, err := r.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		decoded, err := UnmarshalDerivationResult(raw)
		if err != nil {
			t.Fatalf("UnmarshalDerivationResult: %v", err)
		}
		if !decoded.Equal(r) {
			t.Fatal("round-trip mismatch without additive shift")
		}
	})

	t.Run("ed25519 scheme", func(t *testing.T) {
		t.Parallel()
		r := makeResult()
		r.Scheme = DerivationSchemeEd25519KhovratovichLaw
		r.ChildPublicKey = make([]byte, 32)
		r.AdditiveShift = nil
		raw, err := r.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		decoded, err := UnmarshalDerivationResult(raw)
		if err != nil {
			t.Fatalf("UnmarshalDerivationResult: %v", err)
		}
		if !decoded.Equal(r) {
			t.Fatal("round-trip mismatch for ed25519")
		}
	})
}

func TestDerivationResultMarshalDeterministic(t *testing.T) {
	t.Parallel()

	r := &DerivationResult{
		Scheme:            DerivationSchemeBIP32Secp256k1,
		ChildPublicKey:    make([]byte, 33),
		ChildChainCode:    make([]byte, 32),
		RequestedPath:     DerivationPath{0, 1},
		ResolvedPath:      DerivationPath{0, 1},
		Depth:             2,
		ParentFingerprint: [4]byte{0xaa, 0xbb, 0xcc, 0xdd},
		ChildNumber:       1,
		AdditiveShift:     make([]byte, 32),
	}
	first, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("derivation result encoding is not deterministic")
	}
	decoded, err := UnmarshalDerivationResult(first)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reencoded) {
		t.Fatal("re-encoded derivation result differs from original")
	}
}

func TestDerivationResultRejectsMalformed(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		if _, err := UnmarshalDerivationResult(nil); err == nil {
			t.Fatal("nil input accepted")
		}
		if _, err := UnmarshalDerivationResult([]byte{}); err == nil {
			t.Fatal("empty input accepted")
		}
	})

	t.Run("garbage bytes", func(t *testing.T) {
		t.Parallel()
		if _, err := UnmarshalDerivationResult([]byte("not a TLV message")); err == nil {
			t.Fatal("garbage input accepted")
		}
	})

	t.Run("wrong wire type", func(t *testing.T) {
		t.Parallel()
		// Build a valid TLV with the wrong type.
		raw, err := wire.MarshalFields(Version, "tss.wrong-type", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalDerivationResult(raw); err == nil {
			t.Fatal("wrong wire type accepted")
		}
	})
}

func TestDerivationResultValidate(t *testing.T) {
	t.Parallel()

	valid := func() *DerivationResult {
		return &DerivationResult{
			Scheme:            DerivationSchemeBIP32Secp256k1,
			ChildPublicKey:    make([]byte, 33),
			ChildChainCode:    make([]byte, 32),
			RequestedPath:     DerivationPath{0, 1},
			ResolvedPath:      DerivationPath{0, 1},
			Depth:             2,
			ParentFingerprint: [4]byte{1, 2, 3, 4},
			ChildNumber:       1,
			AdditiveShift:     make([]byte, 32),
		}
	}

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()
		if (*DerivationResult)(nil).Validate() == nil {
			t.Fatal("nil receiver accepted")
		}
	})

	t.Run("missing scheme", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.Scheme = ""
		if r.Validate() == nil {
			t.Fatal("missing scheme accepted")
		}
	})

	t.Run("missing child public key", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.ChildPublicKey = nil
		if r.Validate() == nil {
			t.Fatal("missing child public key accepted")
		}
	})

	t.Run("wrong chain code length", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.ChildChainCode = make([]byte, 16)
		if r.Validate() == nil {
			t.Fatal("wrong chain code length accepted")
		}
	})

	t.Run("path depth mismatch", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.RequestedPath = DerivationPath{0, 1, 2}
		if r.Validate() == nil {
			t.Fatal("path depth mismatch accepted")
		}
	})

	t.Run("depth field mismatch", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.Depth = 99
		if r.Validate() == nil {
			t.Fatal("depth field mismatch accepted")
		}
	})

	t.Run("wrong additive shift length", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.AdditiveShift = make([]byte, 16)
		if r.Validate() == nil {
			t.Fatal("wrong additive shift length accepted")
		}
	})

	t.Run("hardened index in path", func(t *testing.T) {
		t.Parallel()
		r := valid()
		r.RequestedPath = DerivationPath{HardenedKeyStart}
		r.ResolvedPath = DerivationPath{HardenedKeyStart}
		r.Depth = 1
		if r.Validate() == nil {
			t.Fatal("hardened index in path accepted")
		}
	})
}

func TestDerivationResultMarshalBinaryNil(t *testing.T) {
	t.Parallel()
	if _, err := (*DerivationResult)(nil).MarshalBinary(); err == nil {
		t.Fatal("nil MarshalBinary accepted")
	}
}

func TestDerivationResultCloneRoundTripViaWire(t *testing.T) {
	t.Parallel()
	original := &DerivationResult{
		Scheme:            DerivationSchemeBIP32Secp256k1,
		ChildPublicKey:    []byte{2, 3, 5, 7, 11},
		ChildChainCode:    bytes.Repeat([]byte{0xcc}, 32),
		RequestedPath:     DerivationPath{44, 0, 0},
		ResolvedPath:      DerivationPath{44, 0, 0},
		Depth:             3,
		ParentFingerprint: [4]byte{0xa, 0xb, 0xc, 0xd},
		ChildNumber:       0,
		AdditiveShift:     bytes.Repeat([]byte{0xaa}, 32),
	}
	raw, err := original.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalDerivationResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	cloned := decoded.Clone()
	if !cloned.Equal(decoded) {
		t.Fatal("clone after wire round-trip differs")
	}
	cloned.ChildPublicKey[0] ^= 0xff
	if cloned.Equal(decoded) {
		t.Fatal("clone should not alias decoded result")
	}
}
