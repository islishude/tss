package mta

import (
	"bytes"
	"context"
	"crypto/rand"
	"math/big"
	"testing"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// setupTestEnv creates fresh Paillier keys and Ring-Pedersen parameters with
// reduced security parameters for Tier 1 tests.
func setupTestEnv(tb testing.TB) (skA, skB *pai.PrivateKey, rpA, rpB *zkpai.RingPedersenParams) {
	tb.Helper()
	restoreSP := zkpai.SetSecurityParamsForTesting(zkpai.SecurityParams{
		Ell: 256, EllPrime: 512, Epsilon: 64, ChallengeBits: 128, MinPaillierBits: 1024,
	})
	tb.Cleanup(restoreSP)
	var err error
	skA, err = pai.GenerateKey(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	skB, err = pai.GenerateKey(context.Background(), nil, 1024)
	if err != nil {
		tb.Fatal(err)
	}
	rpA, _, err = zkpai.GenerateRingPedersenParams(nil, skA)
	if err != nil {
		tb.Fatal(err)
	}
	rpB, _, err = zkpai.GenerateRingPedersenParams(nil, skB)
	if err != nil {
		tb.Fatal(err)
	}
	return skA, skB, rpA, rpB
}

func seedMessages(tb testing.TB) (*StartMessage, *ResponseMessage) {
	tb.Helper()
	skA, skB, rpA, rpB := setupTestEnv(tb)
	a := big.NewInt(13)
	b := big.NewInt(37)
	bCommit, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(b)))
	if err != nil {
		tb.Fatal(err)
	}
	start, err := Start(nil, a, &skA.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	startProof, err := ProveStartForVerifier(nil, []byte("start"), start, &skA.PublicKey, *rpB)
	if err != nil {
		tb.Fatal(err)
	}
	response, _, err := Respond(nil, []byte("start"), []byte("response"), start.Message, startProof, b, bCommit, &skA.PublicKey, &skB.PublicKey, *rpB, *rpA)
	if err != nil {
		tb.Fatal(err)
	}
	return &start.Message, response
}

func assertPayloadRemarshals[P any](t *testing.T, p P, marshal func(P) ([]byte, error), unmarshal func([]byte) (P, error)) {
	t.Helper()
	raw, err := marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("payload did not remarshal deterministically")
	}
}

// Tier 0: helper validation tests (no crypto keygen).

func TestValidatePositiveIntegerBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "empty", input: nil, wantErr: "empty integer"},
		{name: "zero len", input: []byte{}, wantErr: "empty integer"},
		{name: "leading zero", input: []byte{0x00, 0x01}, wantErr: "non-minimal integer encoding"},
		{name: "zero value", input: []byte{0x00}, wantErr: "non-minimal integer encoding"},
		{name: "all zeros", input: []byte{0x00, 0x00, 0x00}, wantErr: "non-minimal integer encoding"},
		{name: "valid small", input: []byte{0x01}, wantErr: ""},
		{name: "valid medium", input: []byte{0x42}, wantErr: ""},
		{name: "valid large", input: []byte{0xFF, 0xFF, 0xFF}, wantErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePositiveIntegerBytes(tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("got error %q, want %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestScalarFixedBytes(t *testing.T) {
	t.Run("short scalar padded to 32 bytes", func(t *testing.T) {
		x := big.NewInt(13)
		b := scalarFixedBytes(x)
		if len(b) != 32 {
			t.Fatalf("got %d bytes, want 32", len(b))
		}
		if new(big.Int).SetBytes(b).Cmp(x) != 0 {
			t.Fatal("round-trip mismatch")
		}
	})
	t.Run("exact 32 byte scalar", func(t *testing.T) {
		x := new(big.Int)
		for i := range 32 {
			x.Lsh(x, 8)
			x.Or(x, big.NewInt(int64(i+1)))
		}
		b := scalarFixedBytes(x)
		if len(b) != 32 {
			t.Fatalf("got %d bytes, want 32", len(b))
		}
		// Truncation expected — only lower 32 bytes preserved.
		got := new(big.Int).SetBytes(b)
		want := new(big.Int).Mod(x, new(big.Int).Lsh(big.NewInt(1), 256))
		if got.Cmp(want) != 0 {
			t.Fatalf("truncation mismatch")
		}
	})
}

func TestRequireExactMessageTags(t *testing.T) {
	tests := []struct {
		name    string
		fields  []wire.Field
		tags    []uint16
		wantErr string
	}{
		{
			name:    "exact match",
			fields:  []wire.Field{{Tag: 1}, {Tag: 2}},
			tags:    []uint16{1, 2},
			wantErr: "",
		},
		{
			name:    "single field",
			fields:  []wire.Field{{Tag: 42}},
			tags:    []uint16{42},
			wantErr: "",
		},
		{
			name:    "too few fields",
			fields:  []wire.Field{{Tag: 1}},
			tags:    []uint16{1, 2},
			wantErr: "got 1 fields, want 2",
		},
		{
			name:    "too many fields",
			fields:  []wire.Field{{Tag: 1}, {Tag: 2}, {Tag: 3}},
			tags:    []uint16{1, 2},
			wantErr: "got 3 fields, want 2",
		},
		{
			name:    "wrong tag order",
			fields:  []wire.Field{{Tag: 2}, {Tag: 1}},
			tags:    []uint16{1, 2},
			wantErr: "unexpected field tag 2 at index 0",
		},
		{
			name:    "wrong tag at position",
			fields:  []wire.Field{{Tag: 1}, {Tag: 99}},
			tags:    []uint16{1, 2},
			wantErr: "unexpected field tag 99 at index 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireExactMessageTags(tt.fields, tt.tags...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("got error %q, want %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestRandomScalar(t *testing.T) {
	x, err := randomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if x.Sign() <= 0 {
		t.Fatal("random scalar must be positive")
	}
	if x.Cmp(secp.Order()) >= 0 {
		t.Fatal("random scalar out of range")
	}
	for i := range 10 {
		y, err := randomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && x.Cmp(y) == 0 {
			t.Fatal("random scalars are not different")
		}
	}
}

func TestMessageVersion(t *testing.T) {
	if messageVersion != 1 {
		t.Fatal("messageVersion changed; wire format may be incompatible")
	}
}
