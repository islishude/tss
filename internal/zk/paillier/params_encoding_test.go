package paillier

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

type wrongTypeSecurityParams SecurityParams

func (wrongTypeSecurityParams) WireType() string    { return "zk.paillier.wrong-security-params" }
func (wrongTypeSecurityParams) WireVersion() uint16 { return 1 }

type wrongVersionSecurityParams SecurityParams

func (wrongVersionSecurityParams) WireType() string    { return securityParamsWireType }
func (wrongVersionSecurityParams) WireVersion() uint16 { return 2 }

func TestSecurityParamsWireEncoding(t *testing.T) {
	t.Parallel()

	params := DefaultSecurityParams()
	raw, err := params.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	again, err := params.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("SecurityParams encoding is not deterministic")
	}
	decoded, err := tss.DecodeBinaryValue[SecurityParams](raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != params {
		t.Fatalf("decoded params = %+v, want %+v", decoded, params)
	}
	if _, err := tss.DecodeBinaryValue[SecurityParams](append(bytes.Clone(raw), 0)); err == nil {
		t.Fatal("SecurityParams accepted trailing bytes")
	}
}

func TestSecurityParamsWireEncodingRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := (SecurityParams{}).MarshalBinary(); err == nil {
		t.Fatal("zero SecurityParams marshaled successfully")
	}
	invalid := DefaultSecurityParams()
	invalid.ChallengeBits = 257
	if _, err := invalid.MarshalBinary(); err == nil {
		t.Fatal("invalid ChallengeBits marshaled successfully")
	}

	raw, err := DefaultSecurityParams().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw, err = testutil.RewriteWireField(raw, securityParamsWireType, 4, wire.Uint32(257))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValue[SecurityParams](raw); err == nil {
		t.Fatal("invalid encoded ChallengeBits was accepted")
	}

	raw, err = DefaultSecurityParams().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw, err = testutil.RewriteWireField(raw, securityParamsWireType, 1, wire.Uint32(^uint32(0)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValue[SecurityParams](raw); err == nil {
		t.Fatal("overflowing encoded proof range was accepted")
	}

	wrongType, err := wire.Marshal(wrongTypeSecurityParams(DefaultSecurityParams()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValue[SecurityParams](wrongType); err == nil {
		t.Fatal("wrong wire type was accepted")
	}
	wrongVersion, err := wire.Marshal(wrongVersionSecurityParams(DefaultSecurityParams()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryValue[SecurityParams](wrongVersion); err == nil {
		t.Fatal("wrong wire version was accepted")
	}
}
