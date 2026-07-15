package ed25519

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestVerificationShareCanonicalBinaryEncoding(t *testing.T) {
	t.Parallel()
	share := testFROSTVerificationShare(t)
	raw1, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("verification share encoding is not deterministic")
	}
	var decoded VerificationShare
	if err := decoded.UnmarshalBinary(raw1); err != nil {
		t.Fatal(err)
	}
	if decoded.Party != share.Party || !decoded.PublicKey.Equal(share.PublicKey) {
		t.Fatal("verification share changed after round trip")
	}
	if err := decoded.UnmarshalBinary(append(raw1, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}

func TestVerificationShareRejectsMalformedAndOversizedFields(t *testing.T) {
	t.Parallel()
	share := testFROSTVerificationShare(t)
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := testutil.RewriteWireFieldByName(
		raw,
		verificationShareWireType,
		VerificationShare{},
		"Party",
		wire.Uint32(tss.BroadcastPartyId),
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded VerificationShare
	if err := decoded.UnmarshalBinary(mutated); err == nil {
		t.Fatal("accepted zero verification-share party")
	}

	limits := DefaultLimits()
	limits.Curve.MaxPointBytes = len(share.PublicKey.Bytes()) - 1
	if _, err := share.MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("encoded verification share above point limit")
	}
}

func TestVerificationShareRejectsIdentityEncodings(t *testing.T) {
	t.Parallel()
	identity := make([]byte, 32)
	identity[0] = 1
	if _, err := NewVerificationSharePoint(identity); err == nil {
		t.Fatal("verification-share constructor accepted the identity")
	}

	share := testFROSTVerificationShare(t)
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		point []byte
	}{
		{name: "canonical", point: identity},
		{name: "non-canonical", point: func() []byte {
			out := bytes.Clone(identity)
			out[len(out)-1] |= 0x80
			return out
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated, err := testutil.RewriteWireFieldByName(
				raw,
				verificationShareWireType,
				VerificationShare{},
				"PublicKey",
				tc.point,
			)
			if err != nil {
				t.Fatal(err)
			}
			var decoded VerificationShare
			if err := decoded.UnmarshalBinary(mutated); err == nil {
				t.Fatalf("verification-share wire accepted the %s identity encoding", tc.name)
			}
		})
	}
}

func testFROSTVerificationShare(t testing.TB) VerificationShare {
	t.Helper()
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := newVerificationSharePointFromPoint(point)
	if err != nil {
		t.Fatal(err)
	}
	return VerificationShare{Party: 1, PublicKey: publicKey}
}
