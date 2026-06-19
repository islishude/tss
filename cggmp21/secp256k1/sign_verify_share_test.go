package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
)

func TestFast_SignVerifyShareCanonicalEncoding(t *testing.T) {
	t.Parallel()

	share := mustPresignVerifyShare(t, minimalCGGMP21Presign(t), 1)
	raw1, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw1, raw2) {
		t.Fatal("sign verify share encoding is not deterministic")
	}

	decoded, err := tss.DecodeBinaryValueWithLimits[SignVerifyShare](raw1, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Party != share.Party ||
		!bytes.Equal(decoded.KPoint, share.KPoint) ||
		!bytes.Equal(decoded.ChiPoint, share.ChiPoint) ||
		!bytes.Equal(decoded.Proof, share.Proof) {
		t.Fatal("sign verify share changed after round trip")
	}
	if err := decoded.UnmarshalBinaryWithLimits(append(raw1, 0), testLimits()); err == nil {
		t.Fatal("sign verify share accepted trailing bytes")
	}
}

func TestFast_SignVerifyShareRejectsMalformedOrOversizedFields(t *testing.T) {
	t.Parallel()

	share := mustPresignVerifyShare(t, minimalCGGMP21Presign(t), 1)
	raw, err := share.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		field string
		value []byte
	}{
		{name: "zero party", field: "Party", value: wire.Uint32(0)},
		{name: "invalid KPoint", field: "KPoint", value: []byte{2}},
		{name: "invalid ChiPoint", field: "ChiPoint", value: []byte{3}},
		{name: "empty proof", field: "Proof", value: []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated, err := testutil.RewriteWireFieldByName(raw, signVerifyShareWireType, SignVerifyShare{}, tc.field, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var decoded SignVerifyShare
			if err := decoded.UnmarshalBinaryWithLimits(mutated, testLimits()); err == nil {
				t.Fatalf("accepted malformed %s", tc.field)
			}
		})
	}

	limits := testLimits()
	limits.SignPrep.MaxProofBytes = len(share.Proof) - 1
	if _, err := share.MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("encoded proof above configured limit")
	}
	var decoded SignVerifyShare
	if err := decoded.UnmarshalBinaryWithLimits(raw, limits); err == nil {
		t.Fatal("decoded proof above configured limit")
	}
}

func TestFast_PresignRejectsLegacyVerifyShareBytes(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	share := mustPresignVerifyShare(t, presign, 1)
	legacy := wire.EncodePartyTriples([]wire.PartyTriple[tss.PartyID]{{
		Party:  share.Party,
		First:  share.KPoint,
		Second: share.ChiPoint,
		Third:  share.Proof,
	}})
	mutated, err := testutil.RewriteWireFieldByName(raw, presignWireType, presignWire{}, "VerifyShares", legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPresignWithLimits(mutated, testLimits()); err == nil {
		t.Fatal("presign accepted legacy party-triple VerifyShares bytes")
	}
}

func TestFast_PresignVerifySharesAggregateLimit(t *testing.T) {
	t.Parallel()

	presign := minimalCGGMP21Presign(t)
	limits := testLimits()
	limits.SignPrep.MaxVerifySharesBytes = 1
	if _, err := presign.MarshalBinaryWithLimits(limits); err == nil {
		t.Fatal("presign encoded VerifyShares above configured aggregate limit")
	}
}

func TestFast_PresignVerifySharesRequireCanonicalSignerOrder(t *testing.T) {
	t.Parallel()

	share1 := mustPresignVerifyShare(t, minimalCGGMP21Presign(t), 1)
	share2 := share1.Clone()
	share2.Party = 2
	if err := validateSignVerifyShares(
		tss.NewPartySet(1, 2),
		[]SignVerifyShare{share2, share1},
		testLimits(),
	); err == nil {
		t.Fatal("accepted VerifyShares outside canonical signer order")
	}
}
