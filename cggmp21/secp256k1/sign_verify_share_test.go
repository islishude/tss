package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/zk/signprep"
)

func TestFast_SignVerifyShareWireRoundTrip(t *testing.T) {
	t.Parallel()

	share := mustPresignVerifyShare(t, minimalCGGMP21Presign(t), 1)
	decoded, err := decodeSignVerifyShareWire(encodeSignVerifyShareWire(share))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.party != share.party {
		t.Fatal("party changed after round trip")
	}
	if !secp.Equal(decoded.kPoint, share.kPoint) {
		t.Fatal("KPoint changed after round trip")
	}
	if !secp.Equal(decoded.chiPoint, share.chiPoint) {
		t.Fatal("ChiPoint changed after round trip")
	}
	gotProof, err := decoded.proofBytes()
	if err != nil {
		t.Fatal(err)
	}
	wantProof, err := share.proofBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotProof) != string(wantProof) {
		t.Fatal("proof changed after round trip")
	}
}

func TestFast_SignVerifyShareWireRejectsMalformedFields(t *testing.T) {
	t.Parallel()

	share := mustPresignVerifyShare(t, minimalCGGMP21Presign(t), 1)
	valid := encodeSignVerifyShareWire(share)
	for _, tc := range []struct {
		name string
		w    signVerifyShareWire
	}{
		{name: "zero party", w: func() signVerifyShareWire {
			w := valid
			w.Party = tss.BroadcastPartyId
			return w
		}()},
		{name: "missing KPoint", w: func() signVerifyShareWire {
			w := valid
			w.KPoint = secp.WirePoint{}
			return w
		}()},
		{name: "missing ChiPoint", w: func() signVerifyShareWire {
			w := valid
			w.ChiPoint = secp.WirePoint{}
			return w
		}()},
		{name: "empty proof", w: func() signVerifyShareWire {
			w := valid
			w.Proof = signprep.Proof{}
			return w
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeSignVerifyShareWire(tc.w); err == nil {
				t.Fatalf("accepted malformed %s", tc.name)
			}
		})
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
	kPoint, err := share.kPointBytes()
	if err != nil {
		t.Fatal(err)
	}
	chiPoint, err := share.chiPointBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := share.proofBytes()
	if err != nil {
		t.Fatal(err)
	}
	legacy := wire.EncodePartyTriples([]wire.PartyTriple[tss.PartyID]{{
		Party:  share.party,
		First:  kPoint,
		Second: chiPoint,
		Third:  proof,
	}})
	mutated, err := testutil.RewriteWireFieldByName(raw, presignWireType, presignWire{}, "VerifyShares", legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tss.DecodeBinaryWithLimits[Presign](mutated, testLimits()); err == nil {
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
	share2 := share1.clone()
	share2.party = 2
	if err := validateSignVerifyShares(
		tss.NewPartySet(1, 2),
		[]signVerifyShare{share2, share1},
		testLimits(),
	); err == nil {
		t.Fatal("accepted VerifyShares outside canonical signer order")
	}
}
