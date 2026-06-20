package secp256k1

import (
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/zk/signprep"
)

type signVerifyShareRecordTestMessage struct {
	Share signVerifyShare `wire:"1,record"`
}

func (signVerifyShareRecordTestMessage) WireType() string {
	return "test.cggmp21.sign-verify-share-record"
}

func (signVerifyShareRecordTestMessage) WireVersion() uint16 { return 1 }

func TestFast_SignVerifyShareWireRoundTrip(t *testing.T) {
	t.Parallel()

	share := mustPresignVerifyShare(t, minimalCGGMP21Presign(t), 1)
	raw, err := wire.Marshal(
		signVerifyShareRecordTestMessage{Share: share},
		wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
	)
	if err != nil {
		t.Fatal(err)
	}
	var decoded signVerifyShareRecordTestMessage
	if err := wire.Unmarshal(raw, &decoded, wire.WithFieldLimits(testLimits().fieldLimits())); err != nil {
		t.Fatal(err)
	}
	if decoded.Share.Party != share.Party {
		t.Fatal("party changed after round trip")
	}
	if !secp.Equal(decoded.Share.KPoint, share.KPoint) {
		t.Fatal("KPoint changed after round trip")
	}
	if !secp.Equal(decoded.Share.ChiPoint, share.ChiPoint) {
		t.Fatal("ChiPoint changed after round trip")
	}
	gotProof, err := decoded.Share.proofBytes()
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
	valid := share.Clone()
	for _, tc := range []struct {
		name  string
		share signVerifyShare
	}{
		{name: "zero party", share: func() signVerifyShare {
			w := valid
			w.Party = tss.BroadcastPartyId
			return w
		}()},
		{name: "missing KPoint", share: func() signVerifyShare {
			w := valid
			w.KPoint = nil
			return w
		}()},
		{name: "missing ChiPoint", share: func() signVerifyShare {
			w := valid
			w.ChiPoint = nil
			return w
		}()},
		{name: "empty proof", share: func() signVerifyShare {
			w := valid
			w.Proof = &signprep.Proof{}
			return w
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wire.Marshal(
				signVerifyShareRecordTestMessage{Share: tc.share},
				wire.WithFieldLimitsForMarshal(testLimits().fieldLimits()),
			)
			if err == nil {
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
		Party:  share.Party,
		First:  kPoint,
		Second: chiPoint,
		Third:  proof,
	}})
	mutated, err := testutil.RewriteWireField(raw, presignWireType, 16, legacy)
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
	share2 := share1.Clone()
	share2.Party = 2
	if err := validateSignVerifyShares(
		tss.NewPartySet(1, 2),
		[]signVerifyShare{share2, share1},
		testLimits(),
	); err == nil {
		t.Fatal("accepted VerifyShares outside canonical signer order")
	}
}
