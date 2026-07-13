package secp256k1

import (
	"bytes"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testvectors"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

func TestFast_GoldenPresignMarshalBinary(t *testing.T) {
	t.Parallel()
	presign := minimalCGGMP21Presign(t)
	raw, err := presign.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/Presign.fast.golden", raw)
	decoded, err := tss.DecodeBinaryWithLimits[Presign](raw, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Destroy()
	raw2, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := tss.DecodeBinaryWithLimits[Presign](append(raw, 0), testLimits()); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestFast_GoldenPublicShareRecords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		golden string
		encode func() ([]byte, error)
	}{
		{name: "verification", golden: "wire/v1/cggmp21/VerificationShare.golden", encode: func() ([]byte, error) {
			return testVerificationShare(t).MarshalBinaryWithLimits(testLimits())
		}},
		{name: "paillier", golden: "wire/v1/cggmp21/PaillierPublicShare.golden", encode: func() ([]byte, error) {
			return testPaillierPublicShare(t).MarshalBinaryWithLimits(testLimits())
		}},
		{name: "ring-pedersen", golden: "wire/v1/cggmp21/RingPedersenPublicShare.golden", encode: func() ([]byte, error) {
			return testRingPedersenPublicShare(t).MarshalBinaryWithLimits(testLimits())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.encode()
			if err != nil {
				t.Fatal(err)
			}
			testvectors.CheckHexGolden(t, tc.golden, raw)
		})
	}
}

func TestFast_GoldenFigure6AndAuxInfoCommitments(t *testing.T) {
	t.Parallel()
	figure6, err := (figure6CommitmentPayload{
		Commitment: bytes.Repeat([]byte{0x41}, 32), ChainCodeCommit: bytes.Repeat([]byte{0x42}, 32), PlanHash: bytes.Repeat([]byte{0x43}, 32),
	}).MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/Figure6CommitmentPayload.golden", figure6)
	aux, err := (auxInfoCommitmentPayload{Commitment: bytes.Repeat([]byte{0x51}, 32), PlanHash: bytes.Repeat([]byte{0x52}, 32)}).MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/AuxInfoCommitmentPayload.golden", aux)
}

func TestFast_GoldenKeygenConfirmation(t *testing.T) {
	t.Parallel()
	confirmation := KeygenConfirmation{
		SessionID:       tss.SessionID(bytes.Repeat([]byte{0x61}, 32)),
		Sender:          1,
		Threshold:       1,
		Parties:         tss.NewPartySet(1),
		PublicKey:       testCurvePointBytes(t, 7),
		TranscriptHash:  bytes.Repeat([]byte{0x62}, 32),
		CommitmentsHash: bytes.Repeat([]byte{0x63}, 32),
		ChainCode:       bytes.Repeat([]byte{0x64}, 32),
		PlanHash:        bytes.Repeat([]byte{0x65}, 32),
		EpochID:         bytes.Repeat([]byte{0x66}, 32),
	}
	raw, err := confirmation.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/KeygenConfirmation.golden", raw)
	decoded, err := tss.DecodeBinaryWithLimits[KeygenConfirmation](raw, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.EpochID, confirmation.EpochID) {
		t.Fatal("keygen confirmation golden lost epoch binding")
	}
}

func TestFast_GoldenSignPartialPayload(t *testing.T) {
	t.Parallel()
	payload := signPartialPayload{
		S:                   testSecretScalar(t, 1),
		PresignID:           bytes.Repeat([]byte{0xa1}, 32),
		EpochID:             bytes.Repeat([]byte{0xa2}, 32),
		PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
		PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
		DigestHash:          bytes.Repeat([]byte{0xcc}, 32),
		PartialEquationHash: bytes.Repeat([]byte{0xdd}, 32),
		PlanHash:            bytes.Repeat([]byte{0xde}, 32),
	}
	defer payload.S.Destroy()
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/SignPartialPayload.golden", raw)
	decoded, err := unmarshalSignPartialPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.S.Destroy()
	raw2, err := marshalSignPartialPayload(decoded)
	if err != nil || !bytes.Equal(raw, raw2) {
		t.Fatalf("sign partial canonical round-trip failed: %v", err)
	}
}

func TestFast_GoldenPresignRound3Payload(t *testing.T) {
	t.Parallel()
	point := testCurvePointBytes(t, 1)
	proof := zkpai.ElogProof{
		A: bytes.Clone(point), N: bytes.Clone(point), B: bytes.Clone(point),
		Z: secp.ScalarOne().Bytes(), U: secp.ScalarOne().Bytes(),
		TranscriptHash: bytes.Repeat([]byte{0x91}, 32),
	}
	payload := presignRound3Payload{
		Delta: testSecretScalar(t, 42), S: bytes.Clone(point), DeltaPoint: bytes.Clone(point), Proof: proof,
		PlanHash: bytes.Repeat([]byte{0x92}, 32), EpochID: bytes.Repeat([]byte{0x93}, 32), PresignID: bytes.Repeat([]byte{0x94}, 32),
	}
	defer payload.Delta.Destroy()
	raw, err := marshalPresignRound3Payload(payload)
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/PresignRound3Payload.golden", raw)
	decoded, err := unmarshalPresignRound3Payload(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Delta.Destroy()
	raw2, err := marshalPresignRound3Payload(decoded)
	if err != nil || !bytes.Equal(raw, raw2) {
		t.Fatalf("round3 canonical round-trip failed: %v", err)
	}
}
