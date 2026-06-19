//go:build integration

package secp256k1

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/testvectors"
)

func TestGoldenKeygenSharePayload(t *testing.T) {
	t.Parallel()

	payload := keygenSharePayload{Share: testSecretScalar(t, 1), PlanHash: bytes.Repeat([]byte{0x90}, 32)}
	raw, err := marshalKeygenSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/KeygenSharePayload.golden", raw)

	decoded, err := unmarshalKeygenSharePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalKeygenSharePayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalKeygenSharePayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenSignPartialPayload(t *testing.T) {
	t.Parallel()

	payload := signPartialPayload{
		S:                   big.NewInt(1),
		PresignTranscript:   bytes.Repeat([]byte{0xaa}, 32),
		PresignContext:      bytes.Repeat([]byte{0xbb}, 32),
		DigestHash:          bytes.Repeat([]byte{0xcc}, 32),
		PartialEquationHash: bytes.Repeat([]byte{0xdd}, 32),
		PlanHash:            bytes.Repeat([]byte{0xde}, 32),
	}
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/SignPartialPayload.golden", raw)

	decoded, err := unmarshalSignPartialPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalSignPartialPayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalSignPartialPayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenPresignRound3Payload(t *testing.T) {
	t.Parallel()

	proof := mustMinimalSignPrepProofForTest(t)
	kPoint, _ := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))))
	twoScalar := secp.ScalarFromBigInt(big.NewInt(2))
	chiPoint, _ := secp.PointBytes(secp.ScalarBaseMult(twoScalar))
	payload := presignRound3Payload{
		Delta:    big.NewInt(42),
		KPoint:   kPoint,
		ChiPoint: chiPoint,
		Proof:    proof,
		PlanHash: bytes.Repeat([]byte{0x91}, 32),
	}
	raw, err := marshalPresignRound3Payload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/cggmp21/PresignRound3Payload.golden", raw)

	decoded, err := unmarshalPresignRound3Payload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalPresignRound3Payload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalPresignRound3Payload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenCGGMP21KeyShare(t *testing.T) {
	t.Parallel()

	const golden = "wire/v1/cggmp21/KeyShare.golden"

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		// Run a deterministic keygen to generate the golden file.
		// Each party gets its own seeded RNG so the full protocol
		// (Paillier keygen, Schnorr proofs) produces reproducible output.
		rng := rand.New(rand.NewSource(700)) //nolint:gosec // deterministic for golden test
		session, err := tss.NewSessionID(rng)
		if err != nil {
			t.Fatal(err)
		}
		parties := tss.NewPartySet(1, 2, 3)
		sessions := make(map[tss.PartyID]*KeygenSession, 3)
		messages := make([]tss.Envelope, 0)
		for _, id := range parties {
			cfg := tss.ThresholdConfig{
				Threshold: 2,
				Parties:   parties,
				Self:      id,
				SessionID: session,
				Rand:      rand.New(rand.NewSource(int64(id * 100))), //nolint:gosec // deterministic for golden test
			}
			kg, out, err := startCGGMP21Keygen(cfg)
			if err != nil {
				t.Fatal(err)
			}
			sessions[id] = kg
			messages = append(messages, out...)
		}
		deliverKeygenMessages(t, sessions, parties, messages)
		share, ok := sessions[1].KeyShare()
		if !ok {
			t.Fatal("keygen not complete")
		}
		raw, err := share.MarshalBinaryWithLimits(testLimits())
		if err != nil {
			t.Fatal(err)
		}
		path, err := testvectors.Path(golden)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}

	// The golden file acts as a format regression check. It verifies that the
	// stored bytes decode, round-trip, and reject trailing bytes.
	wantHex := testvectors.Read(t, golden)
	raw, err := hex.DecodeString(string(bytes.TrimSpace(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := UnmarshalKeyShare(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenCGGMP21Presign(t *testing.T) {
	t.Parallel()

	const golden = "wire/v1/cggmp21/Presign.golden"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		shares := CachedKeygenShares(t, 1, 1)
		presigns := secpPresign(t, shares, tss.NewPartySet(1))
		raw, err := presigns[1].MarshalBinaryWithLimits(testLimits())
		if err != nil {
			t.Fatal(err)
		}
		path, err := testvectors.Path(golden)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantHex := testvectors.Read(t, golden)
	raw, err := hex.DecodeString(string(bytes.TrimSpace(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPresignWithLimits(raw, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := UnmarshalPresignWithLimits(append(raw, 0), testLimits()); err == nil {
		t.Error("accepted trailing byte")
	}
}
