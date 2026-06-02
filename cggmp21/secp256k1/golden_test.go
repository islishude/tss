package secp256k1

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
)

func TestGoldenKeygenSharePayload(t *testing.T) {
	payload := keygenSharePayload{Share: scalarBytes(big.NewInt(1))}
	raw, err := marshalKeygenSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "KeygenSharePayload.golden")
	checkGolden(t, golden, raw)

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
	payload := signPartialPayload{
		S:                 scalarBytes(big.NewInt(1)),
		PresignTranscript: bytes.Repeat([]byte{0xaa}, 32),
		PresignContext:    bytes.Repeat([]byte{0xbb}, 32),
	}
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "SignPartialPayload.golden")
	checkGolden(t, golden, raw)

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
	payload := presignRound3Payload{Delta: scalarBytes(big.NewInt(42))}
	raw, err := marshalPresignRound3Payload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "PresignRound3Payload.golden")
	checkGolden(t, golden, raw)

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
	golden := filepath.Join("testdata", "KeyShare.golden")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		// Run a deterministic keygen to generate the golden file.
		// Each party gets its own seeded RNG so the full protocol
		// (Paillier keygen, Schnorr proofs) produces reproducible output.
		rng := rand.New(rand.NewSource(700)) //nolint:gosec // deterministic for golden test
		session, err := tss.NewSessionID(rng)
		if err != nil {
			t.Fatal(err)
		}
		parties := []tss.PartyID{1, 2, 3}
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
			kg, out, err := StartKeygen(cfg)
			if err != nil {
				t.Fatal(err)
			}
			sessions[id] = kg
			messages = append(messages, out...)
		}
		for _, env := range messages {
			for _, id := range parties {
				if id == env.From {
					continue
				}
				if env.To != 0 && env.To != id {
					continue
				}
				if _, err := sessions[id].HandleKeygenMessage(env); err != nil {
					t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
				}
			}
		}
		share, ok := sessions[1].KeyShare()
		if !ok {
			t.Fatal("keygen not complete")
		}
		raw, err := share.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}

	if _, err := os.Stat(golden); os.IsNotExist(err) {
		t.Skipf("golden file %s does not exist; run with UPDATE_GOLDEN=1 to generate", golden)
	}
	// The golden file acts as a format regression check. It verifies that the
	// stored bytes decode, round-trip, and reject trailing bytes.
	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(string(bytes.TrimSpace(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
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
	golden := filepath.Join("testdata", "Presign.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		shares := secpKeygen(t, 1, 1)
		presigns := secpPresign(t, shares, []tss.PartyID{1})
		raw, err := presigns[1].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := os.Stat(golden); os.IsNotExist(err) {
		t.Skipf("golden file %s does not exist; run with UPDATE_GOLDEN=1 to generate", golden)
	}
	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(string(bytes.TrimSpace(wantHex)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPresign(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := UnmarshalPresign(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func checkGolden(t *testing.T, golden string, raw []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantHex, err := os.ReadFile(golden) //nolint:gosec // path constructed within test package
	if err != nil {
		t.Fatalf("reading golden %s: %v (run with UPDATE_GOLDEN=1 to generate)", golden, err)
	}
	gotHex := hex.EncodeToString(raw)
	if gotHex != string(bytes.TrimSpace(wantHex)) {
		t.Errorf("golden mismatch:\n  got:  %s\n  want: %s", gotHex, string(bytes.TrimSpace(wantHex)))
	}
}
