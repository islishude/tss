package ed25519

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
)

func TestGoldenKeyShare(t *testing.T) {
	rng := rand.New(rand.NewSource(700)) //nolint:gosec // deterministic for golden test
	session, err := tss.NewSessionID(rng)
	if err != nil {
		t.Fatal(err)
	}
	parties := []tss.PartyID{1, 2, 3}
	sessions := make(map[tss.PartyID]*KeygenSession, 3)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		cfg := tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: session, Rand: rand.New(rand.NewSource(int64(id * 100)))} //nolint:gosec // deterministic for golden test
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

	golden := filepath.Join("testdata", "KeyShare.golden")
	checkGolden(t, golden, raw)

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

func TestGoldenKeygenCommitmentsPayload(t *testing.T) {
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := keygenCommitmentsPayload{Commitments: [][]byte{point.Bytes()}}
	raw, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "KeygenCommitmentsPayload.golden")
	checkGolden(t, golden, raw)

	decoded, err := unmarshalKeygenCommitmentsPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalKeygenCommitmentsPayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalKeygenCommitmentsPayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenKeygenSharePayload(t *testing.T) {
	scalar, err := scalarBytes(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := keygenSharePayload{Share: scalar}
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

func TestGoldenNonceCommitmentPayload(t *testing.T) {
	dPoint, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	ePoint, err := edcurve.ScalarBaseMultBig(big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	payload := nonceCommitment{D: dPoint.Bytes(), E: ePoint.Bytes()}
	raw, err := marshalNonceCommitmentPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "NonceCommitmentPayload.golden")
	checkGolden(t, golden, raw)

	decoded, err := unmarshalNonceCommitmentPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalNonceCommitmentPayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalNonceCommitmentPayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenSignPartialPayload(t *testing.T) {
	scalar, err := scalarBytes(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := signPartialPayload{Z: scalar}
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
