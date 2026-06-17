package ed25519

import (
	"bytes"
	"math/big"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestGoldenKeyShare(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(700)) //nolint:gosec // deterministic for golden test
	session, err := tss.NewSessionID(rng)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2, 3)
	sessions := make(map[tss.PartyID]*KeygenSession, 3)
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		cfg := tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: session, Rand: rand.New(rand.NewSource(int64(id * 100)))} //nolint:gosec // deterministic for golden test
		kg, out, err := startFROSTKeygen(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = kg
		messages = append(messages, out...)
	}
	deliverFROSTKeygenMessages(t, parties, sessions, messages)
	share, ok := sessions[1].KeyShare()
	if !ok {
		t.Fatal("keygen not complete")
	}

	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "frost", "KeyShare.golden")
	testutil.CheckGolden(t, golden, raw)

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
	t.Parallel()
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := keygenCommitmentsPayload{
		Commitments:     [][]byte{point.Bytes()},
		ChainCodeCommit: bytes.Repeat([]byte{0x91}, 32),
		PlanHash:        bytes.Repeat([]byte{0x90}, 32),
	}
	raw, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "frost", "KeygenCommitmentsPayload.golden")
	testutil.CheckGolden(t, golden, raw)

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
	t.Parallel()
	scalar, err := scalarBytes(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := keygenSharePayload{Share: scalar, PlanHash: bytes.Repeat([]byte{0x91}, 32)}
	raw, err := marshalKeygenSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "frost", "KeygenSharePayload.golden")
	testutil.CheckGolden(t, golden, raw)

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
	t.Parallel()
	dPoint, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	ePoint, err := edcurve.ScalarBaseMultBig(big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	payload := nonceCommitment{D: dPoint.Bytes(), E: ePoint.Bytes(), PlanHash: bytes.Repeat([]byte{0x92}, 32)}
	raw, err := marshalNonceCommitmentPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "frost", "NonceCommitmentPayload.golden")
	testutil.CheckGolden(t, golden, raw)

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
	t.Parallel()
	scalar, err := scalarBytes(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	payload := signPartialPayload{Z: scalar, PlanHash: bytes.Repeat([]byte{0x93}, 32)}
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("..", "..", "internal", "testvectors", "wire", "v1", "frost", "SignPartialPayload.golden")
	testutil.CheckGolden(t, golden, raw)

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
