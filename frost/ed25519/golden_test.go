package ed25519

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
	"github.com/islishude/tss/internal/testvectors"
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

	testvectors.CheckHexGolden(t, "wire/v1/frost/KeyShare.golden", raw)

	decoded, err := tss.DecodeBinary[KeyShare](raw)
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
	if _, err := tss.DecodeBinary[KeyShare](append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenVerificationShare(t *testing.T) {
	t.Parallel()
	share := testFROSTVerificationShare(t)
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/frost/VerificationShare.golden", raw)
}

func TestGoldenKeygenCommitmentsPayload(t *testing.T) {
	t.Parallel()
	point, err := edcurve.ScalarBaseMultBig(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	commitments, err := newKeygenCommitmentsFromPoints([]*fed.Point{point}, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := keygenCommitmentsPayload{
		Commitments:     commitments,
		ChainCodeCommit: bytes.Repeat([]byte{0x91}, 32),
		PlanHash:        bytes.Repeat([]byte{0x90}, 32),
	}
	raw, err := marshalKeygenCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/frost/KeygenCommitmentsPayload.golden", raw)

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
	secretScalar, err := newEdSecretScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}
	payload := keygenSharePayload{Share: secretScalar, PlanHash: bytes.Repeat([]byte{0x91}, 32)}
	raw, err := marshalKeygenSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/frost/KeygenSharePayload.golden", raw)

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
	dCommitment, err := newNonceCommitmentPointFromPoint(dPoint)
	if err != nil {
		t.Fatal(err)
	}
	eCommitment, err := newNonceCommitmentPointFromPoint(ePoint)
	if err != nil {
		t.Fatal(err)
	}
	payload := nonceCommitment{D: dCommitment, E: eCommitment, PlanHash: bytes.Repeat([]byte{0x92}, 32)}
	raw, err := marshalNonceCommitmentPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/frost/NonceCommitmentPayload.golden", raw)

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
	scalarValue, err := edcurve.ScalarFromCanonical(scalar)
	if err != nil {
		t.Fatal(err)
	}
	z, err := newCanonicalScalar(scalarValue)
	if err != nil {
		t.Fatal(err)
	}
	payload := signPartialPayload{Z: z, PlanHash: bytes.Repeat([]byte{0x93}, 32)}
	raw, err := marshalSignPartialPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	testvectors.CheckHexGolden(t, "wire/v1/frost/SignPartialPayload.golden", raw)

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

func TestGoldenKeygenConfirmation(t *testing.T) {
	t.Parallel()
	publicKey, err := newPublicKeyPointFromPoint(fed.NewGeneratorPoint())
	if err != nil {
		t.Fatal(err)
	}
	confirmation := KeygenConfirmation{
		SessionID:       testutil.MustSessionID(701),
		Sender:          2,
		Threshold:       2,
		Parties:         tss.NewPartySet(1, 2, 3),
		PublicKey:       publicKey,
		TranscriptHash:  bytes.Repeat([]byte{0x94}, 32),
		CommitmentsHash: bytes.Repeat([]byte{0x95}, 32),
		ChainCode:       bytes.Repeat([]byte{0x96}, 32),
		PlanHash:        bytes.Repeat([]byte{0x97}, 32),
	}
	raw, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/frost/KeygenConfirmation.golden", raw)

	decoded, err := tss.DecodeBinary[KeygenConfirmation](raw)
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
	if _, err := tss.DecodeBinary[KeygenConfirmation](append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenReshareCommitmentsPayload(t *testing.T) {
	t.Parallel()
	commitments, err := newReshareCommitmentsFromPoints(
		[]*fed.Point{fed.NewIdentityPoint(), fed.NewGeneratorPoint()},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := reshareCommitmentsPayload{
		Commitments: commitments,
		PlanHash:    bytes.Repeat([]byte{0x98}, 32),
	}
	raw, err := marshalReshareCommitmentsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/frost/ReshareCommitmentsPayload.golden", raw)

	decoded, err := unmarshalReshareCommitmentsPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := marshalReshareCommitmentsPayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalReshareCommitmentsPayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}

func TestGoldenReshareSharePayload(t *testing.T) {
	t.Parallel()
	scalar, err := scalarBytes(big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	share, err := newEdSecretScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}
	defer share.Destroy()
	payload := reshareSharePayload{
		Share:    share,
		PlanHash: bytes.Repeat([]byte{0x99}, 32),
	}
	raw, err := marshalReshareSharePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	testvectors.CheckHexGolden(t, "wire/v1/frost/ReshareSharePayload.golden", raw)

	decoded, err := unmarshalReshareSharePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Share.Destroy()
	raw2, err := marshalReshareSharePayload(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Error("round-trip produced different encoding")
	}
	if _, err := unmarshalReshareSharePayload(append(raw, 0)); err == nil {
		t.Error("accepted trailing byte")
	}
}
