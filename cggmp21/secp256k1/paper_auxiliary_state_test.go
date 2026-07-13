package secp256k1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/testutil"
)

type strictAuxInfoEnvelopeVerifier struct{}

func (strictAuxInfoEnvelopeVerifier) SignEnvelopeDigest([32]byte) ([]byte, error) {
	return []byte{1}, nil
}

func (strictAuxInfoEnvelopeVerifier) VerifyEnvelopeSignature(_ tss.PartyID, _ [32]byte, signature []byte) error {
	if !bytes.Equal(signature, []byte{1}) {
		return errors.New("invalid test signature")
	}
	return nil
}

func TestFigure7AuxInfoTwoPartyHappyPath(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	sid := tss.SessionID(bytes.Repeat([]byte{0x61}, 32))
	stableSID := tss.SessionID(bytes.Repeat([]byte{0x60}, 32))
	planHash := bytes.Repeat([]byte{0x62}, 32)
	contribution1 := testSecretScalar(t, 5)
	defer contribution1.Destroy()
	contribution2 := testSecretScalar(t, 7)
	defer contribution2.Destroy()
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(12)))
	if err != nil {
		t.Fatal(err)
	}
	schedule := auxInfoSchedule{CommitmentRound: 1, RevealRound: 2, ProofRound: 3}
	state1, round1From1, err := startAuxInfo(auxInfoStartOption{
		Config:    tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 1, SessionID: sid, Rand: testutil.DeterministicReader(1901)},
		StableSID: stableSID,
		Limits:    testLimits(), SecurityParams: testSecurityParams(), PlanHash: planHash,
		ExpectedPublicKey: publicKey, Contribution: contribution1, Schedule: schedule,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer state1.destroy()
	state2, round1From2, err := startAuxInfo(auxInfoStartOption{
		Config:    tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: 2, SessionID: sid, Rand: testutil.DeterministicReader(1902)},
		StableSID: stableSID,
		Limits:    testLimits(), SecurityParams: testSecurityParams(), PlanHash: planHash,
		ExpectedPublicKey: publicKey, Contribution: contribution2, Schedule: schedule,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer state2.destroy()

	round2From2 := applyAuxInfoForTest(t, state2, round1From1[0])
	round2From1 := applyAuxInfoForTest(t, state1, round1From2[0])
	if len(round2From1) != 1 || len(round2From2) != 1 {
		t.Fatalf("round 2 output counts = %d, %d", len(round2From1), len(round2From2))
	}
	round3From2 := applyAuxInfoForTest(t, state2, round2From1[0])
	round3From1 := applyAuxInfoForTest(t, state1, round2From2[0])
	if len(round3From1) != 2 || len(round3From2) != 2 {
		t.Fatalf("round 3 output counts = %d, %d", len(round3From1), len(round3From2))
	}
	for _, env := range round3From1 {
		applyAuxInfoForTest(t, state2, env)
	}
	for _, env := range round3From2 {
		applyAuxInfoForTest(t, state1, env)
	}
	result1, ok := state1.resultSnapshot()
	if !ok {
		t.Fatal("party 1 has no auxinfo result")
	}
	defer result1.destroy()
	result2, ok := state2.resultSnapshot()
	if !ok {
		t.Fatal("party 2 has no auxinfo result")
	}
	defer result2.destroy()
	if !bytes.Equal(result1.publicKey, publicKey) || !bytes.Equal(result2.publicKey, publicKey) {
		t.Fatal("auxinfo changed group public key")
	}
	if !bytes.Equal(result1.epoch.EpochID, result2.epoch.EpochID) || result1.epoch.RID != result2.epoch.RID {
		t.Fatal("auxinfo parties derived different epochs")
	}
	if result1.epoch.SID != stableSID || result2.epoch.SID != stableSID {
		t.Fatal("auxinfo changed the stable SID to the run session")
	}
	for _, result := range []*auxInfoResult{result1, result2} {
		secretScalar, err := secpScalarFromSecret(result.secret)
		if err != nil {
			t.Fatal(err)
		}
		publicShare, ok := result.epoch.PublicShare(result.partyDataOwnerForTest())
		if !ok {
			t.Fatal("missing result public share")
		}
		point, err := secp.PointFromBytes(publicShare.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !secp.Equal(secp.ScalarBaseMult(secretScalar), point) {
			t.Fatal("result secret does not match public share")
		}
	}
}

func (r *auxInfoResult) partyDataOwnerForTest() tss.PartyID {
	for _, share := range r.epoch.PublicShares {
		secretScalar, err := secpScalarFromSecret(r.secret)
		if err != nil {
			continue
		}
		point, err := secp.PointFromBytes(share.PublicKey)
		if err == nil && secp.Equal(secp.ScalarBaseMult(secretScalar), point) {
			return share.Party
		}
	}
	return 0
}

func applyAuxInfoForTest(t testing.TB, state *auxInfoState, env tss.Envelope) []tss.Envelope {
	t.Helper()
	prepared, err := state.prepareInbound(env)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.destroy()
	if err := prepared.apply(); err != nil {
		t.Fatal(err)
	}
	return prepared.out
}

func TestFigure7DecryptionErrorAccusationAuthenticatesDirectEnvelopeAndAttributesFailure(t *testing.T) {
	parties := tss.NewPartySet(1, 2)
	runSessionID := tss.SessionID(bytes.Repeat([]byte{0x71}, 32))
	stableSID := tss.SessionID(bytes.Repeat([]byte{0x72}, 32))
	planHash := bytes.Repeat([]byte{0x73}, 32)
	contribution1 := testSecretScalar(t, 5)
	defer contribution1.Destroy()
	contribution2 := testSecretScalar(t, 7)
	defer contribution2.Destroy()
	publicKey, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromUint64(12)))
	if err != nil {
		t.Fatal(err)
	}
	schedule := auxInfoSchedule{CommitmentRound: 1, RevealRound: 2, ProofRound: 3}
	start := func(self tss.PartyID, contribution *secret.Scalar, seed int64) (*auxInfoState, []tss.Envelope) {
		t.Helper()
		state, out, err := startAuxInfo(auxInfoStartOption{
			Config: tss.ThresholdConfig{
				Threshold: 2, Parties: parties, Self: self, SessionID: runSessionID,
				Rand: testutil.DeterministicReader(seed), EnvelopeSigner: strictAuxInfoEnvelopeVerifier{},
			},
			StableSID: stableSID, Limits: testLimits(), SecurityParams: testSecurityParams(),
			EnvelopeVerifier: strictAuxInfoEnvelopeVerifier{}, PlanHash: planHash,
			ExpectedPublicKey: publicKey, Contribution: contribution, Schedule: schedule,
		})
		if err != nil {
			t.Fatal(err)
		}
		return state, out
	}
	state1, round1From1 := start(1, contribution1, 2001)
	defer state1.destroy()
	state2, round1From2 := start(2, contribution2, 2002)
	defer state2.destroy()
	round2From2 := applyAuxInfoForTest(t, state2, round1From1[0])
	round2From1 := applyAuxInfoForTest(t, state1, round1From2[0])
	round3From2 := applyAuxInfoForTest(t, state2, round2From1[0])
	_ = applyAuxInfoForTest(t, state1, round2From2[0])

	var originalDirect tss.Envelope
	for _, env := range round3From2 {
		if env.PayloadType == payloadAuxInfoProofs {
			proofs, decodeErr := tss.DecodeBinaryWithLimits[auxInfoProofsPayload](env.Payload, testLimits())
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			proofs.EpochID[0] ^= 1
			mutatedProofs, marshalErr := proofs.MarshalBinaryWithLimits(testLimits())
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			wrongEpoch := env.Clone()
			wrongEpoch.Payload = mutatedProofs
			prepared, prepareErr := state1.prepareInbound(wrongEpoch)
			if prepareErr == nil || prepared != nil || state1.slots[2].proofs != nil {
				t.Fatal("wrong Figure 7 EpochID committed proofs or emitted effects")
			}
		}
		if env.PayloadType == payloadAuxInfoDirect && env.To == 1 {
			originalDirect = env
			break
		}
	}
	if originalDirect.PayloadType == "" {
		t.Fatal("party 2 emitted no direct Figure 7 envelope for party 1")
	}
	mutatedDirectPayload, err := tss.DecodeBinaryWithLimits[auxInfoDirectPayload](originalDirect.Payload, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	masked, err := secp.ScalarFromBytesAllowZero(mutatedDirectPayload.MaskedShare)
	if err != nil {
		t.Fatal(err)
	}
	mutatedDirectPayload.MaskedShare = secp.ScalarAdd(masked, secp.ScalarOne()).Bytes()
	mutatedBytes, err := mutatedDirectPayload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	mutatedDirect := originalDirect.Clone()
	mutatedDirect.Payload = mutatedBytes
	mutatedDirect, err = tss.SignEnvelope(mutatedDirect, strictAuxInfoEnvelopeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	localPrepared, err := state1.prepareInbound(mutatedDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer localPrepared.destroy()
	if localPrepared.failure == nil || localPrepared.failure.Class != Figure7FailureDecryptionError || localPrepared.failure.Accused != 2 || len(localPrepared.out) != 1 {
		t.Fatal("local decryption mismatch did not prepare one attributed accusation")
	}
	accusation, err := tss.DecodeBinaryWithLimits[auxInfoDecryptionErrorPayload](localPrepared.out[0].Payload, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer accusation.destroy()
	wantDirect, err := mutatedDirect.MarshalBinaryWithLimits(tss.DefaultEnvelopeLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(accusation.SignedDirectEnvelope, wantDirect) {
		t.Fatal("accusation did not bind the exact signed direct envelope")
	}
	clear(wantDirect)

	dhExponent := state1.local.dhSecrets[2].FixedBytes()
	defer clear(dhExponent)
	originalDirectBytes, err := originalDirect.MarshalBinaryWithLimits(tss.DefaultEnvelopeLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(originalDirectBytes)
	falsePayload := &auxInfoDecryptionErrorPayload{
		Accused: 2, DHExponent: bytes.Clone(dhExponent), SignedDirectEnvelope: bytes.Clone(originalDirectBytes),
		SID: stableSID, RID: state1.rid, EpochID: bytes.Clone(state1.epoch.EpochID), PlanHash: bytes.Clone(planHash),
	}
	defer falsePayload.destroy()
	falseBytes, err := falsePayload.MarshalBinaryWithLimits(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	falseEnvelope, err := newEnvelope(state1.cfg, schedule.ProofRound, 1, tss.BroadcastPartyId, payloadAuxInfoDecryptionError, falseBytes)
	clear(falseBytes)
	if err != nil {
		t.Fatal(err)
	}
	falsePrepared, err := state2.prepareInbound(falseEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if falsePrepared.failure == nil || falsePrepared.failure.Class != Figure7FailureFalseAccusation || falsePrepared.failure.Accused != 1 || len(falsePrepared.out) != 0 {
		t.Fatal("accusation for a matching share did not attribute the reporter")
	}
	falsePrepared.destroy()

	if err := localPrepared.apply(); err != nil {
		t.Fatal(err)
	}
	if !state1.aborted || state1.local != nil {
		t.Fatal("local accusation did not terminally destroy Figure 7 witness state")
	}
	remotePrepared, err := state2.prepareInbound(localPrepared.out[0])
	if err != nil {
		t.Fatal(err)
	}
	defer remotePrepared.destroy()
	if remotePrepared.failure == nil || remotePrepared.failure.Class != Figure7FailureDecryptionError || remotePrepared.failure.Accused != 2 {
		t.Fatal("verified decryption-error accusation did not attribute the direct sender")
	}
	if err := remotePrepared.apply(); err != nil {
		t.Fatal(err)
	}
	if !state2.aborted || state2.local != nil {
		t.Fatal("verified accusation did not terminally destroy receiver witness state")
	}
}
