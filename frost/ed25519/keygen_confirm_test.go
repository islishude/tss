package ed25519

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	fed "filippo.io/edwards25519"
	"github.com/islishude/tss"
	edcurve "github.com/islishude/tss/internal/curve/edwards25519"
	"github.com/islishude/tss/internal/testutil"
)

func TestFROSTKeygenConfirmationRoundTrip(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	confirmation, err := shares[1].NewConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := confirmation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tss.DecodeBinary[KeygenConfirmation](raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatal("confirmation did not remarshal deterministically")
	}
	if _, err := tss.DecodeBinary[KeygenConfirmation](append(raw, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}

func TestFROSTKeygenConfirmationRejectsMismatchedTranscriptHash(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	confirmations := frostKeygenConfirmations(t, shares, tss.NewPartySet(1, 2, 3))
	confirmations[1].TranscriptHash = bytes.Clone(confirmations[1].TranscriptHash)
	confirmations[1].TranscriptHash[0] ^= 1
	if err := applyKeygenConfirmationSet(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for mismatched transcript hash")
	}
}

func TestFROSTKeygenConfirmationRejectsMismatchedPublicKey(t *testing.T) {
	t.Parallel()
	shares := frostKeygen(t, 2, 3)
	confirmations := frostKeygenConfirmations(t, shares, tss.NewPartySet(1, 2, 3))
	tampered, err := newPublicKeyPointFromPoint(edcurve.AddPoints(confirmations[1].PublicKey.Point(), fed.NewGeneratorPoint()))
	if err != nil {
		t.Fatal(err)
	}
	confirmations[1].PublicKey = tampered
	if err := applyKeygenConfirmationSet(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for mismatched public key")
	}
}

func TestFROSTKeyShareRejectsTamperedHDChainCode(t *testing.T) {
	t.Parallel()
	shares := frostKeygenHD(t, 2, 3)
	tampered := cloneKeyShareValue(shares[1])
	tampered.state.ChainCode[0] ^= 1
	if err := tampered.ValidateConsistency(); err == nil {
		t.Fatal("expected tampered aggregate chain code to be rejected")
	}
}

func TestFROSTUnmarshalKeyShareRejectsTamperedHDChainCode(t *testing.T) {
	t.Parallel()
	share := frostKeygenHD(t, 2, 3)[1]
	raw, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tamperedChainCode := bytes.Clone(share.state.ChainCode)
	tamperedChainCode[0] ^= 1
	mutated, err := testutil.RewriteWireField(raw, keyShareWireType, 5, tamperedChainCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalKeyShareWithLimits(mutated, testLimits()); err == nil {
		t.Fatal("expected tampered aggregate chain code to be rejected during decode")
	}
}

func TestFROSTKeyShareRejectsTamperedConfirmationChainCode(t *testing.T) {
	t.Parallel()
	shares := frostKeygenHD(t, 2, 3)
	tampered := cloneKeyShareValue(shares[1])
	data := tampered.state.PartyData[2]
	data.KeygenConfirmation = data.KeygenConfirmation.Clone()
	data.KeygenConfirmation.ChainCode = bytes.Clone(data.KeygenConfirmation.ChainCode)
	data.KeygenConfirmation.ChainCode[0] ^= 1
	tampered.state.PartyData[2] = data
	confirmations, err := tampered.orderedKeygenConfirmations()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyKeygenConfirmationSetAggregateChainCode(tampered, confirmations); err == nil {
		t.Fatal("expected tampered confirmation chain code to be rejected")
	}
}

func TestFROSTKeygenSessionRejectsConflictingConfirmation(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2, 3)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	messages := make([]tss.Envelope, 0)
	for _, id := range parties {
		session, out, err := startFROSTKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}

	confirmations := routeFROSTKeygenThroughShareRound(t, parties, sessions, messages)

	var fromParty2 tss.Envelope
	for _, env := range confirmations {
		if env.From == 2 {
			fromParty2 = env
			break
		}
	}
	if fromParty2.PayloadType == "" {
		t.Fatal("missing confirmation from party 2")
	}
	if _, err := sessions[1].Handle(testutil.DeliverEnvelope(fromParty2)); err != nil {
		t.Fatal(err)
	}
	if share, ok := sessions[1].KeyShare(); ok || share != nil {
		t.Fatal("session completed before all confirmations arrived")
	}

	conflicting := fromParty2
	decoded, err := tss.DecodeBinary[KeygenConfirmation](conflicting.Payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded.TranscriptHash = bytes.Clone(decoded.TranscriptHash)
	decoded.TranscriptHash[0] ^= 1
	conflicting.Payload, err = decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = sessions[1].Handle(testutil.DeliverEnvelope(conflicting))
	if !errors.Is(err, tss.ErrEquivocation) {
		t.Fatalf("expected ErrEquivocation for conflicting confirmation, got %v", err)
	}
	if share, ok := sessions[1].KeyShare(); ok || share != nil {
		t.Fatal("aborted session returned a key share")
	}
	for _, slot := range sessions[1].round1.slots {
		if slot.share != nil {
			t.Fatal("aborted keygen retained received share scalars")
		}
	}
	if sessions[1].local != nil {
		t.Fatal("aborted keygen retained local material")
	}
	for _, chainCode := range sessions[1].confirmations.chainCodes {
		if chainCode != nil {
			t.Fatal("aborted keygen retained chain codes")
		}
	}
}

func frostKeygenConfirmations(t *testing.T, shares map[tss.PartyID]*KeyShare, parties tss.PartySet) []*KeygenConfirmation {
	t.Helper()
	confirmations := make([]*KeygenConfirmation, 0, len(parties))
	for _, id := range parties {
		confirmation, err := shares[id].NewConfirmation()
		if err != nil {
			t.Fatal(err)
		}
		confirmations = append(confirmations, confirmation)
	}
	return confirmations
}

func TestFROSTKeygenSessionBuffersConfirmationBeforeRound1Commitment(t *testing.T) {
	t.Parallel()
	sessionID, err := tss.NewSessionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	parties := tss.NewPartySet(1, 2, 3)
	sessions := make(map[tss.PartyID]*KeygenSession, len(parties))
	var messages []tss.Envelope
	for _, id := range parties {
		session, out, err := startFROSTKeygen(tss.ThresholdConfig{Threshold: 2, Parties: parties, Self: id, SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		messages = append(messages, out...)
	}

	commitment1 := mustFROSTEnvelopeFrom(t, messages, payloadKeygenCommitments, tss.BroadcastPartyId, 1)
	commitment2 := mustFROSTEnvelopeFrom(t, messages, payloadKeygenCommitments, tss.BroadcastPartyId, 2)
	commitment3 := mustFROSTEnvelopeFrom(t, messages, payloadKeygenCommitments, tss.BroadcastPartyId, 3)

	// Party 1 deliberately withholds party 2's commitment. Party 2 and party 3
	// still accept the complete R1, allowing them to enter R2. Constructing the
	// party 1 -> party 2 share directly keeps party 1 in the pre-commitment state
	// whose early-confirmation buffering behavior this test exercises.
	if _, err := sessions[1].Handle(testutil.DeliverEnvelope(commitment3)); err != nil {
		t.Fatalf("prepare party 1 with commitment from 3: %v", err)
	}
	var round2From2 []tss.Envelope
	for _, env := range []tss.Envelope{commitment1, commitment3} {
		out, err := sessions[2].Handle(testutil.DeliverEnvelope(env))
		if err != nil {
			t.Fatalf("prepare party 2 with commitment from %d: %v", env.From, err)
		}
		round2From2 = append(round2From2, out...)
	}
	if len(round2From2) == 0 {
		t.Fatal("party 2 did not enter the share round")
	}
	var round2From3 []tss.Envelope
	for _, env := range []tss.Envelope{commitment1, commitment2} {
		out, err := sessions[3].Handle(testutil.DeliverEnvelope(env))
		if err != nil {
			t.Fatalf("prepare party 3 with commitment from %d: %v", env.From, err)
		}
		round2From3 = append(round2From3, out...)
	}

	share1To2 := mustFROSTKeygenShareFromLocal(t, sessions[1], 2)
	share3To2 := mustFROSTEnvelope(t, round2From3, payloadKeygenShare, 2)
	var early tss.Envelope
	for _, env := range []tss.Envelope{share1To2, share3To2} {
		out, err := sessions[2].Handle(testutil.DeliverEnvelope(env))
		if err != nil {
			t.Fatalf("prepare party 2 with share from %d: %v", env.From, err)
		}
		for _, produced := range out {
			if produced.PayloadType == payloadKeygenConfirmation {
				early = produced
			}
		}
	}
	if early.PayloadType == "" {
		t.Fatal("party 2 did not produce a confirmation")
	}
	if _, err := sessions[1].Handle(testutil.DeliverEnvelope(early)); err != nil {
		t.Fatalf("early confirmation: %v", err)
	}
	if sessions[1].aborted || sessions[1].pendingConfirmations[2] == nil {
		t.Fatal("early confirmation was not buffered without aborting")
	}

	if _, err := sessions[1].Handle(testutil.DeliverEnvelope(commitment2)); err != nil {
		t.Fatalf("deliver withheld commitment from 2: %v", err)
	}
	if sessions[1].aborted || sessions[1].pendingConfirmations[2] != nil || sessions[1].confirmations.confirmations[2] == nil {
		t.Fatal("buffered confirmation was not promoted after its commitment arrived")
	}
}

func routeFROSTKeygenThroughShareRound(
	t *testing.T,
	parties tss.PartySet,
	sessions map[tss.PartyID]*KeygenSession,
	messages []tss.Envelope,
) []tss.Envelope {
	t.Helper()
	queue := slices.Clone(messages)
	confirmations := make([]tss.Envelope, 0, len(parties))
	for len(queue) > 0 {
		env := queue[0]
		queue = queue[1:]
		for _, id := range parties {
			if id == env.From || (env.To != tss.BroadcastPartyId && env.To != id) {
				continue
			}
			out, err := sessions[id].Handle(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			for _, produced := range out {
				if produced.PayloadType == payloadKeygenConfirmation {
					confirmations = append(confirmations, produced)
					continue
				}
				queue = append(queue, produced)
			}
		}
	}
	return confirmations
}

func mustFROSTEnvelopeFrom(
	t *testing.T,
	envelopes []tss.Envelope,
	payloadType tss.PayloadType,
	to tss.PartyID,
	from tss.PartyID,
) tss.Envelope {
	t.Helper()
	for _, env := range envelopes {
		if env.From == from && env.To == to && env.PayloadType == payloadType {
			return env
		}
	}
	t.Fatalf("missing %s envelope from %d to %d", payloadType, from, to)
	return tss.Envelope{}
}

func mustFROSTKeygenShareFromLocal(t *testing.T, session *KeygenSession, recipient tss.PartyID) tss.Envelope {
	t.Helper()
	if session == nil || session.local == nil || session.local.polynomial == nil {
		t.Fatal("missing local polynomial for test keygen share")
	}
	share := evalScalarPolynomial(session.local.polynomial, recipient)
	secretShare, err := newEdSecretScalarFromFed(share)
	share.Set(fed.NewScalar())
	if err != nil {
		t.Fatal(err)
	}
	defer secretShare.Destroy()
	payload, err := marshalKeygenSharePayloadWithLimits(keygenSharePayload{
		Share:    secretShare,
		PlanHash: bytes.Clone(session.planHash),
	}, session.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	env, err := newEnvelope(
		session.cfg,
		keygenShareRound,
		session.cfg.Self,
		recipient,
		payloadKeygenShare,
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	return env
}
