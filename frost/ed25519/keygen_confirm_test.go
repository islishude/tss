package ed25519

import (
	"bytes"
	"errors"
	"testing"

	"github.com/islishude/tss"
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
	decoded, err := UnmarshalKeygenConfirmation(raw)
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
	if _, err := UnmarshalKeygenConfirmation(append(raw, 0)); err == nil {
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
	confirmations[1].PublicKey = bytes.Clone(confirmations[1].PublicKey)
	confirmations[1].PublicKey[0] ^= 1
	if err := applyKeygenConfirmationSet(shares[1], confirmations); err == nil {
		t.Fatal("expected rejection for mismatched public key")
	}
}

func TestFROSTKeyShareRejectsTamperedHDChainCode(t *testing.T) {
	t.Parallel()
	shares := frostKeygenHD(t, 2, 3)
	tampered := cloneKeyShareValue(shares[1])
	tampered.state.chainCode[0] ^= 1
	if err := verifyFinalizedKeygenConfirmationSet(tampered, tampered.state.keygenConfirmations, true); err == nil {
		t.Fatal("expected tampered aggregate chain code to be rejected")
	}
}

func TestFROSTKeyShareRejectsTamperedConfirmationChainCode(t *testing.T) {
	t.Parallel()
	shares := frostKeygenHD(t, 2, 3)
	tampered := cloneKeyShareValue(shares[1])
	cc := *tampered.state.keygenConfirmations[1]
	cc.ChainCode = bytes.Clone(cc.ChainCode)
	cc.ChainCode[0] ^= 1
	tampered.state.keygenConfirmations[1] = &cc
	if err := verifyFinalizedKeygenConfirmationSet(tampered, tampered.state.keygenConfirmations, true); err == nil {
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

	confirmations := make([]tss.Envelope, 0, len(parties))
	for _, env := range messages {
		for _, id := range parties {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := sessions[id].HandleKeygenMessage(testutil.DeliverEnvelope(env))
			if err != nil {
				t.Fatalf("deliver %s from %d to %d: %v", env.PayloadType, env.From, id, err)
			}
			for _, produced := range out {
				if produced.PayloadType == payloadKeygenConfirmation {
					confirmations = append(confirmations, produced)
				}
			}
		}
	}

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
	if _, err := sessions[1].HandleKeygenMessage(testutil.DeliverEnvelope(fromParty2)); err != nil {
		t.Fatal(err)
	}
	if share, ok := sessions[1].KeyShare(); ok || share != nil {
		t.Fatal("session completed before all confirmations arrived")
	}

	conflicting := fromParty2
	decoded, err := UnmarshalKeygenConfirmation(conflicting.Payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded.TranscriptHash = bytes.Clone(decoded.TranscriptHash)
	decoded.TranscriptHash[0] ^= 1
	conflicting.Payload, err = decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = sessions[1].HandleKeygenMessage(testutil.DeliverEnvelope(conflicting))
	if !errors.Is(err, tss.ErrEquivocation) {
		t.Fatalf("expected ErrEquivocation for conflicting confirmation, got %v", err)
	}
	if share, ok := sessions[1].KeyShare(); ok || share != nil {
		t.Fatal("aborted session returned a key share")
	}
	for _, pd := range sessions[1].partyData {
		if pd.share != nil {
			t.Fatal("aborted keygen retained received share scalars")
		}
	}
	if sessions[1].ownPoly != nil {
		t.Fatal("aborted keygen retained local polynomial")
	}
	if sessions[1].ownMessages != nil {
		t.Fatal("aborted keygen retained secret outbound messages")
	}
	for _, pd := range sessions[1].partyData {
		if pd.chainCode != nil {
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
