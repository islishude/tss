package ed25519

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
)

const (
	frostEvidenceFieldPartiesHash     = "parties_hash"
	frostEvidenceFieldPublicKeyHash   = "public_key_hash"
	frostEvidenceFieldCommitmentsHash = "commitments_hash"
	frostEvidenceFieldSignerSetHash   = "signer_set_hash"
	frostPartySetHashLabel            = "frost-ed25519-party-set-v1"
	frostCommitmentsHashLabel         = "frost-ed25519-keygen-commitments-v1"
	frostReshareCommitmentsHashLabel  = "frost-ed25519-reshare-commitments-v1"
)

func frostMarshalEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, fields ...tss.EvidenceField) []byte {
	evidence, err := tss.NewBlameEvidence(env, kind, reason, fields)
	if err != nil {
		return nil
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		return nil
	}
	return encoded
}

// frostKeygenBlame builds Blame evidence for an invalid FROST DKG share.
func frostKeygenBlame(config tss.ThresholdConfig, dealer tss.PartyID, commitments [][]byte) *tss.Blame {
	evidenceEnv := envelope(config, 1, dealer, config.Self, payloadKeygenShare, nil, true)
	return &tss.Blame{
		Reason:  "invalid DKG share",
		Parties: []tss.PartyID{dealer},
		Evidence: frostMarshalEvidence(
			evidenceEnv,
			tss.EvidenceKindFrostKeygenShare,
			"invalid DKG share",
			frostRawField(frostEvidenceFieldPartiesHash, frostPartySetHash(config.Parties)),
			frostRawField(frostEvidenceFieldCommitmentsHash, frostByteSlicesHash(frostCommitmentsHashLabel, commitments)),
		),
	}
}

// frostReshareBlame builds Blame evidence for an invalid FROST reshare share.
func frostReshareBlame(config tss.ThresholdConfig, dealer tss.PartyID, commitments [][]byte) *tss.Blame {
	evidenceEnv := envelope(config, 1, dealer, config.Self, payloadReshareShare, nil, true)
	return &tss.Blame{
		Reason:  "invalid reshare share",
		Parties: []tss.PartyID{dealer},
		Evidence: frostMarshalEvidence(
			evidenceEnv,
			tss.EvidenceKindFrostReshareShare,
			"invalid reshare share",
			frostRawField(frostEvidenceFieldPartiesHash, frostPartySetHash(config.Parties)),
			frostRawField(frostEvidenceFieldCommitmentsHash, frostByteSlicesHash(frostReshareCommitmentsHashLabel, commitments)),
		),
	}
}

// frostSignBlame builds Blame evidence for an invalid FROST partial signature.
func frostSignBlame(sessionID tss.SessionID, signers []tss.PartyID, signer tss.PartyID, publicKey []byte) *tss.Blame {
	env := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       2,
		From:        signer,
		PayloadType: payloadSignPartial,
	}.WithTranscriptHash()
	return &tss.Blame{
		Reason:  "invalid FROST partial signature",
		Parties: []tss.PartyID{signer},
		Evidence: frostMarshalEvidence(
			env,
			tss.EvidenceKindFrostPartialSignature,
			"invalid FROST partial signature",
			frostRawField(frostEvidenceFieldSignerSetHash, frostPartySetHash(signers)),
			frostHashField(frostEvidenceFieldPublicKeyHash, publicKey),
		),
	}
}

// frostAggregateBlame builds Blame evidence for a failed aggregate Ed25519 signature.
func frostAggregateBlame(sessionID tss.SessionID, signers []tss.PartyID, publicKey, message, sig []byte) *tss.Blame {
	env := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       2,
		PayloadType: payloadSignPartial,
	}.WithTranscriptHash()
	return &tss.Blame{
		Reason:  "aggregated Ed25519 signature failed verification",
		Parties: append([]tss.PartyID(nil), signers...),
		Evidence: frostMarshalEvidence(
			env,
			tss.EvidenceKindFrostAggregateSignature,
			"aggregated Ed25519 signature failed verification",
			frostRawField(frostEvidenceFieldSignerSetHash, frostPartySetHash(signers)),
			frostHashField(frostEvidenceFieldPublicKeyHash, publicKey),
			frostHashField("message_hash", message),
			frostHashField("signature_hash", sig),
		),
	}
}

func frostPartySetHash(parties []tss.PartyID) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(frostPartySetHashLabel))
	sorted := tss.SortParties(parties)
	for _, id := range sorted {
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
	}
	return h.Sum(nil)
}

func frostByteSlicesHash(label string, values [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(label))
	for _, value := range values {
		wire.WriteHashPart(h, value)
	}
	return h.Sum(nil)
}

func frostRawField(key string, value []byte) tss.EvidenceField {
	return tss.EvidenceField{Key: key, Value: append([]byte(nil), value...)}
}

func frostHashField(key string, value []byte) tss.EvidenceField {
	sum := sha256.Sum256(value)
	return tss.EvidenceField{Key: key, Value: sum[:]}
}
