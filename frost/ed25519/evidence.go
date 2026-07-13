package ed25519

import (
	"crypto/sha256"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
)

const (
	frostEvidenceFieldPartiesHash     = "parties_hash"
	frostEvidenceFieldPublicKeyHash   = "public_key_hash"
	frostEvidenceFieldCommitmentsHash = "commitments_hash"
	frostEvidenceFieldSignerSetHash   = "signer_set_hash"
	frostPartySetHashLabel            = "frost-ed25519-party-set-v1"
	frostCommitmentsHashLabel         = "frost-ed25519-keygen-commitments-v1"
	frostReshareCommitmentsHashLabel  = "frost-ed25519-reshare-commitments-v1"
	frostChainCodeCommitLabel         = "frost-ed25519-chain-code-commit-v1"
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
	evidenceEnv, err := newEnvelope(config, 1, dealer, config.Self, payloadKeygenShare, nil)
	if err != nil {
		// Envelope construction with nil payload is infallible under normal
		// operation; only a corrupted limits config could trigger this path.
		return &tss.Blame{
			Reason:  "invalid DKG share",
			Parties: tss.NewPartySet(dealer),
		}
	}
	return &tss.Blame{
		Reason:  "invalid DKG share",
		Parties: tss.NewPartySet(dealer),
		Evidence: frostMarshalEvidence(
			evidenceEnv,
			tss.EvidenceKindFrostKeygenShare,
			"invalid DKG share",
			tss.EvidenceField{Key: frostEvidenceFieldPartiesHash, Value: tss.PartySetHash(config.Parties, frostPartySetHashLabel)},
			tss.EvidenceField{Key: frostEvidenceFieldCommitmentsHash, Value: transcript.ByteSlicesHash(frostCommitmentsHashLabel, commitments)},
		),
	}
}

// frostReshareBlame builds Blame evidence for an invalid FROST reshare share.
func frostReshareBlame(config tss.ThresholdConfig, dealer tss.PartyID, commitments [][]byte) *tss.Blame {
	evidenceEnv, err := newEnvelope(config, 1, dealer, config.Self, payloadReshareShare, nil)
	if err != nil {
		// Envelope construction with nil payload is infallible under normal
		// operation; only a corrupted limits config could trigger this path.
		return &tss.Blame{
			Reason:  "invalid reshare share",
			Parties: tss.NewPartySet(dealer),
		}
	}
	return &tss.Blame{
		Reason:  "invalid reshare share",
		Parties: tss.NewPartySet(dealer),
		Evidence: frostMarshalEvidence(
			evidenceEnv,
			tss.EvidenceKindFrostReshareShare,
			"invalid reshare share",
			tss.EvidenceField{Key: frostEvidenceFieldPartiesHash, Value: tss.PartySetHash(config.Parties, frostPartySetHashLabel)},
			tss.EvidenceField{Key: frostEvidenceFieldCommitmentsHash, Value: transcript.ByteSlicesHash(frostReshareCommitmentsHashLabel, commitments)},
		),
	}
}

// frostNonceCommitmentBlame builds blame evidence for an invalid FROST nonce commitment.
func frostNonceCommitmentBlame(env tss.Envelope, signers tss.PartySet, publicKey []byte) *tss.Blame {
	return &tss.Blame{
		Reason:  "invalid FROST nonce commitment",
		Parties: tss.NewPartySet(env.From),
		Evidence: frostMarshalEvidence(
			env,
			tss.EvidenceKindFrostNonceCommitment,
			"invalid FROST nonce commitment",
			tss.EvidenceField{Key: frostEvidenceFieldSignerSetHash, Value: tss.PartySetHash(signers, frostPartySetHashLabel)},
			frostHashField(frostEvidenceFieldPublicKeyHash, publicKey),
		),
	}
}

// frostSignBlame builds Blame evidence for an invalid FROST partial signature.
func frostSignBlame(env tss.Envelope, signers tss.PartySet, publicKey []byte) *tss.Blame {
	return &tss.Blame{
		Reason:  "invalid FROST partial signature",
		Parties: tss.NewPartySet(env.From),
		Evidence: frostMarshalEvidence(
			env,
			tss.EvidenceKindFrostPartialSignature,
			"invalid FROST partial signature",
			tss.EvidenceField{Key: frostEvidenceFieldSignerSetHash, Value: tss.PartySetHash(signers, frostPartySetHashLabel)},
			frostHashField(frostEvidenceFieldPublicKeyHash, publicKey),
		),
	}
}

func frostHashField(key string, value []byte) tss.EvidenceField {
	sum := sha256.Sum256(value)
	return tss.EvidenceField{Key: key, Value: sum[:]}
}
