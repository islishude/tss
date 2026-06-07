package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const (
	evidenceFieldPartiesHash             = "parties_hash"
	evidenceFieldSignerSetHash           = "signer_set_hash"
	evidenceFieldPublicKeyHash           = "public_key_hash"
	evidenceFieldKeygenTranscriptHash    = "keygen_transcript_hash"
	evidenceFieldPresignTranscriptHash   = "presign_transcript_hash"
	evidenceFieldPaillierPublicKeysHash  = "paillier_public_keys_hash"
	evidenceFieldExpectedPaillierKeyHash = "expected_paillier_public_key_hash"
	evidenceFieldObservedPaillierKeyHash = "observed_paillier_public_key_hash"
	evidenceFieldCommitmentsHash         = "commitments_hash"
	evidenceFieldDigestHash              = "digest_hash"
	evidenceFieldRHash                   = "r_hash"
	evidenceFieldSHash                   = "s_hash"
	evidenceFieldDeltaResponseHash       = "delta_response_hash"
	evidenceFieldSigmaResponseHash       = "sigma_response_hash"
)

const (
	partySetHashLabel             = "cggmp21-secp256k1-party-set-v1"
	paillierPublicSharesHashLabel = "cggmp21-secp256k1-paillier-public-shares-v1"
)

// EvidenceContext is the public context used to verify CGGMP21 blame evidence.
type EvidenceContext struct {
	SessionID             tss.SessionID
	Parties               []tss.PartyID
	PublicKey             []byte
	PaillierPublicKeys    []PaillierPublicShare
	Signers               []tss.PartyID
	KeygenTranscriptHash  []byte
	PresignTranscriptHash []byte
}

// VerifyBlameEvidence checks that a public blame record belongs to the CGGMP21
// session context the caller already trusts. It does not authenticate transport
// delivery; callers still need authenticated envelopes.
func VerifyBlameEvidence(encoded []byte, ctx EvidenceContext) error {
	evidence, err := tss.UnmarshalBlameEvidence(encoded)
	if err != nil {
		return err
	}
	if evidence.Protocol != protocol {
		return fmt.Errorf("unexpected evidence protocol %q", evidence.Protocol)
	}
	if ctx.SessionID != (tss.SessionID{}) && evidence.SessionID != ctx.SessionID {
		return errors.New("evidence session mismatch")
	}
	if err := validateEvidenceShape(evidence); err != nil {
		return err
	}
	if len(ctx.Parties) > 0 && evidence.From != 0 && !tss.ContainsParty(ctx.Parties, evidence.From) {
		return fmt.Errorf("evidence sender %d is not a participant", evidence.From)
	}
	if evidence.From != 0 && len(ctx.Signers) > 0 && isSignerScopedEvidence(evidence.Kind) && !tss.ContainsParty(ctx.Signers, evidence.From) {
		return fmt.Errorf("evidence sender %d is not in signer set", evidence.From)
	}
	if err := compareEvidenceField(evidence, evidenceFieldPartiesHash, wireutil.PartySetHash(ctx.Parties, partySetHashLabel), len(ctx.Parties) > 0); err != nil {
		return err
	}
	if err := compareEvidenceField(evidence, evidenceFieldSignerSetHash, wireutil.PartySetHash(ctx.Signers, partySetHashLabel), len(ctx.Signers) > 0); err != nil {
		return err
	}
	if err := compareEvidenceField(evidence, evidenceFieldPublicKeyHash, hashBytes(ctx.PublicKey), len(ctx.PublicKey) > 0); err != nil {
		return err
	}
	if err := compareEvidenceField(evidence, evidenceFieldKeygenTranscriptHash, ctx.KeygenTranscriptHash, len(ctx.KeygenTranscriptHash) > 0); err != nil {
		return err
	}
	if err := compareEvidenceField(evidence, evidenceFieldPresignTranscriptHash, ctx.PresignTranscriptHash, len(ctx.PresignTranscriptHash) > 0); err != nil {
		return err
	}
	if err := compareEvidenceField(evidence, evidenceFieldPaillierPublicKeysHash, paillierPublicSharesHash(ctx.PaillierPublicKeys), len(ctx.PaillierPublicKeys) > 0); err != nil {
		return err
	}
	if expected, ok := evidence.Field(evidenceFieldExpectedPaillierKeyHash); ok && len(ctx.PaillierPublicKeys) > 0 {
		share, found := paillierPublicShareFor(ctx.PaillierPublicKeys, evidence.From)
		if !found {
			return fmt.Errorf("missing Paillier public key for evidence sender %d", evidence.From)
		}
		if !bytes.Equal(expected, hashBytes(share.PublicKey)) {
			return errors.New("expected Paillier public key hash mismatch")
		}
	}
	return nil
}

func verificationErrorWithEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, blamed []tss.PartyID, err error, fields ...tss.EvidenceField) *tss.ProtocolError {
	return protocolErrorWithEvidence(tss.ErrCodeVerification, env, kind, reason, blamed, err, fields...)
}

func protocolErrorWithEvidence(code string, env tss.Envelope, kind tss.EvidenceKind, reason string, blamed []tss.PartyID, err error, fields ...tss.EvidenceField) *tss.ProtocolError {
	evidenceBytes := marshalEvidence(env, kind, reason, fields...)
	return &tss.ProtocolError{
		Code:  code,
		Round: env.Round,
		Party: env.From,
		Blame: &tss.Blame{
			Reason:   reason,
			Parties:  append([]tss.PartyID(nil), blamed...),
			Evidence: evidenceBytes,
		},
		Err: err,
	}
}

func marshalEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, fields ...tss.EvidenceField) []byte {
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

func keyContextEvidenceFields(key *KeyShare) []tss.EvidenceField {
	if key == nil {
		return nil
	}
	fields := []tss.EvidenceField{
		rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(key.Parties, partySetHashLabel)),
		hashEvidenceField(evidenceFieldPublicKeyHash, key.PublicKey),
		rawEvidenceField(evidenceFieldPaillierPublicKeysHash, paillierPublicSharesHash(key.PaillierPublicKeys)),
	}
	if len(key.KeygenTranscriptHash) > 0 {
		fields = append(fields, rawEvidenceField(evidenceFieldKeygenTranscriptHash, key.KeygenTranscriptHash))
	}
	return fields
}

func signerEvidenceFields(signers []tss.PartyID) []tss.EvidenceField {
	return []tss.EvidenceField{rawEvidenceField(evidenceFieldSignerSetHash, wireutil.PartySetHash(signers, partySetHashLabel))}
}

func rawEvidenceField(key string, value []byte) tss.EvidenceField {
	return tss.EvidenceField{Key: key, Value: append([]byte(nil), value...)}
}

func hashEvidenceField(key string, value []byte) tss.EvidenceField {
	return rawEvidenceField(key, hashBytes(value))
}

func hashBytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func paillierPublicSharesHash(shares []PaillierPublicShare) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(paillierPublicSharesHashLabel))
	sorted := clonePaillierPublicShares(shares)
	slices.SortFunc(sorted, func(a, b PaillierPublicShare) int {
		return int(a.Party) - int(b.Party)
	})
	for _, share := range sorted {
		wire.WritePartyID(h, share.Party)
		wire.WriteHashPart(h, share.PublicKey)
		wire.WriteHashPart(h, share.Proof)
	}
	return h.Sum(nil)
}

func clonePaillierPublicShares(in []PaillierPublicShare) []PaillierPublicShare {
	if len(in) == 0 {
		return nil
	}
	out := make([]PaillierPublicShare, len(in))
	for i, share := range in {
		out[i] = share.Clone()
	}
	return out
}

func cloneRingPedersenPublicShares(in []RingPedersenPublicShare) []RingPedersenPublicShare {
	if len(in) == 0 {
		return nil
	}
	out := make([]RingPedersenPublicShare, len(in))
	for i, share := range in {
		out[i] = share.Clone()
	}
	return out
}

func paillierPublicShareFor(shares []PaillierPublicShare, id tss.PartyID) (PaillierPublicShare, bool) {
	for _, share := range shares {
		if share.Party == id {
			return share, true
		}
	}
	return PaillierPublicShare{}, false
}

func compareEvidenceField(evidence *tss.BlameEvidence, key string, expected []byte, active bool) error {
	if !active {
		return nil
	}
	actual, ok := evidence.Field(key)
	if !ok {
		return nil
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("evidence field %q mismatch", key)
	}
	return nil
}

func validateEvidenceShape(evidence *tss.BlameEvidence) error {
	switch evidence.Kind {
	case tss.EvidenceKindKeygenCommitment:
		return expectEvidenceMessage(evidence, 1, payloadKeygenCommitments)
	case tss.EvidenceKindKeygenPaillier:
		return expectEvidenceMessage(evidence, 1, payloadKeygenCommitments)
	case tss.EvidenceKindKeygenShare:
		return expectEvidenceMessage(evidence, 1, payloadKeygenShare)
	case tss.EvidenceKindRefreshShare:
		return expectEvidenceMessage(evidence, 1, payloadRefreshShare)
	case tss.EvidenceKindReshareShare:
		return expectEvidenceMessage(evidence, 1, payloadReshareShare)
	case tss.EvidenceKindPresignRound1:
		if evidence.Round != 1 {
			return fmt.Errorf("evidence round %d does not match %d", evidence.Round, 1)
		}
		if evidence.PayloadType != payloadPresignRound1 && evidence.PayloadType != payloadPresignRound1Proof {
			return fmt.Errorf("evidence payload type %q is not a presign round1 payload", evidence.PayloadType)
		}
		return nil
	case tss.EvidenceKindPresignRound2:
		return expectEvidenceMessage(evidence, 2, payloadPresignRound2)
	case tss.EvidenceKindPresignRound3:
		return expectEvidenceMessage(evidence, 3, payloadPresignRound3)
	case tss.EvidenceKindSignPartial, tss.EvidenceKindAggregateSign:
		return expectEvidenceMessage(evidence, 1, payloadSignPartial)
	default:
		return fmt.Errorf("unknown evidence kind %q", evidence.Kind)
	}
}

func expectEvidenceMessage(evidence *tss.BlameEvidence, round uint8, payloadType string) error {
	if evidence.Round != round {
		return fmt.Errorf("evidence round %d does not match %d", evidence.Round, round)
	}
	if evidence.PayloadType != payloadType {
		return fmt.Errorf("evidence payload type %q does not match %q", evidence.PayloadType, payloadType)
	}
	return nil
}

func isSignerScopedEvidence(kind tss.EvidenceKind) bool {
	switch kind {
	case tss.EvidenceKindPresignRound1, tss.EvidenceKindPresignRound2, tss.EvidenceKindPresignRound3, tss.EvidenceKindSignPartial:
		return true
	default:
		return false
	}
}
