package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const (
	evidenceFieldPartiesHash                 = "parties_hash"
	evidenceFieldSignerSetHash               = "signer_set_hash"
	evidenceFieldPublicKeyHash               = "public_key_hash"
	evidenceFieldKeygenTranscriptHash        = "keygen_transcript_hash"
	evidenceFieldPresignTranscriptHash       = "presign_transcript_hash"
	evidenceFieldPaillierPublicKeysHash      = "paillier_public_keys_hash"
	evidenceFieldExpectedPaillierKeyHash     = "expected_paillier_public_key_hash"
	evidenceFieldObservedPaillierKeyHash     = "observed_paillier_public_key_hash"
	evidenceFieldCommitmentsHash             = "commitments_hash"
	evidenceFieldDigestHash                  = "digest_hash"
	evidenceFieldRHash                       = "r_hash"
	evidenceFieldSHash                       = "s_hash"
	evidenceFieldDeltaResponseHash           = "delta_response_hash"
	evidenceFieldSigmaResponseHash           = "sigma_response_hash"
	evidenceFieldSignVerifyKPointHash        = "sign_verify_k_point_hash"
	evidenceFieldSignVerifyChiPointHash      = "sign_verify_chi_point_hash"
	evidenceFieldSignPrepProofHash           = "signprep_proof_hash"
	evidenceFieldPartialEquationHash         = "partial_equation_hash"
	evidenceFieldObservedPartialEquationHash = "observed_partial_equation_hash"
)

const (
	partySetHashLabel             = "cggmp21-secp256k1-party-set-v1"
	paillierPublicSharesHashLabel = "cggmp21-secp256k1-paillier-public-shares-v1"
)

// EvidenceContext is the public context used to verify CGGMP21 blame evidence.
type EvidenceContext struct {
	SessionID             tss.SessionID
	Parties               tss.PartySet
	PublicKey             []byte
	PaillierPublicKeys    []PaillierPublicShare
	Signers               tss.PartySet
	KeygenTranscriptHash  []byte
	PresignTranscriptHash []byte
}

// VerifyBlameEvidence checks that a public blame record belongs to the CGGMP21
// session context the caller already trusts. It does not authenticate transport
// delivery; callers still need authenticated envelopes.
func VerifyBlameEvidence(encoded []byte, ctx EvidenceContext) error {
	evidence, err := tss.DecodeBinary[tss.BlameEvidence](encoded)
	if err != nil {
		return err
	}
	if evidence.Protocol != tss.ProtocolCGGMP21Secp256k1 {
		return fmt.Errorf("unexpected evidence protocol %q", evidence.Protocol)
	}
	if ctx.SessionID.Valid() && evidence.SessionID != ctx.SessionID {
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

func verificationErrorWithEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, blamed tss.PartySet, err error, fields ...tss.EvidenceField) *tss.ProtocolError {
	return protocolErrorWithEvidence(tss.ErrCodeVerification, env, kind, reason, blamed, err, fields...)
}

func protocolErrorWithEvidence(code string, env tss.Envelope, kind tss.EvidenceKind, reason string, blamed tss.PartySet, err error, fields ...tss.EvidenceField) *tss.ProtocolError {
	evidenceBytes, evErr := marshalEvidence(env, kind, reason, fields...)
	if evErr != nil {
		// Evidence construction failed — report an invariant failure instead of
		// returning a blame record with empty evidence. The wrapped error preserves
		// the original cause so callers can still attribute the failure.
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From,
			fmt.Errorf("blame evidence marshal failed: %w (original: %w)", evErr, err))
	}
	return &tss.ProtocolError{
		Code:  code,
		Round: env.Round,
		Party: env.From,
		Blame: &tss.Blame{
			Reason:   reason,
			Parties:  blamed.Clone(),
			Evidence: evidenceBytes,
		},
		Err: err,
	}
}

func marshalEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, fields ...tss.EvidenceField) ([]byte, error) {
	evidence, err := tss.NewBlameEvidence(env, kind, reason, fields)
	if err != nil {
		return nil, err
	}
	encoded, err := evidence.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// newBlame builds a tss.Blame from evidence fields. If evidence marshaling fails,
// it returns nil — the caller should fall back to [tss.ErrCodeInvariant] without blame.
func newBlame(env tss.Envelope, kind tss.EvidenceKind, reason string, blamed tss.PartySet, fields ...tss.EvidenceField) *tss.Blame {
	evidenceBytes, err := marshalEvidence(env, kind, reason, fields...)
	if err != nil {
		return nil
	}
	return &tss.Blame{
		Reason:   reason,
		Parties:  blamed.Clone(),
		Evidence: evidenceBytes,
	}
}

func keyContextEvidenceFields(key *KeyShare) []tss.EvidenceField {
	if key == nil {
		return nil
	}
	paillierPublicKeys, err := key.paillierPublicShares(DefaultLimits())
	if err != nil {
		paillierPublicKeys = nil
	}
	fields := []tss.EvidenceField{
		rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(key.state.parties, partySetHashLabel)),
		hashEvidenceField(evidenceFieldPublicKeyHash, key.state.publicKey),
		rawEvidenceField(evidenceFieldPaillierPublicKeysHash, paillierPublicSharesHash(paillierPublicKeys)),
	}
	if len(key.state.keygenTranscriptHash) > 0 {
		fields = append(fields, rawEvidenceField(evidenceFieldKeygenTranscriptHash, key.state.keygenTranscriptHash))
	}
	return fields
}

func signerEvidenceFields(signers tss.PartySet) []tss.EvidenceField {
	return []tss.EvidenceField{rawEvidenceField(evidenceFieldSignerSetHash, wireutil.PartySetHash(signers, partySetHashLabel))}
}

func rawEvidenceField(key string, value []byte) tss.EvidenceField {
	return tss.EvidenceField{Key: key, Value: append([]byte(nil), value...)}
}

func hashEvidenceField(key string, value []byte) tss.EvidenceField {
	return rawEvidenceField(key, hashBytes(value))
}

func canonicalWireMessageBytes(msg wire.Message, limits Limits) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("nil wire message")
	}
	return wire.Marshal(msg, wire.WithFieldLimitsForMarshal(limits.fieldLimits()))
}

func hashWireEvidenceField(key string, msg wire.Message, limits Limits) (tss.EvidenceField, error) {
	raw, err := canonicalWireMessageBytes(msg, limits)
	if err != nil {
		return tss.EvidenceField{}, fmt.Errorf("%s: %w", key, err)
	}
	return hashEvidenceField(key, raw), nil
}

func hashBytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func paillierPublicSharesHash(shares []PaillierPublicShare) []byte {
	t := transcript.New(paillierPublicSharesHashLabel)
	sorted := tss.CloneSlice(shares)
	slices.SortFunc(sorted, func(a, b PaillierPublicShare) int {
		return int(a.Party) - int(b.Party)
	})
	for _, share := range sorted {
		t.AppendUint32("party", share.Party)
		t.AppendBytes("public_key", share.PublicKey)
		t.AppendBytes("proof", share.Proof)
	}
	return t.Sum()
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
		return fmt.Errorf("missing evidence field %q", key)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("evidence field %q mismatch", key)
	}
	return nil
}

func validateEvidenceShape(evidence *tss.BlameEvidence) error {
	switch evidence.Kind {
	case tss.EvidenceKindKeygenCommitment:
		return expectEvidenceMessage(evidence, keygenStartRound, payloadKeygenCommitments)
	case tss.EvidenceKindKeygenPaillier:
		return expectEvidenceMessage(evidence, keygenStartRound, payloadKeygenCommitments)
	case tss.EvidenceKindKeygenShare:
		return expectEvidenceMessage(evidence, keygenStartRound, payloadKeygenShare)
	case tss.EvidenceKindRefreshShare:
		return expectEvidenceMessage(evidence, refreshStartRound, payloadRefreshShare)
	case tss.EvidenceKindReshareShare:
		return expectEvidenceMessage(evidence, reshareStartRound, payloadReshareShare)
	case tss.EvidenceKindPresignRound1:
		if evidence.Round != presignStartRound {
			return fmt.Errorf("evidence round %d does not match %d", evidence.Round, presignStartRound)
		}
		if evidence.PayloadType != payloadPresignRound1 && evidence.PayloadType != payloadPresignRound1Proof {
			return fmt.Errorf("evidence payload type %q is not a presign round1 payload", evidence.PayloadType)
		}
		return nil
	case tss.EvidenceKindPresignRound2:
		return expectEvidenceMessage(evidence, presignRound2, payloadPresignRound2)
	case tss.EvidenceKindPresignRound3:
		return expectEvidenceMessage(evidence, presignRound3, payloadPresignRound3)
	case tss.EvidenceKindSignPartial, tss.EvidenceKindAggregateSign:
		return expectEvidenceMessage(evidence, signStartRound, payloadSignPartial)
	default:
		return fmt.Errorf("unknown evidence kind %q", evidence.Kind)
	}
}

func expectEvidenceMessage(evidence *tss.BlameEvidence, round uint8, payloadType tss.PayloadType) error {
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
