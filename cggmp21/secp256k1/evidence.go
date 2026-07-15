package secp256k1

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
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
	Threshold             int
	Parties               tss.PartySet
	PublicKey             []byte
	SecurityParams        *SecurityParams
	VerificationShares    []VerificationShare
	PaillierPublicKeys    []PaillierPublicShare
	RingPedersenParams    []RingPedersenPublicShare
	Signers               tss.PartySet
	KeygenTranscriptHash  []byte
	PresignTranscriptHash []byte
	ContextHash           []byte
	DerivationShift       []byte
	// EnvelopeVerifier authenticates portable signed envelopes embedded in an
	// IdentificationRecord.
	EnvelopeVerifier tss.EnvelopeSignatureVerifier
	// BroadcastACKVerifier authenticates public broadcast certificates embedded
	// in an IdentificationRecord.
	BroadcastACKVerifier tss.BroadcastAckVerifier
	// IdentificationVerifier replays a proof-backed accusation against trusted,
	// public protocol transcript material after the library authenticates the
	// portable envelope and optional broadcast certificate. Figure 9 callers use
	// this hook to supply the retained public round transcript.
	IdentificationVerifier IdentificationFailureVerifier
}

// IdentificationFailureVerifier verifies a proof-backed identifiable-abort
// accusation using public, authenticated protocol transcript material.
type IdentificationFailureVerifier interface {
	VerifyIdentificationFailure(evidence tss.BlameEvidence, record tss.IdentificationRecord) error
}

// VerifyBlameEvidence checks that a public blame record belongs to the CGGMP21
// session context the caller already trusts. It does not authenticate transport
// delivery; callers still need authenticated envelopes.
func VerifyBlameEvidence(encoded []byte, ctx EvidenceContext) error {
	var evidence *tss.BlameEvidence
	var err error
	if len(encoded) > tss.DefaultMaxBlameEvidenceBytes {
		evidence, err = tss.UnmarshalBlameEvidenceWithLimits(encoded, figure9EvidenceLimits())
		if err == nil && evidence.Kind != tss.EvidenceKindPresignRedAlert {
			return errors.New("oversized non-Figure 9 blame evidence")
		}
	} else {
		evidence, err = tss.DecodeBinary[tss.BlameEvidence](encoded)
	}
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
	if err := compareEvidenceField(evidence, evidenceFieldPartiesHash, tss.PartySetHash(ctx.Parties, partySetHashLabel), len(ctx.Parties) > 0); err != nil {
		return err
	}
	if err := compareEvidenceField(evidence, evidenceFieldSignerSetHash, tss.PartySetHash(ctx.Signers, partySetHashLabel), len(ctx.Signers) > 0); err != nil {
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
	if encodedRecord, ok := evidence.Field(tss.IdentificationRecordEvidenceKey); ok {
		if err := verifyIdentificationRecord(evidence, encodedRecord, ctx); err != nil {
			return err
		}
	} else if evidence.Kind == tss.EvidenceKindPresignRedAlert {
		return errors.New("identification evidence is missing its public record")
	}
	return nil
}

func verifyIdentificationRecord(evidence *tss.BlameEvidence, encoded []byte, ctx EvidenceContext) error {
	var record tss.IdentificationRecord
	if err := record.UnmarshalBinaryWithLimits(encoded, identificationLimitsForKind(evidence.Kind)); err != nil {
		return fmt.Errorf("invalid identification record: %w", err)
	}
	if record.Accused != evidence.From {
		return errors.New("identification accused party does not match evidence sender")
	}
	if len(ctx.Parties) > 0 && !tss.ContainsParty(ctx.Parties, record.Accused) {
		return errors.New("identification accused party is not a participant")
	}
	for _, field := range record.TranscriptHashes {
		switch field.Key {
		case evidenceFieldPartiesHash:
			if len(ctx.Parties) > 0 && !bytes.Equal(field.Value, tss.PartySetHash(ctx.Parties, partySetHashLabel)) {
				return errors.New("identification party-set hash mismatch")
			}
		case evidenceFieldSignerSetHash:
			if len(ctx.Signers) > 0 && !bytes.Equal(field.Value, tss.PartySetHash(ctx.Signers, partySetHashLabel)) {
				return errors.New("identification signer-set hash mismatch")
			}
		case evidenceFieldKeygenTranscriptHash:
			if len(ctx.KeygenTranscriptHash) > 0 && !bytes.Equal(field.Value, ctx.KeygenTranscriptHash) {
				return errors.New("identification keygen transcript mismatch")
			}
		case evidenceFieldPresignTranscriptHash:
			if len(ctx.PresignTranscriptHash) > 0 && !bytes.Equal(field.Value, ctx.PresignTranscriptHash) {
				return errors.New("identification presign transcript mismatch")
			}
		}
	}
	if len(record.SignedEnvelopeA) == 0 {
		return errors.New("portable identification evidence lacks an authenticated envelope")
	}
	first, err := tss.UnmarshalEnvelopeWithLimits(record.SignedEnvelopeA, envelopeLimitsForEvidence(tss.Envelope{
		Protocol: evidence.Protocol, Round: evidence.Round, PayloadType: evidence.PayloadType,
	}))
	if err != nil {
		return fmt.Errorf("decode first signed identification envelope: %w", err)
	}
	if first.From != record.Accused || first.SessionID != evidence.SessionID || first.Protocol != evidence.Protocol {
		return errors.New("first signed identification envelope context mismatch")
	}
	if len(record.BroadcastCertificate) == 0 {
		if ctx.EnvelopeVerifier == nil {
			return tss.ErrMissingEnvelopeSignatureVerifier
		}
		if err := tss.VerifyEnvelopeSignature(first, ctx.EnvelopeVerifier); err != nil {
			return err
		}
	} else if first.To != tss.BroadcastPartyId {
		return errors.New("broadcast identification certificate accompanies a direct envelope")
	}
	payloadHash := sha256.Sum256(first.Payload)
	envelopeDigest := first.Digest()
	if !bytes.Equal(evidence.PayloadHash, payloadHash[:]) || !bytes.Equal(evidence.EnvelopeDigest, envelopeDigest[:]) {
		return errors.New("evidence does not bind the first signed identification envelope")
	}
	if len(record.SignedEnvelopeB) > 0 {
		second, err := tss.UnmarshalEnvelopeWithLimits(record.SignedEnvelopeB, envelopeLimitsForEvidence(first))
		if err != nil {
			return fmt.Errorf("decode second signed identification envelope: %w", err)
		}
		if second.From != record.Accused || tss.SlotKeyFromEnvelope(first) != tss.SlotKeyFromEnvelope(second) {
			return errors.New("signed identification envelopes do not occupy the same sender slot")
		}
		if err := tss.VerifyEnvelopeSignature(second, ctx.EnvelopeVerifier); err != nil {
			return err
		}
		if tss.EnvelopeSigningDigest(first) == tss.EnvelopeSigningDigest(second) {
			return errors.New("signed identification envelopes are identical")
		}
	}
	if len(record.BroadcastCertificate) > 0 {
		if ctx.BroadcastACKVerifier == nil {
			return tss.ErrMissingAckVerifier
		}
		var certificate tss.BroadcastCertificate
		if err := certificate.UnmarshalBinary(record.BroadcastCertificate); err != nil {
			return err
		}
		if err := certificate.VerifyFull(first, evidenceCertificateRecipients(evidence.Kind, ctx), ctx.BroadcastACKVerifier); err != nil {
			return err
		}
	}
	if len(record.SignedEnvelopeB) > 0 {
		return nil
	}
	if ctx.IdentificationVerifier == nil {
		return fmt.Errorf("identification verifier required for signed failure class %q", record.FailureClass)
	}
	if err := ctx.IdentificationVerifier.VerifyIdentificationFailure(*evidence, record); err != nil {
		return err
	}
	return nil
}

// evidenceCertificateRecipients keeps the full key committee in the public
// evidence context while validating signer-scoped broadcasts against the exact
// signer set that was authorized to receive them.
func evidenceCertificateRecipients(kind tss.EvidenceKind, ctx EvidenceContext) tss.PartySet {
	if isSignerScopedEvidence(kind) {
		return ctx.Signers
	}
	return ctx.Parties
}

func verificationErrorWithEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, blamed tss.PartySet, err error, fields ...tss.EvidenceField) *tss.ProtocolError {
	return protocolErrorWithEvidence(tss.ErrCodeVerification, env, kind, reason, blamed, err, fields...)
}

func protocolErrorWithEvidence(code string, env tss.Envelope, kind tss.EvidenceKind, reason string, blamed tss.PartySet, err error, fields ...tss.EvidenceField) *tss.ProtocolError {
	if env.To != tss.BroadcastPartyId && len(env.SenderSignature) > 0 && !hasEvidenceField(fields, tss.IdentificationRecordEvidenceKey) {
		recordField, recordErr := signedFailureEvidenceField(env, kind, fields)
		if recordErr != nil {
			return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From,
				fmt.Errorf("signed blame record marshal failed: %w (original: %w)", recordErr, err))
		}
		fields = append(fields, recordField)
	}
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

func hasEvidenceField(fields []tss.EvidenceField, key string) bool {
	for i := range fields {
		if fields[i].Key == key {
			return true
		}
	}
	return false
}

func signedFailureEvidenceField(env tss.Envelope, kind tss.EvidenceKind, fields []tss.EvidenceField) (tss.EvidenceField, error) {
	envelopeBytes, err := env.MarshalBinaryWithLimits(envelopeLimitsForEvidence(env))
	if err != nil {
		return tss.EvidenceField{}, err
	}
	record := &tss.IdentificationRecord{
		FailureClass:    string(kind) + "_signed_failure",
		Accused:         env.From,
		SignedEnvelopeA: envelopeBytes,
	}
	for i := range fields {
		if len(fields[i].Value) == sha256.Size && fields[i].Key != tss.IdentificationRecordEvidenceKey {
			record.TranscriptHashes = append(record.TranscriptHashes, fields[i].Clone())
		}
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	return tss.IdentificationEvidenceFieldWithLimits(record, identificationLimitsForKind(kind))
}

// bindInboundAuthenticationEvidence upgrades attributable broadcast failures
// with the exact envelope and broadcast certificate already authenticated by
// the guard. Authentication failures themselves have no Blame and therefore
// remain transport errors rather than public accusations.
func bindInboundAuthenticationEvidence(err error, in tss.InboundEnvelope) error {
	if err == nil {
		return nil
	}
	var protocolErr *tss.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Blame == nil || len(protocolErr.Blame.Evidence) == 0 {
		return err
	}
	env := in.Envelope()
	if env.To != tss.BroadcastPartyId {
		return err
	}
	certificate := in.BroadcastCertificate()
	if certificate == nil {
		return err
	}

	evidenceLimits := evidenceLimitsForKind(tss.EvidenceKindPresignRedAlert)
	if !isFigure9Envelope(env) {
		evidenceLimits = tss.DefaultEvidenceLimits()
	}
	evidence, decodeErr := tss.UnmarshalBlameEvidenceWithLimits(protocolErr.Blame.Evidence, evidenceLimits)
	if decodeErr != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, fmt.Errorf("decode authenticated broadcast evidence: %w", decodeErr))
	}
	envelopeBytes, marshalErr := env.MarshalBinaryWithLimits(envelopeLimitsForEvidence(env))
	if marshalErr != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, fmt.Errorf("marshal authenticated broadcast envelope: %w", marshalErr))
	}
	certificateBytes, marshalErr := certificate.MarshalBinary()
	if marshalErr != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, fmt.Errorf("marshal authenticated broadcast certificate: %w", marshalErr))
	}

	record := tss.IdentificationRecord{
		FailureClass:         string(evidence.Kind) + "_certified_failure",
		Accused:              env.From,
		SignedEnvelopeA:      envelopeBytes,
		BroadcastCertificate: certificateBytes,
	}
	hadRecord := false
	for i := range evidence.PublicInputs {
		if evidence.PublicInputs[i].Key != tss.IdentificationRecordEvidenceKey {
			continue
		}
		if unmarshalErr := record.UnmarshalBinaryWithLimits(evidence.PublicInputs[i].Value, identificationLimitsForKind(evidence.Kind)); unmarshalErr != nil {
			return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, fmt.Errorf("decode identification record before certificate binding: %w", unmarshalErr))
		}
		hadRecord = true
		break
	}
	currentDigest := env.Digest()
	recordBindsCurrentEnvelope := evidence.From == env.From &&
		bytes.Equal(evidence.EnvelopeDigest, currentDigest[:])
	if !hadRecord {
		record.SignedEnvelopeA = bytes.Clone(envelopeBytes)
		record.BroadcastCertificate = bytes.Clone(certificateBytes)
	} else if recordBindsCurrentEnvelope {
		// Proof-backed identification records initially carry no transport
		// artifact. Add the certificate only when the top-level evidence is for
		// this exact broadcast. Cross-envelope blame (for example, a Round 3
		// report exposing signed Round 2 equivocation) must preserve the accused
		// direct envelopes already stored in the record.
		if len(record.SignedEnvelopeA) == 0 {
			record.SignedEnvelopeA = bytes.Clone(envelopeBytes)
		} else {
			bound, decodeErr := tss.UnmarshalEnvelopeWithLimits(record.SignedEnvelopeA, envelopeLimitsForEvidence(env))
			if decodeErr != nil || bound.Digest() != currentDigest {
				return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, errors.New("identification record envelope does not match authenticated broadcast"))
			}
		}
		record.BroadcastCertificate = bytes.Clone(certificateBytes)
	}
	if evidence.Kind == tss.EvidenceKindPresignRedAlert && bytes.Equal(record.Proof, env.Payload) {
		// The authenticated envelope is the canonical proof carrier. Keeping a
		// second copy can make otherwise valid portable evidence exceed its 1 MiB
		// hard cap at the maximum supported signer count.
		clear(record.Proof)
		record.Proof = nil
	}
	inputs := make([]tss.EvidenceField, 0, len(evidence.PublicInputs)+1)
	for i := range evidence.PublicInputs {
		field := evidence.PublicInputs[i]
		if field.Key == tss.IdentificationRecordEvidenceKey {
			continue
		}
		inputs = append(inputs, field.Clone())
		if !hadRecord && len(field.Value) == sha256.Size {
			record.TranscriptHashes = append(record.TranscriptHashes, field.Clone())
		}
	}
	alert := record.ComputeAlertDigest()
	record.AlertDigest = alert[:]
	recordField, marshalErr := tss.IdentificationEvidenceFieldWithLimits(&record, identificationLimitsForKind(evidence.Kind))
	if marshalErr != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, fmt.Errorf("marshal certified broadcast identification record: %w", marshalErr))
	}
	evidence.PublicInputs = append(inputs, recordField)
	evidenceBytes, marshalErr := evidence.MarshalBinaryWithLimits(evidenceLimitsForKind(evidence.Kind))
	if marshalErr != nil {
		return tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, fmt.Errorf("marshal certified broadcast blame evidence: %w", marshalErr))
	}

	copyErr := *protocolErr
	copyBlame := *protocolErr.Blame
	copyBlame.Evidence = evidenceBytes
	copyErr.Blame = &copyBlame
	return &copyErr
}

func marshalEvidence(env tss.Envelope, kind tss.EvidenceKind, reason string, fields ...tss.EvidenceField) ([]byte, error) {
	limits := evidenceLimitsForKind(kind)
	evidence, err := tss.NewBlameEvidenceWithLimits(env, kind, reason, fields, limits)
	if err != nil {
		return nil, err
	}
	encoded, err := evidence.MarshalBinaryWithLimits(limits)
	if err != nil {
		return nil, err
	}
	return encoded, nil
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
		rawEvidenceField(evidenceFieldPartiesHash, tss.PartySetHash(key.state.Parties, partySetHashLabel)),
		hashEvidenceField(evidenceFieldPublicKeyHash, key.state.PublicKey),
		rawEvidenceField(evidenceFieldPaillierPublicKeysHash, paillierPublicSharesHash(paillierPublicKeys)),
	}
	if len(key.state.KeygenTranscriptHash) > 0 {
		fields = append(fields, rawEvidenceField(evidenceFieldKeygenTranscriptHash, key.state.KeygenTranscriptHash))
	}
	return fields
}

func signerEvidenceFields(signers tss.PartySet) []tss.EvidenceField {
	return []tss.EvidenceField{rawEvidenceField(evidenceFieldSignerSetHash, tss.PartySetHash(signers, partySetHashLabel))}
}

func rawEvidenceField(key string, value []byte) tss.EvidenceField {
	return tss.EvidenceField{Key: key, Value: bytes.Clone(value)}
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

func hashObservedPaillierKeyEvidenceField(msg wire.Message, limits Limits) (tss.EvidenceField, error) {
	raw, err := canonicalWireMessageBytes(msg, limits)
	if err != nil {
		return tss.EvidenceField{}, fmt.Errorf("%s: %w", evidenceFieldObservedPaillierKeyHash, err)
	}
	return hashEvidenceField(evidenceFieldObservedPaillierKeyHash, raw), nil
}

func hashBytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func paillierPublicSharesHash(shares []PaillierPublicShare) []byte {
	t := transcript.New(paillierPublicSharesHashLabel)
	sorted := tss.CloneSlice(shares)
	slices.SortFunc(sorted, func(a, b PaillierPublicShare) int {
		return cmp.Compare(a.Party, b.Party)
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
		switch evidence.PayloadType {
		case payloadFigure6Commitment:
			return expectEvidenceMessage(evidence, keygenFigure6CommitmentRound, payloadFigure6Commitment)
		case payloadFigure6Reveal:
			return expectEvidenceMessage(evidence, keygenFigure6RevealRound, payloadFigure6Reveal)
		case payloadFigure6Proof:
			return expectEvidenceMessage(evidence, keygenFigure6ProofRound, payloadFigure6Proof)
		default:
			return fmt.Errorf("evidence payload type %q is not Figure 6 material", evidence.PayloadType)
		}
	case tss.EvidenceKindPaillierAux:
		switch evidence.PayloadType {
		case payloadAuxInfoReveal:
			if evidence.Round != keygenAuxInfoRevealRound && evidence.Round != refreshAuxInfoRevealRound {
				return fmt.Errorf("auxinfo reveal evidence has invalid round %d", evidence.Round)
			}
			return nil
		case payloadAuxInfoProofs, payloadAuxInfoDirect:
			if evidence.Round != keygenAuxInfoProofRound && evidence.Round != refreshAuxInfoProofRound {
				return fmt.Errorf("auxinfo proof evidence has invalid round %d", evidence.Round)
			}
			return nil
		case payloadReshareReceiverMaterial:
			return expectEvidenceMessage(evidence, reshareStartRound, payloadReshareReceiverMaterial)
		case payloadReshareFactorProof:
			return expectEvidenceMessage(evidence, reshareShareRound, payloadReshareFactorProof)
		default:
			return fmt.Errorf("evidence payload type %q is not Paillier auxiliary material", evidence.PayloadType)
		}
	case tss.EvidenceKindReshareShare:
		return expectEvidenceMessage(evidence, reshareShareRound, payloadReshareShare)
	case tss.EvidenceKindReshareCommitment:
		return expectEvidenceMessage(evidence, reshareStartRound, payloadReshareDealerCommitments)
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
	case tss.EvidenceKindPresignRedAlert:
		return expectEvidenceMessage(evidence, presignRedAlertRound, payloadPresignRedAlert)
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
	case tss.EvidenceKindPresignRound1, tss.EvidenceKindPresignRound2, tss.EvidenceKindPresignRound3, tss.EvidenceKindPresignRedAlert, tss.EvidenceKindSignPartial:
		return true
	default:
		return false
	}
}
