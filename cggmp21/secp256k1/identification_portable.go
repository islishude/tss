package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/transcript"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	portableIdentificationStatementType    = "cggmp21.secp256k1.identification-statement"
	portableIdentificationStatementVersion = 1
	portableIdentificationPresign          = "presign"
	portableIdentificationSign             = "sign"
)

type portableIdentificationKeyParty struct {
	Party              tss.PartyID               `wire:"1,u32"`
	VerificationShare  []byte                    `wire:"2,bytes,max_bytes=point"`
	PaillierPublicKey  *pai.PublicKey            `wire:"3,nested,max_bytes=paillier_public_key"`
	RingPedersenParams *zkpai.RingPedersenParams `wire:"4,nested,max_bytes=ring_pedersen_params"`
}

type portableIdentificationPresignParty struct {
	Party         tss.PartyID              `wire:"1,u32"`
	Round1        presignRound1Payload     `wire:"2,record"`
	Delta         []byte                   `wire:"3,bytes,len=32"`
	Contributions []presignMTAContribution `wire:"4,recordlist,max_items=signers"`
}

type portableIdentificationPartial struct {
	Party    tss.PartyID `wire:"1,u32"`
	Scalar   []byte      `wire:"2,bytes,len=32"`
	Envelope []byte      `wire:"3,bytes,max_bytes=envelope"`
}

// portableSignMTAContribution is the minimum authenticated public MtA state
// needed to replay one sign-identification proof. The replacement AffG proof
// is carried by the accused payload, so retaining the original proof and the
// unrelated delta/envelope records would only duplicate large public records.
type portableSignMTAContribution struct {
	Peer               tss.PartyID `wire:"1,u32"`
	InboundCiphertext  []byte      `wire:"2,bytes,max_bytes=paillier_ciphertext"`
	OutboundCiphertext []byte      `wire:"3,bytes,max_bytes=paillier_ciphertext"`
}

type portableSignIdentificationTranscript struct {
	Party         tss.PartyID                   `wire:"1,u32"`
	Contributions []portableSignMTAContribution `wire:"2,recordlist,max_items=signers"`
}

type portableSignIdentificationHash struct {
	Party tss.PartyID `wire:"1,u32"`
	Hash  []byte      `wire:"2,bytes,len=32"`
}

type portableIdentificationStatement struct {
	Kind                  string                                `wire:"1,string"`
	EnvelopeDigest        []byte                                `wire:"2,bytes,len=32"`
	SessionID             tss.SessionID                         `wire:"3,bytes,len=32"`
	Threshold             int                                   `wire:"4,u32"`
	Parties               tss.PartySet                          `wire:"5,u32list,max_items=parties"`
	Signers               tss.PartySet                          `wire:"6,u32list,max_items=signers"`
	PlanHash              []byte                                `wire:"7,bytes,len=32"`
	SecurityParams        SecurityParams                        `wire:"8,record"`
	PublicKey             []byte                                `wire:"9,bytes,max_bytes=point"`
	KeygenTranscriptHash  []byte                                `wire:"10,bytes,len=32"`
	AlertDigest           []byte                                `wire:"11,bytes,len=32"`
	ContextHash           []byte                                `wire:"12,bytes"`
	DerivationShift       []byte                                `wire:"13,bytes"`
	KeyParties            []portableIdentificationKeyParty      `wire:"14,recordlist,max_items=parties"`
	PresignParties        []portableIdentificationPresignParty  `wire:"15,recordlist,max_items=signers"`
	PresignSessionID      tss.SessionID                         `wire:"16,bytes"`
	PresignTranscriptHash []byte                                `wire:"17,bytes"`
	LittleR               []byte                                `wire:"18,bytes"`
	Digest                []byte                                `wire:"19,bytes"`
	Verification          *presignVerificationContext           `wire:"20,record,optional"`
	Identification        *portableSignIdentificationTranscript `wire:"21,record,optional"`
	IdentificationHashes  []portableSignIdentificationHash      `wire:"22,recordlist,max_items=signers"`
	Partials              []portableIdentificationPartial       `wire:"23,recordlist,max_items=signers"`
}

// WireType returns the portable identification statement wire type.
func (portableIdentificationStatement) WireType() string { return portableIdentificationStatementType }

// WireVersion returns the portable identification statement wire version.
func (portableIdentificationStatement) WireVersion() uint16 {
	return portableIdentificationStatementVersion
}

// MarshalBinary returns the canonical portable identification statement.
func (p *portableIdentificationStatement) MarshalBinary() ([]byte, error) {
	return wire.Marshal(p, wire.WithFieldLimitsForMarshal(DefaultLimits().fieldLimits()))
}

// UnmarshalBinary decodes a canonical portable identification statement.
func (p *portableIdentificationStatement) UnmarshalBinary(in []byte) error {
	var decoded portableIdentificationStatement
	limits := DefaultLimits()
	if err := wire.Unmarshal(in, &decoded,
		wire.WithFrameLimits(limits.frameLimits(tss.DefaultMaxBlameEvidenceBytes)),
		wire.WithFieldLimits(limits.fieldLimits())); err != nil {
		return err
	}
	*p = decoded
	return nil
}

func portableKeyParties(key *KeyShare) ([]portableIdentificationKeyParty, error) {
	if key == nil || key.state == nil {
		return nil, errors.New("nil key share")
	}
	out := make([]portableIdentificationKeyParty, 0, len(key.state.Parties))
	for _, id := range key.state.Parties {
		data, err := key.partyDataFor(id)
		if err != nil {
			return nil, err
		}
		out = append(out, portableIdentificationKeyParty{Party: id, VerificationShare: bytes.Clone(data.VerificationShare), PaillierPublicKey: data.PaillierPublicKey.Clone(), RingPedersenParams: data.RingPedersenParams.Clone()})
	}
	return out, nil
}

func (s *PresignSession) portablePresignIdentificationStatement(env tss.Envelope) ([]byte, error) {
	keyParties, err := portableKeyParties(s.key)
	if err != nil {
		return nil, err
	}
	statement := &portableIdentificationStatement{Kind: portableIdentificationPresign, SessionID: s.sessionID, Threshold: s.key.state.Threshold, Parties: s.key.state.Parties.Clone(), Signers: s.signers.Clone(), PlanHash: bytes.Clone(s.planHash), SecurityParams: s.securityParams, PublicKey: bytes.Clone(s.key.state.PublicKey), KeygenTranscriptHash: bytes.Clone(s.key.state.KeygenTranscriptHash), AlertDigest: bytes.Clone(s.identificationAlert), ContextHash: bytes.Clone(s.contextHash), KeyParties: keyParties}
	digest := env.Digest()
	statement.EnvelopeDigest = bytes.Clone(digest[:])
	if s.derivation != nil {
		statement.DerivationShift = bytes.Clone(s.derivation.AdditiveShift)
	}
	for _, id := range s.signers {
		state, ok := s.partyState(id)
		if !ok || !state.round1.havePayload || state.round3.delta == nil {
			return nil, fmt.Errorf("missing public presign identification state for party %d", id)
		}
		statement.PresignParties = append(statement.PresignParties, portableIdentificationPresignParty{Party: id, Round1: clonePortableRound1(state.round1.payload), Delta: state.round3.delta.FixedBytes(), Contributions: cloneMTAContributions(state.round3.verifyShare.mtaContributions)})
	}
	return statement.MarshalBinary()
}

func (s *SignSession) portableSignIdentificationStatement(env tss.Envelope) ([]byte, error) {
	keyParties, err := portableKeyParties(s.key)
	if err != nil {
		return nil, err
	}
	identification, ok := portableSignIdentificationTranscriptFor(s.presign, env.From)
	if !ok {
		return nil, fmt.Errorf("missing public sign identification transcript for party %d", env.From)
	}
	identificationHashes, err := portableSignIdentificationHashes(s.presign)
	if err != nil {
		return nil, err
	}
	statement := &portableIdentificationStatement{Kind: portableIdentificationSign, SessionID: s.sessionID, Threshold: s.key.state.Threshold, Parties: s.key.state.Parties.Clone(), Signers: s.presign.state.Signers.Clone(), PlanHash: bytes.Clone(s.planHash), SecurityParams: s.presign.state.SecurityParams, PublicKey: bytes.Clone(s.key.state.PublicKey), KeygenTranscriptHash: bytes.Clone(s.key.state.KeygenTranscriptHash), AlertDigest: bytes.Clone(s.identificationAlert), ContextHash: bytes.Clone(s.presign.state.ContextHash), DerivationShift: bytes.Clone(s.presign.state.Derivation.AdditiveShift), KeyParties: keyParties, PresignSessionID: s.presign.state.Verification.SessionID, PresignTranscriptHash: bytes.Clone(s.presign.state.TranscriptHash), LittleR: s.presign.state.LittleR.Bytes(), Digest: bytes.Clone(s.digest), Verification: pointerVerificationClone(s.presign.state.Verification), Identification: identification, IdentificationHashes: identificationHashes}
	digest := env.Digest()
	statement.EnvelopeDigest = bytes.Clone(digest[:])
	for _, id := range s.presign.state.Signers {
		partial, ok := s.partials[id]
		if !ok {
			return nil, fmt.Errorf("missing public sign partial for party %d", id)
		}
		envelope, ok := s.partialEnvelopes[id]
		if !ok {
			return nil, fmt.Errorf("missing sign partial envelope for party %d", id)
		}
		raw, err := envelope.MarshalBinaryWithLimits(defaultEnvelopeLimitsForEvidence())
		if err != nil {
			return nil, err
		}
		statement.Partials = append(statement.Partials, portableIdentificationPartial{Party: id, Scalar: partial.Bytes(), Envelope: raw})
	}
	return statement.MarshalBinary()
}

func clonePortableRound1(in presignRound1Payload) presignRound1Payload {
	return presignRound1Payload{Gamma: bytes.Clone(in.Gamma), EncK: bytes.Clone(in.EncK), PaillierPublicKey: in.PaillierPublicKey.Clone(), PlanHash: bytes.Clone(in.PlanHash), EncGamma: bytes.Clone(in.EncGamma), KPoint: bytes.Clone(in.KPoint)}
}

func pointerVerificationClone(in presignVerificationContext) *presignVerificationContext {
	out := in.clone()
	return &out
}

func portableSignIdentificationTranscriptFor(presign *Presign, party tss.PartyID) (*portableSignIdentificationTranscript, bool) {
	value, ok := presignIdentificationTranscriptFor(presign, party)
	if !ok {
		return nil, false
	}
	out := &portableSignIdentificationTranscript{Party: value.Party, Contributions: make([]portableSignMTAContribution, len(value.Contributions))}
	for i := range value.Contributions {
		out.Contributions[i] = portableSignMTAContribution{
			Peer:               value.Contributions[i].Peer,
			InboundCiphertext:  bytes.Clone(value.Contributions[i].Inbound.Ciphertext),
			OutboundCiphertext: bytes.Clone(value.Contributions[i].Outbound.Ciphertext),
		}
	}
	return out, true
}

func portableSignIdentificationTranscriptHash(value *portableSignIdentificationTranscript) ([]byte, error) {
	if value == nil || value.Party == 0 || value.Party == tss.BroadcastPartyId {
		return nil, errors.New("invalid portable sign identification transcript")
	}
	t := transcript.New("cggmp21-secp256k1-sign-identification-public-mta-v1")
	t.AppendUint32("party", value.Party)
	for i := range value.Contributions {
		item := &value.Contributions[i]
		if item.Peer == 0 || item.Peer == tss.BroadcastPartyId || item.Peer == value.Party || (i > 0 && value.Contributions[i-1].Peer >= item.Peer) {
			return nil, errors.New("non-canonical portable sign MtA contributions")
		}
		if err := validatePositiveIntegerBytes(item.InboundCiphertext); err != nil {
			return nil, fmt.Errorf("invalid portable inbound MtA ciphertext: %w", err)
		}
		if err := validatePositiveIntegerBytes(item.OutboundCiphertext); err != nil {
			return nil, fmt.Errorf("invalid portable outbound MtA ciphertext: %w", err)
		}
		t.AppendUint32("peer", item.Peer)
		t.AppendBytes("inbound_ciphertext", item.InboundCiphertext)
		t.AppendBytes("outbound_ciphertext", item.OutboundCiphertext)
	}
	return t.Sum(), nil
}

func portableSignIdentificationHashes(presign *Presign) ([]portableSignIdentificationHash, error) {
	if presign == nil || presign.state == nil {
		return nil, errors.New("nil presign")
	}
	out := make([]portableSignIdentificationHash, 0, len(presign.state.Signers))
	for _, party := range presign.state.Signers {
		value, ok := portableSignIdentificationTranscriptFor(presign, party)
		if !ok {
			return nil, fmt.Errorf("missing sign identification transcript for party %d", party)
		}
		hash, err := portableSignIdentificationTranscriptHash(value)
		if err != nil {
			return nil, err
		}
		out = append(out, portableSignIdentificationHash{Party: party, Hash: hash})
	}
	return out, nil
}

// portableSignPublicStateHash binds every reporter-supplied public value used
// by sign-identification verification. Per-party compact transcript hashes keep
// the portable statement linear in the signer count while the accused party's
// exact compact transcript is supplied separately and checked against its hash.
func portableSignPublicStateHash(verification *presignVerificationContext, identificationHashes []portableSignIdentificationHash, littleR []byte, limits Limits) ([]byte, error) {
	if verification == nil || !verification.SessionID.Valid() || len(verification.Round1Echo) != sha256.Size {
		return nil, errors.New("invalid sign identification verification context")
	}
	if _, err := secp.ScalarFromBytesAllowZero(littleR); err != nil {
		return nil, fmt.Errorf("invalid sign identification little-r: %w", err)
	}
	t := transcript.New("cggmp21-secp256k1-sign-identification-public-state-v1")
	t.AppendBytes("presign_session_id", verification.SessionID[:])
	t.AppendBytes("round1_echo", verification.Round1Echo)
	for i := range verification.Entries {
		entry := &verification.Entries[i]
		if entry.PaillierPublicKey == nil || entry.XBarPoint == nil || entry.Delta == nil {
			return nil, errors.New("incomplete sign identification verification entry")
		}
		paillierKey, err := canonicalWireMessageBytes(entry.PaillierPublicKey, limits)
		if err != nil {
			return nil, err
		}
		xBar, err := secp.PointBytes(entry.XBarPoint)
		if err != nil {
			return nil, err
		}
		t.AppendUint32("party", entry.Party)
		t.AppendBytes("gamma", entry.Gamma)
		t.AppendBytes("enc_k", entry.EncK)
		t.AppendBytes("paillier_public_key", paillierKey)
		t.AppendBytes("x_bar", xBar)
		t.AppendBytes("delta", entry.Delta.Bytes())
		t.AppendBytes("k_point", entry.KPoint)
		t.AppendBytes("enc_gamma", entry.EncGamma)
	}
	for i := range identificationHashes {
		item := &identificationHashes[i]
		if item.Party == 0 || item.Party == tss.BroadcastPartyId || len(item.Hash) != sha256.Size || (i > 0 && identificationHashes[i-1].Party >= item.Party) {
			return nil, errors.New("non-canonical sign identification transcript hashes")
		}
		t.AppendUint32("identification_party", item.Party)
		t.AppendBytes("identification_hash", item.Hash)
	}
	t.AppendBytes("little_r", littleR)
	return t.Sum(), nil
}

// VerifyIdentificationFailure independently verifies a built-in CGGMP21
// identifiable-abort accusation using only authenticated public material.
// It returns nil only when the claimed malformed/invalid payload classification
// is true; a valid accused payload produces an error.
func VerifyIdentificationFailure(evidence tss.BlameEvidence, record tss.IdentificationRecord, ctx EvidenceContext) error {
	if evidence.Kind != tss.EvidenceKindPresignIdentification && evidence.Kind != tss.EvidenceKindSignIdentification {
		return errors.New("not a built-in identification evidence kind")
	}
	if len(record.SignedEnvelopeA) == 0 {
		return errors.New("portable identification evidence lacks an authenticated envelope")
	}
	var statement portableIdentificationStatement
	if err := statement.UnmarshalBinary(record.Statement); err != nil {
		return fmt.Errorf("decode portable identification statement: %w", err)
	}
	if record.Accused != evidence.From || len(statement.EnvelopeDigest) != sha256.Size || !bytes.Equal(statement.EnvelopeDigest, evidence.EnvelopeDigest) {
		return errors.New("portable identification statement envelope mismatch")
	}
	if statement.SessionID != evidence.SessionID {
		return errors.New("portable identification statement context mismatch")
	}
	if err := validatePortableStatementContext(statement, ctx); err != nil {
		return err
	}
	if len(ctx.KeygenTranscriptHash) > 0 && !bytes.Equal(ctx.KeygenTranscriptHash, statement.KeygenTranscriptHash) {
		return errors.New("portable keygen transcript mismatch")
	}
	if evidence.Kind == tss.EvidenceKindSignIdentification && len(ctx.PresignTranscriptHash) > 0 && !bytes.Equal(ctx.PresignTranscriptHash, statement.PresignTranscriptHash) {
		return errors.New("portable presign transcript mismatch")
	}
	first, err := tss.UnmarshalEnvelopeWithLimits(record.SignedEnvelopeA, defaultEnvelopeLimitsForEvidence())
	if err != nil {
		return err
	}
	if len(record.Proof) == 0 {
		// A certified envelope already carries the exact proof payload. Evidence
		// construction drops the duplicate field to stay within the hard cap.
		record.Proof = bytes.Clone(first.Payload)
	} else if !bytes.Equal(first.Payload, record.Proof) {
		return errors.New("portable identification proof does not match authenticated envelope")
	}
	if first.Digest() != evidenceDigestArray(evidence.EnvelopeDigest) {
		return errors.New("portable identification proof does not match authenticated envelope")
	}
	if first.From != record.Accused || first.SessionID != evidence.SessionID || first.Protocol != evidence.Protocol {
		return errors.New("portable identification envelope context mismatch")
	}
	if len(record.BroadcastCertificate) == 0 {
		if ctx.EnvelopeVerifier == nil {
			return tss.ErrMissingEnvelopeSignatureVerifier
		}
		if err := tss.VerifyEnvelopeSignature(first, ctx.EnvelopeVerifier); err != nil {
			return err
		}
	} else {
		if first.To != tss.BroadcastPartyId || ctx.BroadcastACKVerifier == nil {
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
	switch evidence.Kind {
	case tss.EvidenceKindPresignIdentification:
		return verifyPortablePresignFailure(statement, record)
	case tss.EvidenceKindSignIdentification:
		return verifyPortableSignFailure(statement, record)
	default:
		return errors.New("unsupported identification evidence")
	}
}

func validatePortableStatementContext(statement portableIdentificationStatement, ctx EvidenceContext) error {
	if len(ctx.Parties) == 0 || len(ctx.Signers) == 0 || len(ctx.PublicKey) == 0 || len(ctx.ContextHash) == 0 || ctx.SecurityParams == nil {
		return errors.New("portable identification verification requires complete public context")
	}
	if !slices.Equal(statement.Parties, ctx.Parties) || !slices.Equal(statement.Signers, ctx.Signers) || !bytes.Equal(statement.PublicKey, ctx.PublicKey) || !bytes.Equal(statement.ContextHash, ctx.ContextHash) || !bytes.Equal(statement.DerivationShift, ctx.DerivationShift) || statement.SecurityParams != *ctx.SecurityParams {
		return errors.New("portable identification public context mismatch")
	}
	if ctx.Threshold != statement.Threshold || len(statement.KeyParties) != len(ctx.Parties) || len(ctx.VerificationShares) != len(ctx.Parties) || len(ctx.PaillierPublicKeys) != len(ctx.Parties) || len(ctx.RingPedersenParams) != len(ctx.Parties) {
		return errors.New("portable identification public context is incomplete")
	}
	for i, id := range ctx.Parties {
		item := statement.KeyParties[i]
		verification := ctx.VerificationShares[i]
		paillier := ctx.PaillierPublicKeys[i]
		ringPedersen := ctx.RingPedersenParams[i]
		if item.Party != id || verification.Party != id || paillier.Party != id || ringPedersen.Party != id || !bytes.Equal(item.VerificationShare, verification.PublicKey) {
			return errors.New("portable identification party context mismatch")
		}
		paillierKey, err := canonicalWireMessageBytes(item.PaillierPublicKey, DefaultLimits())
		if err != nil || !bytes.Equal(paillierKey, paillier.PublicKey) {
			return errors.New("portable identification Paillier key mismatch")
		}
		ringParams, err := canonicalWireMessageBytes(item.RingPedersenParams, DefaultLimits())
		if err != nil || !bytes.Equal(ringParams, ringPedersen.Params) {
			return errors.New("portable identification Ring-Pedersen parameters mismatch")
		}
	}
	return nil
}

func verifyPortablePresignFailure(statement portableIdentificationStatement, record tss.IdentificationRecord) error {
	session, cleanup, err := reconstructPortablePresign(statement)
	if err != nil {
		return err
	}
	defer cleanup()
	if !bytes.Equal(session.presignIdentificationAlert(), statement.AlertDigest) || !recordTranscriptHashEqual(record, "protocol_alert_digest", statement.AlertDigest) {
		return errors.New("portable presign alert mismatch")
	}
	var payload presignIdentificationPayload
	decodeErr := payload.UnmarshalBinaryWithLimits(record.Proof, DefaultLimits())
	if record.FailureClass == "presign-identification-malformed" {
		if decodeErr != nil {
			return nil
		}
		return errors.New("false accusation: presign identification payload is canonical")
	}
	if record.FailureClass != "presign-identification-invalid-proof" || decodeErr != nil {
		return errors.New("presign identification failure class mismatch")
	}
	if !bytes.Equal(payload.AlertDigest, statement.AlertDigest) {
		return errors.New("portable presign alert mismatch")
	}
	return identificationFailureResult(session.verifyPresignIdentificationPayload(record.Accused, payload), "presign")
}

func verifyPortableSignFailure(statement portableIdentificationStatement, record tss.IdentificationRecord) error {
	session, err := reconstructPortableSign(statement)
	if err != nil {
		return err
	}
	publicStateHash, err := portableSignPublicStateHash(statement.Verification, statement.IdentificationHashes, statement.LittleR, DefaultLimits())
	if err != nil {
		return err
	}
	alert := session.signIdentificationAlertDigestWithPublicState(publicStateHash)
	if !bytes.Equal(alert, statement.AlertDigest) || !recordTranscriptHashEqual(record, "protocol_alert_digest", statement.AlertDigest) {
		return errors.New("portable sign alert mismatch")
	}
	var payload signIdentificationPayload
	decodeErr := payload.UnmarshalBinaryWithLimits(record.Proof, DefaultLimits())
	if record.FailureClass == "sign-identification-malformed" {
		if decodeErr != nil {
			// Evidence succeeds precisely because canonical decoding failed.
			//nolint:nilerr
			return nil
		}
		return errors.New("false accusation: sign identification payload is canonical")
	}
	if record.FailureClass != "sign-identification-invalid-proof" || decodeErr != nil {
		return errors.New("sign identification failure class mismatch")
	}
	if !bytes.Equal(payload.AlertDigest, statement.AlertDigest) {
		return errors.New("portable sign alert mismatch")
	}
	return identificationFailureResult(session.verifySignIdentificationPayload(record.Accused, payload), "sign")
}

// identificationFailureResult inverts the ordinary proof-verifier result:
// evidence succeeds only when replay confirms the accused proof is invalid.
func identificationFailureResult(verificationErr error, phase string) error {
	if verificationErr != nil {
		// Evidence succeeds precisely because cryptographic replay failed.
		//nolint:nilerr
		return nil
	}
	return fmt.Errorf("false accusation: %s identification proof is valid", phase)
}

func recordTranscriptHashEqual(record tss.IdentificationRecord, key string, expected []byte) bool {
	for _, field := range record.TranscriptHashes {
		if field.Key == key {
			return bytes.Equal(field.Value, expected)
		}
	}
	return false
}

func reconstructPortableKey(statement portableIdentificationStatement) (*KeyShare, error) {
	if len(statement.KeyParties) != len(statement.Parties) {
		return nil, errors.New("portable key party count mismatch")
	}
	data := make(map[tss.PartyID]keySharePartyData, len(statement.KeyParties))
	for i, item := range statement.KeyParties {
		if item.Party != statement.Parties[i] || item.PaillierPublicKey == nil || item.RingPedersenParams == nil {
			return nil, errors.New("portable key parties are not canonical")
		}
		data[item.Party] = keySharePartyData{VerificationShare: bytes.Clone(item.VerificationShare), PaillierPublicKey: item.PaillierPublicKey.Clone(), RingPedersenParams: item.RingPedersenParams.Clone()}
	}
	return &KeyShare{state: &keyShareState{SecurityParams: statement.SecurityParams, Threshold: statement.Threshold, Parties: statement.Parties.Clone(), PublicKey: bytes.Clone(statement.PublicKey), KeygenTranscriptHash: bytes.Clone(statement.KeygenTranscriptHash), PlanHash: bytes.Clone(statement.PlanHash), PartyData: data}}, nil
}

func reconstructPortablePresign(statement portableIdentificationStatement) (*PresignSession, func(), error) {
	if statement.Kind != portableIdentificationPresign || len(statement.PresignParties) != len(statement.Signers) {
		return nil, nil, errors.New("invalid portable presign statement")
	}
	key, err := reconstructPortableKey(statement)
	if err != nil {
		return nil, nil, err
	}
	parties, index := newPresignPartyStates(statement.Signers)
	cleanup := func() {
		for i := range parties {
			if parties[i].round3.delta != nil {
				parties[i].round3.delta.Destroy()
			}
		}
	}
	for i, item := range statement.PresignParties {
		if item.Party != statement.Signers[i] {
			cleanup()
			return nil, nil, errors.New("portable presign parties are not canonical")
		}
		delta, err := newSecpSecretScalarAllowZero(item.Delta)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		parties[i].round1 = presignRound1State{payload: clonePortableRound1(item.Round1), havePayload: true}
		parties[i].round3 = presignRound3State{delta: delta, haveDelta: true, haveVerifyShare: true, verifyShare: signVerifyShare{mtaContributions: cloneMTAContributions(item.Contributions)}}
	}
	return &PresignSession{key: key, sessionID: statement.SessionID, signers: statement.Signers.Clone(), parties: parties, partyIndex: index, securityParams: statement.SecurityParams, contextHash: bytes.Clone(statement.ContextHash), planHash: bytes.Clone(statement.PlanHash), derivation: &tss.DerivationResult{AdditiveShift: bytes.Clone(statement.DerivationShift)}, identifying: true, identificationAlert: bytes.Clone(statement.AlertDigest), limits: DefaultLimits()}, cleanup, nil
}

func reconstructPortableSign(statement portableIdentificationStatement) (*SignSession, error) {
	if statement.Kind != portableIdentificationSign || statement.Verification == nil || statement.Identification == nil || len(statement.Partials) != len(statement.Signers) {
		return nil, errors.New("invalid portable sign statement")
	}
	if statement.PresignSessionID != statement.Verification.SessionID {
		return nil, errors.New("portable sign presign session mismatch")
	}
	if err := validatePresignVerificationContext(statement.Signers, *statement.Verification, DefaultLimits()); err != nil {
		return nil, fmt.Errorf("invalid portable presign verification context: %w", err)
	}
	if len(statement.IdentificationHashes) != len(statement.Signers) {
		return nil, errors.New("portable sign identification hash count mismatch")
	}
	var accusedHash []byte
	for i, party := range statement.Signers {
		item := statement.IdentificationHashes[i]
		if item.Party != party || len(item.Hash) != sha256.Size {
			return nil, errors.New("portable sign identification hashes are not canonical")
		}
		if item.Party == statement.Identification.Party {
			accusedHash = item.Hash
		}
	}
	actualHash, err := portableSignIdentificationTranscriptHash(statement.Identification)
	if err != nil {
		return nil, err
	}
	if len(accusedHash) == 0 || !bytes.Equal(actualHash, accusedHash) {
		return nil, errors.New("portable sign identification transcript hash mismatch")
	}
	key, err := reconstructPortableKey(statement)
	if err != nil {
		return nil, err
	}
	littleR, err := secp.ScalarFromBytesAllowZero(statement.LittleR)
	if err != nil {
		return nil, err
	}
	contributions := make([]presignMTAContribution, len(statement.Identification.Contributions))
	for i := range statement.Identification.Contributions {
		item := statement.Identification.Contributions[i]
		contributions[i] = presignMTAContribution{
			Peer:     item.Peer,
			Inbound:  mta.ResponseMessage{Ciphertext: bytes.Clone(item.InboundCiphertext)},
			Outbound: mta.ResponseMessage{Ciphertext: bytes.Clone(item.OutboundCiphertext)},
		}
	}
	presign := &Presign{state: &presignState{Threshold: statement.Threshold, Signers: statement.Signers.Clone(), LittleR: littleR, TranscriptHash: bytes.Clone(statement.PresignTranscriptHash), ContextHash: bytes.Clone(statement.ContextHash), KeygenTranscriptHash: bytes.Clone(statement.KeygenTranscriptHash), PlanHash: bytes.Clone(statement.PlanHash), SecurityParams: statement.SecurityParams, Derivation: &tss.DerivationResult{AdditiveShift: bytes.Clone(statement.DerivationShift)}, Verification: statement.Verification.clone(), IdentificationTranscripts: []presignIdentificationTranscript{{Party: statement.Identification.Party, Contributions: contributions}}}}
	partials := make(map[tss.PartyID]secp.Scalar, len(statement.Partials))
	envelopes := make(map[tss.PartyID]tss.Envelope, len(statement.Partials))
	for i, item := range statement.Partials {
		if item.Party != statement.Signers[i] {
			return nil, errors.New("portable sign partials are not canonical")
		}
		partial, err := secp.ScalarFromBytesAllowZero(item.Scalar)
		if err != nil {
			return nil, err
		}
		env, err := tss.UnmarshalEnvelopeWithLimits(item.Envelope, defaultEnvelopeLimitsForEvidence())
		if err != nil {
			return nil, err
		}
		if env.From != item.Party || env.PayloadType != payloadSignPartial {
			return nil, errors.New("portable sign partial envelope mismatch")
		}
		partials[item.Party] = partial
		envelopes[item.Party] = env
	}
	return &SignSession{key: key, presign: presign, sessionID: statement.SessionID, limits: DefaultLimits(), digest: bytes.Clone(statement.Digest), planHash: bytes.Clone(statement.PlanHash), partials: partials, partialEnvelopes: envelopes, identifying: true, identificationAlert: bytes.Clone(statement.AlertDigest)}, nil
}

func evidenceDigestArray(raw []byte) (out tss.EnvelopeDigest) { copy(out[:], raw); return out }
