package secp256k1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

type aggregateSignAlertError struct{ err error }

// Error describes the aggregate signature verification alert.
func (e *aggregateSignAlertError) Error() string {
	return fmt.Sprintf("aggregate signature alert: %v", e.err)
}

// Unwrap returns the underlying aggregate signature failure.
func (e *aggregateSignAlertError) Unwrap() error { return e.err }

type signIdentificationMulProof struct {
	Verifier tss.PartyID        `wire:"1,u32"`
	Proof    zkpai.MulStarProof `wire:"2,nested,max_bytes=zk_proof"`
}

type signIdentificationPayload struct {
	AlertDigest []byte                          `wire:"1,bytes,len=32"`
	HHat        []byte                          `wire:"2,bytes,max_bytes=paillier_ciphertext"`
	MulProofs   []signIdentificationMulProof    `wire:"3,recordlist,max_items=signers"`
	CSigma      []byte                          `wire:"4,bytes,max_bytes=paillier_ciphertext"`
	Reproofs    []presignIdentificationReproof  `wire:"5,recordlist,max_items=signers"`
	DecProofs   []presignIdentificationDecProof `wire:"6,recordlist,max_items=signers"`
	PlanHash    []byte                          `wire:"7,bytes,len=32"`
}

// WireType returns the sign identification payload wire type.
func (signIdentificationPayload) WireType() string { return signIdentificationPayloadWireType }

// WireVersion returns the sign identification payload wire version.
func (signIdentificationPayload) WireVersion() uint16 { return signIdentificationPayloadWireVersion }

// MarshalBinary encodes the sign identification payload.
func (p signIdentificationPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the payload with explicit limits.
func (p signIdentificationPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a sign identification payload.
func (p *signIdentificationPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the payload with explicit limits.
func (p *signIdentificationPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the public proof-set shape and canonical party ordering.
func (p signIdentificationPayload) Validate() error {
	if len(p.AlertDigest) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid sign identification digest")
	}
	if err := validatePositiveIntegerBytes(p.HHat); err != nil {
		return err
	}
	if err := validatePositiveIntegerBytes(p.CSigma); err != nil {
		return err
	}
	if len(p.MulProofs) == 0 || len(p.Reproofs) == 0 || len(p.DecProofs) == 0 {
		return errors.New("incomplete sign identification proof set")
	}
	for i := range p.MulProofs {
		if i > 0 && p.MulProofs[i-1].Verifier >= p.MulProofs[i].Verifier {
			return errors.New("non-canonical sign identification mul proof order")
		}
		if err := p.MulProofs[i].Proof.Validate(); err != nil {
			return err
		}
	}
	for i := range p.Reproofs {
		if i > 0 && p.Reproofs[i-1].Peer >= p.Reproofs[i].Peer {
			return errors.New("non-canonical sign identification reproof order")
		}
		if err := p.Reproofs[i].Proof.Validate(); err != nil {
			return err
		}
	}
	for i := range p.DecProofs {
		if i > 0 && p.DecProofs[i-1].Verifier >= p.DecProofs[i].Verifier {
			return errors.New("non-canonical sign identification dec proof order")
		}
		if err := p.DecProofs[i].Proof.Validate(); err != nil {
			return err
		}
	}
	return nil
}
func (p *signIdentificationPayload) destroy() {
	if p == nil {
		return
	}
	clear(p.AlertDigest)
	clear(p.HHat)
	clear(p.CSigma)
	clear(p.PlanHash)
	for i := range p.MulProofs {
		p.MulProofs[i].Proof.Destroy()
	}
	for i := range p.Reproofs {
		p.Reproofs[i].Proof.Destroy()
	}
	for i := range p.DecProofs {
		p.DecProofs[i].Proof.Destroy()
	}
	*p = signIdentificationPayload{}
}

func (s *SignSession) signIdentificationAlertDigest() []byte {
	t := transcript.New("cggmp21-secp256k1-sign-identification-alert-v1")
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("presign_transcript", s.presign.state.TranscriptHash)
	t.AppendBytes("digest", s.digest)
	for _, party := range s.presign.state.Signers {
		t.AppendUint32("party", party)
		partial := s.partials[party].Bytes()
		t.AppendBytes("partial", partial)
		clear(partial)
		if env, ok := s.partialEnvelopes[party]; ok {
			digest := env.Digest()
			t.AppendBytes("envelope_digest", digest[:])
		}
	}
	return t.Sum()
}

func presignIdentificationTranscriptFor(p *Presign, party tss.PartyID) (presignIdentificationTranscript, bool) {
	if p == nil || p.state == nil {
		return presignIdentificationTranscript{}, false
	}
	for i := range p.state.IdentificationTranscripts {
		if p.state.IdentificationTranscripts[i].Party == party {
			return p.state.IdentificationTranscripts[i], true
		}
	}
	return presignIdentificationTranscript{}, false
}

func presignVerificationEntryFor(p *Presign, party tss.PartyID) (presignVerificationEntry, bool) {
	if p == nil || p.state == nil {
		return presignVerificationEntry{}, false
	}
	for i := range p.state.Verification.Entries {
		if p.state.Verification.Entries[i].Party == party {
			return p.state.Verification.Entries[i], true
		}
	}
	return presignVerificationEntry{}, false
}

func (s *SignSession) adjustedSigningShare() (*secret.Scalar, *secp.Point, error) {
	lambda, err := shamir.LagrangeCoefficient(s.key.state.Party, s.presign.state.Signers)
	if err != nil {
		return nil, nil, err
	}
	share, err := secpScalarFromSecret(s.key.state.Secret)
	if err != nil {
		return nil, nil, err
	}
	adjusted := secp.ScalarMul(lambda, share)
	verificationShare, ok := s.key.verificationShare(s.key.state.Party)
	if !ok {
		return nil, nil, errors.New("missing local verification share")
	}
	point, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return nil, nil, err
	}
	adjustedPoint := secp.ScalarMult(point, lambda)
	if len(s.presign.state.Derivation.AdditiveShift) > 0 {
		shift, err := secp.ScalarFromBytesAllowZero(s.presign.state.Derivation.AdditiveShift)
		if err != nil {
			return nil, nil, err
		}
		adjusted = secp.ScalarAdd(adjusted, shift)
		if !shift.IsZero() {
			adjustedPoint = secp.Add(adjustedPoint, secp.ScalarBaseMult(shift))
		}
	}
	secretShare, err := secpSecretScalarFromScalarAllowZero(adjusted)
	return secretShare, adjustedPoint, err
}

func scalarAsSignedSecret(value *secret.Scalar) (*secret.SignedInt, error) {
	if value == nil {
		return nil, errors.New("nil scalar")
	}
	encoded := value.FixedBytes()
	defer clear(encoded)
	return secret.NewSignedInt(false, encoded, len(encoded))
}

func onePaillierRandomness(n *big.Int) (*secret.Scalar, error) {
	nLen := (n.BitLen() + 7) / 8
	encoded := make([]byte, nLen)
	encoded[nLen-1] = 1
	defer clear(encoded)
	return secret.NewScalar(encoded, nLen)
}

func (s *SignSession) buildLocalSignIdentificationPayload(alert []byte) (signIdentificationPayload, error) {
	self := s.key.state.Party
	private, err := s.key.paillierPrivate()
	if err != nil {
		return signIdentificationPayload{}, err
	}
	defer private.Destroy()
	entry, ok := presignVerificationEntryFor(s.presign, self)
	if !ok {
		return signIdentificationPayload{}, errors.New("missing local presign verification entry")
	}
	adjusted, adjustedPoint, err := s.adjustedSigningShare()
	if err != nil {
		return signIdentificationPayload{}, err
	}
	defer adjusted.Destroy()
	adjustedSigned, err := scalarAsSignedSecret(adjusted)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	defer adjustedSigned.Destroy()
	encK := new(big.Int).SetBytes(entry.EncK)
	hHat, err := zkpai.OMulCT(private.PublicKey, adjustedSigned, encK, adjusted.FixedLen())
	if err != nil {
		return signIdentificationPayload{}, err
	}
	one, err := onePaillierRandomness(private.N)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	defer one.Destroy()
	payload := signIdentificationPayload{AlertDigest: bytes.Clone(alert), HHat: hHat.Bytes(), PlanHash: bytes.Clone(s.planHash)}
	success := false
	defer func() {
		if !success {
			payload.destroy()
		}
	}()
	for _, verifier := range s.presign.state.Signers {
		if verifier == self {
			continue
		}
		rp, err := s.key.ringPedersenPublicFor(verifier, s.limits)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		mulState := presignIdentificationProofState(alert, self, verifier, "sign-mulstar")
		proof, err := zkpai.ProveMulStar(s.presign.state.SecurityParams, mulState, zkpai.MulStarStatement{
			PaillierN: private.PublicKey, C: encK, D: hHat, X: adjustedPoint,
			B: secp.ScalarBaseMult(secp.ScalarOne()), VerifierAux: rp,
		}, zkpai.MulStarWitness{X: adjusted, Rho: one}, rand.Reader)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		payload.MulProofs = append(payload.MulProofs, signIdentificationMulProof{Verifier: verifier, Proof: *proof})
	}
	transcriptValue, ok := presignIdentificationTranscriptFor(s.presign, self)
	if !ok {
		return signIdentificationPayload{}, errors.New("missing local sigma transcript")
	}
	cChi := new(big.Int).Set(hHat)
	for _, contribution := range transcriptValue.Contributions {
		peer := contribution.Peer
		var opening *presignSigmaOpening
		for i := range s.presign.state.sigmaOpenings {
			if s.presign.state.sigmaOpenings[i].Peer == peer {
				opening = &s.presign.state.sigmaOpenings[i]
				break
			}
		}
		if opening == nil {
			return signIdentificationPayload{}, fmt.Errorf("missing sigma opening for peer %d", peer)
		}
		if opening.Opening == nil {
			return signIdentificationPayload{}, fmt.Errorf("destroyed sigma opening for peer %d", peer)
		}
		peerEntry, ok := presignVerificationEntryFor(s.presign, peer)
		if !ok {
			return signIdentificationPayload{}, errors.New("missing peer verification entry")
		}
		peerPK, err := s.key.paillierPublicFor(peer, s.limits)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		peerRP, err := s.key.ringPedersenPublicFor(peer, s.limits)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		original, err := mtaSigmaResponseDomain(s.key, s.presign.state.Verification.SessionID, s.presign.state.Signers, peer, self, peerPK, s.presign.state.ContextHash, s.presign.state.PlanHash, s.limits)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		domain := identificationResponseDomain(original, alert, self, peer, "sigma-affg")
		proof, err := opening.Opening.Reprove(s.presign.state.SecurityParams, rand.Reader, domain,
			mta.StartMessage{Ciphertext: peerEntry.EncK}, opening.Response, peerEntry.KPoint,
			mustPointBytes(entry.XBarPoint), peerPK, private.PublicKey, peerRP)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		payload.Reproofs = append(payload.Reproofs, presignIdentificationReproof{Peer: peer, Proof: *proof})
		if err := addIdentificationCiphertext(private.NSquared, cChi, contribution.Inbound.Ciphertext); err != nil {
			return signIdentificationPayload{}, err
		}
		inverse, err := inverseIdentificationCiphertext(private.NSquared, contribution.Outbound.Proof.Y)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		cChi.Mul(cChi, inverse)
		cChi.Mod(cChi, private.NSquared)
	}
	m, err := secp.ScalarFromBytesModOrder(s.digest)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	mBig := new(big.Int).SetBytes(m.Bytes())
	rBig := new(big.Int).SetBytes(s.presign.state.LittleR.Bytes())
	encM, err := zkpai.OMulPublic(private.PublicKey, mBig, encK)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	encR, err := zkpai.OMulPublic(private.PublicKey, rBig, cChi)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	cSigma, err := zkpai.OAdd(private.PublicKey, encM, encR)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	payload.CSigma = cSigma.Bytes()
	plaintext, randomness, err := private.RecoverOpening(cSigma)
	if err != nil {
		return signIdentificationPayload{}, err
	}
	defer plaintext.Destroy()
	defer randomness.Destroy()
	partial, ok := s.partials[self]
	if !ok {
		return signIdentificationPayload{}, errors.New("missing local partial")
	}
	for _, verifier := range s.presign.state.Signers {
		if verifier == self {
			continue
		}
		rp, err := s.key.ringPedersenPublicFor(verifier, s.limits)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		state := presignIdentificationProofState(alert, self, verifier, "sign-dec")
		proof, err := zkpai.ProveDec(s.presign.state.SecurityParams, state, zkpai.DecStatement{PaillierN: private.PublicKey, C: cSigma, X: partial, VerifierAux: rp}, zkpai.DecWitness{Y: plaintext, Rho: randomness}, rand.Reader)
		if err != nil {
			return signIdentificationPayload{}, err
		}
		payload.DecProofs = append(payload.DecProofs, presignIdentificationDecProof{Verifier: verifier, Proof: *proof})
	}
	if err := payload.Validate(); err != nil {
		return signIdentificationPayload{}, err
	}
	success = true
	return payload, nil
}

func mustPointBytes(point *secp.Point) []byte { encoded, _ := secp.PointBytes(point); return encoded }

func (s *SignSession) startSignIdentification(cause error) ([]tss.Envelope, error) {
	if s.identifying {
		return nil, nil
	}
	alert := s.signIdentificationAlertDigest()
	payload, err := s.buildLocalSignIdentificationPayload(alert)
	if err != nil {
		return nil, fmt.Errorf("prepare signing identification after %w: %w", cause, err)
	}
	encoded, err := payload.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		payload.destroy()
		return nil, err
	}
	env, err := tss.NewEnvelope(tss.EnvelopeInput{Protocol: tss.ProtocolCGGMP21Secp256k1, SessionID: s.sessionID, Round: signIdentificationRound, From: s.key.state.Party, PayloadType: payloadSignIdentification, Payload: encoded})
	clear(encoded)
	if err != nil {
		payload.destroy()
		return nil, err
	}
	s.identifying = true
	s.identificationAlert = bytes.Clone(alert)
	s.identificationPayloads = map[tss.PartyID]signIdentificationPayload{s.key.state.Party: payload}
	return []tss.Envelope{env}, nil
}

func (s *SignSession) verifySignIdentificationPayload(from tss.PartyID, payload signIdentificationPayload) error {
	if !s.identifying || !bytes.Equal(payload.AlertDigest, s.identificationAlert) || !bytes.Equal(payload.PlanHash, s.planHash) {
		return errors.New("sign identification context mismatch")
	}
	entry, ok := presignVerificationEntryFor(s.presign, from)
	if !ok {
		return errors.New("missing signer verification entry")
	}
	pk, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	lambda, err := shamir.LagrangeCoefficient(from, s.presign.state.Signers)
	if err != nil {
		return err
	}
	verificationShare, ok := s.key.verificationShare(from)
	if !ok {
		return errors.New("missing verification share")
	}
	xPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return err
	}
	xPoint = secp.ScalarMult(xPoint, lambda)
	if len(s.presign.state.Derivation.AdditiveShift) > 0 {
		shift, err := secp.ScalarFromBytesAllowZero(s.presign.state.Derivation.AdditiveShift)
		if err != nil {
			return err
		}
		if !shift.IsZero() {
			xPoint = secp.Add(xPoint, secp.ScalarBaseMult(shift))
		}
	}
	hHat := new(big.Int).SetBytes(payload.HHat)
	encK := new(big.Int).SetBytes(entry.EncK)
	if len(payload.MulProofs) != len(s.presign.state.Signers)-1 {
		return errors.New("sign identification mul proof cardinality mismatch")
	}
	seenMulVerifier := make(map[tss.PartyID]struct{}, len(payload.MulProofs))
	for i := range payload.MulProofs {
		item := &payload.MulProofs[i]
		if item.Verifier == from || !slices.Contains(s.presign.state.Signers, item.Verifier) {
			return errors.New("invalid sign mul verifier")
		}
		if _, ok := seenMulVerifier[item.Verifier]; ok {
			return errors.New("duplicate sign mul verifier")
		}
		seenMulVerifier[item.Verifier] = struct{}{}
		rp, err := s.key.ringPedersenPublicFor(item.Verifier, s.limits)
		if err != nil {
			return err
		}
		state := presignIdentificationProofState(payload.AlertDigest, from, item.Verifier, "sign-mulstar")
		if err := zkpai.VerifyMulStar(s.presign.state.SecurityParams, state, zkpai.MulStarStatement{PaillierN: pk, C: encK, D: hHat, X: xPoint, B: secp.ScalarBaseMult(secp.ScalarOne()), VerifierAux: rp}, &item.Proof); err != nil {
			return err
		}
	}
	transcriptValue, ok := presignIdentificationTranscriptFor(s.presign, from)
	if !ok {
		return errors.New("missing signer sigma transcript")
	}
	if len(payload.Reproofs) != len(s.presign.state.Signers)-1 || len(payload.DecProofs) != len(s.presign.state.Signers)-1 {
		return errors.New("sign identification proof cardinality mismatch")
	}
	cChi := new(big.Int).Set(hHat)
	for _, item := range payload.Reproofs {
		contribution, ok := mtaContributionFor(transcriptValue.Contributions, item.Peer)
		if !ok {
			return errors.New("missing sigma contribution")
		}
		peerEntry, ok := presignVerificationEntryFor(s.presign, item.Peer)
		if !ok {
			return errors.New("missing peer entry")
		}
		peerPK, err := s.key.paillierPublicFor(item.Peer, s.limits)
		if err != nil {
			return err
		}
		peerRP, err := s.key.ringPedersenPublicFor(item.Peer, s.limits)
		if err != nil {
			return err
		}
		original, err := mtaSigmaResponseDomain(s.key, s.presign.state.Verification.SessionID, s.presign.state.Signers, item.Peer, from, peerPK, s.presign.state.ContextHash, s.presign.state.PlanHash, s.limits)
		if err != nil {
			return err
		}
		response := contribution.Outbound.Clone()
		response.Proof.Destroy()
		response.Proof = *item.Proof.Clone()
		domain := identificationResponseDomain(original, payload.AlertDigest, from, item.Peer, "sigma-affg")
		err = mta.VerifyResponse(s.presign.state.SecurityParams, domain, mta.StartMessage{Ciphertext: peerEntry.EncK}, response, peerEntry.KPoint, mustPointBytes(entry.XBarPoint), peerPK, pk, peerRP)
		response.Destroy()
		if err != nil {
			return err
		}
		if err := addIdentificationCiphertext(pk.NSquared, cChi, contribution.Inbound.Ciphertext); err != nil {
			return err
		}
		inverse, err := inverseIdentificationCiphertext(pk.NSquared, contribution.Outbound.Proof.Y)
		if err != nil {
			return err
		}
		cChi.Mul(cChi, inverse)
		cChi.Mod(cChi, pk.NSquared)
	}
	m, err := secp.ScalarFromBytesModOrder(s.digest)
	if err != nil {
		return err
	}
	encM, err := zkpai.OMulPublic(pk, new(big.Int).SetBytes(m.Bytes()), encK)
	if err != nil {
		return err
	}
	encR, err := zkpai.OMulPublic(pk, new(big.Int).SetBytes(s.presign.state.LittleR.Bytes()), cChi)
	if err != nil {
		return err
	}
	cSigma, err := zkpai.OAdd(pk, encM, encR)
	if err != nil {
		return err
	}
	if !bytes.Equal(cSigma.Bytes(), payload.CSigma) {
		return errors.New("sign identification CSigma mismatch")
	}
	partial, ok := s.partials[from]
	if !ok {
		return errors.New("missing sign partial")
	}
	seen := make(map[tss.PartyID]struct{}, len(payload.DecProofs))
	for i := range payload.DecProofs {
		item := &payload.DecProofs[i]
		if item.Verifier == from || !slices.Contains(s.presign.state.Signers, item.Verifier) {
			return errors.New("invalid sign dec verifier")
		}
		if _, ok := seen[item.Verifier]; ok {
			return errors.New("duplicate sign dec verifier")
		}
		seen[item.Verifier] = struct{}{}
		rp, err := s.key.ringPedersenPublicFor(item.Verifier, s.limits)
		if err != nil {
			return err
		}
		state := presignIdentificationProofState(payload.AlertDigest, from, item.Verifier, "sign-dec")
		if err := zkpai.VerifyDec(s.presign.state.SecurityParams, state, zkpai.DecStatement{PaillierN: pk, C: cSigma, X: partial, VerifierAux: rp}, &item.Proof); err != nil {
			return err
		}
	}
	return nil
}

type acceptSignIdentificationTx struct {
	from      tss.PartyID
	payload   signIdentificationPayload
	committed bool
}

func (tx *acceptSignIdentificationTx) apply(s *SignSession) (sessionEffects, error) {
	if s.identificationPayloads == nil {
		s.identificationPayloads = make(map[tss.PartyID]signIdentificationPayload, len(s.presign.state.Signers))
	}
	s.identificationPayloads[tx.from] = tx.payload
	if len(s.identificationPayloads) != len(s.presign.state.Signers) {
		return sessionEffects{}, nil
	}
	// An all-valid identification transcript leaves no attributable peer, but
	// signing cannot continue. Enter the terminal cleared state before exposing
	// the unblamed implementation invariant.
	s.abort()
	return sessionEffects{}, &tss.ProtocolError{Code: tss.ErrCodeInvariant, Round: signIdentificationRound, Err: errors.New("all sign identification proofs verified but aggregate signature failure persisted")}
}
func (tx *acceptSignIdentificationTx) cleanupOnReject() {
	if tx != nil && !tx.committed {
		tx.payload.destroy()
	}
}
func (tx *acceptSignIdentificationTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

func (s *SignSession) buildAcceptSignIdentificationTx(in tss.InboundEnvelope) (*acceptSignIdentificationTx, error) {
	env := in.Envelope()
	if err := s.validateInbound(in); err != nil {
		return nil, err
	}
	if env.Round != signIdentificationRound || env.PayloadType != payloadSignIdentification {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("unexpected sign identification message"))
	}
	if !s.identifying {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("sign identification is not active"))
	}
	if _, exists := s.identificationPayloads[env.From]; exists {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate sign identification payload"))
	}
	payload, err := tss.DecodeBinaryValueWithLimits[signIdentificationPayload](env.Payload, s.limits)
	if err != nil {
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.state.Signers)...)
		recordField, recordErr := identificationProofEvidenceField(env, "sign-identification-malformed", s.identificationAlert, s.key.state.KeygenTranscriptHash, s.presign.state.TranscriptHash)
		if recordErr != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, recordErr)
		}
		fields = append(fields, recordField)
		return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindSignIdentification, "malformed sign identification payload", tss.NewPartySet(env.From), err, fields...)
	}
	if err := s.verifySignIdentificationPayload(env.From, payload); err != nil {
		payload.destroy()
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.state.Signers)...)
		recordField, recordErr := identificationProofEvidenceField(env, "sign-identification-invalid-proof", s.identificationAlert, s.key.state.KeygenTranscriptHash, s.presign.state.TranscriptHash)
		if recordErr != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, recordErr)
		}
		fields = append(fields, recordField)
		return nil, protocolErrorWithEvidence(tss.ErrCodeVerification, env, tss.EvidenceKindSignIdentification, "invalid sign identification proof", tss.NewPartySet(env.From), err, fields...)
	}
	return &acceptSignIdentificationTx{from: env.From, payload: payload}, nil
}
