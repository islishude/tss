package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	"github.com/islishude/tss/internal/transcript"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

type presignAggregateAlertError struct{ err error }

// Error describes the presign aggregate verification alert.
func (e *presignAggregateAlertError) Error() string {
	return fmt.Sprintf("presign aggregate verification alert: %v", e.err)
}

// Unwrap returns the underlying aggregate verification failure.
func (e *presignAggregateAlertError) Unwrap() error { return e.err }

type presignIdentificationReproof struct {
	Peer  tss.PartyID     `wire:"1,u32"`
	Proof zkpai.AffGProof `wire:"2,nested,max_bytes=zk_proof"`
}

type presignIdentificationDecProof struct {
	Verifier tss.PartyID    `wire:"1,u32"`
	Proof    zkpai.DecProof `wire:"2,nested,max_bytes=zk_proof"`
}

type presignIdentificationPayload struct {
	AlertDigest []byte                          `wire:"1,bytes,len=32"`
	H           []byte                          `wire:"2,bytes,max_bytes=paillier_ciphertext"`
	MulProof    zkpai.MulProof                  `wire:"3,nested,max_bytes=zk_proof"`
	CDelta      []byte                          `wire:"4,bytes,max_bytes=paillier_ciphertext"`
	Reproofs    []presignIdentificationReproof  `wire:"5,recordlist,max_items=signers"`
	DecProofs   []presignIdentificationDecProof `wire:"6,recordlist,max_items=signers"`
	PlanHash    []byte                          `wire:"7,bytes,len=32"`
}

// WireType returns the identification payload wire type.
func (presignIdentificationPayload) WireType() string { return presignIdentificationPayloadWireType }

// WireVersion returns the identification payload wire version.
func (presignIdentificationPayload) WireVersion() uint16 {
	return presignIdentificationPayloadWireVersion
}

// MarshalBinary encodes the presign identification payload.
func (p presignIdentificationPayload) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryWithLimits(DefaultLimits())
}

// MarshalBinaryWithLimits encodes the payload with explicit limits.
func (p presignIdentificationPayload) MarshalBinaryWithLimits(limits Limits) ([]byte, error) {
	return marshalPayloadWithLimits(p, limits)
}

// UnmarshalBinary decodes a presign identification payload.
func (p *presignIdentificationPayload) UnmarshalBinary(in []byte) error {
	return p.UnmarshalBinaryWithLimits(in, DefaultLimits())
}

// UnmarshalBinaryWithLimits decodes the payload with explicit limits.
func (p *presignIdentificationPayload) UnmarshalBinaryWithLimits(in []byte, limits Limits) error {
	return unmarshalPayloadWithLimits(p, in, limits)
}

// Validate checks the public proof-set shape and canonical party ordering.
func (p presignIdentificationPayload) Validate() error {
	if len(p.AlertDigest) != sha256.Size || len(p.PlanHash) != sha256.Size {
		return errors.New("invalid presign identification digest")
	}
	if err := validatePositiveIntegerBytes(p.H); err != nil {
		return fmt.Errorf("invalid presign identification H: %w", err)
	}
	if err := validatePositiveIntegerBytes(p.CDelta); err != nil {
		return fmt.Errorf("invalid presign identification CDelta: %w", err)
	}
	if err := p.MulProof.Validate(); err != nil {
		return err
	}
	if len(p.Reproofs) == 0 || len(p.DecProofs) == 0 {
		return errors.New("incomplete presign identification proof set")
	}
	for i := range p.Reproofs {
		if p.Reproofs[i].Peer == 0 || p.Reproofs[i].Peer == tss.BroadcastPartyId {
			return errors.New("invalid presign identification reproof peer")
		}
		if i > 0 && p.Reproofs[i-1].Peer >= p.Reproofs[i].Peer {
			return errors.New("non-canonical presign identification reproof order")
		}
		if err := p.Reproofs[i].Proof.Validate(); err != nil {
			return err
		}
	}
	for i := range p.DecProofs {
		if p.DecProofs[i].Verifier == 0 || p.DecProofs[i].Verifier == tss.BroadcastPartyId {
			return errors.New("invalid presign identification dec verifier")
		}
		if i > 0 && p.DecProofs[i-1].Verifier >= p.DecProofs[i].Verifier {
			return errors.New("non-canonical presign identification dec proof order")
		}
		if err := p.DecProofs[i].Proof.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p *presignIdentificationPayload) destroy() {
	if p == nil {
		return
	}
	clear(p.AlertDigest)
	clear(p.H)
	clear(p.CDelta)
	clear(p.PlanHash)
	p.MulProof.Destroy()
	for i := range p.Reproofs {
		p.Reproofs[i].Proof.Destroy()
	}
	for i := range p.DecProofs {
		p.DecProofs[i].Proof.Destroy()
	}
	*p = presignIdentificationPayload{}
}

func presignIdentificationProofState(alert []byte, prover, verifier tss.PartyID, phase string) []byte {
	t := transcript.New("cggmp21-secp256k1-presign-identification-proof-v1")
	t.AppendBytes("alert_digest", alert)
	t.AppendUint32("prover", prover)
	t.AppendUint32("verifier", verifier)
	t.AppendString("phase", phase)
	return t.Sum()
}

func (s *PresignSession) presignIdentificationAlert() []byte {
	t := transcript.New("cggmp21-secp256k1-presign-identification-alert-v1")
	t.AppendBytes("session_id", s.sessionID[:])
	t.AppendBytes("plan_hash", s.planHash)
	t.AppendBytes("round1_echo", s.round1Echo())
	for _, party := range s.signers {
		state, ok := s.partyState(party)
		if !ok || state.round3.delta == nil {
			continue
		}
		t.AppendUint32("party", party)
		delta := state.round3.delta.FixedBytes()
		t.AppendBytes("delta", delta)
		clear(delta)
		contributionsHash, err := mtaContributionsDigest(state.round3.verifyShare.mtaContributions)
		if err == nil {
			t.AppendBytes("mta_contributions_hash", contributionsHash)
		}
	}
	return t.Sum()
}

func addIdentificationCiphertext(pkN2 *big.Int, accumulator *big.Int, value []byte) error {
	x := new(big.Int).SetBytes(value)
	if x.Sign() <= 0 || x.Cmp(pkN2) >= 0 {
		return errors.New("identification ciphertext out of range")
	}
	accumulator.Mul(accumulator, x)
	accumulator.Mod(accumulator, pkN2)
	return nil
}

func inverseIdentificationCiphertext(pkN2 *big.Int, value *big.Int) (*big.Int, error) {
	inverse := new(big.Int).ModInverse(value, pkN2)
	if inverse == nil {
		return nil, errors.New("identification ciphertext is not invertible")
	}
	return inverse, nil
}

func identificationResponseDomain(original, alert []byte, prover, verifier tss.PartyID, phase string) []byte {
	t := transcript.New("cggmp21-secp256k1-identification-response-domain-v1")
	t.AppendBytes("original_domain", original)
	t.AppendBytes("alert_digest", alert)
	t.AppendUint32("prover", prover)
	t.AppendUint32("verifier", verifier)
	t.AppendString("phase", phase)
	return t.Sum()
}

func (s *PresignSession) buildLocalPresignIdentificationPayload(alert []byte) (presignIdentificationPayload, error) {
	if s.startOpening == nil || s.gammaOpening == nil || s.paillier == nil {
		return presignIdentificationPayload{}, errors.New("presign identification openings unavailable")
	}
	self := s.key.state.Party
	state := presignIdentificationProofState(alert, self, tss.BroadcastPartyId, "mul")
	h, mulProof, err := s.startOpening.ProveProduct(s.securityParams, s.config.Reader(), state, s.gammaOpening, s.paillier.PublicKey)
	if err != nil {
		return presignIdentificationPayload{}, err
	}
	payload := presignIdentificationPayload{
		AlertDigest: bytes.Clone(alert), H: h.Bytes(), MulProof: *mulProof,
		PlanHash: bytes.Clone(s.planHash),
	}
	success := false
	defer func() {
		if !success {
			payload.destroy()
		}
	}()

	cDelta := new(big.Int).Set(h)
	for _, peer := range s.signers {
		if peer == self {
			continue
		}
		peerState, ok := s.partyState(peer)
		if !ok || peerState.mta.deltaOpening == nil || !peerState.round2.havePayload || !peerState.round2.haveOutboundDelta {
			return presignIdentificationPayload{}, fmt.Errorf("missing delta identification state for peer %d", peer)
		}
		peerPK, err := s.key.paillierPublicFor(peer, s.limits)
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		peerRP, err := s.key.ringPedersenPublicFor(peer, s.limits)
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		startState, ok := s.partyState(peer)
		if !ok || !startState.round1.havePayload {
			return presignIdentificationPayload{}, fmt.Errorf("missing peer start state %d", peer)
		}
		originalDomain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, peer, self, peerPK, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		domain := identificationResponseDomain(originalDomain, alert, self, peer, "delta-affg")
		proof, err := peerState.mta.deltaOpening.Reprove(s.securityParams, s.config.Reader(), domain,
			mta.StartMessage{Ciphertext: startState.round1.payload.EncK}, peerState.round2.outboundDelta,
			startState.round1.payload.KPoint, s.gammaComm, peerPK, s.paillier.PublicKey, peerRP)
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		payload.Reproofs = append(payload.Reproofs, presignIdentificationReproof{Peer: peer, Proof: *proof})
		if err := addIdentificationCiphertext(s.paillier.NSquared, cDelta, peerState.round2.payload.Delta.Ciphertext); err != nil {
			return presignIdentificationPayload{}, err
		}
		inverse, err := inverseIdentificationCiphertext(s.paillier.NSquared, peerState.round2.outboundDelta.Proof.Y)
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		cDelta.Mul(cDelta, inverse)
		cDelta.Mod(cDelta, s.paillier.NSquared)
	}
	payload.CDelta = cDelta.Bytes()
	plaintext, randomness, err := s.paillier.RecoverOpening(cDelta)
	if err != nil {
		return presignIdentificationPayload{}, err
	}
	defer plaintext.Destroy()
	defer randomness.Destroy()
	selfState, ok := s.partyState(self)
	if !ok || selfState.round3.delta == nil {
		return presignIdentificationPayload{}, errors.New("missing local delta share")
	}
	delta, err := secp.ScalarFromBytesAllowZero(selfState.round3.delta.FixedBytes())
	if err != nil {
		return presignIdentificationPayload{}, err
	}
	for _, verifier := range s.signers {
		if verifier == self {
			continue
		}
		rp, err := s.key.ringPedersenPublicFor(verifier, s.limits)
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		proofState := presignIdentificationProofState(alert, self, verifier, "dec")
		proof, err := zkpai.ProveDec(s.securityParams, proofState, zkpai.DecStatement{
			PaillierN: s.paillier.PublicKey, C: cDelta, X: delta, VerifierAux: rp,
		}, zkpai.DecWitness{Y: plaintext, Rho: randomness}, s.config.Reader())
		if err != nil {
			return presignIdentificationPayload{}, err
		}
		payload.DecProofs = append(payload.DecProofs, presignIdentificationDecProof{Verifier: verifier, Proof: *proof})
	}
	if err := payload.Validate(); err != nil {
		return presignIdentificationPayload{}, err
	}
	success = true
	return payload, nil
}

func (s *PresignSession) verifyPresignIdentificationPayload(from tss.PartyID, payload presignIdentificationPayload) error {
	if !s.identifying || !bytes.Equal(payload.AlertDigest, s.identificationAlert) {
		return errors.New("presign identification alert mismatch")
	}
	if !bytes.Equal(payload.PlanHash, s.planHash) {
		return errors.New("presign identification plan mismatch")
	}
	fromState, ok := s.partyState(from)
	if !ok || !fromState.round1.havePayload || !fromState.round3.haveDelta || !fromState.round3.haveVerifyShare {
		return errors.New("missing accused presign public state")
	}
	pk, err := s.key.paillierPublicFor(from, s.limits)
	if err != nil {
		return err
	}
	h := new(big.Int).SetBytes(payload.H)
	mulState := presignIdentificationProofState(payload.AlertDigest, from, tss.BroadcastPartyId, "mul")
	if err := zkpai.VerifyMul(s.securityParams, mulState, zkpai.MulStatement{
		PaillierN: pk,
		X:         new(big.Int).SetBytes(fromState.round1.payload.EncK),
		Y:         new(big.Int).SetBytes(fromState.round1.payload.EncGamma),
		C:         h,
	}, &payload.MulProof); err != nil {
		return err
	}
	if len(payload.Reproofs) != len(s.signers)-1 || len(payload.DecProofs) != len(s.signers)-1 {
		return errors.New("presign identification proof set has wrong cardinality")
	}
	cDelta := new(big.Int).Set(h)
	for _, reproof := range payload.Reproofs {
		if reproof.Peer == from || !tss.ContainsParty(s.signers, reproof.Peer) {
			return errors.New("invalid presign identification reproof peer")
		}
		contribution, ok := mtaContributionFor(fromState.round3.verifyShare.mtaContributions, reproof.Peer)
		if !ok {
			return fmt.Errorf("missing public MTA contribution for peer %d", reproof.Peer)
		}
		peerState, ok := s.partyState(reproof.Peer)
		if !ok || !peerState.round1.havePayload {
			return errors.New("missing peer presign state")
		}
		peerPK, err := s.key.paillierPublicFor(reproof.Peer, s.limits)
		if err != nil {
			return err
		}
		peerRP, err := s.key.ringPedersenPublicFor(reproof.Peer, s.limits)
		if err != nil {
			return err
		}
		originalDomain, err := mtaDeltaResponseDomain(s.key, s.sessionID, s.signers, reproof.Peer, from, peerPK, s.contextHash, s.planHash, s.limits)
		if err != nil {
			return err
		}
		response := contribution.OutboundDelta.Clone()
		response.Proof.Destroy()
		response.Proof = *reproof.Proof.Clone()
		domain := identificationResponseDomain(originalDomain, payload.AlertDigest, from, reproof.Peer, "delta-affg")
		err = mta.VerifyResponse(s.securityParams, domain, mta.StartMessage{Ciphertext: peerState.round1.payload.EncK}, response,
			peerState.round1.payload.KPoint, fromState.round1.payload.Gamma, peerPK, pk, peerRP)
		response.Destroy()
		if err != nil {
			return err
		}
		if err := addIdentificationCiphertext(pk.NSquared, cDelta, contribution.InboundDelta.Ciphertext); err != nil {
			return err
		}
		inverse, err := inverseIdentificationCiphertext(pk.NSquared, contribution.OutboundDelta.Proof.Y)
		if err != nil {
			return err
		}
		cDelta.Mul(cDelta, inverse)
		cDelta.Mod(cDelta, pk.NSquared)
	}
	if !bytes.Equal(cDelta.Bytes(), payload.CDelta) {
		return errors.New("presign identification CDelta mismatch")
	}
	deltaBytes := fromState.round3.delta.FixedBytes()
	delta, err := secp.ScalarFromBytesAllowZero(deltaBytes)
	clear(deltaBytes)
	if err != nil {
		return err
	}
	seenVerifier := make(map[tss.PartyID]struct{}, len(payload.DecProofs))
	for i := range payload.DecProofs {
		item := &payload.DecProofs[i]
		if item.Verifier == from || !tss.ContainsParty(s.signers, item.Verifier) {
			return errors.New("invalid presign identification dec verifier")
		}
		if _, ok := seenVerifier[item.Verifier]; ok {
			return errors.New("duplicate presign identification dec verifier")
		}
		seenVerifier[item.Verifier] = struct{}{}
		rp, err := s.key.ringPedersenPublicFor(item.Verifier, s.limits)
		if err != nil {
			return err
		}
		proofState := presignIdentificationProofState(payload.AlertDigest, from, item.Verifier, "dec")
		if err := zkpai.VerifyDec(s.securityParams, proofState, zkpai.DecStatement{
			PaillierN: pk, C: cDelta, X: delta, VerifierAux: rp,
		}, &item.Proof); err != nil {
			return err
		}
	}
	return nil
}

func (s *PresignSession) startPresignIdentification(cause error) ([]tss.Envelope, error) {
	if s.identifying {
		return nil, nil
	}
	alert := s.presignIdentificationAlert()
	payload, err := s.buildLocalPresignIdentificationPayload(alert)
	if err != nil {
		return nil, fmt.Errorf("prepare presign identification after %w: %w", cause, err)
	}
	encoded, err := payload.MarshalBinaryWithLimits(s.limits)
	if err != nil {
		payload.destroy()
		return nil, err
	}
	env, err := newEnvelope(s.config, presignIdentificationRound, s.key.state.Party, tss.BroadcastPartyId, payloadPresignIdentification, encoded)
	clear(encoded)
	if err != nil {
		payload.destroy()
		return nil, err
	}
	s.identifying = true
	s.identificationAlert = bytes.Clone(alert)
	s.identificationPayloads = map[tss.PartyID]presignIdentificationPayload{s.key.state.Party: payload}
	return []tss.Envelope{env}, nil
}

type acceptPresignIdentificationTx struct {
	from      tss.PartyID
	payload   presignIdentificationPayload
	committed bool
}

func (tx *acceptPresignIdentificationTx) apply(s *PresignSession) (sessionEffects, error) {
	if s.identificationPayloads == nil {
		s.identificationPayloads = make(map[tss.PartyID]presignIdentificationPayload, len(s.signers))
	}
	s.identificationPayloads[tx.from] = tx.payload
	if len(s.identificationPayloads) != len(s.signers) {
		return sessionEffects{}, nil
	}
	// All public proofs verified, so there is no remote party to blame. The
	// aggregate failure is nevertheless terminal: clear every retained nonce,
	// MtA opening, and identification payload before returning the invariant.
	s.abort()
	return sessionEffects{}, &tss.ProtocolError{
		Code:  tss.ErrCodeInvariant,
		Round: presignIdentificationRound,
		Err:   errors.New("all presign identification proofs verified but aggregate failure persisted"),
	}
}

func (tx *acceptPresignIdentificationTx) cleanupOnReject() {
	if tx != nil && !tx.committed {
		tx.payload.destroy()
	}
}

func (tx *acceptPresignIdentificationTx) markCommitted() {
	if tx != nil {
		tx.committed = true
	}
}

func (s *PresignSession) buildAcceptPresignIdentificationTx(env tss.Envelope) (*acceptPresignIdentificationTx, error) {
	if !s.identifying {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("presign identification is not active"))
	}
	if _, exists := s.identificationPayloads[env.From]; exists {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign identification payload"))
	}
	payload, err := tss.DecodeBinaryValueWithLimits[presignIdentificationPayload](env.Payload, s.limits)
	if err != nil {
		statement, statementErr := s.portablePresignIdentificationStatement(env)
		if statementErr != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, statementErr)
		}
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		recordField, recordErr := identificationProofEvidenceField(env, "presign-identification-malformed", statement, s.identificationAlert, s.key.state.KeygenTranscriptHash, nil)
		if recordErr != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, recordErr)
		}
		fields = append(fields, recordField)
		return nil, protocolErrorWithEvidence(tss.ErrCodeInvalidMessage, env, tss.EvidenceKindPresignIdentification,
			"malformed presign identification payload", tss.NewPartySet(env.From), err,
			fields...)
	}
	if err := s.verifyPresignIdentificationPayload(env.From, payload); err != nil {
		payload.destroy()
		statement, statementErr := s.portablePresignIdentificationStatement(env)
		if statementErr != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, statementErr)
		}
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
		recordField, recordErr := identificationProofEvidenceField(env, "presign-identification-invalid-proof", statement, s.identificationAlert, s.key.state.KeygenTranscriptHash, nil)
		if recordErr != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, env.From, recordErr)
		}
		fields = append(fields, recordField)
		return nil, protocolErrorWithEvidence(tss.ErrCodeVerification, env, tss.EvidenceKindPresignIdentification,
			"invalid presign identification proof", tss.NewPartySet(env.From), err,
			fields...)
	}
	return &acceptPresignIdentificationTx{from: env.From, payload: payload}, nil
}
