package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"slices"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

// StartSign starts online signing using a context-bound presignature.
func StartSign(key *KeyShare, presign *Presign, sessionID tss.SessionID, request SignRequest) (*SignSession, []tss.Envelope, error) {
	if err := key.Validate(); err != nil {
		return nil, nil, err
	}
	if presign == nil {
		return nil, nil, errors.New("nil presign")
	}
	_, contextHash, additiveShift, err := preparePresignContext(key, request.Context)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(contextHash, presign.ContextHash) {
		return nil, nil, errors.New("presign context mismatch")
	}
	if !bytes.Equal(additiveShift, presign.AdditiveShift) {
		return nil, nil, errors.New("presign additive shift mismatch")
	}
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	return startSignDigestBound(key, presign, sessionID, digest, contextHash, request.LowS, request.PresignStore)
}

func startSignDigestBound(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32, contextHash []byte, lowS bool, store PresignStore) (*SignSession, []tss.Envelope, error) {
	if err := key.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	if err := validatePresign(key, presign); err != nil {
		return nil, nil, err
	}
	if err := presign.VerifySignMaterial(); err != nil {
		return nil, nil, err
	}
	if len(digest32) != 32 {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	if len(contextHash) != sha256.Size || !bytes.Equal(contextHash, presign.ContextHash) {
		return nil, nil, errors.New("presign context mismatch")
	}
	if IsPresignConsumed(presign) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.Party, errors.New("presign already consumed"))
	}
	if presign.restored && store == nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 1, key.Party, errors.New("restored presign requires SignRequest.PresignStore for durable one-use claim"))
	}
	if !claimPresignForSigning(presign) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.Party, errors.New("presign already consumed"))
	}
	// Durable claim: if the caller provided a store, persist Consumed=true before
	// we construct any outbound partial. If persistence fails, revert the in-memory
	// flag so the presign can be retried.
	if store != nil {
		if err := store.MarkConsumed(presign.ID()); err != nil {
			releasePresignID(presign)
			presign.mu.Lock()
			presign.Consumed = false
			presign.mu.Unlock()
			return nil, nil, fmt.Errorf("presign durable claim failed: %w", err)
		}
	}
	kShare, err := secpScalarFromSecret(presign.kShare)
	if err != nil {
		return nil, nil, err
	}
	chiShare, err := secpScalarFromSecret(presign.chiShare)
	if err != nil {
		return nil, nil, err
	}
	verifyKey := append([]byte(nil), key.PublicKey...)
	if len(presign.AdditiveShift) > 0 {
		verifyKey, err = DerivePublicKey(key.PublicKey, presign.AdditiveShift)
		if err != nil {
			return nil, nil, err
		}
	}
	littleR, err := secp.ScalarFromBytes(presign.LittleR)
	if err != nil {
		return nil, nil, err
	}
	z := new(big.Int).SetBytes(digest32)
	// Online ECDSA partial: s_i = m*k_i + r*chi_i mod q.
	partial := new(big.Int).Mul(z, kShare.BigInt())
	rs := new(big.Int).Mul(littleR.BigInt(), chiShare.BigInt())
	partial.Add(partial, rs)
	partial.Mod(partial, secp.Order())
	localVS, ok := presignVerifyShare(presign, key.Party)
	if !ok {
		return nil, nil, fmt.Errorf("missing local verify share for party %d — presign may be corrupted", key.Party)
	}
	payload := signPartialPayload{
		S:                 partial,
		PresignTranscript: slices.Clone(presign.TranscriptHash),
		PresignContext:    slices.Clone(contextHash),
		DigestHash:        digestHash(digest32, contextHash),
		PartialEquationHash: partialEquationHash(
			sessionID, key.Party, presign.TranscriptHash,
			contextHash, digest32,
			littleR.Bytes(), scalarBytes(partial),
			localVS.KPoint, localVS.ChiPoint,
		),
	}
	payloadBytes, err := marshalSignPartialPayload(payload)
	if err != nil {
		return nil, nil, err
	}
	s := &SignSession{
		key:       key,
		presign:   presign,
		sessionID: sessionID,
		log:       tss.NopLogger(),
		limits:    DefaultLimits(),
		digest:    append([]byte(nil), digest32...),
		lowS:      lowS,
		publicKey: verifyKey,
		partials:  make(map[tss.PartyID]*big.Int),
	}
	if _, err := s.verifySignPartial(key.Party, payload); err != nil {
		return nil, nil, fmt.Errorf("local sign partial self-verification failed: %w", err)
	}
	s.partials[key.Party] = partial
	env, err := tss.NewEnvelope(tss.EnvelopeInput{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        key.Party,
		PayloadType: payloadSignPartial,
		Payload:     payloadBytes,
	})
	if err != nil {
		return nil, nil, err
	}
	env.Security.Confidential = true
	if err := s.tryCompleteSign(); err != nil {
		return nil, nil, err
	}
	return s, []tss.Envelope{env}, nil
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *SignSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// SetGuard attaches an envelope guard to the session. It must be called before
// processing any inbound messages. A nil guard causes [HandleSignMessage] to
// return [tss.ErrMissingEnvelopeGuard].
func (s *SignSession) SetGuard(g *tss.EnvelopeGuard) {
	if s != nil {
		s.guard = g
	}
}

// NewGuard creates an EnvelopeGuard suitable for testing this session.
// Production callers must use [tss.GuardConfig.BuildGuard] with a real AckVerifier.
func (s *SignSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	return tss.NewEnvelopeGuard(s.key.Party, tss.PartySet(s.key.Parties), protocol, s.sessionID, CGGMP21Policies(), cache)
}

// validateInbound runs envelope validation through the shared ValidateInbound helper.
func (s *SignSession) validateInbound(env tss.Envelope) error {
	return tss.ValidateInbound(s.guard, env, protocol, s.sessionID, tss.PartySet(s.presign.Signers), s.key.Party)
}

// HandleSignMessage validates and applies one online signing envelope.
//
// Follows the handler template (see doc.go).
func (s *SignSession) HandleSignMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.abort()
		}
	}()
	if err := s.validateInbound(env); err != nil {
		if errors.Is(err, tss.ErrDuplicateMessage) {
			return nil, tss.ErrDuplicateMessage
		}
		return nil, err
	}
	if !tss.ContainsParty(s.presign.Signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}

	// ---- 1 & 2. PARSE + POLICY VALIDATE ----
	if env.Round != 1 || env.PayloadType != payloadSignPartial {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("expected round 1 sign partial"))
	}
	if _, ok := s.partials[env.From]; ok {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate sign partial"))
	}
	p, err := unmarshalSignPartialPayload(env.Payload)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"malformed sign partial payload",
			[]tss.PartyID{env.From},
			err,
			s.signPartialContextEvidenceFields(env.Payload)...,
		)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	partial, err := s.verifySignPartial(env.From, p)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeVerification,
			env,
			tss.EvidenceKindSignPartial,
			"sign partial verification failed",
			[]tss.PartyID{env.From},
			err,
			s.signPartialEvidenceFields(env.From, p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	s.partials[env.From] = partial

	// ---- 5. EMIT ----
	return nil, s.tryCompleteSign()
}

// Signature returns the completed ECDSA signature.
func (s *SignSession) Signature() (*Signature, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return &Signature{R: append([]byte(nil), s.signature.R...), S: append([]byte(nil), s.signature.S...)}, true
}

func (s *SignSession) signPartialEvidenceFields(from tss.PartyID, p signPartialPayload) []tss.EvidenceField {
	fields := s.signPartialContextEvidenceFields(nil)
	fields = append(fields,
		hashEvidenceField("observed_presign_transcript_hash", p.PresignTranscript),
		hashEvidenceField("observed_presign_context_hash", p.PresignContext),
		hashEvidenceField("sign_partial_hash", scalarBytes(p.S)),
	)
	// Include the sender's (blamed party's) KPoint/ChiPoint hashes.
	if vs, ok := presignVerifyShare(s.presign, from); ok {
		fields = append(fields,
			hashEvidenceField(evidenceFieldSignVerifyKPointHash, vs.KPoint),
			hashEvidenceField(evidenceFieldSignVerifyChiPointHash, vs.ChiPoint),
		)
		// Compute the expected equation hash for independent auditability.
		expectedEqHash := partialEquationHash(
			s.sessionID, from, s.presign.TranscriptHash,
			s.presign.ContextHash, s.digest,
			s.presign.LittleR, scalarBytes(p.S),
			vs.KPoint, vs.ChiPoint,
		)
		fields = append(fields,
			rawEvidenceField(evidenceFieldPartialEquationHash, expectedEqHash),
			rawEvidenceField(evidenceFieldObservedPartialEquationHash, p.PartialEquationHash),
		)
	}
	return fields
}

func (s *SignSession) signPartialContextEvidenceFields(rawPayload []byte) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
	fields = append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.TranscriptHash),
		rawEvidenceField("presign_context_hash", s.presign.ContextHash),
		hashEvidenceField(evidenceFieldDigestHash, s.digest),
	)
	if rawPayload != nil {
		fields = append(fields, hashEvidenceField("sign_partial_payload_hash", rawPayload))
	}
	return fields
}

func (s *SignSession) tryCompleteSign() error {
	if s.completed || len(s.partials) != len(s.presign.Signers) {
		return nil
	}
	sigS := new(big.Int)
	for _, id := range s.presign.Signers {
		sigS.Add(sigS, s.partials[id])
		sigS.Mod(sigS, secp.Order())
	}
	if sigS.Sign() == 0 {
		return errors.New("zero ECDSA s")
	}
	if s.lowS && sigS.Cmp(new(big.Int).Rsh(new(big.Int).Set(secp.Order()), 1)) > 0 {
		sigS.Sub(secp.Order(), sigS)
	}
	r, err := secp.ScalarFromBytes(s.presign.LittleR)
	if err != nil {
		return err
	}
	public, err := secp.PointFromBytes(s.publicKey)
	if err != nil {
		return err
	}
	if !secp.VerifyECDSA(public, s.digest, r, secp.ScalarFromBigInt(sigS)) {
		return &tss.ProtocolError{
			Code:  tss.ErrCodeInvariant,
			Round: 1,
			Err:   errors.New("all partials individually verified but aggregate ECDSA signature verification failed"),
		}
	}
	s.signature = &Signature{R: r.Bytes(), S: secp.ScalarFromBigInt(sigS).Bytes()}
	s.completed = true
	s.log.Info(context.Background(), "signing complete",
		"party_id", s.key.Party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	return nil
}

// VerifyDigest verifies a secp256k1 ECDSA signature over a 32-byte digest.
func VerifyDigest(publicKey, digest32 []byte, sig *Signature) bool {
	public, err := secp.PointFromBytes(publicKey)
	if err != nil {
		return false
	}
	if sig == nil {
		return false
	}
	r, err := secp.ScalarFromBytes(sig.R)
	if err != nil {
		return false
	}
	s, err := secp.ScalarFromBytes(sig.S)
	if err != nil {
		return false
	}
	return secp.VerifyECDSA(public, digest32, r, s)
}

// VerifySignature verifies a context-bound secp256k1 ECDSA signature.
func VerifySignature(publicKey []byte, request SignRequest, sig *Signature) bool {
	if err := validatePresignContext(request.Context); err != nil {
		return false
	}
	contextHash := presignContextHash(request.Context)
	digest := signMessageDigest(contextHash, request.Context.MessageDomain, request.Message)
	return VerifyDigest(publicKey, digest, sig)
}

func validatePresign(key *KeyShare, presign *Presign) error {
	if err := presign.Validate(); err != nil {
		return err
	}
	if presign.Party != key.Party {
		return errors.New("presign party mismatch")
	}
	if presign.Threshold != key.Threshold {
		return errors.New("presign threshold mismatch")
	}
	if !bytes.Equal(presign.PublicKey, key.PublicKey) {
		return errors.New("presign public key binding mismatch")
	}
	if !bytes.Equal(presign.KeygenTranscriptHash, key.KeygenTranscriptHash) {
		return errors.New("presign keygen transcript binding mismatch")
	}
	if !bytes.Equal(presign.PartiesHash, wireutil.PartySetHash(key.Parties, partySetHashLabel)) {
		return errors.New("presign participant set binding mismatch")
	}
	if len(presign.Signers) < key.Threshold || !tss.ContainsParty(presign.Signers, key.Party) {
		return errors.New("invalid presign signer set")
	}
	return nil
}

func claimPresignForSigning(presign *Presign) bool {
	presign.mu.Lock()
	if presign.Consumed {
		presign.mu.Unlock()
		return false
	}
	presign.mu.Unlock()
	if !claimPresignID(presign) {
		return false
	}
	// Mark consumed before constructing the outbound sign envelope so accidental
	// reuse fails before any new partial signature can leave the process.
	presign.mu.Lock()
	presign.Consumed = true
	presign.mu.Unlock()
	return true
}

// ClaimPresign atomically checks and marks a presign as consumed.
// It returns [tss.ErrCodeConsumed] if the presign has already been consumed.
// Callers can use this as a pre-flight check before [StartSign] to avoid
// double-consumption across concurrent signing attempts.
//
// ClaimPresign does not perform durable persistence — use [SignRequest.PresignStore]
// for durable consumption tracking during [StartSign].
func ClaimPresign(presign *Presign) error {
	if presign == nil {
		return errors.New("nil presign")
	}
	if !claimPresignForSigning(presign) {
		return tss.NewProtocolError(tss.ErrCodeConsumed, 1, presign.Party, errors.New("presign already consumed"))
	}
	return nil
}

func validateSignerSet(key *KeyShare, signers []tss.PartyID, limits Limits) error {
	return tss.ValidateSignerSet(key.Parties, key.Threshold, signers, limits.ThresholdLimits())
}

func (s *SignSession) verifySignPartial(from tss.PartyID, p signPartialPayload) (*big.Int, error) {
	if !tss.ContainsParty(s.presign.Signers, from) {
		return nil, errors.New("sender is not in signer set")
	}
	if !bytes.Equal(p.PresignTranscript, s.presign.TranscriptHash) {
		return nil, errors.New("presign transcript mismatch")
	}
	if !bytes.Equal(p.PresignContext, s.presign.ContextHash) {
		return nil, errors.New("presign context mismatch")
	}
	expectedDigestHash := digestHash(s.digest, s.presign.ContextHash)
	if !bytes.Equal(p.DigestHash, expectedDigestHash) {
		return nil, errors.New("digest hash mismatch")
	}
	sVal := secp.ScalarFromBigInt(p.S)
	vs, ok := presignVerifyShare(s.presign, from)
	if !ok {
		return nil, fmt.Errorf("missing verify share for party %d", from)
	}
	kPoint, err := secp.PointFromBytes(vs.KPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid KPoint for party %d: %w", from, err)
	}
	chiPoint, err := secp.PointFromBytes(vs.ChiPoint)
	if err != nil {
		return nil, fmt.Errorf("invalid ChiPoint for party %d: %w", from, err)
	}
	littleR, err := secp.ScalarFromBytes(s.presign.LittleR)
	if err != nil {
		return nil, err
	}
	expectedEqHash := partialEquationHash(
		s.sessionID, from, s.presign.TranscriptHash,
		s.presign.ContextHash, s.digest,
		littleR.Bytes(), scalarBytes(p.S),
		vs.KPoint, vs.ChiPoint,
	)
	if !bytes.Equal(p.PartialEquationHash, expectedEqHash) {
		return nil, errors.New("partial equation hash mismatch")
	}
	z := new(big.Int).SetBytes(s.digest)
	zScalar, err := secp.ScalarFromBytes(scalarBytes(z))
	if err != nil {
		return nil, err
	}
	lhs := secp.ScalarBaseMult(sVal)
	term1 := secp.ScalarMult(kPoint, zScalar)
	term2 := secp.ScalarMult(chiPoint, littleR)
	rhs := secp.Add(term1, term2)
	if !secp.Equal(lhs, rhs) {
		return nil, errors.New("sign partial equation verification failed")
	}
	return sVal.BigInt(), nil
}

func digestHash(digest32, contextHash []byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte("cggmp21-secp256k1-sign-digest-binding"))
	wire.WriteHashPart(h, contextHash)
	wire.WriteHashPart(h, digest32)
	return h.Sum(nil)
}

const signPartialEquationDomain = "cggmp21-secp256k1-sign-partial-equation"

func partialEquationHash(sessionID tss.SessionID, party tss.PartyID, presignTranscriptHash, contextHash, digestHash, littleR, s, kPoint, chiPoint []byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(signPartialEquationDomain))
	wire.WriteHashPart(h, sessionID[:])
	wire.WriteHashPart(h, wire.Uint32(uint32(party)))
	wire.WriteHashPart(h, presignTranscriptHash)
	wire.WriteHashPart(h, contextHash)
	wire.WriteHashPart(h, digestHash)
	wire.WriteHashPart(h, littleR)
	wire.WriteHashPart(h, s)
	wire.WriteHashPart(h, kPoint)
	wire.WriteHashPart(h, chiPoint)
	return h.Sum(nil)
}

func presignVerifyShare(presign *Presign, party tss.PartyID) (SignVerifyShare, bool) {
	for _, vs := range presign.VerifyShares {
		if vs.Party == party {
			return vs, true
		}
	}
	return SignVerifyShare{}, false
}
