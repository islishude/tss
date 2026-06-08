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
	if len(digest32) != 32 {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	if len(contextHash) != sha256.Size || !bytes.Equal(contextHash, presign.ContextHash) {
		return nil, nil, errors.New("presign context mismatch")
	}
	if !claimPresignForSigning(presign) {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 1, key.Party, errors.New("presign already consumed"))
	}
	// Durable claim: if the caller provided a store, persist Consumed=true before
	// we construct any outbound partial. If persistence fails, revert the in-memory
	// flag so the presign can be retried.
	if store != nil {
		if err := store.MarkConsumed(slices.Clone(presign.TranscriptHash)); err != nil {
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
	payload, err := marshalSignPartialPayload(signPartialPayload{
		S:                 scalarBytes(partial),
		PresignTranscript: append([]byte(nil), presign.TranscriptHash...),
		PresignContext:    append([]byte(nil), contextHash...),
	})
	if err != nil {
		return nil, nil, err
	}
	env := tss.Envelope{
		Protocol:    protocol,
		Version:     tss.Version,
		SessionID:   sessionID,
		Round:       1,
		From:        key.Party,
		PayloadType: payloadSignPartial,
		Payload:     payload,
	}.WithTranscriptHash()
	s := &SignSession{
		key:       key,
		presign:   presign,
		sessionID: sessionID,
		log:       tss.NopLogger(),
		digest:    append([]byte(nil), digest32...),
		lowS:      lowS,
		publicKey: verifyKey,
		partials:  map[tss.PartyID]*big.Int{key.Party: partial},
	}
	if err := s.tryCompleteSign(); err != nil {
		return nil, nil, err
	}
	return s, []tss.Envelope{env}, nil
}

// HandleSignMessage validates and applies one online signing envelope.
//
// Template: parse → policy validate → cryptographic verify → mutate state → emit.
func (s *SignSession) HandleSignMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	if s.completed {
		return nil, completedSessionError(env.Round, env.From)
	}
	if s.aborted {
		return nil, abortedSessionError(env.Round, env.From)
	}
	defer func() {
		if shouldAbortSession(err) {
			s.aborted = true
		}
	}()
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.presign.Signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
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
		fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"malformed sign partial payload",
			[]tss.PartyID{env.From},
			err,
			fields...,
		)
	}

	// ---- 3. CRYPTOGRAPHIC VERIFY ----
	if !bytes.Equal(p.PresignTranscript, s.presign.TranscriptHash) {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"presign transcript mismatch",
			[]tss.PartyID{env.From},
			errors.New("presign transcript mismatch"),
			s.signPartialEvidenceFields(p)...,
		)
	}
	if !bytes.Equal(p.PresignContext, s.presign.ContextHash) {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"presign context mismatch",
			[]tss.PartyID{env.From},
			errors.New("presign context mismatch"),
			s.signPartialEvidenceFields(p)...,
		)
	}
	partial, err := secp.ScalarFromBytes(p.S)
	if err != nil {
		return nil, protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindSignPartial,
			"malformed sign partial",
			[]tss.PartyID{env.From},
			err,
			s.signPartialEvidenceFields(p)...,
		)
	}

	// ---- 4. MUTATE STATE ----
	s.partials[env.From] = partial.BigInt()

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

func (s *SignSession) signPartialEvidenceFields(p signPartialPayload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
	return append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.TranscriptHash),
		hashEvidenceField("observed_presign_transcript_hash", p.PresignTranscript),
		rawEvidenceField("presign_context_hash", s.presign.ContextHash),
		hashEvidenceField("observed_presign_context_hash", p.PresignContext),
		hashEvidenceField("sign_partial_hash", p.S),
	)
}

func (s *SignSession) aggregateEvidenceFields(r, sigS *big.Int) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.presign.Signers)...)
	fields = append(fields,
		rawEvidenceField(evidenceFieldPresignTranscriptHash, s.presign.TranscriptHash),
		hashEvidenceField(evidenceFieldDigestHash, s.digest),
		hashEvidenceField(evidenceFieldRHash, secp.ScalarFromBigInt(r).Bytes()),
		hashEvidenceField(evidenceFieldSHash, secp.ScalarFromBigInt(sigS).Bytes()),
	)
	for _, id := range s.presign.Signers {
		fields = append(fields, hashEvidenceField(fmt.Sprintf("sign_partial_%d_hash", id), secp.ScalarFromBigInt(s.partials[id]).Bytes()))
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
		env := tss.Envelope{
			Protocol:    protocol,
			Version:     tss.Version,
			SessionID:   s.sessionID,
			Round:       1,
			PayloadType: payloadSignPartial,
			Payload:     aggregateEvidencePayload(s.digest, r.Bytes(), secp.ScalarFromBigInt(sigS).Bytes(), s.presign.TranscriptHash),
		}.WithTranscriptHash()
		return &tss.ProtocolError{
			Code:  tss.ErrCodeVerification,
			Round: 1,
			Blame: &tss.Blame{
				Reason:  "aggregated ECDSA signature failed verification",
				Parties: append([]tss.PartyID(nil), s.presign.Signers...),
				Evidence: marshalEvidence(
					env,
					tss.EvidenceKindAggregateSign,
					"aggregated ECDSA signature failed verification",
					s.aggregateEvidenceFields(r.BigInt(), sigS)...,
				),
			},
			Err: errors.New("ECDSA signature failed verification"),
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
	defer presign.mu.Unlock()
	if presign.Consumed {
		return false
	}
	// Mark consumed before constructing the outbound sign envelope so accidental
	// reuse fails before any new partial signature can leave the process.
	presign.Consumed = true
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

func validateSignerSet(key *KeyShare, signers []tss.PartyID) error {
	limits := DefaultLimits()
	return tss.ValidateSignerSet(key.Parties, key.Threshold, signers, limits)
}
