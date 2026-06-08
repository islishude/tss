package secp256k1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/islishude/tss"
	"github.com/islishude/tss/internal/bip32util"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/mta"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire"
	"github.com/islishude/tss/internal/wire/wireutil"
)

const (
	presignTranscriptHashLabel = "cggmp21-secp256k1-presign-transcript-v1"
	presignContextHashLabel    = "cggmp21-secp256k1-presign-context-v1"
	presignRound1EchoLabel     = "cggmp21-secp256k1-presign-round1-echo-v1"
	presignRound1PublicLabel   = "cggmp21-secp256k1-presign-round1-public-v1"
	signMessageDigestLabel     = "cggmp21-secp256k1-sign-message-v1"
	mtaResponseEvidenceLabel   = "cggmp21-secp256k1-mta-response-evidence-v1"
	aggregateSignEvidenceLabel = "cggmp21-secp256k1-aggregate-sign-evidence-v1"
)

// PresignContext binds a presignature to the key, chain, derivation path,
// policy, and message domain where it may be consumed. An empty DerivationPath
// is the canonical master-key path; non-empty paths are non-hardened BIP32.
type PresignContext struct {
	KeyID          string   `json:"key_id"`
	ChainID        string   `json:"chain_id"`
	DerivationPath []uint32 `json:"derivation_path"`
	PolicyDomain   string   `json:"policy_domain"`
	MessageDomain  string   `json:"message_domain"`
}

// PresignStore is an optional durable claim interface. When provided to StartSign,
// the library calls MarkConsumed with the presign's unique transcript hash before
// it constructs any outbound signing partial. If the store write fails, StartSign
// reverts the in-memory consumed flag and returns an error — the presign is not
// consumed and can be retried.
//
// A typical implementation persists the presign record with Consumed=true in an
// atomic compare-and-swap or conditional-insert operation keyed by the transcript
// hash. The transcript hash uniquely identifies one presign instance and can be
// used as an idempotency key.
type PresignStore interface {
	MarkConsumed(presignTranscriptHash []byte) error
}

// SignRequest is the context-bound online signing request for a persisted
// presignature. Message is hashed with the presign context before ECDSA.
type SignRequest struct {
	Context      PresignContext `json:"context"`
	Message      []byte         `json:"message"`
	LowS         bool           `json:"low_s"`
	PresignStore PresignStore   `json:"-"` // optional durable claim hook
}

// Presign contains one local offline signing record and must be consumed once.
type Presign struct {
	mu *sync.Mutex

	Version              uint16         `json:"version"`
	Party                tss.PartyID    `json:"party"`
	Threshold            int            `json:"threshold"`
	Signers              []tss.PartyID  `json:"signers"`
	R                    []byte         `json:"r"`
	LittleR              []byte         `json:"little_r"`
	TranscriptHash       []byte         `json:"transcript_hash"`
	Context              PresignContext `json:"context"`
	ContextHash          []byte         `json:"context_hash"`
	AdditiveShift        []byte         `json:"additive_shift"`
	PublicKey            []byte         `json:"public_key"`
	KeygenTranscriptHash []byte         `json:"keygen_transcript_hash"`
	PartiesHash          []byte         `json:"parties_hash"`
	Consumed             bool           `json:"consumed"`

	kShare   *secret.Scalar
	chiShare *secret.Scalar
	delta    *secret.Scalar
}

// MarshalJSON rejects default JSON encoding of secret-bearing presign records.
func (p Presign) MarshalJSON() ([]byte, error) {
	return nil, errors.New("cggmp21 secp256k1 presign contains secret material; use MarshalBinary")
}

// Destroy marks the presign consumed and clears its local secret shares.
func (p *Presign) Destroy() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.Consumed = true
	p.mu.Unlock()
	p.kShare.Destroy()
	p.chiShare.Destroy()
	p.delta.Destroy()
	clear(p.AdditiveShift)
}

// PresignSession tracks the CGGMP21-style offline presign exchange.
type PresignSession struct {
	key           *KeyShare
	sessionID     tss.SessionID
	config        tss.ThresholdConfig
	log           tss.Logger
	signers       []tss.PartyID
	context       PresignContext
	contextHash   []byte
	additiveShift []byte
	paillier      *pai.PrivateKey

	kShare    *secret.Scalar
	gamma     *secret.Scalar
	xBar      *secret.Scalar
	gammaComm []byte
	xBarComm  []byte

	round1               map[tss.PartyID]presignRound1Payload
	round1Proofs         map[tss.PartyID]presignRound1ProofPayload
	round1ProofEnvelopes map[tss.PartyID]tss.Envelope
	round1Verified       map[tss.PartyID]bool
	round2               map[tss.PartyID]presignRound2Payload
	deltas               map[tss.PartyID]*big.Int
	startOpening         *mta.StartOpening

	alphaDelta map[tss.PartyID]*big.Int
	betaDelta  map[tss.PartyID]*big.Int
	alphaSigma map[tss.PartyID]*big.Int
	betaSigma  map[tss.PartyID]*big.Int

	round2Sent bool
	round3Sent bool
	completed  bool
	aborted    bool
	presign    *Presign
}

// SignSession tracks the online threshold ECDSA signing exchange.
type SignSession struct {
	key       *KeyShare
	presign   *Presign
	sessionID tss.SessionID
	log       tss.Logger
	digest    []byte
	lowS      bool
	publicKey []byte
	partials  map[tss.PartyID]*big.Int
	completed bool
	aborted   bool
	signature *Signature
}

type presignRound1Payload struct {
	Gamma             []byte `json:"gamma"`
	EncK              []byte `json:"enc_k"`
	PaillierPublicKey []byte `json:"paillier_public_key"`
}

type presignRound1ProofPayload struct {
	PublicRound1Hash []byte `json:"public_round1_hash"`
	EncKProof        []byte `json:"enc_k_proof"`
}

type presignRound2Payload struct {
	Delta      mta.ResponseMessage `json:"delta"`
	Sigma      mta.ResponseMessage `json:"sigma"`
	Round1Echo []byte              `json:"round1_echo"`
}

type presignRound3Payload struct {
	Delta []byte `json:"delta"`
}

type signPartialPayload struct {
	S                 []byte `json:"s"`
	PresignTranscript []byte `json:"presign_transcript"`
	PresignContext    []byte `json:"presign_context"`
}

// StartPresignWithContext starts the offline CGGMP-style presign protocol for
// signers and binds the resulting presignature to ctx before nonce generation.
func StartPresignWithContext(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID, ctx PresignContext) (*PresignSession, []tss.Envelope, error) {
	if err := key.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	signers = tss.SortParties(signers)
	if len(signers) < key.Threshold {
		return nil, nil, errors.New("not enough signers")
	}
	if !tss.ContainsParty(signers, key.Party) {
		return nil, nil, errors.New("local party is not in signer set")
	}
	if err := validateSignerSet(key, signers); err != nil {
		return nil, nil, err
	}
	ctx, contextHash, additiveShift, err := preparePresignContext(key, ctx)
	if err != nil {
		return nil, nil, err
	}
	paillierKey, err := key.paillierPrivate()
	if err != nil {
		return nil, nil, err
	}
	// k_i and gamma_i are local nonce scalars. Only Enc(k_i) and Gamma_i leave
	// the process; the raw nonce scalars stay inside the local presign record.
	kShare, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	gamma, err := secp.RandomScalar(nil)
	if err != nil {
		return nil, nil, err
	}
	gammaComm, err := secp.PointBytes(secp.ScalarBaseMult(gamma))
	if err != nil {
		return nil, nil, err
	}
	lambda, err := shamir.LagrangeCoefficient(key.Party, signers, secp.Order())
	if err != nil {
		return nil, nil, err
	}
	secret, err := key.secretBig()
	if err != nil {
		return nil, nil, err
	}
	// xBar is lambda_i*x_i, the signer-set-adjusted secret share used in
	// chi = k*x. The public commitment is derived from the verification share.
	xBar := new(big.Int).Mul(lambda, secret)
	xBar.Mod(xBar, secp.Order())
	kShareSecret, err := newSecpSecretScalar(kShare.Bytes())
	if err != nil {
		return nil, nil, err
	}
	gammaSecret, err := newSecpSecretScalar(gamma.Bytes())
	if err != nil {
		return nil, nil, err
	}
	xBarSecret, err := secpSecretScalarFromBig(xBar)
	if err != nil {
		return nil, nil, err
	}
	localVerificationShare, ok := key.verificationShare(key.Party)
	if !ok {
		return nil, nil, errors.New("missing local verification share")
	}
	localVerificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, nil, err
	}
	xBarComm, err := secp.PointBytes(secp.ScalarMult(localVerificationPoint, secp.ScalarFromBigInt(lambda)))
	if err != nil {
		return nil, nil, err
	}
	config := tss.ThresholdConfig{Threshold: key.Threshold, Parties: signers, Self: key.Party, SessionID: sessionID}
	// Round 1 publishes Enc_i(k_i); each peer receives a verifier-specific
	// Πenc proof bound to that public payload and the peer's RP parameters.
	startOpening, err := mta.Start(config.Reader(), kShare.BigInt(), &paillierKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	openingReturned := false
	defer func() {
		if !openingReturned {
			startOpening.Destroy()
		}
	}()
	presignPayload := presignRound1Payload{
		Gamma:             gammaComm,
		EncK:              startOpening.Message.Ciphertext,
		PaillierPublicKey: slices.Clone(key.PaillierPublicKey),
	}
	payload, err := marshalPresignRound1Payload(presignPayload)
	if err != nil {
		return nil, nil, err
	}
	publicHash, err := presignRound1PublicHash(presignPayload)
	if err != nil {
		return nil, nil, err
	}
	env := envelope(config, 1, key.Party, 0, payloadPresignRound1, payload, false)
	s := &PresignSession{
		key:                  key,
		sessionID:            sessionID,
		config:               config,
		log:                  config.Logger(),
		signers:              signers,
		context:              ctx,
		contextHash:          contextHash,
		additiveShift:        additiveShift,
		paillier:             paillierKey,
		kShare:               kShareSecret,
		gamma:                gammaSecret,
		xBar:                 xBarSecret,
		gammaComm:            gammaComm,
		xBarComm:             xBarComm,
		round1:               map[tss.PartyID]presignRound1Payload{key.Party: presignPayload},
		round1Proofs:         make(map[tss.PartyID]presignRound1ProofPayload),
		round1ProofEnvelopes: make(map[tss.PartyID]tss.Envelope),
		round1Verified:       map[tss.PartyID]bool{key.Party: true},
		round2:               make(map[tss.PartyID]presignRound2Payload),
		deltas:               make(map[tss.PartyID]*big.Int),
		alphaDelta:           make(map[tss.PartyID]*big.Int),
		betaDelta:            make(map[tss.PartyID]*big.Int),
		alphaSigma:           make(map[tss.PartyID]*big.Int),
		betaSigma:            make(map[tss.PartyID]*big.Int),
		startOpening:         startOpening,
	}
	out := []tss.Envelope{env}
	for _, peer := range signers {
		if peer == key.Party {
			continue
		}
		peerRP, err := key.ringPedersenPublicFor(peer)
		if err != nil {
			return nil, nil, err
		}
		proofDomain := mtaStartProofDomain(key, sessionID, signers, key.Party, peer, key.PaillierPublicKey, contextHash)
		proofBytes, err := mta.ProveStartForVerifier(config.Reader(), proofDomain, startOpening, &paillierKey.PublicKey, peerRP)
		if err != nil {
			return nil, nil, err
		}
		proofPayload, err := marshalPresignRound1ProofPayload(presignRound1ProofPayload{
			PublicRound1Hash: publicHash,
			EncKProof:        proofBytes,
		})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, key.Party, peer, payloadPresignRound1Proof, proofPayload, true))
	}
	round2, err := s.tryEmitRound2()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round2...)
	round3, err := s.tryEmitRound3()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, round3...)
	openingReturned = true
	return s, out, nil
}

// HandlePresignMessage validates and applies one presign envelope.
func (s *PresignSession) HandlePresignMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil presign session")
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
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	switch env.PayloadType {
	case payloadPresignRound1:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round1 payload in wrong round"))
		}
		if env.To != 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("presign round1 public payload must be broadcast"))
		}
		if env.ConfidentialRequired {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("presign round1 public payload must not require confidential transport"))
		}
		if _, ok := s.round1[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round1"))
		}
		p, err := unmarshalPresignRound1Payload(env.Payload)
		if err != nil {
			fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound1,
				"malformed presign round1 payload",
				[]tss.PartyID{env.From},
				err,
				fields...,
			)
		}
		if err := s.validateRound1Public(env.From, p); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPresignRound1,
				"invalid presign round1 public payload",
				[]tss.PartyID{env.From},
				err,
				s.presignRound1EvidenceFields(env.From, p)...,
			)
		}
		s.round1[env.From] = p
		if err := s.maybeValidateRound1Proof(env.From); err != nil {
			proofEnv := s.round1ProofEnvelopes[env.From]
			return nil, verificationErrorWithEvidence(
				proofEnv,
				tss.EvidenceKindPresignRound1,
				"invalid presign round1 proof",
				[]tss.PartyID{env.From},
				err,
				s.presignRound1ProofEvidenceFields(env.From, p, s.round1Proofs[env.From])...,
			)
		}
		return s.tryEmitRound2()
	case payloadPresignRound1Proof:
		if env.Round != 1 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round1 proof payload in wrong round"))
		}
		if env.From == s.key.Party {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("self presign round1 proof is not expected"))
		}
		if err := requireDirectConfidential(env, s.key.Party, payloadPresignRound1Proof); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, ok := s.round1Proofs[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round1 proof"))
		}
		p, err := unmarshalPresignRound1ProofPayload(env.Payload)
		if err != nil {
			fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound1,
				"malformed presign round1 proof payload",
				[]tss.PartyID{env.From},
				err,
				fields...,
			)
		}
		s.round1Proofs[env.From] = p
		s.round1ProofEnvelopes[env.From] = env
		if err := s.maybeValidateRound1Proof(env.From); err != nil {
			public := s.round1[env.From]
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPresignRound1,
				"invalid presign round1 proof",
				[]tss.PartyID{env.From},
				err,
				s.presignRound1ProofEvidenceFields(env.From, public, p)...,
			)
		}
		return s.tryEmitRound2()
	case payloadPresignRound2:
		if env.Round != 2 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round2 payload in wrong round"))
		}
		if _, ok := s.round2[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate presign round2"))
		}
		p, err := unmarshalPresignRound2Payload(env.Payload)
		if err != nil {
			fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound2,
				"malformed presign round2 payload",
				[]tss.PartyID{env.From},
				err,
				fields...,
			)
		}
		if err := s.finishRound2(env.From, p); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindPresignRound2,
				"invalid presign round2 proof",
				[]tss.PartyID{env.From},
				err,
				s.presignRound2EvidenceFields(p)...,
			)
		}
		s.round2[env.From] = p
		return s.tryEmitRound3()
	case payloadPresignRound3:
		if env.Round != 3 {
			return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("round3 payload in wrong round"))
		}
		if _, ok := s.deltas[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate delta share"))
		}
		p, err := unmarshalPresignRound3Payload(env.Payload)
		if err != nil {
			fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound3,
				"malformed presign round3 payload",
				[]tss.PartyID{env.From},
				err,
				fields...,
			)
		}
		delta, err := secp.ScalarFromBytes(p.Delta)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindPresignRound3,
				"malformed presign delta",
				[]tss.PartyID{env.From},
				err,
				s.presignRound3EvidenceFields(p)...,
			)
		}
		s.deltas[env.From] = delta.BigInt()
		return nil, s.tryComplete()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
}

// Presign returns a deep copy of the completed local presign record.
func (s *PresignSession) Presign() (*Presign, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.presign.Clone(), true
}

func (s *PresignSession) presignRound1EvidenceFields(from tss.PartyID, p presignRound1Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	publicHash, _ := presignRound1PublicHash(p)
	fields = append(fields,
		hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		rawEvidenceField("round1_public_hash", publicHash),
		hashEvidenceField("gamma_hash", p.Gamma),
		hashEvidenceField("enc_k_hash", p.EncK),
	)
	if expected, err := s.key.paillierPublicFor(from); err == nil {
		if encoded, err := expected.MarshalBinary(); err == nil {
			fields = append(fields, hashEvidenceField(evidenceFieldExpectedPaillierKeyHash, encoded))
		}
	}
	return fields
}

func (s *PresignSession) presignRound1ProofEvidenceFields(from tss.PartyID, public presignRound1Payload, proof presignRound1ProofPayload) []tss.EvidenceField {
	fields := s.presignRound1EvidenceFields(from, public)
	return append(fields,
		rawEvidenceField("proof_public_round1_hash", proof.PublicRound1Hash),
		hashEvidenceField("enc_k_proof_hash", proof.EncKProof),
	)
}

func (s *PresignSession) presignRound2EvidenceFields(p presignRound2Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields,
		rawEvidenceField(evidenceFieldDeltaResponseHash, mtaResponseHash("delta", p.Delta)),
		rawEvidenceField(evidenceFieldSigmaResponseHash, mtaResponseHash("sigma", p.Sigma)),
		hashEvidenceField("round1_echo_hash", p.Round1Echo),
	)
}

func (s *PresignSession) presignRound3EvidenceFields(p presignRound3Payload) []tss.EvidenceField {
	fields := append(keyContextEvidenceFields(s.key), signerEvidenceFields(s.signers)...)
	return append(fields, hashEvidenceField("delta_hash", p.Delta))
}

func (s *PresignSession) validateRound1Public(from tss.PartyID, p presignRound1Payload) error {
	if _, err := secp.PointFromBytes(p.Gamma); err != nil {
		return fmt.Errorf("invalid gamma: %w", err)
	}
	expectedPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	expectedPKBytes, err := expectedPK.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedPKBytes, p.PaillierPublicKey) {
		return errors.New("round1 Paillier public key does not match keygen")
	}
	ciphertext := new(big.Int).SetBytes(p.EncK)
	if err := expectedPK.ValidateCiphertext(ciphertext); err != nil {
		return fmt.Errorf("invalid encrypted nonce ciphertext: %w", err)
	}
	return nil
}

func (s *PresignSession) maybeValidateRound1Proof(from tss.PartyID) error {
	if from == s.key.Party {
		s.round1Verified[from] = true
		return nil
	}
	if s.round1Verified[from] {
		return nil
	}
	public, havePublic := s.round1[from]
	proof, haveProof := s.round1Proofs[from]
	if !havePublic || !haveProof {
		return nil
	}
	if err := s.validateRound1Proof(from, public, proof); err != nil {
		return err
	}
	s.round1Verified[from] = true
	return nil
}

func (s *PresignSession) validateRound1Proof(from tss.PartyID, public presignRound1Payload, proof presignRound1ProofPayload) error {
	publicHash, err := presignRound1PublicHash(public)
	if err != nil {
		return err
	}
	if !bytes.Equal(publicHash, proof.PublicRound1Hash) {
		return errors.New("presign round1 proof public hash mismatch")
	}
	proverPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.Party)
	if err != nil {
		return err
	}
	start := mta.StartMessage{Ciphertext: public.EncK}
	domain := mtaStartProofDomain(s.key, s.sessionID, s.signers, from, s.key.Party, public.PaillierPublicKey, s.contextHash)
	return mta.VerifyStart(domain, start, proverPK, localRP, proof.EncKProof)
}

func (s *PresignSession) tryEmitRound2() ([]tss.Envelope, error) {
	if s.round2Sent || len(s.round1) != len(s.signers) {
		return nil, nil
	}
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		if !s.round1Verified[peer] {
			return nil, nil
		}
	}
	out := make([]tss.Envelope, 0, len(s.signers)-1)
	selfPK, err := s.key.paillierPublic()
	if err != nil {
		return nil, err
	}
	localRP, err := s.key.ringPedersenPublicFor(s.key.Party)
	if err != nil {
		return nil, err
	}
	gamma, err := secpSecretBig(s.gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gamma)
	xBar, err := secpSecretBig(s.xBar)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(xBar)
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		peerPK, err := s.key.paillierPublicFor(peer)
		if err != nil {
			return nil, err
		}
		peerRP, err := s.key.ringPedersenPublicFor(peer)
		if err != nil {
			return nil, err
		}
		start := mta.StartMessage{Ciphertext: s.round1[peer].EncK}
		startProofDomain := mtaStartProofDomain(s.key, s.sessionID, s.signers, peer, s.key.Party, s.round1[peer].PaillierPublicKey, s.contextHash)
		startProof := s.round1Proofs[peer].EncKProof
		// The delta MtA instance creates additive shares of k_i*gamma_j.
		deltaResp, betaDelta, err := mta.Respond(
			nil,
			startProofDomain,
			mtaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.Party, "delta", s.round1[peer].PaillierPublicKey, s.contextHash),
			start,
			startProof,
			gamma,
			s.gammaComm,
			peerPK,
			selfPK,
			localRP,
			peerRP,
		)
		if err != nil {
			return nil, err
		}
		// The sigma MtA instance creates additive shares of k_i*x_j, where x_j
		// is already adjusted by the signer-set Lagrange coefficient.
		sigmaResp, betaSigma, err := mta.Respond(
			nil,
			startProofDomain,
			mtaResponseDomain(s.key, s.sessionID, s.signers, peer, s.key.Party, "sigma", s.round1[peer].PaillierPublicKey, s.contextHash),
			start,
			startProof,
			xBar,
			s.xBarComm,
			peerPK,
			selfPK,
			localRP,
			peerRP,
		)
		if err != nil {
			return nil, err
		}
		s.betaDelta[peer] = betaDelta
		s.betaSigma[peer] = betaSigma
		payload, err := marshalPresignRound2Payload(presignRound2Payload{Delta: *deltaResp, Sigma: *sigmaResp, Round1Echo: s.round1Echo()})
		if err != nil {
			return nil, err
		}
		out = append(out, envelope(s.config, 2, s.key.Party, peer, payloadPresignRound2, payload, true))
	}
	s.round2Sent = true
	return out, nil
}

func (s *PresignSession) finishRound2(from tss.PartyID, p presignRound2Payload) error {
	if !bytes.Equal(p.Round1Echo, s.round1Echo()) {
		return errors.New("presign round1 echo mismatch")
	}
	start := mta.StartMessage{Ciphertext: s.round1[s.key.Party].EncK}
	gammaCommit := s.round1[from].Gamma

	// Responder's Paillier public key (for verifying the Y commitment in Πaff-g).
	responderPK, err := s.key.paillierPublicFor(from)
	if err != nil {
		return err
	}
	// Initiator's own Ring-Pedersen params (the verifier's auxiliary input).
	selfRP, err := s.key.ringPedersenPublicFor(s.key.Party)
	if err != nil {
		return err
	}

	alphaDelta, err := mta.Finish(
		mtaResponseDomain(s.key, s.sessionID, s.signers, s.key.Party, from, "delta", s.key.PaillierPublicKey, s.contextHash),
		start,
		p.Delta,
		gammaCommit,
		s.paillier,
		responderPK,
		selfRP,
	)
	if err != nil {
		return err
	}
	xBarCommit, err := s.xBarCommitment(from)
	if err != nil {
		return err
	}
	alphaSigma, err := mta.Finish(
		mtaResponseDomain(s.key, s.sessionID, s.signers, s.key.Party, from, "sigma", s.key.PaillierPublicKey, s.contextHash),
		start,
		p.Sigma,
		xBarCommit,
		s.paillier,
		responderPK,
		selfRP,
	)
	if err != nil {
		return err
	}
	s.alphaDelta[from] = alphaDelta
	s.alphaSigma[from] = alphaSigma
	return nil
}

func (s *PresignSession) tryEmitRound3() ([]tss.Envelope, error) {
	if s.round3Sent || len(s.round2) != len(s.signers)-1 {
		return nil, nil
	}
	kShare, err := secpSecretBig(s.kShare)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(kShare)
	gamma, err := secpSecretBig(s.gamma)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(gamma)
	xBar, err := secpSecretBig(s.xBar)
	if err != nil {
		return nil, err
	}
	defer secret.ClearBigInt(xBar)
	deltaShare := new(big.Int).Mul(kShare, gamma)
	chiShare := new(big.Int).Mul(kShare, xBar)
	order := secp.Order()
	for _, peer := range s.signers {
		if peer == s.key.Party {
			continue
		}
		// delta_i = k_i*gamma_i + sum_j alpha_ij + sum_j beta_ji.
		deltaShare.Add(deltaShare, s.alphaDelta[peer])
		deltaShare.Add(deltaShare, s.betaDelta[peer])
		// chi_i = k_i*x_i + sum_j alphaHat_ij + sum_j betaHat_ji.
		chiShare.Add(chiShare, s.alphaSigma[peer])
		chiShare.Add(chiShare, s.betaSigma[peer])
	}
	deltaShare.Mod(deltaShare, order)
	chiShare.Mod(chiShare, order)
	if len(s.additiveShift) > 0 {
		shift, err := secp.ScalarFromBytes(s.additiveShift)
		if err != nil {
			return nil, err
		}
		shiftTerm := new(big.Int).Mul(kShare, shift.BigInt())
		chiShare.Add(chiShare, shiftTerm)
		chiShare.Mod(chiShare, order)
	}
	s.deltas[s.key.Party] = deltaShare
	payload, err := marshalPresignRound3Payload(presignRound3Payload{Delta: scalarBytes(deltaShare)})
	if err != nil {
		return nil, err
	}
	s.round3Sent = true
	s.presign = &Presign{
		mu:                   &sync.Mutex{},
		Version:              tss.Version,
		Party:                s.key.Party,
		Threshold:            s.key.Threshold,
		Signers:              append([]tss.PartyID(nil), s.signers...),
		Context:              s.context,
		ContextHash:          append([]byte(nil), s.contextHash...),
		AdditiveShift:        append([]byte(nil), s.additiveShift...),
		PublicKey:            append([]byte(nil), s.key.PublicKey...),
		KeygenTranscriptHash: append([]byte(nil), s.key.KeygenTranscriptHash...),
		PartiesHash:          wireutil.PartySetHash(s.key.Parties, partySetHashLabel),
		kShare:               s.kShare.Clone(),
	}
	s.presign.chiShare, err = secpSecretScalarFromBig(chiShare)
	if err != nil {
		return nil, err
	}
	if err := s.tryComplete(); err != nil {
		return nil, err
	}
	return []tss.Envelope{envelope(s.config, 3, s.key.Party, 0, payloadPresignRound3, payload, false)}, nil
}

func (s *PresignSession) tryComplete() error {
	if s.completed || len(s.deltas) != len(s.signers) {
		return nil
	}
	order := secp.Order()
	delta := new(big.Int)
	gammaPoints := make([]*secp.Point, 0, len(s.signers))
	for _, id := range s.signers {
		delta.Add(delta, s.deltas[id])
		delta.Mod(delta, order)
		gammaPoint, err := secp.PointFromBytes(s.round1[id].Gamma)
		if err != nil {
			return err
		}
		gammaPoints = append(gammaPoints, gammaPoint)
	}
	if delta.Sign() == 0 {
		return errors.New("zero presign delta")
	}
	deltaInv := new(big.Int).ModInverse(delta, order)
	if deltaInv == nil {
		return errors.New("non-invertible presign delta")
	}
	gamma := secp.AddPoints(gammaPoints...)
	RPoint := secp.ScalarMult(gamma, secp.ScalarFromBigInt(deltaInv))
	R, err := secp.PointBytes(RPoint)
	if err != nil {
		return err
	}
	littleR := new(big.Int).Mod(RPoint.X.BigInt(), order)
	if littleR.Sign() == 0 {
		return errors.New("zero ECDSA r")
	}
	if s.presign == nil {
		return errors.New("local presign shares not computed")
	}
	// R = delta^{-1} * Gamma, with Gamma=sum_i Gamma_i. LittleR is the ECDSA r.
	s.presign.R = R
	s.presign.LittleR = scalarBytes(littleR)
	s.presign.delta, err = secpSecretScalarFromBig(delta)
	if err != nil {
		return err
	}
	s.presign.TranscriptHash = s.presignTranscriptHash(R, littleR, delta)
	s.completed = true
	s.log.Info(s.config.Ctx(), "presign complete",
		"party_id", s.key.Party,
		"session_id", fmt.Sprintf("%x", s.sessionID[:8]),
	)
	return nil
}

func (s *PresignSession) xBarCommitment(id tss.PartyID) ([]byte, error) {
	verificationShare, ok := s.key.verificationShare(id)
	if !ok {
		return nil, fmt.Errorf("missing verification share for %d", id)
	}
	point, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return nil, err
	}
	lambda, err := shamir.LagrangeCoefficient(id, s.signers, secp.Order())
	if err != nil {
		return nil, err
	}
	return secp.PointBytes(secp.ScalarMult(point, secp.ScalarFromBigInt(lambda)))
}

func (s *PresignSession) presignTranscriptHash(R []byte, littleR, delta *big.Int) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignTranscriptHashLabel))
	wire.WriteHashPart(h, s.sessionID[:])
	wire.WriteHashPart(h, s.contextHash)
	wire.WriteHashPart(h, s.additiveShift)
	wire.WriteHashPart(h, s.key.PublicKey)
	wire.WriteHashPart(h, s.key.KeygenTranscriptHash)
	wire.WriteHashPart(h, wireutil.PartySetHash(s.key.Parties, partySetHashLabel))
	for _, id := range s.signers {
		// Binding every signer id, nonce commitment, encrypted nonce, and delta
		// share prevents replaying presign material across signer sets.
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		wire.WriteHashPart(h, s.round1[id].Gamma)
		wire.WriteHashPart(h, s.round1[id].EncK)
		wire.WriteHashPart(h, scalarBytes(s.deltas[id]))
	}
	wire.WriteHashPart(h, R)
	wire.WriteHashPart(h, scalarBytes(littleR))
	wire.WriteHashPart(h, scalarBytes(delta))
	return h.Sum(nil)
}

func (s *PresignSession) round1Echo() []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignRound1EchoLabel))
	wire.WriteHashPart(h, s.sessionID[:])
	wire.WriteHashPart(h, s.contextHash)
	wire.WriteHashPart(h, s.additiveShift)
	for _, id := range s.signers {
		p := s.round1[id]
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		wire.WriteHashPart(h, p.Gamma)
		wire.WriteHashPart(h, p.EncK)
		wire.WriteHashPart(h, p.PaillierPublicKey)
	}
	return h.Sum(nil)
}

func presignRound1PublicHash(p presignRound1Payload) ([]byte, error) {
	payload, err := marshalPresignRound1Payload(p)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignRound1PublicLabel))
	wire.WriteHashPart(h, payload)
	return h.Sum(nil), nil
}

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
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, []tss.Envelope{env}, nil
}

// HandleSignMessage validates and applies one online signing envelope.
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
	s.partials[env.From] = partial.BigInt()
	return nil, s.tryComplete()
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

func (s *SignSession) tryComplete() error {
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

// Sign runs an in-memory presign and signing exchange for a context-bound message.
func Sign(message []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	return signWithDigest(message, signers, ctx, false)
}

// SignDigestInteractive runs a full interactive signing exchange for a raw
// digest after binding ctx before nonce generation. It does not return or
// persist a reusable Presign.
func SignDigestInteractive(digest32 []byte, signers []*KeyShare, ctx PresignContext) ([]byte, *Signature, error) {
	if len(digest32) != sha256.Size {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	return signWithDigest(digest32, signers, ctx, true)
}

func signWithDigest(input []byte, signers []*KeyShare, ctx PresignContext, rawDigest bool) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.requireMPCMaterial(); err != nil {
			return nil, nil, err
		}
		ids[i] = share.Party
		shares[share.Party] = share
	}
	ids = tss.SortParties(ids)
	presignID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	presignSessions := make(map[tss.PartyID]*PresignSession, len(ids))
	presignQueue := make([]tss.Envelope, 0)
	for _, id := range ids {
		session, out, err := StartPresignWithContext(shares[id], presignID, ids, ctx)
		if err != nil {
			return nil, nil, err
		}
		presignSessions[id] = session
		presignQueue = append(presignQueue, out...)
	}
	for len(presignQueue) > 0 {
		env := presignQueue[0]
		presignQueue = presignQueue[1:]
		for _, id := range ids {
			if id == env.From || (env.To != 0 && env.To != id) {
				continue
			}
			out, err := presignSessions[id].HandlePresignMessage(env)
			if err != nil {
				return nil, nil, err
			}
			presignQueue = append(presignQueue, out...)
		}
	}
	signID, err := tss.NewSessionID(nil)
	if err != nil {
		return nil, nil, err
	}
	signSessions := make(map[tss.PartyID]*SignSession, len(ids))
	signMessages := make([]tss.Envelope, 0, len(ids))
	for _, id := range ids {
		presign, ok := presignSessions[id].Presign()
		if !ok {
			return nil, nil, fmt.Errorf("presign not completed for %d", id)
		}
		var session *SignSession
		var out []tss.Envelope
		var err error
		if rawDigest {
			session, out, err = startSignDigestBound(shares[id], presign, signID, input, presign.ContextHash, true, nil)
		} else {
			session, out, err = StartSign(shares[id], presign, signID, SignRequest{
				Context: ctx,
				Message: input,
				LowS:    true,
			})
		}
		if err != nil {
			return nil, nil, err
		}
		signSessions[id] = session
		signMessages = append(signMessages, out...)
	}
	for _, env := range signMessages {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if _, err := signSessions[id].HandleSignMessage(env); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, id := range ids {
		if sig, ok := signSessions[id].Signature(); ok {
			return append([]byte(nil), signSessions[id].publicKey...), sig, nil
		}
	}
	return nil, nil, errors.New("signature not completed")
}

func validatePresignContext(ctx PresignContext) error {
	if ctx.KeyID == "" {
		return errors.New("presign context key id is required")
	}
	if ctx.ChainID == "" {
		return errors.New("presign context chain id is required")
	}
	if ctx.PolicyDomain == "" {
		return errors.New("presign context policy domain is required")
	}
	if ctx.MessageDomain == "" {
		return errors.New("presign context message domain is required")
	}
	for _, index := range ctx.DerivationPath {
		if index >= bip32util.HardenedKeyStart {
			return fmt.Errorf("hardened derivation index %d is not supported", index)
		}
	}
	return nil
}

func preparePresignContext(key *KeyShare, ctx PresignContext) (PresignContext, []byte, []byte, error) {
	if err := validatePresignContext(ctx); err != nil {
		return PresignContext{}, nil, nil, err
	}
	ctx.DerivationPath = append([]uint32(nil), ctx.DerivationPath...)
	var additiveShift []byte
	if len(ctx.DerivationPath) > 0 {
		result, err := DeriveNonHardenedBIP32Extended(key.PublicKey, key.ChainCode, ctx.DerivationPath)
		if err != nil {
			return PresignContext{}, nil, nil, err
		}
		additiveShift = result.AdditiveShift
	}
	return ctx, presignContextHash(ctx), additiveShift, nil
}

func presignContextHash(ctx PresignContext) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(presignContextHashLabel))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, []byte("secp256k1"))
	wire.WriteHashPart(h, []byte(ctx.KeyID))
	wire.WriteHashPart(h, []byte(ctx.ChainID))
	wire.WriteHashPart(h, wire.EncodeUint32List(ctx.DerivationPath))
	wire.WriteHashPart(h, []byte(ctx.PolicyDomain))
	wire.WriteHashPart(h, []byte(ctx.MessageDomain))
	return h.Sum(nil)
}

func signMessageDigest(contextHash []byte, messageDomain string, message []byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(signMessageDigestLabel))
	wire.WriteHashPart(h, []byte(protocol))
	wire.WriteHashPart(h, wire.Uint32(uint32(tss.Version)))
	wire.WriteHashPart(h, []byte("secp256k1"))
	wire.WriteHashPart(h, contextHash)
	wire.WriteHashPart(h, []byte(messageDomain))
	wire.WriteHashPart(h, message)
	return h.Sum(nil)
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

func mtaResponseHash(label string, response mta.ResponseMessage) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(mtaResponseEvidenceLabel))
	wire.WriteHashPart(h, []byte(label))
	wire.WriteHashPart(h, response.Ciphertext)
	wire.WriteHashPart(h, response.Proof)
	return h.Sum(nil)
}

func aggregateEvidencePayload(digest, r, sValue, transcript []byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(aggregateSignEvidenceLabel))
	wire.WriteHashPart(h, digest)
	wire.WriteHashPart(h, r)
	wire.WriteHashPart(h, sValue)
	wire.WriteHashPart(h, transcript)
	return h.Sum(nil)
}
