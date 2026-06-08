package secp256k1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire/wireutil"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

const (
	refreshCommitmentsHashLabel = "cggmp21-secp256k1-refresh-commitments-v1"
	refreshTranscriptHashLabel  = "cggmp21-secp256k1-refresh-transcript-v1"
)

// RefreshSession refreshes CGGMP21 key shares and rotates Paillier keys while
// preserving the group public key and chain code. The participant set and
// threshold are fixed to the original key share. Each existing participant
// generates a polynomial with zero constant term (to refresh the secret share)
// and a new Paillier keypair (to rotate encryption material).
type RefreshSession struct {
	oldKey          *KeyShare
	cfg             tss.ThresholdConfig
	log             tss.Logger
	commits         map[tss.PartyID][][]byte
	shares          map[tss.PartyID]*big.Int
	completed       bool
	aborted         bool
	guard           *tss.EnvelopeGuard
	newShare        *KeyShare
	confirmations   map[tss.PartyID][]byte
	ownPoly         []*big.Int
	newPaillier     *pai.PrivateKey
	newPaillierPubs map[tss.PartyID]PaillierPublicShare
	newPaillierPriv []byte
	newRingPedersen map[tss.PartyID]RingPedersenPublicShare
}

// StartRefresh starts CGGMP21 key-share refresh with Paillier key rotation.
// The participant set and threshold are fixed to oldKey.Parties and
// oldKey.Threshold. The group public key and chain code are preserved from the
// original key share.
func StartRefresh(oldKey *KeyShare, config tss.ThresholdConfig) (*RefreshSession, []tss.Envelope, error) {
	if err := oldKey.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	if config.Self != oldKey.Party {
		return nil, nil, errors.New("config.Self must match the old key's party ID")
	}
	if config.Threshold != oldKey.Threshold {
		return nil, nil, ErrUnsupportedRefreshThresholdChange
	}
	config.Parties = append([]tss.PartyID(nil), oldKey.Parties...)
	if err := config.ValidateWithLimits(DefaultLimits()); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	// Generate a new Paillier keypair for key rotation.
	newPaillierKey, err := pai.GenerateKey(config.Ctx(), config.Reader(), defaultPaillierBits())
	if err != nil {
		return nil, nil, err
	}
	newPaillierPubBytes, err := newPaillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	newPaillierPriv, err := newPaillierKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	modProof, err := zkpai.ProveModulus(config.Reader(), refreshPaillierDomain(config, config.Self, newPaillierPubBytes), newPaillierKey, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(config.Reader(), newPaillierKey)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenParamsBytes, err := zkpai.MarshalRingPedersenParams(ringPedersenParams)
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(config.Reader(), refreshRingPedersenDomain(config, config.Self, ringPedersenParamsBytes), newPaillierKey, ringPedersenParams, ringPedersenLambda, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	ringPedersenProofBytes, err := zkpai.Marshal(ringPedersenProof)
	if err != nil {
		return nil, nil, err
	}
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, big.NewInt(0))
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.Sign() == 0 {
			commitments[i] = nil
			continue
		}
		enc, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff)))
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &RefreshSession{
		oldKey:          oldKey,
		cfg:             config,
		log:             config.Logger(),
		commits:         map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:          map[tss.PartyID]*big.Int{oldKey.Party: shamir.Eval(poly, oldKey.Party, secp.Order())},
		confirmations:   make(map[tss.PartyID][]byte, len(oldKey.Parties)),
		ownPoly:         poly,
		newPaillier:     newPaillierKey,
		newPaillierPriv: newPaillierPriv,
		newPaillierPubs: map[tss.PartyID]PaillierPublicShare{
			oldKey.Party: {Party: oldKey.Party, PublicKey: newPaillierPubBytes, Proof: modProofBytes},
		},
		newRingPedersen: map[tss.PartyID]RingPedersenPublicShare{
			oldKey.Party: {Party: oldKey.Party, Params: ringPedersenParamsBytes, Proof: ringPedersenProofBytes},
		},
	}
	commitPayload, err := marshalRefreshCommitmentsPayload(refreshCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  newPaillierPubBytes,
		PaillierProof:      modProofBytes,
		RingPedersenParams: ringPedersenParamsBytes,
		RingPedersenProof:  ringPedersenProofBytes,
	})
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{envelope(config, 1, oldKey.Party, 0, payloadRefreshCommitments, commitPayload, false)}
	for _, id := range oldKey.Parties {
		if id == oldKey.Party {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := marshalRefreshSharePayload(refreshSharePayload{Share: scalarBytes(share)})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, oldKey.Party, id, payloadRefreshShare, payload, true))
	}
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, nil, err
	}
	out = append(out, completionOut...)
	return s, out, nil
}

// Guard returns the session's envelope guard for use by transport adapters.
func (s *RefreshSession) Guard() *tss.EnvelopeGuard {
	if s == nil {
		return nil
	}
	return s.guard
}

// SetGuard attaches an envelope guard to the session. When set, all inbound
// envelopes are validated against protocol policies, transport authentication,
// confidentiality requirements, broadcast consistency, and replay detection.
func (s *RefreshSession) SetGuard(g *tss.EnvelopeGuard) {
	if s != nil {
		s.guard = g
	}
}

// NewGuard creates an EnvelopeGuard configured for this refresh session.
// cache may be nil to use an in-memory cache suitable for testing.
func (s *RefreshSession) NewGuard(cache tss.ReplayCache) (*tss.EnvelopeGuard, error) {
	if s == nil {
		return nil, errors.New("nil refresh session")
	}
	if cache == nil {
		cache = tss.NewInMemoryReplayCache()
	}
	return tss.NewEnvelopeGuard(s.cfg.Self, tss.PartySet(s.cfg.Parties), protocol, s.cfg.SessionID, CGGMP21Policies, cache)
}

// validateInbound runs envelope validation through the guard when set, or
// falls back to basic structural checks for sessions without a guard (tests).
// Production deployments MUST attach a guard via SetGuard before processing
// authenticated transport messages.
func (s *RefreshSession) validateInbound(env tss.Envelope) error {
	if s.guard != nil {
		return s.guard.Validate(env)
	}
	// Guard is required when the transport authenticates the sender.
	if env.Security.Authenticated {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From,
			errors.New("envelope guard is required for authenticated transport; call SetGuard before processing messages"))
	}
	if err := tss.ValidateEnvelope(env, protocol, s.cfg.SessionID, s.cfg.Parties); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if err := tss.ValidateEnvelopePolicy(env, s.cfg.Self, CGGMP21Policies); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	return nil
}

// HandleRefreshMessage validates and applies one refresh envelope.
func (s *RefreshSession) HandleRefreshMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil refresh session")
	}
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
		return nil, err
	}
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleRefreshConfirmation(env)
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("refresh only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadRefreshCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh commitments"))
		}
		p, err := unmarshalRefreshCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateRefreshCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		pk, err := pai.UnmarshalPublicKey(p.PaillierPublicKey)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		proof, err := zkpai.UnmarshalModulusProof(p.PaillierProof)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if !zkpai.VerifyModulus(refreshPaillierDomain(s.cfg, env.From, p.PaillierPublicKey), pk, uint32(env.From), proof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Paillier modulus proof",
				[]tss.PartyID{env.From},
				errors.New("invalid refresh Paillier modulus proof"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.Parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		ringParams, err := zkpai.UnmarshalRingPedersenParams(p.RingPedersenParams)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed refresh Ring-Pedersen parameters",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.Parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if ringParams.N.Cmp(pk.N) != 0 {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"refresh Ring-Pedersen modulus mismatch",
				[]tss.PartyID{env.From},
				errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.Parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		ringProof, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed refresh Ring-Pedersen proof",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.Parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyRingPedersen(refreshRingPedersenDomain(s.cfg, env.From, p.RingPedersenParams), ringParams, uint32(env.From), ringProof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Ring-Pedersen proof",
				[]tss.PartyID{env.From},
				errors.New("invalid refresh Ring-Pedersen proof"),
				rawEvidenceField(evidenceFieldPartiesHash, wireutil.PartySetHash(s.oldKey.Parties, partySetHashLabel)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		s.commits[env.From] = p.Commitments
		s.newPaillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
		s.newRingPedersen[env.From] = RingPedersenPublicShare{Party: env.From, Params: p.RingPedersenParams, Proof: p.RingPedersenProof}
	case payloadRefreshShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh share"))
		}
		p, err := unmarshalRefreshSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		share, err := secp.ScalarFromBytes(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		s.shares[env.From] = share.BigInt()
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return s.tryComplete()
}

// KeyShare returns the refreshed key share when refresh completes.
func (s *RefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.newShare.Clone(), true
}

// Destroy clears sensitive session state. Use only on material that will
// never be needed for processing further messages.
func (s *RefreshSession) Destroy() {
	if s == nil {
		return
	}
	s.abort()
	clear(s.newPaillierPriv)
	s.newPaillier = nil
}

func (s *RefreshSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	if s.newShare != nil && !s.completed {
		s.newShare.Destroy()
	}
}
