package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/secret"
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const (
	payloadReshareDealerCommitments = "cggmp21.secp256k1.reshare.dealer_commitments"
	payloadReshareShare             = "cggmp21.secp256k1.reshare.share"
	payloadReshareReceiverMaterial  = "cggmp21.secp256k1.reshare.receiver_material"
	reshareCommitmentsHashLabel     = "cggmp21-secp256k1-reshare-commitments-v1"
	reshareTranscriptHashLabel      = "cggmp21-secp256k1-reshare-transcript-v1"
)

// ErrUnsupportedRefreshThresholdChange is returned when fixed-party refresh is asked to change the threshold.
var ErrUnsupportedRefreshThresholdChange = errors.New("cggmp21/secp256k1: threshold change requires StartReshare")

// ReshareSession tracks a CGGMP21 party-set-changing resharing exchange.
//
// Old parties act as dealers. Each dealer uses a polynomial whose constant is
// its old share multiplied by the Lagrange coefficient for the old dealer set,
// so summing all dealer polynomials preserves the original group secret. New
// parties, including old/new overlap parties, generate fresh Paillier and
// Ring-Pedersen material and receive a new key share.
type ReshareSession struct {
	plan          ResharePlan
	oldKey        *KeyShare
	oldPublicKey  []byte
	oldChainCode  []byte
	oldParties    []tss.PartyID
	dealerParties []tss.PartyID
	newParties    []tss.PartyID
	newThreshold  int
	selfID        tss.PartyID
	isDealer      bool
	isReceiver    bool

	cfg           tss.ThresholdConfig
	log           tss.Logger
	commits       map[tss.PartyID][][]byte
	shares        map[tss.PartyID]*big.Int
	completed     bool
	aborted       bool
	newShare      *KeyShare
	confirmations map[tss.PartyID][]byte
	ownPoly       []*big.Int

	newPaillier     *pai.PrivateKey
	newPaillierPubs map[tss.PartyID]PaillierPublicShare
	newPaillierPriv []byte
	newRingPedersen map[tss.PartyID]RingPedersenPublicShare
	dealerSent      bool
}

type reshareDealerCommitmentsPayload struct {
	Commitments [][]byte
}

type reshareReceiverMaterialPayload struct {
	PaillierPublicKey  []byte
	PaillierProof      []byte
	RingPedersenParams []byte
	RingPedersenProof  []byte
}

type reshareSharePayload struct {
	Dealer               tss.PartyID
	Receiver             tss.PartyID
	Share                []byte
	DealerCommitmentHash []byte
}

// StartReshare starts CGGMP21 resharing as an old-party dealer.
//
// The target participant set is newParties and the target threshold is
// config.Threshold. If the local old party is also in newParties, it also acts
// as a receiver and will produce a new KeyShare after all old dealers and new
// receivers contribute. Old-only parties complete without producing a new share.
func StartReshare(oldKey *KeyShare, config tss.ThresholdConfig, newParties []tss.PartyID) (*ReshareSession, []tss.Envelope, error) {
	if oldKey == nil {
		return nil, nil, errors.New("nil old key share")
	}
	if config.Self != oldKey.Party {
		return nil, nil, errors.New("config.Self must match the old key's party ID")
	}
	plan, err := NewResharePlan(oldKey, config.SessionID, oldKey.Parties, newParties, config.Threshold, SecurityParameters{})
	if err != nil {
		return nil, nil, err
	}
	if tss.ContainsParty(plan.NewParties, oldKey.Party) {
		return StartReshareOverlap(oldKey, plan, config.Rand)
	}
	return StartReshareDealer(oldKey, plan, config.Rand)
}

// StartReshareDealer starts resharing for an old-party dealer.
func StartReshareDealer(oldKey *KeyShare, plan ResharePlan, rng io.Reader) (*ReshareDealerSession, []tss.Envelope, error) {
	if oldKey == nil {
		return nil, nil, errors.New("nil old key share")
	}
	return startReshareSession(oldKey, plan, oldKey.Party, rng, true, false)
}

// StartReshareReceiver starts resharing for a new-party receiver.
func StartReshareReceiver(plan ResharePlan, localParty tss.PartyID, rng io.Reader) (*ReshareReceiverSession, []tss.Envelope, error) {
	return startReshareSession(nil, plan, localParty, rng, false, true)
}

// StartReshareOverlap starts resharing for a party that is both dealer and receiver.
func StartReshareOverlap(oldKey *KeyShare, plan ResharePlan, rng io.Reader) (*ReshareOverlapSession, []tss.Envelope, error) {
	if oldKey == nil {
		return nil, nil, errors.New("nil old key share")
	}
	return startReshareSession(oldKey, plan, oldKey.Party, rng, true, true)
}

func startReshareSession(oldKey *KeyShare, plan ResharePlan, localParty tss.PartyID, rng io.Reader, dealer, receiver bool) (*ReshareSession, []tss.Envelope, error) {
	if err := plan.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, localParty, err)
	}
	if dealer {
		if oldKey == nil {
			return nil, nil, errors.New("dealer requires old key share")
		}
		if oldKey.Party != localParty {
			return nil, nil, errors.New("old key party does not match local party")
		}
		if !IsDealer(plan, localParty) {
			return nil, nil, errors.New("local party is not in dealer set")
		}
		if err := validateOldKeyMatchesResharePlan(oldKey, plan); err != nil {
			return nil, nil, err
		}
		if err := oldKey.requireMPCMaterial(); err != nil {
			return nil, nil, err
		}
	}
	if receiver && !IsReceiver(plan, localParty) {
		return nil, nil, errors.New("local party is not in new receiver set")
	}
	if !dealer && !receiver {
		return nil, nil, errors.New("reshare session requires dealer or receiver role")
	}
	config := tss.ThresholdConfig{
		Threshold: plan.NewThreshold,
		Parties:   append([]tss.PartyID(nil), plan.NewParties...),
		Self:      localParty,
		SessionID: plan.SessionID,
		Rand:      rng,
	}
	s := &ReshareSession{
		plan:            cloneResharePlan(plan),
		oldKey:          oldKey,
		oldPublicKey:    append([]byte(nil), plan.OldGroupPublicKey...),
		oldChainCode:    append([]byte(nil), plan.ChainCode...),
		oldParties:      append([]tss.PartyID(nil), plan.OldParties...),
		dealerParties:   append([]tss.PartyID(nil), plan.DealerParties...),
		newParties:      append([]tss.PartyID(nil), plan.NewParties...),
		newThreshold:    plan.NewThreshold,
		selfID:          localParty,
		isDealer:        dealer,
		isReceiver:      receiver,
		cfg:             config,
		log:             config.Logger(),
		commits:         make(map[tss.PartyID][][]byte),
		shares:          make(map[tss.PartyID]*big.Int),
		confirmations:   make(map[tss.PartyID][]byte, len(plan.NewParties)),
		newPaillierPubs: make(map[tss.PartyID]PaillierPublicShare),
		newRingPedersen: make(map[tss.PartyID]RingPedersenPublicShare),
	}
	if receiver {
		if err := s.initReceiverMaterial(); err != nil {
			return nil, nil, err
		}
		payload, err := marshalReshareReceiverMaterialPayload(reshareReceiverMaterialPayload{
			PaillierPublicKey:  s.newPaillierPubs[s.selfID].PublicKey,
			PaillierProof:      s.newPaillierPubs[s.selfID].Proof,
			RingPedersenParams: s.newRingPedersen[s.selfID].Params,
			RingPedersenProof:  s.newRingPedersen[s.selfID].Proof,
		})
		if err != nil {
			return nil, nil, err
		}
		out := []tss.Envelope{envelope(s.receiverConfig(), 1, s.selfID, 0, payloadReshareReceiverMaterial, payload, false)}
		dealerOut, err := s.maybeSendDealerMessages()
		if err != nil {
			return nil, nil, err
		}
		out = append(out, dealerOut...)
		return s, out, nil
	}
	return s, nil, nil
}

func (s *ReshareSession) maybeSendDealerMessages() ([]tss.Envelope, error) {
	if !s.isDealer || s.dealerSent {
		return nil, nil
	}
	if len(s.newPaillierPubs) != len(s.newParties) || len(s.newRingPedersen) != len(s.newParties) {
		return nil, nil
	}
	out, err := s.dealerMessages()
	if err != nil {
		return nil, err
	}
	s.dealerSent = true
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, err
	}
	out = append(out, completionOut...)
	return out, nil
}

func (s *ReshareSession) dealerMessages() ([]tss.Envelope, error) {
	order := secp.Order()
	lambda, err := shamir.LagrangeCoefficient(s.selfID, s.dealerParties, order)
	if err != nil {
		return nil, err
	}
	oldSecret, err := s.oldKey.secretBig()
	if err != nil {
		return nil, err
	}
	constant := new(big.Int).Mul(oldSecret, lambda)
	constant.Mod(constant, order)
	// The wire format has no SEC 1 encoding for infinity, so every dealer
	// contribution commitment must be representable as a finite point.
	if constant.Sign() == 0 {
		return nil, errors.New("reshare dealer constant is zero")
	}
	poly, err := shamir.RandomPolynomial(s.cfg.Reader(), order, s.newThreshold, constant)
	if err != nil {
		return nil, err
	}
	commitments, err := polynomialCommitments(poly)
	if err != nil {
		return nil, err
	}
	if err := s.validateDealerCommitments(s.selfID, commitments); err != nil {
		return nil, err
	}
	s.ownPoly = poly
	s.commits[s.selfID] = commitments
	if s.isReceiver {
		s.shares[s.selfID] = shamir.Eval(poly, s.selfID, order)
	}
	payload, err := marshalReshareDealerCommitmentsPayload(reshareDealerCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, err
	}
	dealerConfig := s.dealerConfig()
	out := []tss.Envelope{envelope(dealerConfig, 1, s.selfID, 0, payloadReshareDealerCommitments, payload, false)}
	commitmentsHash := byteSlicesHash(reshareCommitmentsHashLabel, commitments)
	for _, id := range s.newParties {
		if id == s.selfID {
			continue
		}
		share := shamir.Eval(s.ownPoly, id, order)
		sharePayload, err := marshalReshareSharePayload(reshareSharePayload{
			Dealer:               s.selfID,
			Receiver:             id,
			Share:                scalarBytes(share),
			DealerCommitmentHash: commitmentsHash,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, envelope(dealerConfig, 1, s.selfID, id, payloadReshareShare, sharePayload, true))
	}
	return out, nil
}

func (s *ReshareSession) initReceiverMaterial() error {
	newPaillierKey, err := pai.GenerateKey(s.cfg.Ctx(), s.cfg.Reader(), s.plan.SecurityParameters.paillierBits())
	if err != nil {
		return err
	}
	newPaillierPubBytes, err := newPaillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	newPaillierPriv, err := newPaillierKey.MarshalBinary()
	if err != nil {
		return err
	}
	proofConfig := s.receiverConfig()
	modProof, err := zkpai.ProveModulus(s.cfg.Reader(), resharePaillierDomain(proofConfig, s.selfID, newPaillierPubBytes), newPaillierKey, uint32(s.selfID))
	if err != nil {
		return err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return err
	}
	ringPedersenParams, ringPedersenLambda, err := zkpai.GenerateRingPedersenParams(s.cfg.Reader(), newPaillierKey)
	if err != nil {
		return err
	}
	ringPedersenParamsBytes, err := zkpai.MarshalRingPedersenParams(ringPedersenParams)
	if err != nil {
		return err
	}
	ringPedersenProof, err := zkpai.ProveRingPedersen(s.cfg.Reader(), reshareRingPedersenDomain(proofConfig, s.selfID, ringPedersenParamsBytes), newPaillierKey, ringPedersenParams, ringPedersenLambda, uint32(s.selfID))
	if err != nil {
		return err
	}
	ringPedersenProofBytes, err := zkpai.Marshal(ringPedersenProof)
	if err != nil {
		return err
	}
	s.newPaillier = newPaillierKey
	s.newPaillierPriv = newPaillierPriv
	s.newPaillierPubs[s.selfID] = PaillierPublicShare{Party: s.selfID, PublicKey: newPaillierPubBytes, Proof: modProofBytes}
	s.newRingPedersen[s.selfID] = RingPedersenPublicShare{Party: s.selfID, Params: ringPedersenParamsBytes, Proof: ringPedersenProofBytes}
	return nil
}

func (s *ReshareSession) dealerConfig() tss.ThresholdConfig {
	config := s.cfg
	config.Parties = append([]tss.PartyID(nil), s.dealerParties...)
	return config
}

func (s *ReshareSession) receiverConfig() tss.ThresholdConfig {
	config := s.cfg
	config.Parties = append([]tss.PartyID(nil), s.newParties...)
	config.Threshold = s.newThreshold
	return config
}

// HandleReshareMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleReshareMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
	}
	if s.completed {
		if (!s.isReceiver && env.PayloadType == payloadReshareReceiverMaterial) || env.PayloadType == payloadKeygenConfirmation {
			return nil, nil
		}
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
	if env.PayloadType == payloadKeygenConfirmation {
		return s.handleReshareConfirmation(env)
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadReshareDealerCommitments:
		if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.dealerParties); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if env.To != 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer commitments must be broadcast"))
		}
		// Dealer-only sessions (not receivers) can validate commitments without
		// waiting for receiver material — they do not derive a new key share.
		if s.isReceiver && (len(s.newPaillierPubs) != len(s.newParties) || len(s.newRingPedersen) != len(s.newParties)) {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer commitments arrived before receiver material completed"))
		}
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare dealer commitments"))
		}
		p, err := unmarshalReshareDealerCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := s.validateDealerCommitments(env.From, p.Commitments); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		s.commits[env.From] = p.Commitments
	case payloadReshareShare:
		if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.dealerParties); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if !s.isReceiver {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("local party is not a reshare receiver"))
		}
		if err := requireDirectConfidential(env, s.selfID, payloadReshareShare); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare share"))
		}
		commitments, ok := s.commits[env.From]
		if !ok {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer share arrived before dealer commitments"))
		}
		p, err := unmarshalReshareSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if p.Dealer != env.From {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer share payload sender mismatch"))
		}
		if p.Receiver != s.selfID {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer share payload receiver mismatch"))
		}
		if !bytes.Equal(p.DealerCommitmentHash, byteSlicesHash(reshareCommitmentsHashLabel, commitments)) {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer share commitment hash mismatch"))
		}
		share, err := secp.ScalarFromBytes(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := secp.VerifyShare(commitments, uint32(s.selfID), share); err != nil {
			evidenceEnv := envelope(s.dealerConfig(), 1, env.From, s.selfID, payloadReshareShare, env.Payload, true)
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: env.From,
				Blame: &tss.Blame{
					Reason:  "invalid reshare share",
					Parties: []tss.PartyID{env.From},
					Evidence: marshalEvidence(
						evidenceEnv,
						tss.EvidenceKindReshareShare,
						"invalid reshare share",
						rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.dealerParties)),
						rawEvidenceField(evidenceFieldCommitmentsHash, byteSlicesHash(reshareCommitmentsHashLabel, commitments)),
						hashEvidenceField("dealer_share_payload_hash", env.Payload),
					),
				},
				Err: err,
			}
		}
		s.shares[env.From] = share.BigInt()
	case payloadReshareReceiverMaterial:
		if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.newParties); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if env.To != 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("receiver material must be broadcast"))
		}
		if _, ok := s.newPaillierPubs[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare receiver material"))
		}
		p, err := unmarshalReshareReceiverMaterialPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := s.verifyAndStoreReceiverMaterial(env, p); err != nil {
			return nil, err
		}
		out, err = s.maybeSendDealerMessages()
		if err != nil {
			return nil, err
		}
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	completionOut, err := s.tryComplete()
	if err != nil {
		return nil, err
	}
	out = append(out, completionOut...)
	return out, nil
}

func (s *ReshareSession) verifyAndStoreReceiverMaterial(env tss.Envelope, p reshareReceiverMaterialPayload) error {
	pk, err := pai.UnmarshalPublicKey(p.PaillierPublicKey)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	proof, err := zkpai.UnmarshalModulusProof(p.PaillierProof)
	if err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !zkpai.VerifyModulus(resharePaillierDomain(s.receiverConfig(), env.From, p.PaillierPublicKey), pk, uint32(env.From), proof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid reshare Paillier modulus proof",
			[]tss.PartyID{env.From},
			errors.New("invalid reshare Paillier modulus proof"),
			rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.newParties)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	ringParams, err := zkpai.UnmarshalRingPedersenParams(p.RingPedersenParams)
	if err != nil {
		return protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed reshare Ring-Pedersen parameters",
			[]tss.PartyID{env.From},
			err,
			rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.newParties)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	if ringParams.N.Cmp(pk.N) != 0 {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"reshare Ring-Pedersen modulus mismatch",
			[]tss.PartyID{env.From},
			errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
			rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.newParties)),
			hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
		)
	}
	ringProof, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof)
	if err != nil {
		return protocolErrorWithEvidence(
			tss.ErrCodeInvalidMessage,
			env,
			tss.EvidenceKindKeygenPaillier,
			"malformed reshare Ring-Pedersen proof",
			[]tss.PartyID{env.From},
			err,
			rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.newParties)),
		)
	}
	if !zkpai.VerifyRingPedersen(reshareRingPedersenDomain(s.receiverConfig(), env.From, p.RingPedersenParams), ringParams, uint32(env.From), ringProof) {
		return verificationErrorWithEvidence(
			env,
			tss.EvidenceKindKeygenPaillier,
			"invalid reshare Ring-Pedersen proof",
			[]tss.PartyID{env.From},
			errors.New("invalid reshare Ring-Pedersen proof"),
			rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.newParties)),
		)
	}
	s.newPaillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
	s.newRingPedersen[env.From] = RingPedersenPublicShare{Party: env.From, Params: p.RingPedersenParams, Proof: p.RingPedersenProof}
	return nil
}

// KeyShare returns the new key share when this session is a new receiver and resharing completes.
func (s *ReshareSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed || s.newShare == nil {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}

func (s *ReshareSession) tryComplete() ([]tss.Envelope, error) {
	if s.completed {
		return nil, nil
	}
	if s.newShare != nil {
		if len(s.confirmations) == len(s.newParties) {
			return nil, s.finalizeConfirmedShare()
		}
		return nil, nil
	}
	if len(s.commits) != len(s.dealerParties) {
		return nil, nil
	}
	if !s.isReceiver {
		newCommitments, err := s.aggregateCommitments()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
			return nil, errors.New("reshared group public key does not match original")
		}
		s.completed = true
		return nil, nil
	}
	if len(s.shares) != len(s.dealerParties) || len(s.newPaillierPubs) != len(s.newParties) || len(s.newRingPedersen) != len(s.newParties) {
		return nil, nil
	}
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.selfID), secp.ScalarFromBigInt(share)); err != nil {
			evidenceEnv := envelope(s.dealerConfig(), 1, dealer, s.selfID, payloadReshareShare, nil, true)
			return nil, &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{
					Reason:  "invalid reshare share",
					Parties: []tss.PartyID{dealer},
					Evidence: marshalEvidence(
						evidenceEnv,
						tss.EvidenceKindReshareShare,
						"invalid reshare share",
						rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.dealerParties)),
						rawEvidenceField(evidenceFieldCommitmentsHash, byteSlicesHash(reshareCommitmentsHashLabel, s.commits[dealer])),
					),
				},
				Err: err,
			}
		}
	}
	order := secp.Order()
	newSecret := new(big.Int)
	for _, dealer := range s.dealerParties {
		newSecret.Add(newSecret, s.shares[dealer])
		newSecret.Mod(newSecret, order)
	}
	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
		return nil, errors.New("reshared group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := secp.EvalCommitments(newCommitments, uint32(id))
		if err != nil {
			return nil, err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return nil, err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.reshareTranscriptHash(newCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.selfID)
	if !ok {
		return nil, errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, newSecret)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		return nil, errors.New("local share proof public key mismatch")
	}
	shareProofBytes, err := shareProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	localProofShare := &KeyShare{
		Party:                  s.selfID,
		Threshold:              s.newThreshold,
		Parties:                s.newParties,
		PublicKey:              newCommitments[0],
		PaillierPublicKey:      s.newPaillierPubs[s.selfID].PublicKey,
		KeygenTranscriptHash:   transcriptHash,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
	}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.newPaillier, uint32(s.selfID))
	if err != nil {
		return nil, err
	}
	paillierProofBytes, err := zkpai.Marshal(paillierProof)
	if err != nil {
		return nil, err
	}
	s.newShare = &KeyShare{
		Version:                tss.Version,
		Party:                  s.selfID,
		Threshold:              s.newThreshold,
		Parties:                append([]tss.PartyID(nil), s.newParties...),
		PublicKey:              append([]byte(nil), newCommitments[0]...),
		ChainCode:              append([]byte(nil), s.oldChainCode...),
		secret:                 scalarBytes(newSecret),
		GroupCommitments:       newCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      append([]byte(nil), s.newPaillierPubs[s.selfID].PublicKey...),
		paillierPrivateKey:     append([]byte(nil), s.newPaillierPriv...),
		PaillierProof:          paillierProofBytes,
		PaillierPublicKeys:     s.sortedNewPaillierPublicKeys(),
		RingPedersenParams:     append([]byte(nil), s.newRingPedersen[s.selfID].Params...),
		RingPedersenProof:      append([]byte(nil), s.newRingPedersen[s.selfID].Proof...),
		RingPedersenPublic:     s.sortedNewRingPedersenPublic(),
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
		ShareProof:             shareProofBytes,
		KeygenTranscriptHash:   transcriptHash,
	}
	logCiphertext, logRandomness, err := s.newPaillier.Encrypt(s.cfg.Reader(), newSecret)
	if err != nil {
		return nil, err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParams(s.newRingPedersen[s.selfID].Params)
	if err != nil {
		return nil, fmt.Errorf("unmarshal local RP params: %w", err)
	}
	logDomain := logProofDomain(localProofShare, &s.newPaillier.PublicKey, localVerificationShare, transcriptHash)
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return nil, fmt.Errorf("invalid verification share: %w", err)
	}
	logStmt := zkpai.LogStarStatement{
		PaillierN:   &s.newPaillier.PublicKey,
		C:           logCiphertext,
		X:           verificationPoint,
		B:           secp.ScalarBaseMult(secp.ScalarFromBigInt(big.NewInt(1))),
		VerifierAux: *localRP,
	}
	logWitness := zkpai.LogStarWitness{
		X:   new(big.Int).Set(newSecret),
		Rho: new(big.Int).Set(logRandomness),
	}
	logProof, err := zkpai.ProveLogStar(zkpai.ActiveSecurityParams(), logDomain, logStmt, logWitness, s.cfg.Reader())
	if err != nil {
		return nil, err
	}
	logProofBytes, err := logProof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.newShare.LogCiphertext = logCiphertext.Bytes()
	s.newShare.LogProof = logProofBytes
	s.newShare.logRandomness = logRandomness.Bytes()
	if err := s.newShare.validateWithoutConfirmations(); err != nil {
		return nil, err
	}
	confirmation, err := s.newShare.KeygenConfirmation()
	if err != nil {
		return nil, err
	}
	encodedConfirmation, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.confirmations[s.selfID] = append([]byte(nil), encodedConfirmation...)
	out := []tss.Envelope{
		envelope(s.receiverConfig(), keygenConfirmationRound, s.selfID, 0, payloadKeygenConfirmation, encodedConfirmation, false),
	}
	s.log.Info(s.cfg.Ctx(), "reshare local material complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	if len(s.confirmations) == len(s.newParties) {
		if err := s.finalizeConfirmedShare(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *ReshareSession) handleReshareConfirmation(env tss.Envelope) ([]tss.Envelope, error) {
	if !s.isReceiver {
		return nil, nil
	}
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.newParties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.Round != keygenConfirmationRound {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare confirmation in wrong round"))
	}
	if env.To != 0 {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("reshare confirmation must be broadcast"))
	}
	if env.ConfidentialRequired {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("reshare confirmation must not require confidential transport"))
	}
	confirmation, err := UnmarshalKeygenConfirmation(env.Payload)
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if confirmation.Sender != env.From {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("keygen confirmation sender mismatch: env from %d, payload sender %d", env.From, confirmation.Sender))
	}
	canonical, err := confirmation.MarshalBinary()
	if err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("non-canonical reshare confirmation"))
	}
	if existing, ok := s.confirmations[env.From]; ok {
		if bytes.Equal(existing, canonical) {
			return nil, nil
		}
		return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, fmt.Errorf("conflicting keygen confirmation from party %d", env.From))
	}
	if s.newShare != nil {
		if err := verifyKeygenConfirmationForShare(s.newShare, confirmation); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
	}
	s.confirmations[env.From] = append([]byte(nil), canonical...)
	if s.newShare != nil && len(s.confirmations) == len(s.newParties) {
		return nil, s.finalizeConfirmedShare()
	}
	return nil, nil
}

func (s *ReshareSession) finalizeConfirmedShare() error {
	if s.newShare == nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, errors.New("missing pending reshare share"))
	}
	encoded := make([][]byte, len(s.newParties))
	for i, id := range s.newParties {
		confirmation, ok := s.confirmations[id]
		if !ok {
			s.abort()
			return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, id, fmt.Errorf("missing keygen confirmation from party %d", id))
		}
		encoded[i] = append([]byte(nil), confirmation...)
	}
	if err := verifyKeygenConfirmationSet(s.newShare, encoded); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, err)
	}
	s.newShare.KeygenConfirmations = cloneKeyShareByteSlices(encoded)
	if err := s.newShare.Validate(); err != nil {
		s.abort()
		return tss.NewProtocolError(tss.ErrCodeVerification, keygenConfirmationRound, s.selfID, err)
	}
	s.completed = true
	confirmationSetHash := keygenConfirmationSetHash(s.newShare.KeygenConfirmations)
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"confirmation_set_hash", fmt.Sprintf("%x", confirmationSetHash[:8]),
	)
	return nil
}

func (s *ReshareSession) aggregateCommitments() ([][]byte, error) {
	newCommitments := make([][]byte, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*secp.Point, 0, len(s.dealerParties))
		for _, dealer := range s.dealerParties {
			commitment := s.commits[dealer][degree]
			p, err := secp.PointFromBytes(commitment)
			if err != nil {
				return nil, fmt.Errorf("invalid reshare commitment: dealer=%d degree=%d: %w", dealer, degree, err)
			}
			points = append(points, p)
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return nil, err
		}
		newCommitments[degree] = enc
	}
	if len(newCommitments[0]) == 0 {
		return nil, errors.New("reshare produced empty group public key commitment")
	}
	return newCommitments, nil
}

func (s *ReshareSession) reshareTranscriptHash(newCommitments [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(reshareTranscriptHashLabel))
	wire.WriteHashPart(h, []byte(s.plan.CurveID))
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	wire.WriteHashPart(h, s.oldPublicKey)
	wire.WriteHashPart(h, wire.EncodeBytesList(s.plan.OldGroupCommitments))
	wire.WritePartySet(h, s.oldParties)
	wire.WritePartySet(h, s.dealerParties)
	wire.WritePartySet(h, s.newParties)
	wire.WriteHashPart(h, wire.Uint32(uint32(s.plan.OldThreshold)))
	wire.WriteHashPart(h, wire.Uint32(uint32(s.newThreshold)))
	wire.WriteHashPart(h, s.plan.ChainCode)
	wire.WriteHashPart(h, wire.Uint32(uint32(s.plan.SecurityParameters.paillierBits())))
	for _, dealer := range s.oldParties {
		wire.WritePartyID(h, dealer)
		wire.WriteHashPart(h, s.plan.OldVerificationShares[dealer])
	}
	for _, dealer := range s.dealerParties {
		wire.WriteHashPart(h, wire.EncodeBytesList(s.commits[dealer]))
	}
	for _, id := range s.newParties {
		item := s.newPaillierPubs[id]
		wire.WriteHashPart(h, item.PublicKey)
		wire.WriteHashPart(h, item.Proof)
		rp := s.newRingPedersen[id]
		wire.WriteHashPart(h, rp.Params)
		wire.WriteHashPart(h, rp.Proof)
	}
	for _, commitment := range newCommitments {
		wire.WriteHashPart(h, commitment)
	}
	return h.Sum(nil)
}

func validateReshareCommitments(commitments [][]byte, threshold int) error {
	if len(commitments) != threshold {
		return fmt.Errorf("got %d commitments, want %d", len(commitments), threshold)
	}
	for i, commitment := range commitments {
		if len(commitment) == 0 {
			return fmt.Errorf("commitment %d is empty", i)
		}
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return err
		}
	}
	return nil
}

func (s *ReshareSession) validateDealerCommitments(dealer tss.PartyID, commitments [][]byte) error {
	if err := validateReshareCommitments(commitments, s.newThreshold); err != nil {
		return err
	}
	if !tss.ContainsParty(s.dealerParties, dealer) {
		return fmt.Errorf("sender %d is not a dealer", dealer)
	}
	verificationShare, ok := s.plan.OldVerificationShares[dealer]
	if !ok {
		return fmt.Errorf("missing old verification share for dealer %d", dealer)
	}
	oldPoint, err := secp.PointFromBytes(verificationShare)
	if err != nil {
		return fmt.Errorf("invalid old verification share for dealer %d: %w", dealer, err)
	}
	lambda, err := shamir.LagrangeCoefficient(dealer, s.dealerParties, secp.Order())
	if err != nil {
		return err
	}
	// The dealer contribution preserves the old secret only if its constant
	// commitment is the old verification share weighted for this dealer set.
	expected, err := secp.PointBytes(secp.ScalarMult(oldPoint, secp.ScalarFromBigInt(lambda)))
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, commitments[0]) {
		return errors.New("dealer constant commitment does not match weighted old verification share")
	}
	return nil
}

func polynomialCommitments(poly []*big.Int) ([][]byte, error) {
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.Sign() == 0 {
			return nil, fmt.Errorf("polynomial coefficient %d is zero", i)
		}
		enc, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff)))
		if err != nil {
			return nil, err
		}
		commitments[i] = enc
	}
	return commitments, nil
}

func (s *ReshareSession) sortedNewPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		item := s.newPaillierPubs[id]
		out = append(out, PaillierPublicShare{
			Party:     item.Party,
			PublicKey: append([]byte(nil), item.PublicKey...),
			Proof:     append([]byte(nil), item.Proof...),
		})
	}
	return out
}

func (s *ReshareSession) sortedNewRingPedersenPublic() []RingPedersenPublicShare {
	out := make([]RingPedersenPublicShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		item := s.newRingPedersen[id]
		out = append(out, RingPedersenPublicShare{
			Party:  item.Party,
			Params: append([]byte(nil), item.Params...),
			Proof:  append([]byte(nil), item.Proof...),
		})
	}
	return out
}

// HandleMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleMessage(msg IncomingMessage) ([]OutgoingMessage, error) {
	return s.HandleReshareMessage(msg)
}

// Result returns the completed receiver key share.
func (s *ReshareSession) Result() (*KeyShare, error) {
	share, ok := s.KeyShare()
	if !ok {
		return nil, errors.New("reshare result is not available")
	}
	return share, nil
}

func validateOldKeyMatchesResharePlan(oldKey *KeyShare, plan ResharePlan) error {
	if oldKey.Threshold != plan.OldThreshold {
		return errors.New("old key threshold does not match reshare plan")
	}
	if !bytes.Equal(oldKey.PublicKey, plan.OldGroupPublicKey) {
		return errors.New("old key public key does not match reshare plan")
	}
	if !bytes.Equal(oldKey.ChainCode, plan.ChainCode) {
		return errors.New("old key chain code does not match reshare plan")
	}
	if !sameParties(oldKey.Parties, plan.OldParties) {
		return errors.New("old key party set does not match reshare plan")
	}
	if !sameByteSlices(oldKey.GroupCommitments, plan.OldGroupCommitments) {
		return errors.New("old key commitments do not match reshare plan")
	}
	for _, vs := range oldKey.VerificationShares {
		if !bytes.Equal(vs.PublicKey, plan.OldVerificationShares[vs.Party]) {
			return fmt.Errorf("old key verification share for party %d does not match reshare plan", vs.Party)
		}
	}
	return nil
}

func cloneResharePlan(in ResharePlan) ResharePlan {
	out := in
	out.OldGroupPublicKey = append([]byte(nil), in.OldGroupPublicKey...)
	out.OldGroupCommitments = cloneKeyShareByteSlices(in.OldGroupCommitments)
	out.OldVerificationShares = make(map[tss.PartyID][]byte, len(in.OldVerificationShares))
	for id, share := range in.OldVerificationShares {
		out.OldVerificationShares[id] = append([]byte(nil), share...)
	}
	out.OldParties = append([]tss.PartyID(nil), in.OldParties...)
	out.DealerParties = append([]tss.PartyID(nil), in.DealerParties...)
	out.NewParties = append([]tss.PartyID(nil), in.NewParties...)
	out.ChainCode = append([]byte(nil), in.ChainCode...)
	return out
}

func sameParties(a, b []tss.PartyID) bool {
	if len(a) != len(b) {
		return false
	}
	a = tss.SortParties(a)
	b = tss.SortParties(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// Destroy clears local secret material retained by the reshare session.
func (s *ReshareSession) Destroy() {
	if s == nil {
		return
	}
	s.abort()
}

func (s *ReshareSession) abort() {
	if s == nil {
		return
	}
	s.aborted = true
	clearBigIntMap(s.shares)
	for _, coeff := range s.ownPoly {
		secret.ClearBigInt(coeff)
	}
	if s.newPaillier != nil {
		s.newPaillier.Destroy()
		s.newPaillier = nil
	}
	clear(s.newPaillierPriv)
	if s.newShare != nil {
		s.newShare.Destroy()
	}
}
