package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
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
	oldKey                  *KeyShare
	oldPublicKey            []byte
	oldChainCode            []byte
	oldKeygenTranscriptHash []byte
	oldParties              []tss.PartyID
	newParties              []tss.PartyID
	newThreshold            int
	selfID                  tss.PartyID
	isReceiver              bool

	cfg       tss.ThresholdConfig
	log       tss.Logger
	commits   map[tss.PartyID][][]byte
	shares    map[tss.PartyID]*big.Int
	completed bool
	aborted   bool
	newShare  *KeyShare
	ownPoly   []*big.Int

	newPaillier     *pai.PrivateKey
	newPaillierPubs map[tss.PartyID]PaillierPublicShare
	newPaillierPriv []byte
	newRingPedersen map[tss.PartyID]RingPedersenPublicShare
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
	Share []byte
}

// StartReshare starts CGGMP21 resharing as an old-party dealer.
//
// The target participant set is newParties and the target threshold is
// config.Threshold. If the local old party is also in newParties, it also acts
// as a receiver and will produce a new KeyShare after all old dealers and new
// receivers contribute. Old-only parties complete without producing a new share.
func StartReshare(oldKey *KeyShare, config tss.ThresholdConfig, newParties []tss.PartyID) (*ReshareSession, []tss.Envelope, error) {
	if err := oldKey.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	if config.Self != oldKey.Party {
		return nil, nil, errors.New("config.Self must match the old key's party ID")
	}
	limits := tss.DefaultLimitsForAlgorithm(tss.AlgorithmCGGMP21Secp256k1)
	oldParties := append([]tss.PartyID(nil), oldKey.Parties...)
	newParties = tss.SortParties(newParties)
	if err := validateReshareNewParties(newParties, config.Threshold, limits); err != nil {
		return nil, nil, err
	}
	if len(oldParties) > limits.MaxParties {
		return nil, nil, fmt.Errorf("too many old parties: %d > %d", len(oldParties), limits.MaxParties)
	}
	if err := wire.ValidateStrictSortedIDs(oldParties); err != nil {
		return nil, nil, fmt.Errorf("invalid old participant set: %w", err)
	}

	order := secp.Order()
	lambda, err := shamir.LagrangeCoefficient(oldKey.Party, oldParties, order)
	if err != nil {
		return nil, nil, err
	}
	oldSecret, err := oldKey.secretBig()
	if err != nil {
		return nil, nil, err
	}
	constant := new(big.Int).Mul(oldSecret, lambda)
	constant.Mod(constant, order)

	poly, err := shamir.RandomPolynomial(config.Reader(), order, config.Threshold, constant)
	if err != nil {
		return nil, nil, err
	}
	commitments, err := polynomialCommitments(poly)
	if err != nil {
		return nil, nil, err
	}

	s := &ReshareSession{
		oldKey:                  oldKey,
		oldPublicKey:            oldKey.PublicKeyBytes(),
		oldChainCode:            append([]byte(nil), oldKey.ChainCode...),
		oldKeygenTranscriptHash: append([]byte(nil), oldKey.KeygenTranscriptHash...),
		oldParties:              oldParties,
		newParties:              newParties,
		newThreshold:            config.Threshold,
		selfID:                  oldKey.Party,
		isReceiver:              tss.ContainsParty(newParties, oldKey.Party),
		cfg:                     config,
		log:                     config.Logger(),
		commits:                 map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:                  make(map[tss.PartyID]*big.Int),
		ownPoly:                 poly,
		newPaillierPubs:         make(map[tss.PartyID]PaillierPublicShare),
		newRingPedersen:         make(map[tss.PartyID]RingPedersenPublicShare),
	}
	if s.isReceiver {
		s.shares[oldKey.Party] = shamir.Eval(poly, oldKey.Party, order)
		if err := s.initReceiverMaterial(); err != nil {
			return nil, nil, err
		}
	}

	out, err := s.dealerMessages(commitments)
	if err != nil {
		return nil, nil, err
	}
	if s.isReceiver {
		materialPayload, err := marshalReshareReceiverMaterialPayload(reshareReceiverMaterialPayload{
			PaillierPublicKey:  s.newPaillierPubs[oldKey.Party].PublicKey,
			PaillierProof:      s.newPaillierPubs[oldKey.Party].Proof,
			RingPedersenParams: s.newRingPedersen[oldKey.Party].Params,
			RingPedersenProof:  s.newRingPedersen[oldKey.Party].Proof,
		})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(s.receiverConfig(), 1, oldKey.Party, 0, payloadReshareReceiverMaterial, materialPayload, false))
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

// StartReshareRecipient starts CGGMP21 resharing for a new-only receiver.
//
// oldPublicKey, oldChainCode, oldKeygenTranscriptHash, and oldParties must come
// from the old committee's authenticated key metadata. The recipient produces
// fresh Paillier/Ring-Pedersen material and waits for all old dealers to send
// weighted Shamir shares.
func StartReshareRecipient(oldPublicKey, oldChainCode, oldKeygenTranscriptHash []byte, oldParties, newParties []tss.PartyID, config tss.ThresholdConfig) (*ReshareSession, []tss.Envelope, error) {
	if _, err := secp.PointFromBytes(oldPublicKey); err != nil {
		return nil, nil, fmt.Errorf("invalid old public key: %w", err)
	}
	if len(oldChainCode) != 0 && len(oldChainCode) != 32 {
		return nil, nil, errors.New("old chain code must be empty or 32 bytes")
	}
	if len(oldKeygenTranscriptHash) != sha256.Size {
		return nil, nil, errors.New("old keygen transcript hash must be 32 bytes")
	}
	limits := tss.DefaultLimitsForAlgorithm(tss.AlgorithmCGGMP21Secp256k1)
	oldParties = tss.SortParties(oldParties)
	newParties = tss.SortParties(newParties)
	if len(oldParties) > limits.MaxParties {
		return nil, nil, fmt.Errorf("too many old parties: %d > %d", len(oldParties), limits.MaxParties)
	}
	if err := wire.ValidateStrictSortedIDs(oldParties); err != nil {
		return nil, nil, fmt.Errorf("invalid old participant set: %w", err)
	}
	if tss.ContainsParty(oldParties, config.Self) {
		return nil, nil, errors.New("recipient is in the old participant set; use StartReshare instead")
	}
	if err := validateReshareNewParties(newParties, config.Threshold, limits); err != nil {
		return nil, nil, err
	}
	if !tss.ContainsParty(newParties, config.Self) {
		return nil, nil, errors.New("recipient must be in the new participant set")
	}
	s := &ReshareSession{
		oldPublicKey:            append([]byte(nil), oldPublicKey...),
		oldChainCode:            append([]byte(nil), oldChainCode...),
		oldKeygenTranscriptHash: append([]byte(nil), oldKeygenTranscriptHash...),
		oldParties:              oldParties,
		newParties:              newParties,
		newThreshold:            config.Threshold,
		selfID:                  config.Self,
		isReceiver:              true,
		cfg:                     config,
		log:                     config.Logger(),
		commits:                 make(map[tss.PartyID][][]byte),
		shares:                  make(map[tss.PartyID]*big.Int),
		newPaillierPubs:         make(map[tss.PartyID]PaillierPublicShare),
		newRingPedersen:         make(map[tss.PartyID]RingPedersenPublicShare),
	}
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
	return s, out, nil
}

func validateReshareNewParties(newParties []tss.PartyID, newThreshold int, limits tss.Limits) error {
	if len(newParties) == 0 {
		return errors.New("new participant set must not be empty")
	}
	if err := wire.ValidateStrictSortedIDs(newParties); err != nil {
		return fmt.Errorf("invalid new participant set: %w", err)
	}
	config := tss.ThresholdConfig{
		Threshold: newThreshold,
		Parties:   newParties,
		Self:      newParties[0],
	}
	if err := config.ValidateWithLimits(limits); err != nil {
		return tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, 0, err)
	}
	return nil
}

func (s *ReshareSession) dealerMessages(commitments [][]byte) ([]tss.Envelope, error) {
	payload, err := marshalReshareDealerCommitmentsPayload(reshareDealerCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, err
	}
	dealerConfig := s.dealerConfig()
	out := []tss.Envelope{envelope(dealerConfig, 1, s.selfID, 0, payloadReshareDealerCommitments, payload, false)}
	for _, id := range s.newParties {
		if id == s.selfID {
			continue
		}
		share := shamir.Eval(s.ownPoly, id, secp.Order())
		payload, err := marshalReshareSharePayload(reshareSharePayload{Share: scalarBytes(share)})
		if err != nil {
			return nil, err
		}
		out = append(out, envelope(dealerConfig, 1, s.selfID, id, payloadReshareShare, payload, true))
	}
	return out, nil
}

func (s *ReshareSession) initReceiverMaterial() error {
	newPaillierKey, err := pai.GenerateKey(s.cfg.Ctx(), s.cfg.Reader(), defaultPaillierBits)
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
	config.Parties = append([]tss.PartyID(nil), s.oldParties...)
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
		if !s.isReceiver && env.PayloadType == payloadReshareReceiverMaterial {
			return nil, nil
		}
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
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadReshareDealerCommitments:
		if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.oldParties); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if env.To != 0 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("dealer commitments must be broadcast"))
		}
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare dealer commitments"))
		}
		p, err := unmarshalReshareDealerCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateReshareCommitments(p.Commitments, s.newThreshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		s.commits[env.From] = p.Commitments
	case payloadReshareShare:
		if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.oldParties); err != nil {
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
		p, err := unmarshalReshareSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		share, err := secp.ScalarFromBytes(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
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
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
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

func (s *ReshareSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.oldParties) {
		return nil
	}
	if !s.isReceiver {
		newCommitments, err := s.aggregateCommitments()
		if err != nil {
			return err
		}
		if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
			return errors.New("reshared group public key does not match original")
		}
		s.completed = true
		return nil
	}
	if len(s.shares) != len(s.oldParties) || len(s.newPaillierPubs) != len(s.newParties) || len(s.newRingPedersen) != len(s.newParties) {
		return nil
	}
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.selfID), secp.ScalarFromBigInt(share)); err != nil {
			evidenceEnv := envelope(s.dealerConfig(), 1, dealer, s.selfID, payloadReshareShare, nil, true)
			return &tss.ProtocolError{
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
						rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldParties)),
						rawEvidenceField(evidenceFieldCommitmentsHash, byteSlicesHash(reshareCommitmentsHashLabel, s.commits[dealer])),
					),
				},
				Err: err,
			}
		}
	}
	newSecret := new(big.Int)
	for _, dealer := range s.oldParties {
		newSecret.Add(newSecret, s.shares[dealer])
		newSecret.Mod(newSecret, secp.Order())
	}
	newCommitments, err := s.aggregateCommitments()
	if err != nil {
		return err
	}
	if !bytes.Equal(newCommitments[0], s.oldPublicKey) {
		return errors.New("reshared group public key does not match original")
	}
	verificationShares := make([]VerificationShare, 0, len(s.newParties))
	for _, id := range s.newParties {
		pub, err := secp.EvalCommitments(newCommitments, uint32(id))
		if err != nil {
			return err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.reshareTranscriptHash(newCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.selfID)
	if !ok {
		return errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, newSecret)
	if err != nil {
		return err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		return errors.New("local share proof public key mismatch")
	}
	shareProofBytes, err := shareProof.MarshalBinary()
	if err != nil {
		return err
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
		return err
	}
	paillierProofBytes, err := zkpai.Marshal(paillierProof)
	if err != nil {
		return err
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
		return err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParams(s.newRingPedersen[s.selfID].Params)
	if err != nil {
		return fmt.Errorf("unmarshal local RP params: %w", err)
	}
	logDomain := logProofDomain(localProofShare, &s.newPaillier.PublicKey, localVerificationShare, transcriptHash)
	verificationPoint, err := secp.PointFromBytes(localVerificationShare)
	if err != nil {
		return fmt.Errorf("invalid verification share: %w", err)
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
		return err
	}
	logProofBytes, err := logProof.MarshalBinary()
	if err != nil {
		return err
	}
	s.newShare.LogCiphertext = logCiphertext.Bytes()
	s.newShare.LogProof = logProofBytes
	s.newShare.logRandomness = logRandomness.Bytes()
	s.completed = true
	s.log.Info(s.cfg.Ctx(), "reshare complete",
		"party_id", s.selfID,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return s.newShare.Validate()
}

func (s *ReshareSession) aggregateCommitments() ([][]byte, error) {
	newCommitments := make([][]byte, s.newThreshold)
	for degree := 0; degree < s.newThreshold; degree++ {
		points := make([]*secp.Point, 0, len(s.oldParties))
		for _, dealer := range s.oldParties {
			commitment := s.commits[dealer][degree]
			if len(commitment) == 0 {
				continue
			}
			p, err := secp.PointFromBytes(commitment)
			if err != nil {
				return nil, fmt.Errorf("invalid reshare commitment: dealer=%d degree=%d: %w", dealer, degree, err)
			}
			points = append(points, p)
		}
		if len(points) == 0 {
			newCommitments[degree] = nil
			continue
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
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	wire.WriteHashPart(h, s.oldPublicKey)
	wire.WriteHashPart(h, s.oldKeygenTranscriptHash)
	wire.WritePartySet(h, s.oldParties)
	wire.WritePartySet(h, s.newParties)
	wire.WriteHashPart(h, wire.Uint32(uint32(s.newThreshold)))
	for _, dealer := range s.oldParties {
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
	for _, commitment := range commitments {
		if len(commitment) == 0 {
			continue
		}
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return err
		}
	}
	return nil
}

func polynomialCommitments(poly []*big.Int) ([][]byte, error) {
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		if coeff.Sign() == 0 {
			commitments[i] = nil
			continue
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

// Destroy clears local secret material retained by the reshare session.
func (s *ReshareSession) Destroy() {
	if s == nil {
		return
	}
	clearBigIntMap(s.shares)
	for _, coeff := range s.ownPoly {
		clearBigInt(coeff)
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
