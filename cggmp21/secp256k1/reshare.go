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
	payloadReshareCommitments   = "cggmp21.secp256k1.reshare.commitments"
	payloadReshareShare         = "cggmp21.secp256k1.reshare.share"
	reshareCommitmentsHashLabel = "cggmp21-secp256k1-reshare-commitments-v1"
	reshareTranscriptHashLabel  = "cggmp21-secp256k1-reshare-transcript-v1"
)

// ReshareSession refreshes CGGMP21 key shares and rotates Paillier keys while
// preserving the group public key. Each existing participant generates a
// polynomial with zero constant term (to refresh the secret share) and a new
// Paillier keypair (to rotate encryption material).
type ReshareSession struct {
	oldKey     *KeyShare
	cfg        tss.ThresholdConfig
	log        tss.Logger
	newParties []tss.PartyID
	commits    map[tss.PartyID][][]byte
	shares     map[tss.PartyID]*big.Int
	completed  bool
	aborted    bool
	newShare   *KeyShare
	ownPoly    []*big.Int

	newPaillier     *pai.PrivateKey
	newPaillierPubs map[tss.PartyID]PaillierPublicShare
	newPaillierPriv []byte
	newRingPedersen map[tss.PartyID]RingPedersenPublicShare
}

type reshareCommitmentsPayload struct {
	Commitments        [][]byte `json:"commitments"`
	PaillierPublicKey  []byte   `json:"paillier_public_key"`
	PaillierProof      []byte   `json:"paillier_proof"`
	RingPedersenParams []byte   `json:"ring_pedersen_params"`
	RingPedersenProof  []byte   `json:"ring_pedersen_proof"`
}

type reshareSharePayload struct {
	Share []byte `json:"share"`
}

// StartReshare starts CGGMP21 key-share refresh with Paillier key rotation.
// newParties defines the target participant set.
func StartReshare(oldKey *KeyShare, config tss.ThresholdConfig, newParties []tss.PartyID) (*ReshareSession, []tss.Envelope, error) {
	if err := oldKey.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	newParties = tss.SortParties(newParties)
	if !tss.ContainsParty(newParties, oldKey.Party) {
		return nil, nil, errors.New("local party must be in the new participant set")
	}
	config.Parties = append([]tss.PartyID(nil), oldKey.Parties...)
	// Generate a new Paillier keypair for key rotation.
	newPaillierKey, err := pai.GenerateKey(config.Ctx(), config.Reader(), defaultPaillierBits)
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
	modProof, err := zkpai.ProveModulus(config.Reader(), resharePaillierDomain(config, config.Self, newPaillierPubBytes), newPaillierKey, uint32(config.Self))
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
	ringPedersenProof, err := zkpai.ProveRingPedersen(config.Reader(), reshareRingPedersenDomain(config, config.Self, ringPedersenParamsBytes), newPaillierKey, ringPedersenParams, ringPedersenLambda, uint32(config.Self))
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
	s := &ReshareSession{
		oldKey:          oldKey,
		cfg:             config,
		log:             config.Logger(),
		newParties:      newParties,
		commits:         map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:          map[tss.PartyID]*big.Int{oldKey.Party: shamir.Eval(poly, oldKey.Party, secp.Order())},
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
	commitPayload, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{
		Commitments:        commitments,
		PaillierPublicKey:  newPaillierPubBytes,
		PaillierProof:      modProofBytes,
		RingPedersenParams: ringPedersenParamsBytes,
		RingPedersenProof:  ringPedersenProofBytes,
	})
	if err != nil {
		return nil, nil, err
	}
	out := []tss.Envelope{envelope(config, 1, oldKey.Party, 0, payloadReshareCommitments, commitPayload, false)}
	for _, id := range newParties {
		if id == oldKey.Party {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := marshalReshareSharePayload(reshareSharePayload{Share: scalarBytes(share)})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, oldKey.Party, id, payloadReshareShare, payload, true))
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

// HandleReshareMessage validates and applies one reshare envelope.
func (s *ReshareSession) HandleReshareMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil reshare session")
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
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.oldKey.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.To != 0 && env.To != s.oldKey.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("reshare only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadReshareCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare commitments"))
		}
		p, err := unmarshalReshareCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateReshareCommitments(p.Commitments, s.cfg.Threshold); err != nil {
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
		if !zkpai.VerifyModulus(resharePaillierDomain(s.cfg, env.From, p.PaillierPublicKey), pk, uint32(env.From), proof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid reshare Paillier modulus proof",
				[]tss.PartyID{env.From},
				errors.New("invalid reshare Paillier modulus proof"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		ringParams, err := zkpai.UnmarshalRingPedersenParams(p.RingPedersenParams)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed reshare Ring-Pedersen parameters",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if ringParams.N.Cmp(pk.N) != 0 {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"reshare Ring-Pedersen modulus mismatch",
				[]tss.PartyID{env.From},
				errors.New("Ring-Pedersen modulus does not match Paillier modulus"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		ringProof, err := zkpai.UnmarshalRingPedersenProof(p.RingPedersenProof)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed reshare Ring-Pedersen proof",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyRingPedersen(reshareRingPedersenDomain(s.cfg, env.From, p.RingPedersenParams), ringParams, uint32(env.From), ringProof) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid reshare Ring-Pedersen proof",
				[]tss.PartyID{env.From},
				errors.New("invalid reshare Ring-Pedersen proof"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		s.commits[env.From] = p.Commitments
		s.newPaillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
		s.newRingPedersen[env.From] = RingPedersenPublicShare{Party: env.From, Params: p.RingPedersenParams, Proof: p.RingPedersenProof}
	case payloadReshareShare:
		if err := requireDirectConfidential(env, s.oldKey.Party, payloadReshareShare); err != nil {
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
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
}

// KeyShare returns the refreshed key share when resharing completes.
func (s *ReshareSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return cloneKeyShareValue(s.newShare), true
}

func (s *ReshareSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.oldKey.Parties) || len(s.shares) != len(s.oldKey.Parties) || len(s.newPaillierPubs) != len(s.oldKey.Parties) || len(s.newRingPedersen) != len(s.oldKey.Parties) {
		return nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.oldKey.Party), secp.ScalarFromBigInt(share)); err != nil {
			evidenceEnv := envelope(s.cfg, 1, dealer, s.oldKey.Party, payloadReshareShare, nil, true)
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
						rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
						rawEvidenceField(evidenceFieldCommitmentsHash, byteSlicesHash(reshareCommitmentsHashLabel, s.commits[dealer])),
					),
				},
				Err: err,
			}
		}
	}
	oldSecret, err := s.oldKey.secretBig()
	if err != nil {
		return err
	}
	newSecret := new(big.Int).Set(oldSecret)
	for _, dealer := range s.oldKey.Parties {
		newSecret.Add(newSecret, s.shares[dealer])
		newSecret.Mod(newSecret, order)
	}
	newCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*secp.Point, 0, len(s.oldKey.Parties))
		for _, dealer := range s.oldKey.Parties {
			p, err := secp.PointFromBytes(s.commits[dealer][degree])
			if err != nil {
				return err
			}
			points = append(points, p)
		}
		if degree < len(s.oldKey.GroupCommitments) {
			oldCommitment, err := secp.PointFromBytes(s.oldKey.GroupCommitments[degree])
			if err != nil {
				return err
			}
			points = append(points, oldCommitment)
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return err
		}
		newCommitments[degree] = enc
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
	localVerificationShare, ok := verificationShareFor(verificationShares, s.oldKey.Party)
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
		Party:                  s.oldKey.Party,
		Threshold:              s.cfg.Threshold,
		Parties:                s.newParties,
		PublicKey:              newCommitments[0],
		PaillierPublicKey:      s.newPaillierPubs[s.oldKey.Party].PublicKey,
		KeygenTranscriptHash:   transcriptHash,
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
	}
	paillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.newPaillier, uint32(s.oldKey.Party))
	if err != nil {
		return err
	}
	paillierProofBytes, err := zkpai.Marshal(paillierProof)
	if err != nil {
		return err
	}
	s.newShare = &KeyShare{
		Version:                tss.Version,
		Party:                  s.oldKey.Party,
		Threshold:              s.cfg.Threshold,
		Parties:                append([]tss.PartyID(nil), s.newParties...),
		PublicKey:              append([]byte(nil), newCommitments[0]...),
		secret:                 scalarBytes(newSecret),
		GroupCommitments:       newCommitments,
		VerificationShares:     verificationShares,
		PaillierPublicKey:      append([]byte(nil), s.newPaillierPubs[s.oldKey.Party].PublicKey...),
		paillierPrivateKey:     append([]byte(nil), s.newPaillierPriv...),
		PaillierProof:          paillierProofBytes,
		PaillierPublicKeys:     s.sortedNewPaillierPublicKeys(),
		RingPedersenParams:     append([]byte(nil), s.newRingPedersen[s.oldKey.Party].Params...),
		RingPedersenProof:      append([]byte(nil), s.newRingPedersen[s.oldKey.Party].Proof...),
		RingPedersenPublic:     s.sortedNewRingPedersenPublic(),
		PaillierProofSessionID: s.cfg.SessionID,
		PaillierProofDomain:    domainLabelResharePaillier,
		ShareProof:             shareProofBytes,
		KeygenTranscriptHash:   transcriptHash,
	}
	// Π^log*: prove that Enc_new(x'_i) and V'_i = x'_i·G share the same secret,
	// using the prover's own Ring-Pedersen parameters for the commitment.
	logCiphertext, logRandomness, err := s.newPaillier.Encrypt(s.cfg.Reader(), newSecret)
	if err != nil {
		return err
	}
	localRP, err := zkpai.UnmarshalRingPedersenParams(s.newRingPedersen[s.oldKey.Party].Params)
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
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return s.newShare.Validate()
}

func (s *ReshareSession) reshareTranscriptHash(newCommitments [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(reshareTranscriptHashLabel))
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	wire.WriteHashPart(h, s.oldKey.KeygenTranscriptHash)
	for _, id := range s.oldKey.Parties {
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
