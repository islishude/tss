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
	payloadReshareCommitments  = "cggmp21.secp256k1.reshare.commitments"
	payloadReshareShare        = "cggmp21.secp256k1.reshare.share"
	reshareTranscriptHashLabel = "cggmp21-secp256k1-reshare-transcript-v1"
)

// ReshareSession refreshes CGGMP21 key shares and rotates Paillier keys while
// preserving the group public key. Each existing participant generates a
// polynomial with zero constant term (to refresh the secret share) and a new
// Paillier keypair (to rotate encryption material).
type ReshareSession struct {
	oldKey     *KeyShare
	cfg        tss.ThresholdConfig
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
}

type reshareCommitmentsPayload struct {
	Commitments       [][]byte `json:"commitments"`
	PaillierPublicKey []byte   `json:"paillier_public_key"`
	PaillierProof     []byte   `json:"paillier_proof"`
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
	newPaillierKey, err := pai.GenerateKey(config.Reader(), defaultPaillierBits)
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
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, big.NewInt(0))
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		enc, err := secp.PointBytes(secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff)))
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &ReshareSession{
		oldKey:          oldKey,
		cfg:             config,
		newParties:      newParties,
		commits:         map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:          map[tss.PartyID]*big.Int{oldKey.Party: shamir.Eval(poly, oldKey.Party, secp.Order())},
		ownPoly:         poly,
		newPaillier:     newPaillierKey,
		newPaillierPriv: newPaillierPriv,
		newPaillierPubs: map[tss.PartyID]PaillierPublicShare{
			oldKey.Party: {Party: oldKey.Party, PublicKey: newPaillierPubBytes, Proof: modProofBytes},
		},
	}
	commitPayload, err := marshalReshareCommitmentsPayload(reshareCommitmentsPayload{
		Commitments:       commitments,
		PaillierPublicKey: newPaillierPubBytes,
		PaillierProof:     modProofBytes,
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
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("invalid reshare Paillier modulus proof"))
		}
		s.commits[env.From] = p.Commitments
		s.newPaillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
	case payloadReshareShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate reshare share"))
		}
		p, err := unmarshalReshareSharePayload(env.Payload)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		share, err := secp.ParseScalar(p.Share)
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
	return s.newShare, true
}

func (s *ReshareSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.oldKey.Parties) || len(s.shares) != len(s.oldKey.Parties) || len(s.newPaillierPubs) != len(s.oldKey.Parties) {
		return nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.oldKey.Party), secp.ScalarFromBigInt(share)); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{Reason: "invalid reshare share", Parties: []tss.PartyID{dealer}},
				Err:   err,
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
	s.newShare = &KeyShare{
		Version:              tss.Version,
		Party:                s.oldKey.Party,
		Threshold:            s.cfg.Threshold,
		Parties:              append([]tss.PartyID(nil), s.newParties...),
		PublicKey:            append([]byte(nil), newCommitments[0]...),
		Secret:               scalarBytes(newSecret),
		GroupCommitments:     newCommitments,
		VerificationShares:   verificationShares,
		PaillierPublicKey:    append([]byte(nil), s.newPaillierPubs[s.oldKey.Party].PublicKey...),
		PaillierPrivateKey:   append([]byte(nil), s.newPaillierPriv...),
		PaillierProof:        append([]byte(nil), s.newPaillierPubs[s.oldKey.Party].Proof...),
		PaillierPublicKeys:   s.sortedNewPaillierPublicKeys(),
		ShareProof:           shareProofBytes,
		KeygenTranscriptHash: transcriptHash,
		SecurityNotice:       ExperimentalSecurityNotice,
	}
	s.completed = true
	return s.newShare.Validate()
}

func (s *ReshareSession) reshareTranscriptHash(newCommitments [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(reshareTranscriptHashLabel))
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	wire.WriteHashPart(h, s.oldKey.KeygenTranscriptHash)
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
		if _, err := secp.PointFromBytes(commitment); err != nil {
			return err
		}
	}
	return nil
}

func (s *ReshareSession) sortedNewPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.oldKey.Parties))
	for _, id := range s.oldKey.Parties {
		item := s.newPaillierPubs[id]
		out = append(out, PaillierPublicShare{
			Party:     item.Party,
			PublicKey: append([]byte(nil), item.PublicKey...),
			Proof:     append([]byte(nil), item.Proof...),
		})
	}
	return out
}
