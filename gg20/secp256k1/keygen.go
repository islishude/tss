package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	"github.com/islishude/tss/internal/shamir"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

type KeygenOptions struct {
	PaillierBits int
}

type KeygenSession struct {
	cfg          tss.ThresholdConfig
	commits      map[tss.PartyID][][]byte
	shares       map[tss.PartyID]*big.Int
	paillier     *pai.PrivateKey
	paillierPubs map[tss.PartyID]PaillierPublicShare
	completed    bool
	keyShare     *KeyShare
}

type keygenCommitmentsPayload struct {
	Commitments       [][]byte `json:"commitments"`
	PaillierPublicKey []byte   `json:"paillier_public_key"`
	PaillierProof     []byte   `json:"paillier_proof"`
}

type keygenSharePayload struct {
	Share []byte `json:"share"`
}

func StartKeygen(config tss.ThresholdConfig) (*KeygenSession, []tss.Envelope, error) {
	return StartKeygenWithOptions(config, KeygenOptions{})
}

func StartKeygenWithOptions(config tss.ThresholdConfig, opts KeygenOptions) (*KeygenSession, []tss.Envelope, error) {
	if err := config.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	parties := config.SortedParties()
	config.Parties = parties
	paillierBits := opts.PaillierBits
	if paillierBits == 0 {
		paillierBits = DefaultPaillierBits
	}
	paillierKey, err := pai.GenerateKey(config.Reader(), paillierBits)
	if err != nil {
		return nil, nil, err
	}
	paillierPubBytes, err := paillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	modProof, err := zkpai.ProveModulus(config.SessionID[:], &paillierKey.PublicKey, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return nil, nil, err
	}
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := secp.ScalarBaseMult(coeff)
		enc, err := secp.PointBytes(point)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &KeygenSession{
		cfg:      config,
		commits:  map[tss.PartyID][][]byte{config.Self: commitments},
		shares:   map[tss.PartyID]*big.Int{config.Self: shamir.Eval(poly, config.Self, secp.Order())},
		paillier: paillierKey,
		paillierPubs: map[tss.PartyID]PaillierPublicShare{
			config.Self: {Party: config.Self, PublicKey: paillierPubBytes, Proof: modProofBytes},
		},
	}
	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := json.Marshal(keygenCommitmentsPayload{
		Commitments:       commitments,
		PaillierPublicKey: paillierPubBytes,
		PaillierProof:     modProofBytes,
	})
	if err != nil {
		return nil, nil, err
	}
	out = append(out, envelope(config, 1, config.Self, 0, payloadKeygenCommitments, commitPayload, false))
	for _, id := range parties {
		if id == config.Self {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := json.Marshal(keygenSharePayload{Share: scalarBytes(share)})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, config.Self, id, payloadKeygenShare, payload, true))
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

func (s *KeygenSession) HandleKeygenMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
	}
	if err := env.ValidateBasic(protocol, s.cfg.SessionID, s.cfg.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if env.To != 0 && env.To != s.cfg.Self {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("keygen only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadKeygenCommitments:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate commitments"))
		}
		var p keygenCommitmentsPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
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
		if !zkpai.VerifyModulus(s.cfg.SessionID[:], pk, uint32(env.From), proof) {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, errors.New("invalid Paillier modulus proof"))
		}
		s.commits[env.From] = p.Commitments
		s.paillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
	case payloadKeygenShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
		}
		var p keygenSharePayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		share, err := secp.ParseScalar(p.Share)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		s.shares[env.From] = share
	default:
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, fmt.Errorf("unexpected payload type %q", env.PayloadType))
	}
	return nil, s.tryComplete()
}

func (s *KeygenSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.keyShare, true
}

func (s *KeygenSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) || len(s.paillierPubs) != len(s.cfg.Parties) {
		return nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.cfg.Self), share); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{Reason: "invalid DKG share", Parties: []tss.PartyID{dealer}},
				Err:   err,
			}
		}
	}
	secret := new(big.Int)
	for _, dealer := range s.cfg.Parties {
		secret.Add(secret, s.shares[dealer])
		secret.Mod(secret, order)
	}
	groupCommitments := make([][]byte, s.cfg.Threshold)
	for degree := 0; degree < s.cfg.Threshold; degree++ {
		points := make([]*secp.Point, 0, len(s.cfg.Parties))
		for _, dealer := range s.cfg.Parties {
			p, err := secp.PointFromBytes(s.commits[dealer][degree])
			if err != nil {
				return err
			}
			points = append(points, p)
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return err
		}
		groupCommitments[degree] = enc
	}
	verificationShares := make([]VerificationShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		pub, err := secp.EvalCommitments(groupCommitments, uint32(id))
		if err != nil {
			return err
		}
		enc, err := secp.PointBytes(pub)
		if err != nil {
			return err
		}
		verificationShares = append(verificationShares, VerificationShare{Party: id, PublicKey: enc})
	}
	transcriptHash := s.keygenTranscriptHash(groupCommitments)
	localVerificationShare, ok := verificationShareFor(verificationShares, s.cfg.Self)
	if !ok {
		return errors.New("missing local verification share")
	}
	shareProof, proofPublic, err := schnorr.Prove(transcriptHash, secret)
	if err != nil {
		return err
	}
	if !bytes.Equal(proofPublic, localVerificationShare) {
		return errors.New("local share proof public key mismatch")
	}
	shareProofBytes, err := json.Marshal(shareProof)
	if err != nil {
		return err
	}
	localPaillierPub, err := s.paillier.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	localPaillierPriv, err := s.paillier.MarshalBinary()
	if err != nil {
		return err
	}
	localPaillierProof, err := zkpai.ProveModulus(transcriptHash, &s.paillier.PublicKey, uint32(s.cfg.Self))
	if err != nil {
		return err
	}
	localPaillierProofBytes, err := zkpai.Marshal(localPaillierProof)
	if err != nil {
		return err
	}
	s.keyShare = &KeyShare{
		Version:              tss.Version,
		Party:                s.cfg.Self,
		Threshold:            s.cfg.Threshold,
		Parties:              append([]tss.PartyID(nil), s.cfg.Parties...),
		PublicKey:            append([]byte(nil), groupCommitments[0]...),
		Secret:               scalarBytes(secret),
		GroupCommitments:     groupCommitments,
		VerificationShares:   verificationShares,
		PaillierPublicKey:    localPaillierPub,
		PaillierPrivateKey:   localPaillierPriv,
		PaillierProof:        localPaillierProofBytes,
		PaillierPublicKeys:   s.sortedPaillierPublicKeys(),
		ShareProof:           shareProofBytes,
		KeygenTranscriptHash: transcriptHash,
		SecurityNotice:       ExperimentalSecurityNotice,
	}
	s.completed = true
	return s.keyShare.Validate()
}

func (s *KeygenSession) sortedPaillierPublicKeys() []PaillierPublicShare {
	out := make([]PaillierPublicShare, 0, len(s.cfg.Parties))
	for _, id := range s.cfg.Parties {
		item := s.paillierPubs[id]
		out = append(out, PaillierPublicShare{
			Party:     item.Party,
			PublicKey: append([]byte(nil), item.PublicKey...),
			Proof:     append([]byte(nil), item.Proof...),
		})
	}
	return out
}

func (s *KeygenSession) keygenTranscriptHash(groupCommitments [][]byte) []byte {
	h := sha256.New()
	writeHashPart(h, []byte("gg20-secp256k1-keygen-transcript-v1"))
	writeHashPart(h, s.cfg.SessionID[:])
	for _, id := range s.cfg.Parties {
		writeHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		for _, commitment := range s.commits[id] {
			writeHashPart(h, commitment)
		}
		item := s.paillierPubs[id]
		writeHashPart(h, item.PublicKey)
		writeHashPart(h, item.Proof)
	}
	for _, commitment := range groupCommitments {
		writeHashPart(h, commitment)
	}
	return h.Sum(nil)
}

func verificationShareFor(shares []VerificationShare, id tss.PartyID) ([]byte, bool) {
	for _, share := range shares {
		if share.Party == id {
			return share.PublicKey, true
		}
	}
	return nil, false
}

func writeHashPart(h interface{ Write([]byte) (int, error) }, part []byte) {
	_, _ = h.Write([]byte{byte(len(part) >> 24), byte(len(part) >> 16), byte(len(part) >> 8), byte(len(part))})
	_, _ = h.Write(part)
}

func validateCommitments(commitments [][]byte, threshold int) error {
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
