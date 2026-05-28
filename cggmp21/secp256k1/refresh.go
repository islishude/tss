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
	refreshTranscriptHashLabel = "cggmp21-secp256k1-refresh-transcript-v1"
)

// RefreshSession refreshes CGGMP21 key shares and rotates Paillier keys while
// preserving the group public key and chain code. Unlike ReshareSession, the
// participant set is fixed to the original key's party set. Each existing
// participant generates a polynomial with zero constant term (to refresh the
// secret share) and a new Paillier keypair (to rotate encryption material).
type RefreshSession struct {
	oldKey                     *KeyShare
	cfg                        tss.ThresholdConfig
	log                        tss.Logger
	commits                    map[tss.PartyID][][]byte
	shares                     map[tss.PartyID]*big.Int
	completed                  bool
	aborted                    bool
	newShare                   *KeyShare
	ownPoly                    []*big.Int
	newPaillier                *pai.PrivateKey
	newPaillierPubs            map[tss.PartyID]PaillierPublicShare
	newPaillierPriv            []byte
	newPaillierPrimalityProof  []byte
	newPaillierPrimalityProofs map[tss.PartyID][]byte
}

// StartRefresh starts CGGMP21 key-share refresh with Paillier key rotation.
// The participant set is fixed to oldKey.Parties; unlike StartReshare, the
// caller cannot change the party set. The group public key and chain code
// are preserved from the original key share.
func StartRefresh(oldKey *KeyShare, config tss.ThresholdConfig) (*RefreshSession, []tss.Envelope, error) {
	if err := oldKey.requireMPCMaterial(); err != nil {
		return nil, nil, err
	}
	config.Parties = append([]tss.PartyID(nil), oldKey.Parties...)
	if err := config.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
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
	modProof, err := zkpai.ProveModulus(config.Reader(), refreshPaillierDomain(config, config.Self, newPaillierPubBytes), newPaillierKey, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return nil, nil, err
	}
	// Generate primality proof for the new Paillier key (Π^prm).
	primalityProof, err := zkpai.ProvePrimality(config.Reader(), refreshPaillierDomain(config, config.Self, newPaillierPubBytes), newPaillierKey, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	primalityProofBytes, err := zkpai.Marshal(primalityProof)
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
		oldKey:                    oldKey,
		cfg:                       config,
		log:                       config.Logger(),
		commits:                   map[tss.PartyID][][]byte{oldKey.Party: commitments},
		shares:                    map[tss.PartyID]*big.Int{oldKey.Party: shamir.Eval(poly, oldKey.Party, secp.Order())},
		ownPoly:                   poly,
		newPaillier:               newPaillierKey,
		newPaillierPriv:           newPaillierPriv,
		newPaillierPrimalityProof: primalityProofBytes,
		newPaillierPrimalityProofs: map[tss.PartyID][]byte{
			oldKey.Party: primalityProofBytes,
		},
		newPaillierPubs: map[tss.PartyID]PaillierPublicShare{
			oldKey.Party: {Party: oldKey.Party, PublicKey: newPaillierPubBytes, Proof: modProofBytes},
		},
	}
	commitPayload, err := marshalRefreshCommitmentsPayload(refreshCommitmentsPayload{
		Commitments:       commitments,
		PaillierPublicKey: newPaillierPubBytes,
		PaillierProof:     modProofBytes,
		PrimalityProof:    primalityProofBytes,
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
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
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
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if len(p.PrimalityProof) == 0 {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"empty refresh Paillier primality proof",
				[]tss.PartyID{env.From},
				errors.New("empty refresh Paillier primality proof"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		pp, err := zkpai.UnmarshalPrimalityProof(p.PrimalityProof)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed refresh Paillier primality proof",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyPrimality(refreshPaillierDomain(s.cfg, env.From, p.PaillierPublicKey), pk, uint32(env.From), pp) {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid refresh Paillier primality proof",
				[]tss.PartyID{env.From},
				errors.New("invalid refresh Paillier primality proof"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.oldKey.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		s.commits[env.From] = p.Commitments
		s.newPaillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
		s.newPaillierPrimalityProofs[env.From] = p.PrimalityProof
	case payloadRefreshShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate refresh share"))
		}
		p, err := unmarshalRefreshSharePayload(env.Payload)
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

// KeyShare returns the refreshed key share when refresh completes.
func (s *RefreshSession) KeyShare() (*KeyShare, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.newShare, true
}

func (s *RefreshSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.oldKey.Parties) || len(s.shares) != len(s.oldKey.Parties) || len(s.newPaillierPubs) != len(s.oldKey.Parties) || len(s.newPaillierPrimalityProofs) != len(s.oldKey.Parties) {
		return nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.oldKey.Party), secp.ScalarFromBigInt(share)); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{Reason: "invalid refresh share", Parties: []tss.PartyID{dealer}},
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
			if len(s.commits[dealer][degree]) == 0 {
				continue
			}
			p, err := secp.PointFromBytes(s.commits[dealer][degree])
			if err != nil {
				return err
			}
			points = append(points, p)
		}
		if degree < len(s.oldKey.GroupCommitments) {
			if len(s.oldKey.GroupCommitments[degree]) > 0 {
				oldCommitment, err := secp.PointFromBytes(s.oldKey.GroupCommitments[degree])
				if err != nil {
					return err
				}
				points = append(points, oldCommitment)
			}
		}
		if len(points) == 0 {
			newCommitments[degree] = nil
			continue
		}
		enc, err := secp.PointBytes(secp.AddPoints(points...))
		if err != nil {
			return err
		}
		newCommitments[degree] = enc
	}
	verificationShares := make([]VerificationShare, 0, len(s.oldKey.Parties))
	for _, id := range s.oldKey.Parties {
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
	transcriptHash := s.refreshTranscriptHash(newCommitments)
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
	// Construct a temporary share for domain-separated Paillier proof binding.
	localProofShare := &KeyShare{
		Party:                s.oldKey.Party,
		Threshold:            s.cfg.Threshold,
		Parties:              s.oldKey.Parties,
		PublicKey:            newCommitments[0],
		PaillierPublicKey:    s.newPaillierPubs[s.oldKey.Party].PublicKey,
		KeygenTranscriptHash: transcriptHash,
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
		Version:                 tss.Version,
		Party:                   s.oldKey.Party,
		Threshold:               s.cfg.Threshold,
		Parties:                 append([]tss.PartyID(nil), s.oldKey.Parties...),
		PublicKey:               append([]byte(nil), newCommitments[0]...),
		ChainCode:               append([]byte(nil), s.oldKey.ChainCode...),
		Secret:                  scalarBytes(newSecret),
		GroupCommitments:        newCommitments,
		VerificationShares:      verificationShares,
		PaillierPublicKey:       append([]byte(nil), s.newPaillierPubs[s.oldKey.Party].PublicKey...),
		PaillierPrivateKey:      append([]byte(nil), s.newPaillierPriv...),
		PaillierProof:           paillierProofBytes,
		PaillierPrimalityProof:  append([]byte(nil), s.newPaillierPrimalityProof...),
		PaillierPrimalityProofs: sortedPaillierPrimalityProofs(s.oldKey.Parties, s.newPaillierPrimalityProofs),
		PaillierPublicKeys:      s.sortedNewPaillierPublicKeys(),
		ShareProof:              shareProofBytes,
		KeygenTranscriptHash:    transcriptHash,
		SecurityNotice:          ExperimentalSecurityNotice,
	}
	s.completed = true
	s.log.Info(s.cfg.Ctx(), "refresh complete",
		"party_id", s.oldKey.Party,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
	)
	return s.newShare.Validate()
}

func (s *RefreshSession) refreshTranscriptHash(newCommitments [][]byte) []byte {
	h := sha256.New()
	wire.WriteHashPart(h, []byte(refreshTranscriptHashLabel))
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	wire.WriteHashPart(h, s.oldKey.KeygenTranscriptHash)
	for _, commitment := range newCommitments {
		wire.WriteHashPart(h, commitment)
	}
	return h.Sum(nil)
}

func validateRefreshCommitments(commitments [][]byte, threshold int) error {
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

func (s *RefreshSession) sortedNewPaillierPublicKeys() []PaillierPublicShare {
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

// Destroy clears sensitive session state. Use only on material that will
// never be needed for processing further messages.
func (s *RefreshSession) Destroy() {
	if s == nil {
		return
	}
	s.aborted = true
	clear(s.newPaillierPriv)
	s.newPaillier = nil
}
