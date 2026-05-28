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
	"github.com/islishude/tss/internal/shamir"
	"github.com/islishude/tss/internal/wire"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
	"github.com/islishude/tss/internal/zk/schnorr"
)

const (
	keygenCommitmentsHashLabel = "cggmp21-secp256k1-keygen-commitments-v1"
	keygenTranscriptHashLabel  = "cggmp21-secp256k1-keygen-transcript-v1"
)

// KeygenOptions controls non-default CGGMP21 keygen parameters.
type KeygenOptions struct {
	PaillierBits  int
	SecurityLevel int
	EnableHD      bool
}

// KeygenSession tracks CGGMP21-style DKG state for one local party.
type KeygenSession struct {
	cfg             tss.ThresholdConfig
	log             tss.Logger
	commits         map[tss.PartyID][][]byte
	shares          map[tss.PartyID]*big.Int
	chainCodes      map[tss.PartyID][]byte
	paillier        *pai.PrivateKey
	paillierPubs    map[tss.PartyID]PaillierPublicShare
	primalityProofs map[tss.PartyID][]byte
	completed       bool
	aborted         bool
	keyShare        *KeyShare
}

type keygenCommitmentsPayload struct {
	Commitments       [][]byte `json:"commitments"`
	PaillierPublicKey []byte   `json:"paillier_public_key"`
	PaillierProof     []byte   `json:"paillier_proof"`
	ChainCode         []byte   `json:"chain_code,omitempty"`
	PrimalityProof    []byte   `json:"primality_proof"`
}

type keygenSharePayload struct {
	Share []byte `json:"share"`
}

// StartKeygen starts CGGMP21-style threshold ECDSA key generation.
func StartKeygen(config tss.ThresholdConfig) (*KeygenSession, []tss.Envelope, error) {
	return StartKeygenWithOptions(config, KeygenOptions{})
}

// StartKeygenWithOptions starts keygen with explicit Paillier key-size options.
func StartKeygenWithOptions(config tss.ThresholdConfig, opts KeygenOptions) (*KeygenSession, []tss.Envelope, error) {
	if err := config.Validate(); err != nil {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeInvalidConfig, 0, config.Self, err)
	}
	parties := config.SortedParties()
	config.Parties = parties
	paillierBits := opts.PaillierBits
	if paillierBits == 0 {
		paillierBits = defaultPaillierBits
	}
	var chainCode []byte
	if opts.EnableHD {
		chainCode = make([]byte, 32)
		if _, err := io.ReadFull(config.Reader(), chainCode); err != nil {
			return nil, nil, err
		}
	}
	paillierKey, err := pai.GenerateKey(config.Ctx(), config.Reader(), paillierBits)
	if err != nil {
		return nil, nil, err
	}
	paillierPubBytes, err := paillierKey.PublicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	modProof, err := zkpai.ProveModulus(config.Reader(), keygenModulusDomain(config, config.Self, paillierPubBytes), paillierKey, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	modProofBytes, err := zkpai.Marshal(modProof)
	if err != nil {
		return nil, nil, err
	}
	primalityProof, err := zkpai.ProvePrimality(config.Reader(), keygenModulusDomain(config, config.Self, paillierPubBytes), paillierKey, uint32(config.Self))
	if err != nil {
		return nil, nil, err
	}
	primalityProofBytes, err := zkpai.Marshal(primalityProof)
	if err != nil {
		return nil, nil, err
	}
	poly, err := shamir.RandomPolynomial(config.Reader(), secp.Order(), config.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		point := secp.ScalarBaseMult(secp.ScalarFromBigInt(coeff))
		enc, err := secp.PointBytes(point)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &KeygenSession{
		cfg:     config,
		log:     config.Logger(),
		commits: map[tss.PartyID][][]byte{config.Self: commitments},
		shares:  map[tss.PartyID]*big.Int{config.Self: shamir.Eval(poly, config.Self, secp.Order())},
		chainCodes: map[tss.PartyID][]byte{
			config.Self: append([]byte(nil), chainCode...),
		},
		paillier: paillierKey,
		paillierPubs: map[tss.PartyID]PaillierPublicShare{
			config.Self: {Party: config.Self, PublicKey: paillierPubBytes, Proof: modProofBytes},
		},
		primalityProofs: map[tss.PartyID][]byte{config.Self: append([]byte(nil), primalityProofBytes...)},
	}
	out := make([]tss.Envelope, 0, len(parties))
	commitPayload, err := marshalKeygenCommitmentsPayload(keygenCommitmentsPayload{
		Commitments:       commitments,
		PaillierPublicKey: paillierPubBytes,
		PaillierProof:     modProofBytes,
		ChainCode:         chainCode,
		PrimalityProof:    primalityProofBytes,
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
		payload, err := marshalKeygenSharePayload(keygenSharePayload{Share: scalarBytes(share)})
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

// HandleKeygenMessage validates and applies one keygen envelope.
func (s *KeygenSession) HandleKeygenMessage(env tss.Envelope) (out []tss.Envelope, err error) {
	if s == nil {
		return nil, errors.New("nil keygen session")
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
		p, err := unmarshalKeygenCommitmentsPayload(env.Payload)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenCommitment,
				"malformed keygen commitment payload",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
			)
		}
		if err := validateCommitments(p.Commitments, s.cfg.Threshold); err != nil {
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenCommitment,
				"invalid keygen commitment",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
				rawEvidenceField(evidenceFieldCommitmentsHash, byteSlicesHash(keygenCommitmentsHashLabel, p.Commitments)),
			)
		}
		pk, err := pai.UnmarshalPublicKey(p.PaillierPublicKey)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed Paillier public key",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		proof, err := zkpai.UnmarshalModulusProof(p.PaillierProof)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed Paillier modulus proof",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyModulus(keygenModulusDomain(s.cfg, env.From, p.PaillierPublicKey), pk, uint32(env.From), proof) {
			s.log.Warn(s.cfg.Ctx(), "invalid Paillier modulus proof",
				"party_id", s.cfg.Self,
				"from", env.From,
			)
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid Paillier modulus proof",
				[]tss.PartyID{env.From},
				errors.New("invalid Paillier modulus proof"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		pp, err := zkpai.UnmarshalPrimalityProof(p.PrimalityProof)
		if err != nil {
			return nil, protocolErrorWithEvidence(
				tss.ErrCodeInvalidMessage,
				env,
				tss.EvidenceKindKeygenPaillier,
				"malformed Paillier primality proof",
				[]tss.PartyID{env.From},
				err,
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		if !zkpai.VerifyPrimality(keygenModulusDomain(s.cfg, env.From, p.PaillierPublicKey), pk, uint32(env.From), pp) {
			s.log.Warn(s.cfg.Ctx(), "invalid Paillier primality proof",
				"party_id", s.cfg.Self,
				"from", env.From,
			)
			return nil, verificationErrorWithEvidence(
				env,
				tss.EvidenceKindKeygenPaillier,
				"invalid Paillier primality proof",
				[]tss.PartyID{env.From},
				errors.New("invalid Paillier primality proof"),
				rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
				hashEvidenceField(evidenceFieldObservedPaillierKeyHash, p.PaillierPublicKey),
			)
		}
		s.commits[env.From] = p.Commitments
		if len(p.ChainCode) != 0 && len(p.ChainCode) != 32 {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("chain code must be 32 bytes"))
		}
		s.chainCodes[env.From] = append([]byte(nil), p.ChainCode...)
		s.paillierPubs[env.From] = PaillierPublicShare{Party: env.From, PublicKey: p.PaillierPublicKey, Proof: p.PaillierProof}
		s.primalityProofs[env.From] = append([]byte(nil), p.PrimalityProof...)
	case payloadKeygenShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
		}
		p, err := unmarshalKeygenSharePayload(env.Payload)
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

// KeyShare returns the completed local key share when DKG has finished.
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
	if len(s.commits) != len(s.cfg.Parties) || len(s.shares) != len(s.cfg.Parties) || len(s.paillierPubs) != len(s.cfg.Parties) || len(s.chainCodes) != len(s.cfg.Parties) || len(s.primalityProofs) != len(s.cfg.Parties) {
		return nil
	}
	order := secp.Order()
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.cfg.Self), secp.ScalarFromBigInt(share)); err != nil {
			s.log.Warn(s.cfg.Ctx(), "invalid DKG share",
				"party_id", s.cfg.Self,
				"dealer", dealer,
			)
			evidenceEnv := envelope(s.cfg, 1, dealer, s.cfg.Self, payloadKeygenShare, nil, true)
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{
					Reason:  "invalid DKG share",
					Parties: []tss.PartyID{dealer},
					Evidence: marshalEvidence(
						evidenceEnv,
						tss.EvidenceKindKeygenShare,
						"invalid DKG share",
						rawEvidenceField(evidenceFieldPartiesHash, partySetHash(s.cfg.Parties)),
						rawEvidenceField(evidenceFieldCommitmentsHash, byteSlicesHash(keygenCommitmentsHashLabel, s.commits[dealer])),
					),
				},
				Err: err,
			}
		}
	}
	secret := new(big.Int)
	for _, dealer := range s.cfg.Parties {
		secret.Add(secret, s.shares[dealer])
		secret.Mod(secret, order)
	}
	chainCode, err := aggregateChainCode(s.cfg.Parties, s.chainCodes)
	if err != nil {
		return err
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
	shareProofBytes, err := shareProof.MarshalBinary()
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
	localProofShare := &KeyShare{
		Party:                s.cfg.Self,
		Threshold:            s.cfg.Threshold,
		Parties:              s.cfg.Parties,
		PublicKey:            groupCommitments[0],
		PaillierPublicKey:    localPaillierPub,
		KeygenTranscriptHash: transcriptHash,
	}
	localPaillierProof, err := zkpai.ProveModulus(s.cfg.Reader(), keySharePaillierProofDomain(localProofShare), s.paillier, uint32(s.cfg.Self))
	if err != nil {
		return err
	}
	localPaillierProofBytes, err := zkpai.Marshal(localPaillierProof)
	if err != nil {
		return err
	}
	primalityProofs := make([][]byte, len(s.cfg.Parties))
	for i, id := range s.cfg.Parties {
		primalityProofs[i] = append([]byte(nil), s.primalityProofs[id]...)
	}
	s.keyShare = &KeyShare{
		Version:                 tss.Version,
		Party:                   s.cfg.Self,
		Threshold:               s.cfg.Threshold,
		Parties:                 append([]tss.PartyID(nil), s.cfg.Parties...),
		PublicKey:               append([]byte(nil), groupCommitments[0]...),
		ChainCode:               chainCode,
		Secret:                  scalarBytes(secret),
		GroupCommitments:        groupCommitments,
		VerificationShares:      verificationShares,
		PaillierPublicKey:       localPaillierPub,
		PaillierPrivateKey:      localPaillierPriv,
		PaillierProof:           localPaillierProofBytes,
		PaillierPrimalityProof:  append([]byte(nil), s.primalityProofs[s.cfg.Self]...),
		PaillierPrimalityProofs: primalityProofs,
		PaillierPublicKeys:      s.sortedPaillierPublicKeys(),
		ShareProof:              shareProofBytes,
		KeygenTranscriptHash:    transcriptHash,
		SecurityNotice:          ExperimentalSecurityNotice,
	}
	s.completed = true
	pubKeyHash := sha256.Sum256(groupCommitments[0])
	s.log.Info(s.cfg.Ctx(), "keygen complete",
		"party_id", s.cfg.Self,
		"session_id", fmt.Sprintf("%x", s.cfg.SessionID[:8]),
		"public_key_hash", fmt.Sprintf("%x", pubKeyHash[:8]),
	)
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
	wire.WriteHashPart(h, []byte(keygenTranscriptHashLabel))
	wire.WriteHashPart(h, s.cfg.SessionID[:])
	for _, id := range s.cfg.Parties {
		wire.WriteHashPart(h, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		for _, commitment := range s.commits[id] {
			wire.WriteHashPart(h, commitment)
		}
		item := s.paillierPubs[id]
		wire.WriteHashPart(h, item.PublicKey)
		wire.WriteHashPart(h, item.Proof)
		wire.WriteHashPart(h, s.chainCodes[id])
	}
	for _, commitment := range groupCommitments {
		wire.WriteHashPart(h, commitment)
	}
	return h.Sum(nil)
}

func aggregateChainCode(parties []tss.PartyID, chainCodes map[tss.PartyID][]byte) ([]byte, error) {
	enabled := false
	for _, id := range parties {
		switch len(chainCodes[id]) {
		case 0:
		case 32:
			enabled = true
		default:
			return nil, fmt.Errorf("invalid chain code for party %d", id)
		}
	}
	if !enabled {
		return nil, nil
	}
	out := make([]byte, 32)
	for _, id := range parties {
		if len(chainCodes[id]) != 32 {
			return nil, fmt.Errorf("missing chain code for party %d", id)
		}
		for i := range out {
			out[i] ^= chainCodes[id][i]
		}
	}
	return out, nil
}

func verificationShareFor(shares []VerificationShare, id tss.PartyID) ([]byte, bool) {
	for _, share := range shares {
		if share.Party == id {
			return share.PublicKey, true
		}
	}
	return nil, false
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
