package secp256k1

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
)

type Presign struct {
	Version        uint16        `json:"version"`
	Party          tss.PartyID   `json:"party"`
	Threshold      int           `json:"threshold"`
	Signers        []tss.PartyID `json:"signers"`
	R              []byte        `json:"r"`
	NonceShare     []byte        `json:"nonce_share"`
	Used           bool          `json:"used"` // local nonce-reuse guard
	SecurityNotice string        `json:"security_notice"`
}

type PresignSession struct {
	key       *KeyShare
	sessionID tss.SessionID
	config    tss.ThresholdConfig
	signers   []tss.PartyID
	commits   map[tss.PartyID][][]byte
	shares    map[tss.PartyID]*big.Int
	completed bool
	presign   *Presign
}

type SignSession struct {
	key       *KeyShare
	presign   *Presign
	sessionID tss.SessionID
	digest    []byte
	lowS      bool
	shares    map[tss.PartyID]signShare
	completed bool
	signature *Signature
}

type presignCommitmentsPayload struct {
	Commitments [][]byte `json:"commitments"`
}

type presignSharePayload struct {
	Share []byte `json:"share"`
}

type signShare struct {
	SecretShare []byte `json:"secret_share"`
	NonceShare  []byte `json:"nonce_share"`
}

func StartPresign(key *KeyShare, sessionID tss.SessionID, signers []tss.PartyID) (*PresignSession, []tss.Envelope, error) {
	if err := key.Validate(); err != nil {
		return nil, nil, err
	}
	signers = tss.SortParties(signers)
	if len(signers) < key.Threshold {
		return nil, nil, errors.New("not enough signers")
	}
	if !tss.ContainsParty(signers, key.Party) {
		return nil, nil, errors.New("local party is not in signer set")
	}
	config := tss.ThresholdConfig{Threshold: key.Threshold, Parties: signers, Self: key.Party, SessionID: sessionID}
	// This experimental presign creates a Shamir-shared ECDSA nonce. Full GG20
	// would replace the later reconstruction path with Paillier MtA and ZK proofs.
	poly, err := shamir.RandomPolynomial(nil, secp.Order(), key.Threshold, nil)
	if err != nil {
		return nil, nil, err
	}
	commitments := make([][]byte, len(poly))
	for i, coeff := range poly {
		enc, err := secp.PointBytes(secp.ScalarBaseMult(coeff))
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = enc
	}
	s := &PresignSession{
		key:       key,
		sessionID: sessionID,
		config:    config,
		signers:   signers,
		commits:   map[tss.PartyID][][]byte{key.Party: commitments},
		shares:    map[tss.PartyID]*big.Int{key.Party: shamir.Eval(poly, key.Party, secp.Order())},
	}
	out := make([]tss.Envelope, 0, len(signers))
	payload, err := json.Marshal(presignCommitmentsPayload{Commitments: commitments})
	if err != nil {
		return nil, nil, err
	}
	out = append(out, envelope(config, 1, key.Party, 0, payloadPresignCommitment, payload, false))
	for _, id := range signers {
		if id == key.Party {
			continue
		}
		share := shamir.Eval(poly, id, secp.Order())
		payload, err := json.Marshal(presignSharePayload{Share: scalarBytes(share)})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, envelope(config, 1, key.Party, id, payloadPresignShare, payload, true))
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, out, nil
}

func (s *PresignSession) HandlePresignMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil presign session")
	}
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.Round != 1 {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("presign only accepts round 1 messages"))
	}
	switch env.PayloadType {
	case payloadPresignCommitment:
		if _, ok := s.commits[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate commitments"))
		}
		var p presignCommitmentsPayload
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
		}
		if err := validateCommitments(p.Commitments, s.key.Threshold); err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		s.commits[env.From] = p.Commitments
	case payloadPresignShare:
		if _, ok := s.shares[env.From]; ok {
			return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate share"))
		}
		var p presignSharePayload
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

func (s *PresignSession) Presign() (*Presign, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return s.presign, true
}

func (s *PresignSession) tryComplete() error {
	if s.completed {
		return nil
	}
	if len(s.commits) != len(s.signers) || len(s.shares) != len(s.signers) {
		return nil
	}
	for dealer, share := range s.shares {
		if err := secp.VerifyShare(s.commits[dealer], uint32(s.key.Party), share); err != nil {
			return &tss.ProtocolError{
				Code:  tss.ErrCodeVerification,
				Round: 1,
				Party: dealer,
				Blame: &tss.Blame{Reason: "invalid presign nonce share", Parties: []tss.PartyID{dealer}},
				Err:   err,
			}
		}
	}
	order := secp.Order()
	nonceShare := new(big.Int)
	for _, dealer := range s.signers {
		nonceShare.Add(nonceShare, s.shares[dealer])
		nonceShare.Mod(nonceShare, order)
	}
	constantPoints := make([]*secp.Point, 0, len(s.signers))
	for _, dealer := range s.signers {
		p, err := secp.PointFromBytes(s.commits[dealer][0])
		if err != nil {
			return err
		}
		constantPoints = append(constantPoints, p)
	}
	R, err := secp.PointBytes(secp.AddPoints(constantPoints...))
	if err != nil {
		return err
	}
	s.presign = &Presign{
		Version:        tss.Version,
		Party:          s.key.Party,
		Threshold:      s.key.Threshold,
		Signers:        append([]tss.PartyID(nil), s.signers...),
		R:              R,
		NonceShare:     scalarBytes(nonceShare),
		SecurityNotice: ExperimentalSecurityNotice,
	}
	s.completed = true
	return nil
}

func StartSignDigest(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte) (*SignSession, []tss.Envelope, error) {
	if err := key.Validate(); err != nil {
		return nil, nil, err
	}
	return StartSignDigestWithOptions(key, presign, sessionID, digest32, true)
}

func StartSignDigestWithOptions(key *KeyShare, presign *Presign, sessionID tss.SessionID, digest32 []byte, lowS bool) (*SignSession, []tss.Envelope, error) {
	if err := key.Validate(); err != nil {
		return nil, nil, err
	}
	if err := validatePresign(key, presign); err != nil {
		return nil, nil, err
	}
	if len(digest32) != 32 {
		return nil, nil, errors.New("digest must be 32 bytes")
	}
	if presign.Used {
		return nil, nil, tss.NewProtocolError(tss.ErrCodeConsumed, 2, key.Party, errors.New("presign already used"))
	}
	// Consume before emitting any share so retries cannot accidentally reuse a nonce.
	presign.Used = true
	payload, err := json.Marshal(signShare{SecretShare: key.Secret, NonceShare: presign.NonceShare})
	if err != nil {
		return nil, nil, err
	}
	env := tss.Envelope{
		Protocol:             protocol,
		Version:              tss.Version,
		SessionID:            sessionID,
		Round:                2,
		From:                 key.Party,
		PayloadType:          payloadSignShare,
		Payload:              payload,
		ConfidentialRequired: true,
	}.WithTranscriptHash()
	s := &SignSession{
		key:       key,
		presign:   presign,
		sessionID: sessionID,
		digest:    append([]byte(nil), digest32...),
		lowS:      lowS,
		shares:    map[tss.PartyID]signShare{key.Party: {SecretShare: append([]byte(nil), key.Secret...), NonceShare: append([]byte(nil), presign.NonceShare...)}},
	}
	if err := s.tryComplete(); err != nil {
		return nil, nil, err
	}
	return s, []tss.Envelope{env}, nil
}

func (s *SignSession) HandleSignMessage(env tss.Envelope) ([]tss.Envelope, error) {
	if s == nil {
		return nil, errors.New("nil sign session")
	}
	if err := env.ValidateBasic(protocol, s.sessionID, s.key.Parties); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if !tss.ContainsParty(s.presign.Signers, env.From) {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("sender is not in signer set"))
	}
	if env.To != 0 && env.To != s.key.Party {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, errors.New("message addressed to another party"))
	}
	if env.Round != 2 || env.PayloadType != payloadSignShare {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("expected round 2 sign share"))
	}
	if _, ok := s.shares[env.From]; ok {
		return nil, tss.NewProtocolError(tss.ErrCodeDuplicate, env.Round, env.From, errors.New("duplicate sign share"))
	}
	var p signShare
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if _, err := secp.ParseScalar(p.SecretShare); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	if _, err := secp.ParseScalar(p.NonceShare); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvalidMessage, env.Round, env.From, err)
	}
	s.shares[env.From] = p
	return nil, s.tryComplete()
}

func (s *SignSession) Signature() (*Signature, bool) {
	if s == nil || !s.completed {
		return nil, false
	}
	return &Signature{R: append([]byte(nil), s.signature.R...), S: append([]byte(nil), s.signature.S...)}, true
}

func (s *SignSession) tryComplete() error {
	if s.completed || len(s.shares) != len(s.presign.Signers) {
		return nil
	}
	secretShares := make([]shamir.Share, 0, len(s.presign.Signers))
	nonceShares := make([]shamir.Share, 0, len(s.presign.Signers))
	for _, id := range s.presign.Signers {
		share := s.shares[id]
		secret, err := secp.ParseScalar(share.SecretShare)
		if err != nil {
			return err
		}
		nonce, err := secp.ParseScalar(share.NonceShare)
		if err != nil {
			return err
		}
		secretShares = append(secretShares, shamir.Share{ID: id, Value: secret})
		nonceShares = append(nonceShares, shamir.Share{ID: id, Value: nonce})
	}
	// Experimental shortcut: reconstruct threshold secret and nonce locally.
	// This is intentionally not a production GG20 signing step.
	secret, err := shamir.InterpolateConstant(secretShares, secp.Order())
	if err != nil {
		return err
	}
	nonce, err := shamir.InterpolateConstant(nonceShares, secp.Order())
	if err != nil {
		return err
	}
	r, sigS, err := secp.SignECDSAWithNonce(s.digest, secret, nonce, s.lowS)
	if err != nil {
		return err
	}
	public, err := secp.PointFromBytes(s.key.PublicKey)
	if err != nil {
		return err
	}
	if !secp.VerifyECDSA(public, s.digest, r, sigS) {
		return errors.New("ECDSA signature failed verification")
	}
	s.signature = &Signature{R: scalarBytes(r), S: scalarBytes(sigS)}
	s.completed = true
	return nil
}

func VerifyDigest(publicKey, digest32 []byte, sig *Signature) bool {
	public, err := secp.PointFromBytes(publicKey)
	if err != nil {
		return false
	}
	if sig == nil {
		return false
	}
	r, err := secp.ParseScalar(sig.R)
	if err != nil {
		return false
	}
	s, err := secp.ParseScalar(sig.S)
	if err != nil {
		return false
	}
	return secp.VerifyECDSA(public, digest32, r, s)
}

func SignDigest(digest32 []byte, signers []*KeyShare) ([]byte, *Signature, error) {
	if len(signers) == 0 {
		return nil, nil, errors.New("no signers")
	}
	ids := make([]tss.PartyID, len(signers))
	shares := make(map[tss.PartyID]*KeyShare, len(signers))
	for i, share := range signers {
		if err := share.Validate(); err != nil {
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
	presignMessages := make([]tss.Envelope, 0)
	for _, id := range ids {
		session, out, err := StartPresign(shares[id], presignID, ids)
		if err != nil {
			return nil, nil, err
		}
		presignSessions[id] = session
		presignMessages = append(presignMessages, out...)
	}
	for _, env := range presignMessages {
		for _, id := range ids {
			if id == env.From {
				continue
			}
			if env.To != 0 && env.To != id {
				continue
			}
			if _, err := presignSessions[id].HandlePresignMessage(env); err != nil {
				return nil, nil, err
			}
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
		session, out, err := StartSignDigest(shares[id], presign, signID, digest32)
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
			return signers[0].PublicKeyBytes(), sig, nil
		}
	}
	return nil, nil, errors.New("signature not completed")
}

func validatePresign(key *KeyShare, presign *Presign) error {
	if presign == nil {
		return errors.New("nil presign")
	}
	if presign.Version != tss.Version {
		return fmt.Errorf("unexpected presign version %d", presign.Version)
	}
	if presign.Party != key.Party {
		return errors.New("presign party mismatch")
	}
	if presign.Threshold != key.Threshold {
		return errors.New("presign threshold mismatch")
	}
	if len(presign.Signers) < key.Threshold || !tss.ContainsParty(presign.Signers, key.Party) {
		return errors.New("invalid presign signer set")
	}
	if _, err := secp.PointFromBytes(presign.R); err != nil {
		return fmt.Errorf("invalid presign R: %w", err)
	}
	if _, err := secp.ParseScalar(presign.NonceShare); err != nil {
		return fmt.Errorf("invalid nonce share: %w", err)
	}
	return nil
}
